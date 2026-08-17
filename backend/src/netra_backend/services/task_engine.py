"""NETRA Task Engine & State Machine Lifecycle Service.

Provides explicit state transition rules, atomic task claiming, idempotency, audit logging,
and task lifecycle orchestration.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from netra_backend.logging import get_logger
from netra_backend.models import AuditEvent, Device, Task, TaskExecution
from netra_backend.rls import with_tenant_context
from netra_shared.enums import TaskStatus
from netra_shared.schemas.task import (
    CapabilityEnum,
    FindingItem,
    TaskPriorityEnum,
)

logger = get_logger(__name__)

# Explicit Allowed State Transitions
ALLOWED_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.CREATED: {TaskStatus.QUEUED, TaskStatus.CANCELLED},
    TaskStatus.QUEUED: {
        TaskStatus.DELIVERED,
        TaskStatus.RUNNING,
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.EXPIRED,
        TaskStatus.CANCELLED,
    },
    TaskStatus.DELIVERED: {
        TaskStatus.ACKNOWLEDGED,
        TaskStatus.RUNNING,
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.TIMEOUT,
        TaskStatus.CANCELLED,
    },
    TaskStatus.ACKNOWLEDGED: {
        TaskStatus.RUNNING,
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.TIMEOUT,
    },
    TaskStatus.RUNNING: {
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.TIMEOUT,
    },
    # Terminal states: no further transitions allowed
    TaskStatus.COMPLETED: set(),
    TaskStatus.FAILED: set(),
    TaskStatus.CANCELLED: set(),
    TaskStatus.EXPIRED: set(),
    TaskStatus.TIMEOUT: set(),
}


def validate_state_transition(current_status: TaskStatus, new_status: TaskStatus) -> None:
    """Validate whether transitioning from current_status to new_status is permitted.

    Raises:
        HTTPException: If transition is invalid.
    """
    if current_status == new_status:
        # Idempotent re-entry
        return

    allowed = ALLOWED_TRANSITIONS.get(current_status, set())
    if new_status not in allowed:
        detail_msg = (
            f"Invalid task state transition: Cannot transition from "
            f"'{current_status.value}' to '{new_status.value}'."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail_msg,
        )


async def create_task(
    db: AsyncSession,
    tenant_id: str,
    user_id: str,
    target_device_id: str,
    capability: CapabilityEnum,
    parameters: dict[str, Any],
    priority: TaskPriorityEnum = TaskPriorityEnum.NORMAL,
) -> Task:
    """Create and queue a new task transactionally."""
    async with with_tenant_context(tenant_id, db):
        # Verify target device exists and belongs to tenant
        device_stmt = select(Device).where(
            Device.id == target_device_id, Device.tenant_id == tenant_id
        )
        res = await db.execute(device_stmt)
        device = res.scalar_one_or_none()
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target device '{target_device_id}' not found in tenant.",
            )

        now = datetime.now(UTC)
        task = Task(
            tenant_id=tenant_id,
            device_id=target_device_id,
            created_by_id=user_id,
            capability=capability.value,
            parameters=parameters,
            status=TaskStatus.QUEUED,
            priority=priority,
            queued_at=now,
        )
        db.add(task)
        await db.flush()

        audit = AuditEvent(
            tenant_id=tenant_id,
            actor_id=user_id,
            actor_type="USER",
            event="TASK_CREATED",
            details={
                "task_id": task.id,
                "device_id": target_device_id,
                "capability": capability.value,
                "priority": priority.value,
            },
        )
        db.add(audit)
        await db.commit()

        logger.info(
            "task_created_and_queued",
            task_id=task.id,
            tenant_id=tenant_id,
            device_id=target_device_id,
            capability=capability.value,
        )
        return task


async def claim_next_task_for_device(
    db: AsyncSession,
    tenant_id: str,
    device_id: str,
    request_id: str = "req_internal",
) -> tuple[Task | None, str | None]:
    """Atomically claim the highest priority QUEUED task for device.

    Returns:
        tuple[Task | None, execution_id | None]
    """
    async with with_tenant_context(tenant_id, db):
        # Candidate selection
        stmt = (
            select(Task.id)
            .where(
                Task.tenant_id == tenant_id,
                Task.device_id == device_id,
                Task.status == TaskStatus.QUEUED,
            )
            .order_by(
                Task.priority.desc(),
                Task.created_at.asc(),
            )
            .limit(1)
        )
        res = await db.execute(stmt)
        candidate_id = res.scalar_one_or_none()

        if not candidate_id:
            return None, None

        now = datetime.now(UTC)

        # Atomic conditional update
        update_stmt = (
            update(Task)
            .where(
                Task.id == candidate_id,
                Task.status == TaskStatus.QUEUED,
            )
            .values(status=TaskStatus.DELIVERED, delivered_at=now)
        )
        update_res = await db.execute(update_stmt)
        if getattr(update_res, "rowcount", 0) == 0:
            return None, None

        task = await db.get(Task, candidate_id)
        if not task:
            return None, None

        execution_id = f"exec_{uuid.uuid4().hex}"

        execution = TaskExecution(
            task_id=task.id,
            tenant_id=tenant_id,
            execution_id=execution_id,
            request_id=request_id,
            status=TaskStatus.DELIVERED,
            started_at=now,
        )
        db.add(execution)

        audit = AuditEvent(
            tenant_id=tenant_id,
            actor_id=device_id,
            actor_type="AGENT",
            event="TASK_DELIVERED",
            details={
                "task_id": task.id,
                "execution_id": execution_id,
                "device_id": device_id,
            },
        )
        db.add(audit)
        await db.commit()

        logger.info(
            "task_claimed_and_delivered",
            task_id=task.id,
            tenant_id=tenant_id,
            device_id=device_id,
            execution_id=execution_id,
        )
        return task, execution_id


async def acknowledge_task(
    db: AsyncSession,
    tenant_id: str,
    device_id: str,
    task_id: str,
    execution_id: str,
) -> Task:
    """Acknowledge receipt of task delivery."""
    async with with_tenant_context(tenant_id, db):
        stmt = select(Task).where(
            Task.id == task_id, Task.tenant_id == tenant_id, Task.device_id == device_id
        )
        res = await db.execute(stmt)
        task = res.scalar_one_or_none()
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Task not found or unauthorized."
            )

        if task.status == TaskStatus.ACKNOWLEDGED:
            return task  # Idempotent re-entry

        validate_state_transition(task.status, TaskStatus.ACKNOWLEDGED)

        now = datetime.now(UTC)
        task.status = TaskStatus.ACKNOWLEDGED
        task.acknowledged_at = now

        exec_stmt = select(TaskExecution).where(
            TaskExecution.task_id == task_id, TaskExecution.execution_id == execution_id
        )
        exec_res = await db.execute(exec_stmt)
        execution = exec_res.scalar_one_or_none()
        if execution:
            execution.status = TaskStatus.ACKNOWLEDGED

        audit = AuditEvent(
            tenant_id=tenant_id,
            actor_id=device_id,
            actor_type="AGENT",
            event="TASK_ACKNOWLEDGED",
            details={"task_id": task.id, "execution_id": execution_id},
        )
        db.add(audit)
        await db.commit()

        return task


async def start_task(
    db: AsyncSession,
    tenant_id: str,
    device_id: str,
    task_id: str,
    execution_id: str,
) -> Task:
    """Mark task execution started by host agent."""
    async with with_tenant_context(tenant_id, db):
        stmt = select(Task).where(
            Task.id == task_id, Task.tenant_id == tenant_id, Task.device_id == device_id
        )
        res = await db.execute(stmt)
        task = res.scalar_one_or_none()
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Task not found or unauthorized."
            )

        if task.status == TaskStatus.RUNNING:
            return task  # Idempotent re-entry

        validate_state_transition(task.status, TaskStatus.RUNNING)

        now = datetime.now(UTC)
        task.status = TaskStatus.RUNNING
        task.started_at = now

        exec_stmt = select(TaskExecution).where(
            TaskExecution.task_id == task_id, TaskExecution.execution_id == execution_id
        )
        exec_res = await db.execute(exec_stmt)
        execution = exec_res.scalar_one_or_none()
        if execution:
            execution.status = TaskStatus.RUNNING

        audit = AuditEvent(
            tenant_id=tenant_id,
            actor_id=device_id,
            actor_type="AGENT",
            event="TASK_STARTED",
            details={"task_id": task.id, "execution_id": execution_id},
        )
        db.add(audit)
        await db.commit()

        return task


async def submit_task_result(
    db: AsyncSession,
    tenant_id: str,
    device_id: str,
    task_id: str,
    execution_id: str,
    result_status: TaskStatus,
    findings: list[FindingItem],
    error_message: str | None = None,
) -> Task:
    """Submit task execution result (COMPLETED or FAILED) with findings."""
    if result_status not in (TaskStatus.COMPLETED, TaskStatus.FAILED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Result status must be COMPLETED or FAILED.",
        )

    async with with_tenant_context(tenant_id, db):
        stmt = select(Task).where(
            Task.id == task_id, Task.tenant_id == tenant_id, Task.device_id == device_id
        )
        res = await db.execute(stmt)
        task = res.scalar_one_or_none()
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Task not found or unauthorized."
            )

        # Idempotency check: if already completed or failed, return existing task
        if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
            return task

        validate_state_transition(task.status, result_status)

        now = datetime.now(UTC)
        task.status = result_status
        task.completed_at = now
        db.add(task)
        await db.flush()

        exec_stmt = select(TaskExecution).where(
            TaskExecution.task_id == task_id, TaskExecution.execution_id == execution_id
        )
        exec_res = await db.execute(exec_stmt)
        execution = exec_res.scalar_one_or_none()
        if execution:
            execution.status = result_status
            execution.completed_at = now
            execution.error_message = error_message
        else:
            execution = TaskExecution(
                task_id=task_id,
                tenant_id=tenant_id,
                execution_id=execution_id,
                request_id=f"req_{execution_id}",
                status=result_status,
                started_at=now,
                completed_at=now,
                error_message=error_message,
            )
        task_capability = task.capability
        target_task_id = task.id

        event_name = "TASK_COMPLETED" if result_status == TaskStatus.COMPLETED else "TASK_FAILED"
        audit = AuditEvent(
            tenant_id=tenant_id,
            actor_id=device_id,
            actor_type="AGENT",
            event=event_name,
            details={
                "task_id": target_task_id,
                "execution_id": execution_id,
                "findings_count": len(findings),
                "error": error_message,
            },
        )
        db.add(audit)

        # Process findings if completed successfully
        if result_status == TaskStatus.COMPLETED and findings:
            from netra_backend.services.finding_engine import process_finding_ingestion

            await process_finding_ingestion(
                db=db,
                tenant_id=tenant_id,
                device_id=device_id,
                task_id=task_id,
                execution_id=execution_id,
                capability=task_capability,
                raw_findings=findings,
            )
        else:
            await db.commit()

        await db.refresh(task)

        logger.info(
            "task_result_submitted",
            task_id=target_task_id,
            tenant_id=tenant_id,
            device_id=device_id,
            status=result_status.value,
        )
        return task


async def cancel_task(
    db: AsyncSession,
    tenant_id: str,
    user_id: str,
    task_id: str,
) -> Task:
    """Cancel a pending or running task."""
    async with with_tenant_context(tenant_id, db):
        stmt = select(Task).where(Task.id == task_id, Task.tenant_id == tenant_id)
        res = await db.execute(stmt)
        task = res.scalar_one_or_none()
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Task not found or unauthorized."
            )

        if task.status in (
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.EXPIRED,
            TaskStatus.TIMEOUT,
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel task in terminal state '{task.status.value}'.",
            )

        validate_state_transition(task.status, TaskStatus.CANCELLED)

        task.status = TaskStatus.CANCELLED
        now = datetime.now(UTC)
        task.updated_at = now

        audit = AuditEvent(
            tenant_id=tenant_id,
            actor_id=user_id,
            actor_type="USER",
            event="TASK_CANCELLED",
            details={"task_id": task.id},
        )
        db.add(audit)
        await db.commit()

        logger.info("task_cancelled", task_id=task.id, tenant_id=tenant_id, user_id=user_id)
        return task
