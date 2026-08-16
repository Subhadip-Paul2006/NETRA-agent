"""Task Orchestration Control and Agent Lifecycle REST Endpoints."""

import time
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra_backend.api.v1.devices import get_current_user_id
from netra_backend.database import get_db_session
from netra_backend.logging import get_logger
from netra_backend.models import Device, DeviceCredential, NonceCache, TenantMembership
from netra_backend.rls import with_tenant_context
from netra_backend.services import task_engine
from netra_shared.crypto import construct_canonical_payload, verify_ed25519_signature
from netra_shared.enums import DeviceCredentialStatus, Role, TaskStatus
from netra_shared.schemas.task import (
    TaskAckRequest,
    TaskCancelResponse,
    TaskCreateRequest,
    TaskResponse,
    TaskResultRequest,
    TaskStartRequest,
)

logger = get_logger(__name__)

router = APIRouter(tags=["Task Orchestration"])


async def verify_agent_signature_headers(
    request: Request,
    db: AsyncSession,
    device_id: str,
    timestamp: str,
    nonce: str,
    request_id: str,
    signature: str,
    path: str,
) -> Device:
    """Verify Ed25519 signature headers for agent request."""
    # 1. Timestamp validation window (5 min limit)
    try:
        req_timestamp = float(timestamp)
        now_timestamp = time.time()
        if abs(now_timestamp - req_timestamp) > 300:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Expired timestamp window",
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid timestamp format",
        ) from exc

    # 2. Lookup device and active Ed25519 public key
    stmt = (
        select(Device, DeviceCredential.public_key)
        .join(DeviceCredential, Device.id == DeviceCredential.device_id)
        .where(
            Device.id == device_id,
            Device.is_paired == True,  # noqa: E712
            DeviceCredential.status == DeviceCredentialStatus.ACTIVE,
        )
    )
    res = await db.execute(stmt)
    row = res.first()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device unauthenticated, unpaired, or revoked",
        )

    device, public_key_hex = row

    # 3. Check NonceCache replay protection
    nonce_stmt = select(NonceCache).where(
        NonceCache.device_id == device_id,
        NonceCache.nonce == nonce,
    )
    nonce_res = await db.execute(nonce_stmt)
    if nonce_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Replay attack detected (duplicate nonce)",
        )

    # 4. Body bytes
    raw_body = await request.body()

    canonical = construct_canonical_payload(
        method="POST",
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        request_id=request_id,
        body=raw_body,
    )

    if not verify_ed25519_signature(public_key_hex, signature, canonical):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Ed25519 signature",
        )

    # Record Nonce
    nonce_entry = NonceCache(
        device_id=device_id,
        nonce=nonce,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    db.add(nonce_entry)
    await db.flush()

    return device


@router.post("/control/tasks", response_model=TaskResponse)
async def create_task_endpoint(
    payload: TaskCreateRequest,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db_session),
) -> TaskResponse:
    """Control plane endpoint for users to create and queue a task."""
    # Resolve target device to get tenant_id
    device_stmt = select(Device).where(Device.id == payload.target_device_id)
    res = await db.execute(device_stmt)
    device = res.scalar_one_or_none()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target device '{payload.target_device_id}' not found.",
        )

    tenant_id = device.tenant_id

    # Verify user has ADMIN or OPERATOR role in target tenant
    async with with_tenant_context(tenant_id, db):
        mem_stmt = select(TenantMembership).where(
            TenantMembership.tenant_id == tenant_id,
            TenantMembership.user_id == user_id,
        )
        mem_res = await db.execute(mem_stmt)
        membership = mem_res.scalar_one_or_none()

        if not membership or membership.role not in (Role.ADMIN, Role.OPERATOR):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to create task in tenant.",
            )

    task = await task_engine.create_task(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        target_device_id=payload.target_device_id,
        capability=payload.capability,
        parameters=payload.parameters,
        priority=payload.priority,
    )

    return TaskResponse(
        id=task.id,
        tenant_id=task.tenant_id,
        device_id=task.device_id,
        capability=task.capability,  # type: ignore[arg-type]
        parameters=task.parameters,
        status=task.status,
        priority=task.priority,
        created_at=task.created_at,
        queued_at=task.queued_at,
    )


@router.post("/control/tasks/{task_id}/cancel", response_model=TaskCancelResponse)
async def cancel_task_endpoint(
    task_id: str,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db_session),
) -> TaskCancelResponse:
    # First get task tenant
    task_stmt = select(task_engine.Task).where(task_engine.Task.id == task_id)
    task_res = await db.execute(task_stmt)
    task = task_res.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found.")

    tenant_id = task.tenant_id

    # Verify membership
    async with with_tenant_context(tenant_id, db):
        mem_stmt = select(TenantMembership).where(
            TenantMembership.tenant_id == tenant_id,
            TenantMembership.user_id == user_id,
        )
        mem_res = await db.execute(mem_stmt)
        membership = mem_res.scalar_one_or_none()

        if not membership or membership.role not in (Role.ADMIN, Role.OPERATOR):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to cancel task in tenant.",
            )

    cancelled_task = await task_engine.cancel_task(
        db=db, tenant_id=tenant_id, user_id=user_id, task_id=task_id
    )

    return TaskCancelResponse(task_id=cancelled_task.id, status=TaskStatus.CANCELLED)


@router.post("/agent/tasks/{task_id}/ack")
async def ack_task_endpoint(
    task_id: str,
    payload: TaskAckRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    x_netra_device_id: str = Header(..., alias="X-NETRA-Device-ID"),
    x_netra_timestamp: str = Header(..., alias="X-NETRA-Timestamp"),
    x_netra_nonce: str = Header(..., alias="X-NETRA-Nonce"),
    x_netra_request_id: str = Header(..., alias="X-NETRA-Request-ID"),
    x_netra_signature: str = Header(..., alias="X-NETRA-Signature"),
) -> dict[str, Any]:
    """Agent endpoint for acknowledging task delivery."""
    path = f"/api/v1/agent/tasks/{task_id}/ack"
    device = await verify_agent_signature_headers(
        request,
        db,
        x_netra_device_id,
        x_netra_timestamp,
        x_netra_nonce,
        x_netra_request_id,
        x_netra_signature,
        path,
    )

    task = await task_engine.acknowledge_task(
        db=db,
        tenant_id=device.tenant_id,
        device_id=device.id,
        task_id=task_id,
        execution_id=payload.execution_id,
    )

    return {"success": True, "task_id": task.id, "status": task.status.value}


@router.post("/agent/tasks/{task_id}/start")
async def start_task_endpoint(
    task_id: str,
    payload: TaskStartRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    x_netra_device_id: str = Header(..., alias="X-NETRA-Device-ID"),
    x_netra_timestamp: str = Header(..., alias="X-NETRA-Timestamp"),
    x_netra_nonce: str = Header(..., alias="X-NETRA-Nonce"),
    x_netra_request_id: str = Header(..., alias="X-NETRA-Request-ID"),
    x_netra_signature: str = Header(..., alias="X-NETRA-Signature"),
) -> dict[str, Any]:
    """Agent endpoint for marking task execution started."""
    path = f"/api/v1/agent/tasks/{task_id}/start"
    device = await verify_agent_signature_headers(
        request,
        db,
        x_netra_device_id,
        x_netra_timestamp,
        x_netra_nonce,
        x_netra_request_id,
        x_netra_signature,
        path,
    )

    task = await task_engine.start_task(
        db=db,
        tenant_id=device.tenant_id,
        device_id=device.id,
        task_id=task_id,
        execution_id=payload.execution_id,
    )

    return {"success": True, "task_id": task.id, "status": task.status.value}


@router.post("/agent/tasks/{task_id}/results")
async def submit_task_result_endpoint(
    task_id: str,
    payload: TaskResultRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    x_netra_device_id: str = Header(..., alias="X-NETRA-Device-ID"),
    x_netra_timestamp: str = Header(..., alias="X-NETRA-Timestamp"),
    x_netra_nonce: str = Header(..., alias="X-NETRA-Nonce"),
    x_netra_request_id: str = Header(..., alias="X-NETRA-Request-ID"),
    x_netra_signature: str = Header(..., alias="X-NETRA-Signature"),
) -> dict[str, Any]:
    """Agent endpoint for submitting task execution results."""
    path = f"/api/v1/agent/tasks/{task_id}/results"
    device = await verify_agent_signature_headers(
        request,
        db,
        x_netra_device_id,
        x_netra_timestamp,
        x_netra_nonce,
        x_netra_request_id,
        x_netra_signature,
        path,
    )

    task = await task_engine.submit_task_result(
        db=db,
        tenant_id=device.tenant_id,
        device_id=device.id,
        task_id=task_id,
        execution_id=payload.execution_id,
        result_status=payload.status,
        findings=payload.findings,
        error_message=payload.error_message,
    )

    return {"success": True, "task_id": task.id, "status": task.status.value}
