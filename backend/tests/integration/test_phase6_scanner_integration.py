"""End-to-End Integration and Cross-Tenant Security Tests for Phase 6 Security Scanner Subsystem."""

import pytest
from httpx import AsyncClient
from netra_agent.executor import execute_task
from sqlalchemy import select

from netra_backend.database import get_session_factory
from netra_backend.models import (
    Device,
    Finding,
    FindingEvidence,
    Tenant,
    User,
)
from netra_backend.security import hash_password
from netra_backend.services.task_engine import (
    claim_next_task_for_device,
    create_task,
    submit_task_result,
)
from netra_shared.enums import TaskStatus
from netra_shared.schemas.task import CapabilityEnum, FindingItem, TaskPriorityEnum


@pytest.mark.asyncio
async def test_full_scanner_execution_and_finding_persistence(client: AsyncClient, app) -> None:
    """Verify flow: Task Creation -> Claim -> Scanner Exec -> Finding Submission -> DB Store."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        tenant = Tenant(name="Scanner Integration Tenant", slug="scanner-int-tenant")
        user = User(
            email="u@scanner.io",
            password_hash=hash_password("Pass123!"),
            display_name="Scanner Operator",
            is_active=True,
        )
        db.add_all([tenant, user])
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="scan-host-01",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        db.add(device)
        await db.commit()

        tenant_id = tenant.id
        user_id = user.id
        device_id = device.id

    # 1. Create task for SCAN_NETWORK capability
    async with session_factory() as db:
        task = await create_task(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            target_device_id=device_id,
            capability=CapabilityEnum.SCAN_NETWORK,
            parameters={},
            priority=TaskPriorityEnum.NORMAL,
        )
        task_id = task.id

    # 2. Agent claims task
    async with session_factory() as db:
        claimed_task, exec_id = await claim_next_task_for_device(
            db=db, tenant_id=tenant_id, device_id=device_id
        )
        assert claimed_task is not None
        assert claimed_task.id == task_id
        assert exec_id is not None

    # 3. Host agent executes real NetworkScanner engine
    exec_result = execute_task(
        task_id=task_id,
        execution_id=exec_id,
        capability=claimed_task.capability,
        parameters=claimed_task.parameters,
    )
    assert exec_result["status"] == TaskStatus.COMPLETED
    raw_findings = exec_result["findings"]
    assert len(raw_findings) >= 1
    finding_items = [FindingItem(**f) for f in raw_findings]

    # 4. Agent submits task results to backend
    async with session_factory() as db:
        completed_task = await submit_task_result(
            db=db,
            tenant_id=tenant_id,
            device_id=device_id,
            task_id=task_id,
            execution_id=exec_id,
            result_status=TaskStatus.COMPLETED,
            findings=finding_items,
        )
        assert completed_task.status == TaskStatus.COMPLETED

    # 5. Verify database storage: Finding and FindingEvidence records persisted
    async with session_factory() as db:
        db_findings = (
            await db.scalars(select(Finding).where(Finding.tenant_id == tenant_id))
        ).all()
        assert len(db_findings) >= 1

        db_evidence = (
            await db.scalars(select(FindingEvidence).where(FindingEvidence.tenant_id == tenant_id))
        ).all()
        assert len(db_evidence) >= 1
        assert db_evidence[0].device_id == device_id
        assert db_evidence[0].task_id == task_id
        assert db_evidence[0].execution_id == exec_id


@pytest.mark.asyncio
async def test_cross_tenant_scanner_finding_isolation(client: AsyncClient, app) -> None:
    """Verify scanner findings submitted by Device A in Tenant A do not leak into Tenant B."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        tenant_a = Tenant(name="Tenant Alpha", slug="tenant-alpha")
        tenant_b = Tenant(name="Tenant Beta", slug="tenant-beta")
        user_a = User(
            email="u@alpha.io",
            password_hash=hash_password("Pass123!"),
            display_name="User Alpha",
            is_active=True,
        )
        db.add_all([tenant_a, tenant_b, user_a])
        await db.flush()

        device_a = Device(
            tenant_id=tenant_a.id,
            hostname="host-alpha",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        db.add(device_a)
        await db.commit()

        tenant_a_id = tenant_a.id
        tenant_b_id = tenant_b.id
        user_a_id = user_a.id
        device_a_id = device_a.id

    # Create & execute task in Tenant A
    async with session_factory() as db:
        task = await create_task(
            db=db,
            tenant_id=tenant_a_id,
            user_id=user_a_id,
            target_device_id=device_a_id,
            capability=CapabilityEnum.SCAN_USERS,
            parameters={},
            priority=TaskPriorityEnum.NORMAL,
        )
        claimed_task, exec_id = await claim_next_task_for_device(
            db=db, tenant_id=tenant_a_id, device_id=device_a_id
        )
        assert claimed_task is not None
        assert exec_id is not None

        exec_res = execute_task(
            task_id=task.id,
            execution_id=exec_id,
            capability=claimed_task.capability,
            parameters=claimed_task.parameters,
        )
        findings = [FindingItem(**f) for f in exec_res["findings"]]

        await submit_task_result(
            db=db,
            tenant_id=tenant_a_id,
            device_id=device_a_id,
            task_id=task.id,
            execution_id=exec_id,
            result_status=TaskStatus.COMPLETED,
            findings=findings,
        )

    # Query Tenant B findings database: Must be empty!
    async with session_factory() as db:
        b_findings = (
            await db.scalars(select(Finding).where(Finding.tenant_id == tenant_b_id))
        ).all()
        b_evidence = (
            await db.scalars(
                select(FindingEvidence).where(FindingEvidence.tenant_id == tenant_b_id)
            )
        ).all()
        assert len(b_findings) == 0, (
            "Tenant B must have 0 findings from Tenant A scanner execution!"
        )
        assert len(b_evidence) == 0, (
            "Tenant B must have 0 evidence from Tenant A scanner execution!"
        )
