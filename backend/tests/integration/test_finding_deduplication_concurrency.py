"""Concurrency and RLS Integration Test Suite for Security Finding Deduplication and Lifecycle."""

import asyncio

import pytest
from sqlalchemy import select

from netra_backend.database import get_session_factory
from netra_backend.models import Device, Finding, FindingEvidence, Tenant, User
from netra_backend.security import hash_password
from netra_backend.services.finding_engine import process_finding_ingestion
from netra_backend.services.task_engine import create_task, submit_task_result
from netra_shared.enums import FindingStatus, TaskStatus
from netra_shared.schemas.task import CapabilityEnum, FindingItem, TaskPriorityEnum


@pytest.mark.asyncio
async def test_concurrent_result_submissions_deduplicate_to_single_finding(app) -> None:
    """Verify 5 concurrent result submissions produce exactly 1 logical finding master entity."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        tenant = Tenant(name="Concurrent Finding Org", slug="conc-finding-1")
        user = User(
            email="user@concfind.com", password_hash=hash_password("Pass1!"), display_name="User"
        )
        db.add_all([tenant, user])
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="host-conc",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1",
        )
        db.add(device)
        await db.commit()

        t_id = tenant.id
        u_id = user.id
        d_id = device.id

    # Create 5 distinct tasks for the same device
    task_ids: list[str] = []
    exec_ids: list[str] = []
    for i in range(5):
        async with session_factory() as db:
            task = await create_task(
                db=db,
                tenant_id=t_id,
                user_id=u_id,
                target_device_id=d_id,
                capability=CapabilityEnum.SCAN_NETWORK,
                parameters={},
                priority=TaskPriorityEnum.NORMAL,
            )
            # Mark task running
            task.status = TaskStatus.RUNNING
            await db.commit()
            task_ids.append(task.id)
            exec_ids.append(f"exec_conc_{i}_{task.id[:8]}")

    finding_item = FindingItem(
        title="Open Port 8080",
        category="NETWORK",
        severity="HIGH",
        fingerprint="fp_concurrent_test_port_8080_001",
        details={"port": 8080, "service": "http-alt"},
    )

    async def submit_one(t_id_arg: str, exec_id_arg: str) -> None:
        async with session_factory() as db:
            await submit_task_result(
                db=db,
                tenant_id=t_id,
                device_id=d_id,
                task_id=t_id_arg,
                execution_id=exec_id_arg,
                result_status=TaskStatus.COMPLETED,
                findings=[finding_item],
            )

    # Launch 5 concurrent submissions
    tasks = [submit_one(t_ids, e_ids) for t_ids, e_ids in zip(task_ids, exec_ids, strict=False)]
    await asyncio.gather(*tasks)

    # Verify findings table has EXACTLY 1 finding entry for this fingerprint
    async with session_factory() as db:
        stmt = select(Finding).where(
            Finding.tenant_id == t_id, Finding.fingerprint == finding_item.fingerprint
        )
        res = await db.execute(stmt)
        findings = res.scalars().all()
        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "Open Port 8080"
        assert finding.status == FindingStatus.OPEN

        # Verify 5 evidence records exist under the single finding
        ev_stmt = select(FindingEvidence).where(FindingEvidence.finding_id == finding.id)
        ev_res = await db.execute(ev_stmt)
        evidences = ev_res.scalars().all()
        assert len(evidences) == 5


@pytest.mark.asyncio
async def test_resolved_finding_reopens_upon_reappearance(app) -> None:
    """Verify an identical finding marked RESOLVED transitions to REOPENED when re-detected."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        tenant = Tenant(name="Reopen Org", slug="reopen-org-1")
        user = User(
            email="u@reopen.com", password_hash=hash_password("Pass1!"), display_name="User"
        )
        db.add_all([tenant, user])
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="host-reopen",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1",
        )
        db.add(device)
        await db.flush()

        task = await create_task(
            db=db,
            tenant_id=tenant.id,
            user_id=user.id,
            target_device_id=device.id,
            capability=CapabilityEnum.SCAN_PROCESSES,
            parameters={},
            priority=TaskPriorityEnum.NORMAL,
        )
        task.status = TaskStatus.RUNNING
        await db.commit()

        t_id = tenant.id
        d_id = device.id
        task_id = task.id

    finding_item = FindingItem(
        title="Suspicious Malware Process",
        category="PROCESS",
        severity="CRITICAL",
        fingerprint="fp_malware_process_reopen_01",
        details={"pid": 1337, "name": "xmrig"},
    )

    # 1. Ingest initial scan finding -> Status OPEN
    async with session_factory() as db:
        await process_finding_ingestion(
            db=db,
            tenant_id=t_id,
            device_id=d_id,
            task_id=task_id,
            execution_id="exec_1",
            capability="SCAN_PROCESSES",
            raw_findings=[finding_item],
        )
        await db.commit()

    # 2. Mark finding RESOLVED in database
    async with session_factory() as db:
        res = await db.execute(
            select(Finding).where(
                Finding.tenant_id == t_id, Finding.fingerprint == finding_item.fingerprint
            )
        )
        finding = res.scalar_one()
        assert finding.status == FindingStatus.OPEN
        finding.status = FindingStatus.RESOLVED
        await db.commit()

    # 3. Subsequent scan detects identical finding again
    async with session_factory() as db:
        await process_finding_ingestion(
            db=db,
            tenant_id=t_id,
            device_id=d_id,
            task_id=task_id,
            execution_id="exec_2",
            capability="SCAN_PROCESSES",
            raw_findings=[finding_item],
        )
        await db.commit()

    # 4. Verify finding status was automatically mutated to REOPENED
    async with session_factory() as db:
        res = await db.execute(
            select(Finding).where(
                Finding.tenant_id == t_id, Finding.fingerprint == finding_item.fingerprint
            )
        )
        finding = res.scalar_one()
        assert finding.status == FindingStatus.REOPENED
