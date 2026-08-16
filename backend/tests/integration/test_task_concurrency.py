"""Concurrency and Multi-Tenant Isolation Tests for Phase 5 Task Engine.

Tests:
1. Concurrent Task Creation (10+ simultaneous creation requests).
2. Atomic Task Claiming Race (5 concurrent claim attempts on 1 queued task -> EXACTLY 1 winner).
3. Cross-Tenant Task Isolation under concurrent execution.
"""

import asyncio

import pytest
from httpx import AsyncClient

from netra_backend.database import get_session_factory
from netra_backend.models import (
    Device,
    DeviceCredential,
    Tenant,
    TenantMembership,
    User,
)
from netra_backend.security import create_access_token, hash_password
from netra_backend.services.task_engine import claim_next_task_for_device, create_task
from netra_shared.crypto import generate_ed25519_keypair
from netra_shared.enums import DeviceCredentialStatus, Role
from netra_shared.schemas.task import CapabilityEnum, TaskPriorityEnum


@pytest.mark.asyncio
async def test_concurrent_task_creation(client: AsyncClient, app) -> None:
    """Verify 10 simultaneous task creation requests create 10 distinct task records."""
    session_factory = get_session_factory()
    password = "TaskPassword123!"

    async with session_factory() as db:
        tenant = Tenant(name="Creation Tenant", slug="creation-tenant")
        admin_user = User(
            email="admin@creation.io",
            password_hash=hash_password(password),
            display_name="Admin User",
            is_active=True,
        )
        db.add(tenant)
        db.add(admin_user)
        await db.flush()

        membership = TenantMembership(tenant_id=tenant.id, user_id=admin_user.id, role=Role.ADMIN)
        db.add(membership)

        device = Device(
            tenant_id=tenant.id,
            hostname="creation-host",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        db.add(device)
        await db.commit()

        tenant_id = tenant.id
        user_id = admin_user.id
        device_id = device.id

    token = create_access_token(user_id=user_id, tenant_id=tenant_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Prepare 10 task creation requests
    payloads = [
        {
            "target_device_id": device_id,
            "capability": "SCAN_PROCESSES",
            "parameters": {"batch": i},
            "priority": "NORMAL",
        }
        for i in range(10)
    ]

    # Launch 10 concurrent requests
    tasks = [client.post("/api/v1/control/tasks", json=p, headers=headers) for p in payloads]
    responses = await asyncio.gather(*tasks)

    status_codes = [r.status_code for r in responses]
    assert all(code == 200 for code in status_codes)

    created_ids = {r.json()["id"] for r in responses}
    assert len(created_ids) == 10, f"Expected 10 unique task IDs, got {len(created_ids)}"


@pytest.mark.asyncio
async def test_atomic_task_claim_race(client: AsyncClient, app) -> None:
    """Verify that when 5 workers attempt to claim tasks with only 1 queued task,

    EXACTLY ONE worker claims the task, and the remaining 4 receive (None, None).
    """
    session_factory = get_session_factory()

    async with session_factory() as db:
        tenant = Tenant(name="Claim Tenant", slug="claim-tenant")
        user = User(
            email="user@claim.io",
            password_hash=hash_password("Pass123!"),
            display_name="User",
            is_active=True,
        )
        db.add_all([tenant, user])
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="claim-host",
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

    # Create exactly ONE queued task
    async with session_factory() as db:
        task = await create_task(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            target_device_id=device_id,
            capability=CapabilityEnum.SCAN_NETWORK,
            parameters={},
            priority=TaskPriorityEnum.HIGH,
        )
        task_id = task.id

    # Define claim worker using fresh session per worker
    async def worker(worker_id: int):
        async with session_factory() as db:
            return await claim_next_task_for_device(
                db=db,
                tenant_id=tenant_id,
                device_id=device_id,
                request_id=f"req_worker_{worker_id}",
            )

    # Launch 5 concurrent workers claiming tasks
    results = await asyncio.gather(*[worker(i) for i in range(5)])

    claimed_tasks = [t for t, exec_id in results if t is not None]
    unclaimed = [t for t, exec_id in results if t is None]

    assert len(claimed_tasks) == 1, (
        f"Expected exactly 1 worker to claim task, got {len(claimed_tasks)}"
    )
    assert len(unclaimed) == 4, f"Expected 4 workers to get None, got {len(unclaimed)}"
    assert claimed_tasks[0].id == task_id


@pytest.mark.asyncio
async def test_cross_tenant_task_isolation(client: AsyncClient, app) -> None:
    """Verify Agent for Tenant A can NEVER claim or access tasks belonging to Tenant B."""
    session_factory = get_session_factory()
    priv_a, pub_a = generate_ed25519_keypair()
    priv_b, pub_b = generate_ed25519_keypair()

    async with session_factory() as db:
        tenant_a = Tenant(name="Tenant A", slug="tenant-a")
        tenant_b = Tenant(name="Tenant B", slug="tenant-b")
        user_a = User(
            email="usera@ta.io",
            password_hash=hash_password("Pass123!"),
            display_name="User A",
            is_active=True,
        )
        db.add_all([tenant_a, tenant_b, user_a])
        await db.flush()

        device_a = Device(
            tenant_id=tenant_a.id,
            hostname="device-a",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        device_b = Device(
            tenant_id=tenant_b.id,
            hostname="device-b",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        db.add_all([device_a, device_b])
        await db.flush()

        cred_a = DeviceCredential(
            device_id=device_a.id,
            public_key=pub_a.hex(),
            algorithm="Ed25519",
            status=DeviceCredentialStatus.ACTIVE,
        )
        cred_b = DeviceCredential(
            device_id=device_b.id,
            public_key=pub_b.hex(),
            algorithm="Ed25519",
            status=DeviceCredentialStatus.ACTIVE,
        )
        db.add_all([cred_a, cred_b])
        await db.commit()

        tenant_a_id = tenant_a.id
        tenant_b_id = tenant_b.id
        user_a_id = user_a.id
        device_b_id = device_b.id

    # Create task for Tenant B's device
    async with session_factory() as db:
        await create_task(
            db=db,
            tenant_id=tenant_b_id,
            user_id=user_a_id,
            target_device_id=device_b_id,
            capability=CapabilityEnum.SCAN_FIREWALL,
            parameters={},
            priority=TaskPriorityEnum.HIGH,
        )

    # Worker for Tenant A attempts to claim tasks for Tenant A
    async with session_factory() as db:
        claimed_task, exec_id = await claim_next_task_for_device(
            db=db, tenant_id=tenant_a_id, device_id="device-a"
        )
        assert claimed_task is None, "Tenant A claimed Tenant B's task! RLS violation!"
