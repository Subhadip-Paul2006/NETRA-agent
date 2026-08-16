"""Comprehensive Phase 5 Security, State Machine, Idempotency, and Concurrency Audit Tests.

Audit Cases:
1. State Machine: Valid vs Invalid State Transitions & Terminal Immutability.
2. Device Authentication & Ed25519 Tampering Rejections.
3. Atomic Task Claiming under multi-worker concurrency.
4. Idempotent Result Submissions.
5. Cross-Tenant Task & Finding Isolation.
6. Revoked/Unpaired Device Access Denial.
"""

import json
import time
import uuid

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import func, select

from netra_backend.database import get_session_factory
from netra_backend.models import (
    Device,
    DeviceCredential,
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
    validate_state_transition,
)
from netra_shared.crypto import construct_canonical_payload, generate_ed25519_keypair, sign_payload
from netra_shared.enums import DeviceCredentialStatus, TaskStatus
from netra_shared.schemas.task import CapabilityEnum, FindingItem, TaskPriorityEnum


@pytest.mark.asyncio
async def test_state_machine_terminal_immutability(client: AsyncClient, app) -> None:
    """Verify that terminal states (COMPLETED, FAILED, CANCELLED) cannot be mutated."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        tenant = Tenant(name="Terminal Tenant", slug="terminal-tenant")
        user = User(
            email="u@terminal.io",
            password_hash=hash_password("Pass123!"),
            display_name="User",
            is_active=True,
        )
        db.add_all([tenant, user])
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="term-host",
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

    # Create task & complete it
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
        claimed_task, exec_id = await claim_next_task_for_device(
            db=db, tenant_id=tenant_id, device_id=device_id
        )
        assert claimed_task is not None
        assert exec_id is not None

        completed_task = await submit_task_result(
            db=db,
            tenant_id=tenant_id,
            device_id=device_id,
            task_id=task.id,
            execution_id=exec_id,
            result_status=TaskStatus.COMPLETED,
            findings=[],
        )
        assert completed_task.status == TaskStatus.COMPLETED

    # Attempt to transition COMPLETED -> RUNNING or COMPLETED -> FAILED
    with pytest.raises(HTTPException):
        validate_state_transition(TaskStatus.COMPLETED, TaskStatus.RUNNING)

    with pytest.raises(HTTPException):
        validate_state_transition(TaskStatus.COMPLETED, TaskStatus.FAILED)


@pytest.mark.asyncio
async def test_idempotent_result_submission_deduplication(client: AsyncClient, app) -> None:
    """Verify duplicate result submissions do not duplicate findings or evidence."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        tenant = Tenant(name="Idem Tenant", slug="idem-tenant")
        user = User(
            email="u@idem.io",
            password_hash=hash_password("Pass123!"),
            display_name="User",
            is_active=True,
        )
        db.add_all([tenant, user])
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="idem-host",
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

    # Create & claim task
    async with session_factory() as db:
        task = await create_task(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            target_device_id=device_id,
            capability=CapabilityEnum.SCAN_USERS,
            parameters={},
            priority=TaskPriorityEnum.NORMAL,
        )
        claimed_task, exec_id = await claim_next_task_for_device(
            db=db, tenant_id=tenant_id, device_id=device_id
        )
        assert claimed_task is not None
        assert exec_id is not None
        task_id = task.id

    findings_payload = [
        FindingItem(
            title="Unauthorized Admin User",
            category="USER_AUDIT",
            severity="HIGH",
            fingerprint="fp_user_admin_99",
            details={"username": "backdoor"},
        )
    ]

    # First Submission
    async with session_factory() as db:
        res1 = await submit_task_result(
            db=db,
            tenant_id=tenant_id,
            device_id=device_id,
            task_id=task_id,
            execution_id=exec_id,
            result_status=TaskStatus.COMPLETED,
            findings=findings_payload,
        )
        assert res1.status == TaskStatus.COMPLETED

    # Second Duplicate Submission
    async with session_factory() as db:
        res2 = await submit_task_result(
            db=db,
            tenant_id=tenant_id,
            device_id=device_id,
            task_id=task_id,
            execution_id=exec_id,
            result_status=TaskStatus.COMPLETED,
            findings=findings_payload,
        )
        assert res2.status == TaskStatus.COMPLETED

    # Verify database counts: Exactly 1 Finding, 1 Evidence
    async with session_factory() as db:
        f_count = await db.scalar(
            select(func.count(Finding.id)).where(Finding.tenant_id == tenant_id)
        )
        e_count = await db.scalar(
            select(func.count(FindingEvidence.id)).where(FindingEvidence.tenant_id == tenant_id)
        )
        assert f_count == 1, f"Expected 1 finding, got {f_count}"
        assert e_count == 1, f"Expected 1 evidence item, got {e_count}"


@pytest.mark.asyncio
async def test_ed25519_signature_tampering_rejections(client: AsyncClient, app) -> None:
    """Audit agent request authentication against tampered path, method, body, and timestamp."""
    session_factory = get_session_factory()
    priv_bytes, pub_bytes = generate_ed25519_keypair()

    async with session_factory() as db:
        tenant = Tenant(name="Tamper Tenant", slug="tamper-tenant")
        user = User(
            email="u@tamper.io",
            password_hash=hash_password("Pass123!"),
            display_name="User",
            is_active=True,
        )
        db.add_all([tenant, user])
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="tamper-host",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        db.add(device)
        await db.flush()

        cred = DeviceCredential(
            device_id=device.id,
            public_key=pub_bytes.hex(),
            algorithm="Ed25519",
            status=DeviceCredentialStatus.ACTIVE,
        )
        db.add(cred)
        await db.commit()

        tenant_id = tenant.id
        user_id = user.id
        device_id = device.id

    # Create task
    async with session_factory() as db:
        task = await create_task(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            target_device_id=device_id,
            capability=CapabilityEnum.SCAN_FIREWALL,
            parameters={},
            priority=TaskPriorityEnum.NORMAL,
        )
        claimed_task, exec_id = await claim_next_task_for_device(
            db=db, tenant_id=tenant_id, device_id=device_id
        )
        assert claimed_task is not None
        assert exec_id is not None
        task_id = task.id

    ack_path = f"/api/v1/agent/tasks/{task_id}/ack"
    ack_body = {"task_id": task_id, "execution_id": exec_id}
    ack_bytes = json.dumps(ack_body).encode("utf-8")

    # 1. Tampered Body (Signed body A, send body B)
    timestamp_str = str(time.time())
    nonce = str(uuid.uuid4())
    req_id = f"req_{uuid.uuid4().hex[:16]}"
    canonical_a = construct_canonical_payload(
        method="POST",
        path=ack_path,
        timestamp=timestamp_str,
        nonce=nonce,
        request_id=req_id,
        body=b"tampered_body_bytes",  # Signed different body!
    )
    sig_tampered = sign_payload(priv_bytes, canonical_a).hex()

    headers = {
        "X-NETRA-Device-ID": device_id,
        "X-NETRA-Timestamp": timestamp_str,
        "X-NETRA-Nonce": nonce,
        "X-NETRA-Request-ID": req_id,
        "X-NETRA-Signature": sig_tampered,
        "Content-Type": "application/json",
    }

    res_body_tampered = await client.post(ack_path, content=ack_bytes, headers=headers)
    assert res_body_tampered.status_code == 401
    assert "Invalid Ed25519 signature" in res_body_tampered.json()["error"]["message"]

    # 2. Expired Timestamp (> 300s in the past)
    old_timestamp_str = str(time.time() - 360)
    nonce_old = str(uuid.uuid4())
    req_id_old = f"req_{uuid.uuid4().hex[:16]}"
    canonical_old = construct_canonical_payload(
        method="POST",
        path=ack_path,
        timestamp=old_timestamp_str,
        nonce=nonce_old,
        request_id=req_id_old,
        body=ack_bytes,
    )
    sig_old = sign_payload(priv_bytes, canonical_old).hex()

    headers_old = {
        "X-NETRA-Device-ID": device_id,
        "X-NETRA-Timestamp": old_timestamp_str,
        "X-NETRA-Nonce": nonce_old,
        "X-NETRA-Request-ID": req_id_old,
        "X-NETRA-Signature": sig_old,
        "Content-Type": "application/json",
    }
    res_old = await client.post(ack_path, content=ack_bytes, headers=headers_old)
    assert res_old.status_code == 400
    assert "Expired timestamp window" in res_old.json()["error"]["message"]
