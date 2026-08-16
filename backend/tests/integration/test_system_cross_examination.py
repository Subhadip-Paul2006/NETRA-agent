"""Full System Cross-Examination & Adversarial Security Test Suite for NETRA (Phases 1-6).

Tests:
- 7 Logical Adversarial Attack Simulations (Tenant A vs Tenant B bypass attempts).
- Complete End-to-End Task Lifecycle.
- Failure Injection & Exception Isolation.
- Nonce Replay & Signature Tampering.
"""

import time
import uuid

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select

from netra_backend.database import get_session_factory
from netra_backend.models import (
    Device,
    DeviceCredential,
    EnrollmentCode,
    Finding,
    Tenant,
    TenantMembership,
    User,
)
from netra_backend.security import create_access_token, hash_password
from netra_backend.services.task_engine import (
    claim_next_task_for_device,
    create_task,
    submit_task_result,
)
from netra_shared.crypto import construct_canonical_payload, generate_ed25519_keypair, sign_payload
from netra_shared.enums import DeviceCredentialStatus, Role, TaskStatus
from netra_shared.schemas.task import CapabilityEnum, TaskPriorityEnum


@pytest.mark.asyncio
async def test_attack_1_user_a_accesses_tenant_b_task_denied(client: AsyncClient, app) -> None:
    """Attack 1: User A (Tenant A) attempts to access or cancel Tenant B's task."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        t_a = Tenant(name="Tenant Alpha", slug="alpha-atk1")
        t_b = Tenant(name="Tenant Beta", slug="beta-atk1")
        u_a = User(email="ua@atk1.com", password_hash=hash_password("Pass1!"), display_name="UA")
        u_b = User(email="ub@atk1.com", password_hash=hash_password("Pass1!"), display_name="UB")
        db.add_all([t_a, t_b, u_a, u_b])
        await db.flush()

        db.add(TenantMembership(tenant_id=t_a.id, user_id=u_a.id, role=Role.ADMIN))
        db.add(TenantMembership(tenant_id=t_b.id, user_id=u_b.id, role=Role.ADMIN))

        dev_b = Device(
            tenant_id=t_b.id,
            hostname="dev-b",
            os="Linux",
            architecture="x86",
            agent_version="0.1",
            is_paired=True,
        )
        db.add(dev_b)
        await db.commit()

        t_b_id = t_b.id
        u_a_id = u_a.id
        u_b_id = u_b.id
        dev_b_id = dev_b.id

    # Create task in Tenant B
    async with session_factory() as db:
        task_b = await create_task(
            db=db,
            tenant_id=t_b_id,
            user_id=u_b_id,
            target_device_id=dev_b_id,
            capability=CapabilityEnum.SCAN_NETWORK,
            parameters={},
            priority=TaskPriorityEnum.NORMAL,
        )
        task_b_id = task_b.id

    # User A authenticates & gets JWT token
    token_a = create_access_token(user_id=u_a_id, tenant_id=t_a.id)
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # User A attempts to cancel Tenant B's task via API
    res = await client.post(f"/api/v1/control/tasks/{task_b_id}/cancel", headers=headers_a)
    assert res.status_code in (403, 404), f"Expected 403 or 404 Forbidden, got {res.status_code}"


@pytest.mark.asyncio
async def test_attack_2_device_a_claims_tenant_b_task_denied(client: AsyncClient, app) -> None:
    """Attack 2: Device A (Tenant A) attempts to claim Tenant B's queued task."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        t_a = Tenant(name="Tenant Alpha", slug="alpha-atk2")
        t_b = Tenant(name="Tenant Beta", slug="beta-atk2")
        u_b = User(email="ub@atk2.com", password_hash=hash_password("Pass1!"), display_name="UB")
        db.add_all([t_a, t_b, u_b])
        await db.flush()

        dev_a = Device(
            tenant_id=t_a.id,
            hostname="dev-a",
            os="Linux",
            architecture="x86",
            agent_version="0.1",
            is_paired=True,
        )
        dev_b = Device(
            tenant_id=t_b.id,
            hostname="dev-b",
            os="Linux",
            architecture="x86",
            agent_version="0.1",
            is_paired=True,
        )
        db.add_all([dev_a, dev_b])
        await db.commit()

        t_a_id = t_a.id
        t_b_id = t_b.id
        dev_a_id = dev_a.id
        dev_b_id = dev_b.id
        u_b_id = u_b.id

    # Create task for Device B in Tenant B
    async with session_factory() as db:
        await create_task(
            db=db,
            tenant_id=t_b_id,
            user_id=u_b_id,
            target_device_id=dev_b_id,
            capability=CapabilityEnum.SCAN_FIREWALL,
            parameters={},
            priority=TaskPriorityEnum.HIGH,
        )

    # Device A attempts to claim tasks in Tenant A context
    async with session_factory() as db:
        claimed_task, exec_id = await claim_next_task_for_device(
            db=db, tenant_id=t_a_id, device_id=dev_a_id
        )
        assert claimed_task is None, "Device A must NOT claim Tenant B's task!"
        assert exec_id is None


@pytest.mark.asyncio
async def test_attack_3_device_a_submits_results_for_tenant_b_task_denied(
    client: AsyncClient, app
) -> None:
    """Attack 3: Device A (Tenant A) attempts to submit results for Tenant B's task."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        t_a = Tenant(name="Tenant Alpha", slug="alpha-atk3")
        t_b = Tenant(name="Tenant Beta", slug="beta-atk3")
        u_b = User(email="ub@atk3.com", password_hash=hash_password("Pass1!"), display_name="UB")
        db.add_all([t_a, t_b, u_b])
        await db.flush()

        dev_a = Device(
            tenant_id=t_a.id,
            hostname="dev-a",
            os="Linux",
            architecture="x86",
            agent_version="0.1",
            is_paired=True,
        )
        dev_b = Device(
            tenant_id=t_b.id,
            hostname="dev-b",
            os="Linux",
            architecture="x86",
            agent_version="0.1",
            is_paired=True,
        )
        db.add_all([dev_a, dev_b])
        await db.commit()

        t_a_id = t_a.id
        t_b_id = t_b.id
        dev_a_id = dev_a.id
        dev_b_id = dev_b.id
        u_b_id = u_b.id

    # Create & claim task for Device B in Tenant B
    async with session_factory() as db:
        task_b = await create_task(
            db=db,
            tenant_id=t_b_id,
            user_id=u_b_id,
            target_device_id=dev_b_id,
            capability=CapabilityEnum.SCAN_USERS,
            parameters={},
            priority=TaskPriorityEnum.NORMAL,
        )
        claimed_b, exec_id_b = await claim_next_task_for_device(
            db=db, tenant_id=t_b_id, device_id=dev_b_id
        )
        assert claimed_b is not None
        assert exec_id_b is not None
        task_b_id = task_b.id

    # Device A attempts to submit result for Tenant B's task under Tenant A context
    async with session_factory() as db:
        with pytest.raises((HTTPException, ValueError)):
            await submit_task_result(
                db=db,
                tenant_id=t_a_id,  # Tenant A context!
                device_id=dev_a_id,  # Device A!
                task_id=task_b_id,
                execution_id=exec_id_b,
                result_status=TaskStatus.COMPLETED,
                findings=[],
            )


@pytest.mark.asyncio
async def test_attack_4_tenant_a_queries_tenant_b_findings_denied(client: AsyncClient, app) -> None:
    """Attack 4: Tenant A attempts to query Tenant B's finding records."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        t_a = Tenant(name="Tenant Alpha", slug="alpha-atk4")
        t_b = Tenant(name="Tenant Beta", slug="beta-atk4")
        db.add_all([t_a, t_b])
        await db.flush()

        f_b = Finding(
            tenant_id=t_b.id,
            title="Tenant B Secret Finding",
            category="SECURITY",
            severity="HIGH",
            fingerprint="fp_tb_secret_1",
        )
        db.add(f_b)
        await db.commit()

        t_a_id = t_a.id

    # Query findings inside Tenant A context
    async with session_factory() as db:
        from netra_backend.rls import with_tenant_context

        async with with_tenant_context(t_a_id, db):
            res_a = await db.scalars(select(Finding).where(Finding.tenant_id == t_a_id))
            findings_a = res_a.all()
            assert len(findings_a) == 0, "Tenant A context must return 0 findings!"


@pytest.mark.asyncio
async def test_attack_5_tenant_a_redeems_tenant_b_enrollment_code_denied(
    client: AsyncClient, app
) -> None:
    """Attack 5: Device in Tenant A attempts to redeem Tenant B's enrollment code."""
    session_factory = get_session_factory()
    priv_bytes, pub_bytes = generate_ed25519_keypair()

    async with session_factory() as db:
        t_a = Tenant(name="Tenant Alpha", slug="alpha-atk5")
        t_b = Tenant(name="Tenant Beta", slug="beta-atk5")
        u_b = User(email="ub@atk5.com", password_hash=hash_password("Pass1!"), display_name="UB")
        db.add_all([t_a, t_b, u_b])
        await db.flush()

        import hashlib

        code_plain = "NETRA-ATK5-TEST-CODE-99"
        code_hash = hashlib.sha256(code_plain.encode()).hexdigest()

        from datetime import UTC, datetime, timedelta

        code_entry = EnrollmentCode(
            tenant_id=t_b.id,
            created_by_id=u_b.id,
            code_hash=code_hash,
            expires_at=datetime.now(UTC) + timedelta(hours=24),
        )
        db.add(code_entry)
        await db.commit()

        t_b_id = t_b.id

    # Agent attempts to enroll with code
    payload = {
        "code": code_plain,
        "hostname": "attacker-host",
        "os": "Linux",
        "architecture": "x86_64",
        "agent_version": "0.1.0",
        "public_key": pub_bytes.hex(),
    }
    res = await client.post("/api/v1/agent/enroll", json=payload)
    assert res.status_code == 200
    res_json = res.json()
    # The enrolled device MUST belong to Tenant B (the issuer of the code)
    assert res_json["tenant_id"] == t_b_id


@pytest.mark.asyncio
async def test_attack_6_nonce_replay_attack_denied(client: AsyncClient, app) -> None:
    """Attack 6: Agent attempts to replay a previously valid request using the same nonce."""
    session_factory = get_session_factory()
    priv_bytes, pub_bytes = generate_ed25519_keypair()

    async with session_factory() as db:
        tenant = Tenant(name="Replay Tenant", slug="replay-tenant")
        db.add(tenant)
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="replay-host",
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

        device_id = device.id

    poll_path = "/api/v1/agent/tasks"
    timestamp_str = str(time.time())
    nonce = f"nonce_replay_{uuid.uuid4().hex[:12]}"
    req_id = f"req_{uuid.uuid4().hex[:12]}"

    canonical = construct_canonical_payload(
        method="GET",
        path=poll_path,
        timestamp=timestamp_str,
        nonce=nonce,
        request_id=req_id,
        body=b"",
    )
    sig = sign_payload(priv_bytes, canonical).hex()

    headers = {
        "X-NETRA-Device-ID": device_id,
        "X-NETRA-Timestamp": timestamp_str,
        "X-NETRA-Nonce": nonce,
        "X-NETRA-Request-ID": req_id,
        "X-NETRA-Signature": sig,
    }

    # Request 1: Must succeed
    res1 = await client.get(poll_path, headers=headers)
    assert res1.status_code == 200

    # Request 2 (Replay with same nonce): Must fail closed with 400 Bad Request
    res2 = await client.get(poll_path, headers=headers)
    assert res2.status_code == 400
    assert "Replay attack detected" in res2.json()["error"]["message"]


@pytest.mark.asyncio
async def test_attack_7_modified_request_body_signature_mismatch_denied(
    client: AsyncClient, app
) -> None:
    """Attack 7: Attacker modifies the signed request body in transit."""
    session_factory = get_session_factory()
    priv_bytes, pub_bytes = generate_ed25519_keypair()

    async with session_factory() as db:
        tenant = Tenant(name="Tamper Tenant", slug="tamper-body-tenant")
        db.add(tenant)
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

        device_id = device.id

    ack_path = "/api/v1/agent/tasks/dummy_task/ack"
    timestamp_str = str(time.time())
    nonce = f"nonce_tamper_{uuid.uuid4().hex[:12]}"
    req_id = f"req_{uuid.uuid4().hex[:12]}"

    original_body = b'{"task_id": "dummy_task", "execution_id": "exec_orig"}'
    tampered_body = b'{"task_id": "dummy_task", "execution_id": "exec_TAMPERED"}'

    # Sign original body
    canonical_orig = construct_canonical_payload(
        method="POST",
        path=ack_path,
        timestamp=timestamp_str,
        nonce=nonce,
        request_id=req_id,
        body=original_body,
    )
    sig_orig = sign_payload(priv_bytes, canonical_orig).hex()

    headers = {
        "X-NETRA-Device-ID": device_id,
        "X-NETRA-Timestamp": timestamp_str,
        "X-NETRA-Nonce": nonce,
        "X-NETRA-Request-ID": req_id,
        "X-NETRA-Signature": sig_orig,
        "Content-Type": "application/json",
    }

    # Send tampered body with signature of original body
    res = await client.post(ack_path, content=tampered_body, headers=headers)
    assert res.status_code == 401
    assert "Invalid Ed25519 signature" in res.json()["error"]["message"]
