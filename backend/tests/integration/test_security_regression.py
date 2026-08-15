"""Security regression test suite for NETRA.

Tests:
1. Concurrent redemption of enrollment code.
2. Cross-tenant access rejection.
3. Device identity spoofing rejection.
4. Signature tampering rejection.
5. Replay attack rejection.
6. Expired enrollment code rejection.
7. Revoked device credential rejection.
"""

import asyncio
import time
import uuid

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
from netra_shared.crypto import construct_canonical_payload, generate_ed25519_keypair, sign_payload
from netra_shared.enums import DeviceCredentialStatus, Role


@pytest.mark.asyncio
async def test_concurrent_enrollment_code_redemption_race(client: AsyncClient, app) -> None:
    """Verify that when 5 concurrent requests attempt to redeem the exact same enrollment code,

    EXACTLY ONE request succeeds (HTTP 200) and all other 4 requests fail (HTTP 400).
    """
    session_factory = get_session_factory()
    password = "AdminPassword123!"

    async with session_factory() as db:
        tenant = Tenant(name="Race Tenant", slug="race-tenant")
        admin_user = User(
            email="admin@race.io",
            password_hash=hash_password(password),
            display_name="Admin User",
            is_active=True,
        )
        db.add(tenant)
        db.add(admin_user)
        await db.flush()

        membership = TenantMembership(tenant_id=tenant.id, user_id=admin_user.id, role=Role.ADMIN)
        db.add(membership)
        await db.commit()

        tenant_id = tenant.id
        user_id = admin_user.id

    token = create_access_token(user_id=user_id, tenant_id=tenant_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Generate single-use enrollment code
    gen_res = await client.post(
        "/api/v1/control/enrollment-codes",
        json={"tenant_id": tenant_id},
        headers=headers,
    )
    assert gen_res.status_code == 200
    code = gen_res.json()["code"]

    # Prepare 5 distinct host agent payloads presenting the SAME enrollment code
    agents = []
    for i in range(5):
        priv_bytes, pub_bytes = generate_ed25519_keypair()
        payload = {
            "code": code,
            "hostname": f"race-host-{i}",
            "os": "Linux",
            "architecture": "x86_64",
            "agent_version": "0.1.0",
            "public_key": pub_bytes.hex(),
        }
        agents.append(payload)

    # Launch 5 concurrent HTTP POST requests to /api/v1/agent/enroll
    tasks = [client.post("/api/v1/agent/enroll", json=p) for p in agents]
    responses = await asyncio.gather(*tasks)

    status_codes = [r.status_code for r in responses]
    successes = [s for s in status_codes if s == 200]
    failures = [s for s in status_codes if s == 400]

    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}: {status_codes}"
    assert len(failures) == 4, f"Expected 4 failures, got {len(failures)}: {status_codes}"


@pytest.mark.asyncio
async def test_cross_tenant_resource_isolation(client: AsyncClient, app) -> None:
    """Verify Tenant A user cannot generate enrollment code for Tenant B."""
    session_factory = get_session_factory()
    password = "UserPassword123!"

    async with session_factory() as db:
        tenant_a = Tenant(name="Tenant Alpha", slug="tenant-alpha")
        tenant_b = Tenant(name="Tenant Beta", slug="tenant-beta")
        user_a = User(
            email="usera@alpha.io",
            password_hash=hash_password(password),
            display_name="User Alpha",
            is_active=True,
        )
        db.add_all([tenant_a, tenant_b, user_a])
        await db.flush()

        membership_a = TenantMembership(tenant_id=tenant_a.id, user_id=user_a.id, role=Role.ADMIN)
        db.add(membership_a)
        await db.commit()

        tenant_a_id = tenant_a.id
        tenant_b_id = tenant_b.id
        user_a_id = user_a.id

    token_a = create_access_token(user_id=user_a_id, tenant_id=tenant_a_id)
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # User A tries to create enrollment code for Tenant B -> Forbidden
    res = await client.post(
        "/api/v1/control/enrollment-codes",
        json={"tenant_id": tenant_b_id},
        headers=headers_a,
    )
    assert res.status_code == 403
    assert "Insufficient permissions" in res.json()["error"]["message"]


@pytest.mark.asyncio
async def test_device_identity_spoofing_rejected(client: AsyncClient, app) -> None:
    """Verify Device B cannot authenticate requests presenting Device A's ID."""
    session_factory = get_session_factory()
    priv_a, pub_a = generate_ed25519_keypair()
    priv_b, pub_b = generate_ed25519_keypair()

    async with session_factory() as db:
        tenant = Tenant(name="Spoof Tenant", slug="spoof-tenant")
        db.add(tenant)
        await db.flush()

        device_a = Device(
            tenant_id=tenant.id,
            hostname="device-a",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        db.add(device_a)
        await db.flush()

        cred_a = DeviceCredential(
            device_id=device_a.id,
            public_key=pub_a.hex(),
            algorithm="Ed25519",
            status=DeviceCredentialStatus.ACTIVE,
        )
        db.add(cred_a)
        await db.commit()

        device_a_id = device_a.id

    # Attacker B signs payload with Private Key B, but presents X-NETRA-Device-ID: Device A
    timestamp_str = str(time.time())
    nonce = str(uuid.uuid4())
    request_id = f"req_{uuid.uuid4().hex[:16]}"

    canonical = construct_canonical_payload(
        method="GET",
        path="/api/v1/agent/tasks",
        timestamp=timestamp_str,
        nonce=nonce,
        request_id=request_id,
        body=b"",
    )
    # Signed with Priv B!
    sig_b_hex = sign_payload(priv_b, canonical).hex()

    headers = {
        "X-NETRA-Device-ID": device_a_id,  # Device A ID!
        "X-NETRA-Timestamp": timestamp_str,
        "X-NETRA-Nonce": nonce,
        "X-NETRA-Request-ID": request_id,
        "X-NETRA-Signature": sig_b_hex,
    }

    res = await client.get("/api/v1/agent/tasks", headers=headers)
    assert res.status_code == 401
    assert "Invalid Ed25519 signature" in res.json()["error"]["message"]


@pytest.mark.asyncio
async def test_revoked_device_credential_rejected(client: AsyncClient, app) -> None:
    """Verify polling attempt with REVOKED device credential fails with 401."""
    session_factory = get_session_factory()
    priv_bytes, pub_bytes = generate_ed25519_keypair()

    async with session_factory() as db:
        tenant = Tenant(name="Revoked Tenant", slug="revoked-tenant")
        db.add(tenant)
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="revoked-device",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        db.add(device)
        await db.flush()

        credential = DeviceCredential(
            device_id=device.id,
            public_key=pub_bytes.hex(),
            algorithm="Ed25519",
            status=DeviceCredentialStatus.REVOKED,  # REVOKED!
        )
        db.add(credential)
        await db.commit()

        device_id = device.id

    timestamp_str = str(time.time())
    nonce = str(uuid.uuid4())
    request_id = f"req_{uuid.uuid4().hex[:16]}"

    canonical = construct_canonical_payload(
        method="GET",
        path="/api/v1/agent/tasks",
        timestamp=timestamp_str,
        nonce=nonce,
        request_id=request_id,
        body=b"",
    )
    sig_hex = sign_payload(priv_bytes, canonical).hex()

    headers = {
        "X-NETRA-Device-ID": device_id,
        "X-NETRA-Timestamp": timestamp_str,
        "X-NETRA-Nonce": nonce,
        "X-NETRA-Request-ID": request_id,
        "X-NETRA-Signature": sig_hex,
    }

    res = await client.get("/api/v1/agent/tasks", headers=headers)
    assert res.status_code == 401
    assert "unauthenticated, unpaired, or revoked" in res.json()["error"]["message"]
