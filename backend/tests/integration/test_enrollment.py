"""Integration tests for Device Enrollment and Ed25519 Credential Registration."""

import pytest
from httpx import AsyncClient

from netra_backend.models import Tenant, TenantMembership, User
from netra_backend.security import create_access_token, hash_password
from netra_shared.crypto import generate_ed25519_keypair
from netra_shared.enums import Role


@pytest.mark.asyncio
async def test_generate_and_redeem_enrollment_code(client: AsyncClient, app) -> None:
    """Verify admin generates enrollment code and agent redeems it to enroll device."""
    from netra_backend.database import get_session_factory

    session_factory = get_session_factory()
    password = "AdminPassword123!"

    async with session_factory() as db:
        tenant = Tenant(name="Enrollment Tenant", slug="enrollment-tenant")
        admin_user = User(
            email="admin@enrollment.io",
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

    admin_token = create_access_token(user_id=user_id, tenant_id=tenant_id)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Generate Enrollment Code
    code_res = await client.post(
        "/api/v1/control/enrollment-codes",
        json={"tenant_id": tenant_id},
        headers=headers,
    )
    assert code_res.status_code == 200
    code_data = code_res.json()
    raw_code = code_data["code"]
    assert raw_code.startswith("NETRA-")

    # 2. Agent Enrollment using generated code
    _, public_key_bytes = generate_ed25519_keypair()
    public_key_hex = public_key_bytes.hex()

    enroll_payload = {
        "code": raw_code,
        "hostname": "test-workstation-01",
        "os": "Linux 6.5.0-generic",
        "architecture": "x86_64",
        "agent_version": "0.1.0",
        "public_key": public_key_hex,
    }

    enroll_res = await client.post("/api/v1/agent/enroll", json=enroll_payload)
    assert enroll_res.status_code == 200
    enroll_data = enroll_res.json()
    assert enroll_data["status"] == "ENROLLED"
    device_id = enroll_data["device_id"]
    assert device_id is not None
    assert enroll_data["tenant_id"] == tenant_id

    # 3. Verify single-use code redemption enforcement
    reuse_res = await client.post("/api/v1/agent/enroll", json=enroll_payload)
    assert reuse_res.status_code == 400
    assert "already been redeemed" in reuse_res.json()["error"]["message"]


@pytest.mark.asyncio
async def test_unauthorized_user_cannot_generate_code(client: AsyncClient, app) -> None:
    """Verify user with AUDITOR role cannot generate enrollment code."""
    from netra_backend.database import get_session_factory

    session_factory = get_session_factory()
    password = "AuditorPassword123!"

    async with session_factory() as db:
        tenant = Tenant(name="Auditor Tenant", slug="auditor-tenant")
        auditor_user = User(
            email="auditor@enrollment.io",
            password_hash=hash_password(password),
            display_name="Auditor User",
            is_active=True,
        )
        db.add(tenant)
        db.add(auditor_user)
        await db.flush()

        membership = TenantMembership(
            tenant_id=tenant.id, user_id=auditor_user.id, role=Role.AUDITOR
        )
        db.add(membership)
        await db.commit()

        tenant_id = tenant.id
        user_id = auditor_user.id

    token = create_access_token(user_id=user_id, tenant_id=tenant_id)
    headers = {"Authorization": f"Bearer {token}"}

    res = await client.post(
        "/api/v1/control/enrollment-codes",
        json={"tenant_id": tenant_id},
        headers=headers,
    )
    assert res.status_code == 403
    assert "Insufficient permissions" in res.json()["error"]["message"]
