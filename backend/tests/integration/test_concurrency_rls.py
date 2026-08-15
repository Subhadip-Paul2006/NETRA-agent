"""Integration tests for Multi-Tenant Concurrency and Async Session Isolation."""

import asyncio

import pytest
from httpx import AsyncClient

from netra_backend.models import Tenant, TenantMembership, User
from netra_backend.rls import with_tenant_context
from netra_backend.security import decode_token, hash_password
from netra_shared.enums import Role


@pytest.mark.asyncio
async def test_concurrent_multi_tenant_user_isolation(client: AsyncClient, app) -> None:
    """Verify concurrent multi-tenant requests execute cleanly in complete isolation."""
    from netra_backend.database import get_session_factory

    session_factory = get_session_factory()
    password = "TenantPassword123!"

    # 1. Setup Tenants and Users in database
    tenants_data = [
        ("Tenant-Alpha", "alpha-tenant", "user_alpha@netra.io"),
        ("Tenant-Beta", "beta-tenant", "user_beta@netra.io"),
        ("Tenant-Gamma", "gamma-tenant", "user_gamma@netra.io"),
    ]

    tenant_ids: dict[str, str] = {}
    user_ids: dict[str, str] = {}

    async with session_factory() as db:
        for t_name, t_slug, u_email in tenants_data:
            t = Tenant(name=t_name, slug=t_slug)
            u = User(
                email=u_email,
                password_hash=hash_password(password),
                display_name=t_name,
                is_active=True,
            )
            db.add(t)
            db.add(u)
            await db.flush()

            m = TenantMembership(tenant_id=t.id, user_id=u.id, role=Role.ADMIN)
            db.add(m)
            await db.commit()

            tenant_ids[t_slug] = t.id
            user_ids[u_email] = u.id

    # 2. Define concurrent worker task
    async def run_tenant_worker(t_slug: str, u_email: str) -> dict[str, str]:
        expected_t_id = tenant_ids[t_slug]
        expected_u_id = user_ids[u_email]

        # Login request
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": u_email, "password": password, "tenant_id": expected_t_id},
        )
        assert login_res.status_code == 200
        token_data = login_res.json()
        assert token_data["tenant_id"] == expected_t_id
        assert token_data["user_id"] == expected_u_id

        # Validate token payload
        decoded = decode_token(token_data["access_token"], expected_type="access")
        assert decoded["sub"] == expected_u_id
        assert decoded["tenant_id"] == expected_t_id

        # Database session context execution
        async with session_factory() as db, with_tenant_context(expected_t_id, db):
            await asyncio.sleep(0.01)  # Yield control to simulate concurrent I/O
            current_u = await db.get(User, expected_u_id)
            assert current_u is not None
            assert current_u.email == u_email

        return {"user_id": token_data["user_id"], "tenant_id": token_data["tenant_id"]}

    # 3. Execute workers concurrently
    tasks = [
        run_tenant_worker("alpha-tenant", "user_alpha@netra.io"),
        run_tenant_worker("beta-tenant", "user_beta@netra.io"),
        run_tenant_worker("gamma-tenant", "user_gamma@netra.io"),
    ]

    results = await asyncio.gather(*tasks)

    # 4. Verify all concurrent tasks completed with strict tenant identity matching
    assert results[0]["tenant_id"] == tenant_ids["alpha-tenant"]
    assert results[1]["tenant_id"] == tenant_ids["beta-tenant"]
    assert results[2]["tenant_id"] == tenant_ids["gamma-tenant"]
