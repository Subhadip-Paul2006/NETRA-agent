"""Integration tests for Authentication REST API endpoints."""

import pytest
from httpx import AsyncClient

from netra_backend.models import Tenant, TenantMembership, User
from netra_backend.security import create_refresh_token, hash_password
from netra_shared.enums import Role


@pytest.mark.asyncio
async def test_login_invalid_credentials(client: AsyncClient) -> None:
    """Verify non-existent user or invalid password returns 401 generic unauthorized response."""
    payload = {"email": "nonexistent@netra.io", "password": "WrongPassword123!"}
    response = await client.post("/api/v1/auth/login", json=payload)

    assert response.status_code == 401
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "UNAUTHORIZED"
    assert data["error"]["message"] == "Invalid email or password"


@pytest.mark.asyncio
async def test_login_and_refresh_rotation_flow(client: AsyncClient, app) -> None:
    """Verify valid login issues tokens, and refresh endpoint rotates refresh tokens cleanly."""
    from netra_backend.database import get_session_factory

    session_factory = get_session_factory()
    password = "CorrectHorseBatteryStaple123!"

    async with session_factory() as db:
        # Create test tenant and user
        tenant = Tenant(name="Test Tenant", slug="test-tenant")
        user = User(
            email="alice@netra.io",
            password_hash=hash_password(password),
            display_name="Alice",
            is_active=True,
        )
        db.add(tenant)
        db.add(user)
        await db.flush()

        membership = TenantMembership(tenant_id=tenant.id, user_id=user.id, role=Role.ADMIN)
        db.add(membership)
        await db.commit()

        user_id = user.id
        tenant_id = tenant.id

    # 1. Login
    login_payload = {"email": "alice@netra.io", "password": password, "tenant_id": tenant_id}
    login_res = await client.post("/api/v1/auth/login", json=login_payload)

    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["user_id"] == user_id
    assert login_data["tenant_id"] == tenant_id
    assert "access_token" in login_data
    assert "refresh_token" in login_data

    first_refresh = login_data["refresh_token"]

    # 2. Refresh Token Rotation
    refresh_payload = {"refresh_token": first_refresh}
    refresh_res = await client.post("/api/v1/auth/refresh", json=refresh_payload)

    assert refresh_res.status_code == 200
    refresh_data = refresh_res.json()
    assert refresh_data["user_id"] == user_id
    assert "access_token" in refresh_data
    assert "refresh_token" in refresh_data
    assert refresh_data["refresh_token"] != first_refresh


@pytest.mark.asyncio
async def test_logout_endpoint(client: AsyncClient, app) -> None:
    """Verify logout endpoint revokes user refresh session."""
    refresh_token = create_refresh_token(user_id="usr-999")
    logout_payload = {"refresh_token": refresh_token}
    response = await client.post("/api/v1/auth/logout", json=logout_payload)

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
