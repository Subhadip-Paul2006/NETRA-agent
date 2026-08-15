"""Unit tests for NETRA Backend Health & Readiness Probes."""

import pytest
from httpx import AsyncClient

from netra_backend.api.v1.health import readiness_manager


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient) -> None:
    """Verify Liveness probe returns 200 OK with status UP."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UP"
    assert data["service"] == "netra-backend"


@pytest.mark.asyncio
async def test_readiness_endpoint_default(client: AsyncClient) -> None:
    """Verify Readiness probe returns 200 OK with status READY by default."""
    response = await client.get("/api/v1/readiness")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "READY"
    assert data["service"] == "netra-backend"
    assert data["checks"]["app"] == "ok"


@pytest.mark.asyncio
async def test_readiness_custom_check_registration(client: AsyncClient) -> None:
    """Verify registering and executing custom subsystem readiness checks."""

    async def mock_subsystem_check() -> bool:
        return True

    readiness_manager.register("mock_subsystem", mock_subsystem_check)

    try:
        response = await client.get("/api/v1/readiness")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "READY"
        assert data["checks"]["mock_subsystem"] == "ok"
    finally:
        readiness_manager.unregister("mock_subsystem")


@pytest.mark.asyncio
async def test_readiness_failing_check(client: AsyncClient) -> None:
    """Verify readiness returns NOT_READY status when a check fails."""

    def failing_check() -> bool:
        return False

    readiness_manager.register("failing_subsystem", failing_check)

    try:
        response = await client.get("/api/v1/readiness")
        data = response.json()
        assert data["status"] == "NOT_READY"
        assert data["checks"]["failing_subsystem"] == "failed"
    finally:
        readiness_manager.unregister("failing_subsystem")
