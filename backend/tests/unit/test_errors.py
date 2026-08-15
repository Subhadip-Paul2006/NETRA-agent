"""Unit tests for Centralized Error Handling contract."""

import pytest
from httpx import ASGITransport, AsyncClient

from netra_backend.main import create_app


@pytest.mark.asyncio
async def test_404_not_found_envelope(client: AsyncClient) -> None:
    """Verify unknown routes return HTTP 404 with standard machine-readable error envelope."""
    response = await client.get("/api/v1/unknown-endpoint-path")

    assert response.status_code == 404
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "NOT_FOUND"
    assert data["error"]["message"] == "Resource not found"
    assert "request_id" in data["error"]
    assert "timestamp" in data["error"]


@pytest.mark.asyncio
async def test_405_method_not_allowed_envelope(client: AsyncClient) -> None:
    """Verify invalid HTTP method returns HTTP 405 with standard error envelope."""
    response = await client.post("/api/v1/health")

    assert response.status_code == 405
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert "not allowed" in data["error"]["message"]
    assert "request_id" in data["error"]


@pytest.mark.asyncio
async def test_500_internal_error_sanitization() -> None:
    """Verify unhandled exceptions return 500 error envelope without leaking tracebacks."""
    app = create_app()

    @app.get("/api/v1/test-crash")
    async def crash_route() -> None:
        raise RuntimeError("Database connection string postgresql://user:secret_password@db/db")

    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://testserver"
    ) as ac:
        response = await ac.get("/api/v1/test-crash")

    assert response.status_code == 500
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "INTERNAL_ERROR"
    assert data["error"]["message"] == "An internal server error occurred"

    # Crucial security check: Ensure raw exception message, secrets, and tracebacks are sanitized
    raw_response_text = response.text
    assert "secret_password" not in raw_response_text
    assert "RuntimeError" not in raw_response_text
    assert "Traceback" not in raw_response_text
