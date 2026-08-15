"""Unit tests for Request ID & Correlation ID middleware."""

import pytest
from httpx import AsyncClient

from netra_backend.middleware.request_id import is_valid_identifier


def test_is_valid_identifier() -> None:
    """Verify identifier pattern validation logic."""
    assert is_valid_identifier("valid-request-id-123_ABC") is True
    assert is_valid_identifier("a" * 128) is True

    # Invalid cases
    assert is_valid_identifier("") is False
    assert is_valid_identifier(None) is False
    assert is_valid_identifier("invalid header with spaces") is False
    assert is_valid_identifier("header\nwith\nnewlines") is False
    assert is_valid_identifier("a" * 129) is False
    assert is_valid_identifier("<script>alert(1)</script>") is False


@pytest.mark.asyncio
async def test_valid_request_id_preserved(client: AsyncClient) -> None:
    """Verify valid X-Request-ID is preserved in response headers."""
    headers = {"X-Request-ID": "test-request-id-999"}
    response = await client.get("/api/v1/health", headers=headers)

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "test-request-id-999"
    assert response.headers["X-Correlation-ID"] == "test-request-id-999"


@pytest.mark.asyncio
async def test_missing_request_id_generated(client: AsyncClient) -> None:
    """Verify missing X-Request-ID automatically generates a secure hex identifier."""
    response = await client.get("/api/v1/health")

    assert response.status_code == 200
    req_id = response.headers.get("X-Request-ID")
    assert req_id is not None
    assert is_valid_identifier(req_id) is True
    assert len(req_id) == 32  # uuid4 hex string length


@pytest.mark.asyncio
async def test_invalid_request_id_replaced(client: AsyncClient) -> None:
    """Verify malformed or injection attempt request IDs are safely replaced with UUIDs."""
    headers = {"X-Request-ID": "malformed id with spaces\r\nHeader-Injection: bad"}
    response = await client.get("/api/v1/health", headers=headers)

    assert response.status_code == 200
    req_id = response.headers["X-Request-ID"]
    assert req_id != headers["X-Request-ID"]
    assert is_valid_identifier(req_id) is True


@pytest.mark.asyncio
async def test_explicit_correlation_id_preserved(client: AsyncClient) -> None:
    """Verify explicit X-Correlation-ID is preserved distinctly from X-Request-ID."""
    headers = {
        "X-Request-ID": "req-12345",
        "X-Correlation-ID": "corr-67890",
    }
    response = await client.get("/api/v1/health", headers=headers)

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "req-12345"
    assert response.headers["X-Correlation-ID"] == "corr-67890"
