"""Unit tests for Backend Security controls and log redaction."""

import pytest
from httpx import AsyncClient

from netra_backend.logging import redact_sensitive_processor


@pytest.mark.asyncio
async def test_security_headers_present(client: AsyncClient) -> None:
    """Verify standard security headers are attached to API responses."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200

    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "default-src 'none'" in response.headers.get("Content-Security-Policy", "")


@pytest.mark.asyncio
async def test_cors_headers(client: AsyncClient) -> None:
    """Verify CORS origin header handling."""
    headers = {"Origin": "http://localhost:3000"}
    response = await client.get("/api/v1/health", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"


def test_sensitive_log_data_redaction() -> None:
    """Verify sensitive fields in log event dicts are masked by redaction processor."""
    event_dict = {
        "event": "user_login_attempt",
        "username": "alice",
        "password": "SuperSecretPassword123!",
        "authorization": "Bearer eyJhbGciOiJIUzI1Ni...",
        "jwt_token": "secret_token_val",
        "private_key_pem": "-----BEGIN PRIVATE KEY-----",
    }

    processed = redact_sensitive_processor(None, "info", event_dict)

    assert processed["username"] == "alice"
    assert processed["password"] == "[REDACTED]"
    assert processed["authorization"] == "[REDACTED]"
    assert processed["jwt_token"] == "[REDACTED]"
    assert processed["private_key_pem"] == "[REDACTED]"
