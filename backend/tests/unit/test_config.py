"""Unit tests for NETRA Configuration Settings module."""

import pytest
from pydantic import ValidationError

from netra_backend.config import Settings, get_settings, reset_settings_cache


def test_default_settings() -> None:
    """Verify default settings construct cleanly with expected default values."""
    settings = Settings()
    assert settings.env == "development"
    assert settings.host == "127.0.0.1"
    assert settings.port == 4000
    assert settings.log_level == "INFO"
    assert settings.api_prefix == "/api/v1"


def test_invalid_port() -> None:
    """Verify out-of-bounds port numbers raise validation errors."""
    with pytest.raises(ValidationError):
        Settings(port=0)

    with pytest.raises(ValidationError):
        Settings(port=70000)


def test_invalid_env() -> None:
    """Verify unapproved environment names raise validation errors."""
    with pytest.raises(ValidationError):
        Settings(env="invalid_environment")  # type: ignore[arg-type]


def test_invalid_api_prefix() -> None:
    """Verify API prefix must start with slash."""
    with pytest.raises(ValidationError):
        Settings(api_prefix="api/v1")


def test_cors_origins_parsing() -> None:
    """Verify string parsing for CORS origins."""
    settings = Settings(allowed_origins="http://localhost:3000, http://127.0.0.1:3000")  # type: ignore[arg-type]
    assert settings.allowed_origins == [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


def test_cors_origins_json_array_parsing() -> None:
    """Verify JSON array string parsing for CORS origins."""
    settings = Settings(allowed_origins='["http://localhost:3000", "http://localhost:8080"]')  # type: ignore[arg-type]
    assert settings.allowed_origins == [
        "http://localhost:3000",
        "http://localhost:8080",
    ]


def test_production_wildcard_cors_rejected() -> None:
    """Verify wildcard '*' CORS origins are rejected in production environment."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            env="production",
            allowed_origins=["*"],
            database_url="postgresql+asyncpg://u:p@db/db",
            jwt_secret="netra_prod_jwt_access_auth_key_32chars_long",
            jwt_refresh_secret="netra_prod_jwt_refresh_auth_key_32chars",
        )
    assert "Wildcard CORS origin '*' is strictly prohibited" in str(exc_info.value)


def test_production_valid_cors_accepted() -> None:
    """Verify non-wildcard explicit CORS origins are accepted in production."""
    settings = Settings(
        env="production",
        allowed_origins=["https://dashboard.netra.io"],
        database_url="postgresql+asyncpg://u:p@db/db",
        jwt_secret="netra_prod_jwt_access_auth_key_32chars_long",
        jwt_refresh_secret="netra_prod_jwt_refresh_auth_key_32chars",
    )
    assert settings.env == "production"
    assert settings.allowed_origins == ["https://dashboard.netra.io"]


def test_settings_dependency_injection_caching() -> None:
    """Verify get_settings() returns cached instance and reset_settings_cache() clears it."""
    reset_settings_cache()
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2

    reset_settings_cache()
    s3 = get_settings()
    assert s1 is not s3
