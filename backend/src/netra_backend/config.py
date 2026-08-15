"""NETRA Backend Configuration Module.

Uses pydantic-settings for strongly typed environment configuration with strict validation
and production secret enforcement.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SUSPICIOUS_SECRET_PATTERNS = {
    "change_this",
    "password",
    "secret",
    "placeholder",
    "123456",
    "default",
}


class Settings(BaseSettings):
    """Centralized, strongly-typed application settings."""

    model_config = SettingsConfigDict(
        env_prefix="NETRA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["development", "staging", "production", "test"] = "development"
    host: str = "127.0.0.1"
    port: int = Field(default=4000, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    api_prefix: str = "/api/v1"
    allowed_origins: list[str] = Field(default_factory=list)

    # Database Settings
    database_url: str | None = None
    database_pool_min: int = Field(default=2, ge=1)
    database_pool_max: int = Field(default=10, ge=1)

    # Authentication & JWT Settings
    jwt_secret: str | None = None
    jwt_refresh_secret: str | None = None
    jwt_algorithm: str = "HS256"
    jwt_access_expiration_minutes: int = Field(default=15, ge=1)
    jwt_refresh_expiration_days: int = Field(default=7, ge=1)
    jwt_issuer: str = "netra-backend"
    jwt_audience: str = "netra-client"

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: str | list[str] | None) -> list[str]:
        """Parse comma-separated string or list into a list of origins."""
        if value is None:
            return []
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return []
            if value.startswith("[") and value.endswith("]"):
                import json

                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if item]
                except json.JSONDecodeError:
                    pass
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("api_prefix")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        """Ensure API prefix starts with slash and does not end with trailing slash."""
        if not value.startswith("/"):
            raise ValueError("api_prefix must start with '/'")
        if len(value) > 1 and value.endswith("/"):
            return value.rstrip("/")
        return value

    @model_validator(mode="after")
    def apply_defaults_and_validate_secrets(self) -> "Settings":
        """Apply environment defaults and enforce strict security rules for production/staging."""
        # Development / Test defaults
        if self.env in ("development", "test"):
            if not self.database_url:
                self.database_url = "sqlite+aiosqlite:///:memory:"
            if not self.jwt_secret:
                self.jwt_secret = "netra_dev_jwt_access_secret_key_32chars_long!"
            if not self.jwt_refresh_secret:
                self.jwt_refresh_secret = "netra_dev_jwt_refresh_secret_key_32chars!"

        # Production / Staging enforcement
        if self.env in ("production", "staging"):
            if "*" in self.allowed_origins:
                raise ValueError(
                    "Wildcard CORS origin '*' is strictly prohibited in production environment."
                )

            if not self.database_url:
                raise ValueError(
                    "NETRA_DATABASE_URL is required in staging/production environment."
                )

            if not self.jwt_secret:
                raise ValueError("NETRA_JWT_SECRET is required in staging/production environment.")

            if len(self.jwt_secret) < 32:
                raise ValueError("NETRA_JWT_SECRET must be at least 32 characters long.")

            if any(pat in self.jwt_secret.lower() for pat in SUSPICIOUS_SECRET_PATTERNS):
                raise ValueError("NETRA_JWT_SECRET contains a placeholder or weak secret pattern.")

            if not self.jwt_refresh_secret:
                raise ValueError(
                    "NETRA_JWT_REFRESH_SECRET is required in staging/production environment."
                )

            if len(self.jwt_refresh_secret) < 32:
                raise ValueError("NETRA_JWT_REFRESH_SECRET must be at least 32 characters long.")

            if any(pat in self.jwt_refresh_secret.lower() for pat in SUSPICIOUS_SECRET_PATTERNS):
                raise ValueError(
                    "NETRA_JWT_REFRESH_SECRET contains a placeholder or weak secret pattern."
                )

        return self


@lru_cache
def get_settings() -> Settings:
    """Dependency injection accessor for application settings with caching."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear cached settings (primarily used for test environment isolation)."""
    get_settings.cache_clear()
