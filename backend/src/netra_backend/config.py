"""NETRA Backend Configuration Module.

Uses pydantic-settings for strongly typed environment configuration with strict validation.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
            # Check if JSON array format or comma-separated
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
    def validate_production_security(self) -> "Settings":
        """Enforce strict security constraints for production environments."""
        if self.env == "production" and "*" in self.allowed_origins:
            raise ValueError(
                "Wildcard CORS origin '*' is strictly prohibited in production environment."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    """Dependency injection accessor for application settings with caching."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear cached settings (primarily used for test environment isolation)."""
    get_settings.cache_clear()
