"""Pytest Configuration and Shared Fixtures for NETRA Backend Test Suite."""

from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from netra_backend.config import Settings, reset_settings_cache
from netra_backend.main import create_app


@pytest.fixture(autouse=True)
def reset_config_state() -> None:
    """Reset configuration cache before and after every test for complete environment isolation."""
    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture
def test_settings() -> Settings:
    """Fixture providing standard test environment settings."""
    return Settings(
        env="test",
        host="127.0.0.1",
        port=4000,
        log_level="DEBUG",
        api_prefix="/api/v1",
        allowed_origins=["http://localhost:3000"],
    )


@pytest.fixture
def app(test_settings: Settings) -> FastAPI:
    """Fixture providing FastAPI application instance configured for testing."""
    return create_app(test_settings)


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Fixture providing async HTTP client connected to test application."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as ac:
        yield ac
