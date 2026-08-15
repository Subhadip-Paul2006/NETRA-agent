"""Pytest Configuration and Shared Fixtures for NETRA Backend Test Suite."""

from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netra_backend.config import Settings, reset_settings_cache
from netra_backend.main import create_app


@pytest.fixture(autouse=True)
def reset_config_state() -> None:
    """Reset configuration cache before and after every test for complete environment isolation."""
    reset_settings_cache()
    try:
        from netra_backend.database import get_engine

        get_engine.cache_clear()
    except Exception:
        pass
    yield
    reset_settings_cache()
    try:
        from netra_backend.database import get_engine

        get_engine.cache_clear()
    except Exception:
        pass


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
        database_url="sqlite+aiosqlite:///:memory:",
    )


@pytest_asyncio.fixture
async def db_session(test_settings: Settings) -> AsyncGenerator[AsyncSession, None]:
    """Fixture providing an isolated database session with tables created."""
    from netra_backend.database import get_engine, get_session_factory
    from netra_backend.models import Base

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = get_session_factory(engine)
    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def app(test_settings: Settings) -> FastAPI:
    """Fixture providing FastAPI application instance configured for testing."""
    return create_app(test_settings)


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Fixture providing async HTTP client connected to test application."""
    from netra_backend.database import get_engine
    from netra_backend.models import Base

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as ac:
        yield ac

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
