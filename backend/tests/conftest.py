"""Pytest Configuration and Shared Fixtures for NETRA Backend Test Suite.

The default unit/integration database is a SQLite in-memory file shared across all
connections of the engine (StaticPool) so that concurrent sessions observe the same
database. When the environment variable NETRA_DATABASE_URL points at a PostgreSQL
database (e.g. CI), every test runs against that real database instead, enabling
genuine PostgreSQL semantics (RLS, concurrency, constraint violation retries).
"""

import os
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.pool import StaticPool

from netra_backend.config import Settings, reset_settings_cache
from netra_backend.main import create_app

POSTGRES_TEST_URL = os.environ.get("NETRA_DATABASE_URL")


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
        log_level="INFO",
        api_prefix="/api/v1",
        allowed_origins=["http://localhost:3000"],
        database_url=POSTGRES_TEST_URL or "sqlite+aiosqlite:///:memory:",
    )


def _is_postgres(settings: Settings) -> bool:
    url = settings.database_url or ""
    return url.startswith("postgresql")


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


_TEST_MEMORY_ENGINE = None


def get_shared_test_engine():
    global _TEST_MEMORY_ENGINE
    if _TEST_MEMORY_ENGINE is None:
        from sqlalchemy.ext.asyncio import create_async_engine

        _TEST_MEMORY_ENGINE = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False, "timeout": 30},
            echo=False,
        )
    return _TEST_MEMORY_ENGINE


@pytest.fixture
def app(test_settings: Settings) -> FastAPI:
    """Fixture providing FastAPI application instance configured for testing."""
    if not _is_postgres(test_settings):
        import netra_backend.database as database_module

        original_get_engine = database_module.get_engine
        database_module.get_engine = get_shared_test_engine  # type: ignore[assignment]
        app_instance = create_app(test_settings)
        database_module.get_engine = original_get_engine  # type: ignore[assignment]
        return app_instance
    return create_app(test_settings)


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Fixture providing async HTTP client connected to test application."""
    from netra_backend.database import get_engine
    from netra_backend.models import Base

    engine = get_engine()

    # PostgreSQL CI mode: apply real Alembic migrations (including RLS DDL)
    if _is_postgres(Settings(database_url=POSTGRES_TEST_URL, env="test")):
        await run_alembic_migrations(reset_engine_cache_after=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Ensure a clean slate per test while keeping PostgreSQL schema
    async with engine.begin() as conn:
        tables = reversed(Base.metadata.sorted_tables)
        for table in tables:
            await conn.execute(table.delete())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as ac:
        yield ac

    async with engine.begin() as conn:
        tables = reversed(Base.metadata.sorted_tables)
        for table in tables:
            await conn.execute(table.delete())


async def run_alembic_migrations(reset_engine_cache_after: bool = True) -> None:
    """Run Alembic migrations to head against the configured PostgreSQL database."""
    import contextlib

    from alembic import command
    from alembic.config import Config

    import netra_backend.config as config_module

    config_module.get_settings.cache_clear()

    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    alembic_cfg = Config(os.path.join(backend_dir, "alembic.ini"))
    alembic_cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))

    # Alembic env.py uses asyncio.run internally; run it in a worker thread to avoid
    # nested event loop conflicts.
    import asyncio

    await asyncio.to_thread(command.upgrade, alembic_cfg, "head")

    if reset_engine_cache_after:
        with contextlib.suppress(Exception):
            from netra_backend.database import get_engine

            get_engine.cache_clear()
