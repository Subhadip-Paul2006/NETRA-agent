"""SQLAlchemy 2.x Async Engine and Session Management Module."""

from collections.abc import AsyncGenerator
from functools import lru_cache

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from netra_backend.config import get_settings


@lru_cache
def get_engine() -> AsyncEngine:
    """Create and cache the primary SQLAlchemy AsyncEngine instance."""
    settings = get_settings()
    url = settings.database_url
    if not url:
        raise ValueError("DATABASE_URL must be configured.")

    # Convert standard postgresql:// to postgresql+asyncpg:// if needed
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

    from typing import Any

    from sqlalchemy.pool import StaticPool

    is_sqlite = url.startswith("sqlite")
    engine_kwargs: dict[str, Any] = {"echo": settings.log_level == "DEBUG"}

    if is_sqlite:
        # SQLite in-memory databases are per-connection by default; a StaticPool makes
        # every session share one connection (and therefore one database), which is
        # required for concurrency tests and cross-session consistency.
        if ":memory:" in url:
            engine_kwargs["poolclass"] = StaticPool
            engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    else:
        engine_kwargs["pool_size"] = settings.database_pool_min
        engine_kwargs["max_overflow"] = settings.database_pool_max - settings.database_pool_min

    return create_async_engine(url, **engine_kwargs)


def get_session_factory(engine: AsyncEngine | None = None) -> async_sessionmaker[AsyncSession]:
    """Create async session factory bound to engine."""
    if engine is None:
        engine = get_engine()
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an isolated AsyncSession per request."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
