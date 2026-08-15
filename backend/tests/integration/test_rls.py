"""Integration tests for with_tenant_context and PostgreSQL Row-Level Security (RLS)."""

import pytest

from netra_backend.rls import with_tenant_context


@pytest.mark.asyncio
async def test_missing_tenant_context_raises_fatal(app) -> None:
    """Verify database operations without valid tenant_id raise fatal security exception."""
    from netra_backend.database import get_session_factory

    session_factory = get_session_factory()

    async with session_factory() as session:
        with pytest.raises(ValueError) as exc_info:
            async with with_tenant_context("", session):
                pass

        assert "MissingTenantContextException" in str(exc_info.value)


@pytest.mark.asyncio
async def test_with_tenant_context_execution() -> None:
    """Verify with_tenant_context executes cleanly within an async database transaction."""
    from netra_backend.database import get_session_factory

    session_factory = get_session_factory()

    async with session_factory() as session, with_tenant_context("tenant-alpha-123", session):
        # Session is active inside tenant context
        assert session.is_active is True
