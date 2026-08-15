"""PostgreSQL Row-Level Security (RLS) Session Context Module.

Enforces transaction-scoped tenant isolation via set_config('app.current_tenant_id', ...).
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@asynccontextmanager
async def with_tenant_context(
    tenant_id: str, session: AsyncSession
) -> AsyncGenerator[AsyncSession, None]:
    """Wrap database operations inside transaction-scoped PostgreSQL tenant context (`SET LOCAL`).

    Raises:
        ValueError: If tenant_id is missing, empty, or whitespace.
    """
    if not tenant_id or not tenant_id.strip():
        raise ValueError(
            "SECURITY_FATAL: MissingTenantContextException - "
            "Cannot query tenant data without valid tenant_id context."
        )

    clean_tenant_id = tenant_id.strip()

    # If running against PostgreSQL engine, set transaction-local GUC variable
    bind = session.get_bind()
    if bind and bind.dialect.name == "postgresql":
        await session.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": clean_tenant_id},
        )

    try:
        yield session
    finally:
        pass
