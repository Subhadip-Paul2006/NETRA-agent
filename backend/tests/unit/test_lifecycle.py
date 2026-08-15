"""Unit tests for FastAPI Lifespan Startup and Shutdown lifecycle events."""

import pytest

from netra_backend.config import Settings
from netra_backend.main import create_app, lifespan


@pytest.mark.asyncio
async def test_lifespan_startup_and_shutdown() -> None:
    """Verify application lifespan manager executes startup and shutdown cleanly."""
    settings = Settings(env="test")
    app = create_app(settings)

    async with lifespan(app):
        # Application is active inside lifespan context
        assert app.title == "NETRA Central Security Engine"
