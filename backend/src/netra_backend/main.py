"""NETRA Backend FastAPI Main Application Module.

Provides application factory create_app() and server entrypoint.
"""

import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netra_backend.api.v1.auth import router as auth_router
from netra_backend.api.v1.health import router as health_router
from netra_backend.config import Settings, get_settings
from netra_backend.logging import get_logger, setup_logging
from netra_backend.middleware.error_handler import add_exception_handlers
from netra_backend.middleware.request_id import RequestIDMiddleware
from netra_backend.middleware.security_headers import SecurityHeadersMiddleware

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager for application startup and graceful shutdown."""
    logger.info("netra_backend_startup_initiated")

    # Extension point: Initialize future resources (e.g. PostgreSQL pool, Redis, WSS)

    logger.info("netra_backend_startup_complete")
    yield

    logger.info("netra_backend_shutdown_initiated")

    # Extension point: Release future resources cleanly during graceful shutdown

    logger.info("netra_backend_shutdown_complete")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory for constructing and configuring the FastAPI instance."""
    if settings is None:
        settings = get_settings()

    # Initialize structured JSON logging
    setup_logging(settings)

    # Determine OpenAPI docs URLs based on environment
    docs_url = f"{settings.api_prefix}/docs" if settings.env in ("development", "test") else None
    redoc_url = f"{settings.api_prefix}/redoc" if settings.env in ("development", "test") else None

    app = FastAPI(
        title="NETRA Central Security Engine",
        description="Production-grade multi-tenant security operations engine API.",
        version="0.1.0",
        docs_url=docs_url,
        redoc_url=redoc_url,
        lifespan=lifespan,
    )

    # 1. Install Request ID middleware (must be registered first)
    app.add_middleware(RequestIDMiddleware)

    # 2. Install Security Headers middleware
    app.add_middleware(SecurityHeadersMiddleware)

    # 3. Configure CORS middleware
    allowed_origins = settings.allowed_origins if settings.allowed_origins else []
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 4. Register global exception handlers
    add_exception_handlers(app)

    # 5. Register API routes
    app.include_router(health_router, prefix=settings.api_prefix)
    app.include_router(auth_router, prefix=f"{settings.api_prefix}/auth")

    return app


def run_server() -> None:
    """Execute server startup with configuration validation and graceful Uvicorn runner."""
    try:
        settings = get_settings()
    except Exception as exc:
        print(f"FATAL: Configuration validation failed: {exc}", file=sys.stderr)
        sys.exit(1)

    app = create_app(settings)

    logger.info(
        "starting_netra_backend_server",
        host=settings.host,
        port=settings.port,
        env=settings.env,
    )

    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_config=None,  # Use structlog logger configuration
        timeout_graceful_shutdown=10,
    )


if __name__ == "__main__":
    run_server()
