"""NETRA Request ID & Correlation ID Middleware.

Maintains request-scoped execution context using contextvars to guarantee complete
concurrency isolation across asynchronous tasks.
"""

import re
import uuid
from contextvars import ContextVar

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

# Request-scoped ContextVars (task-local in asyncio)
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)

# Pattern for safe header identifiers (alphanumeric, hyphens, underscores, 1-128 chars)
SAFE_HEADER_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")


def is_valid_identifier(val: str | None) -> bool:
    """Validate header value to prevent header injection or control character attacks."""
    if not val:
        return False
    return bool(SAFE_HEADER_ID_REGEX.match(val))


def generate_secure_id() -> str:
    """Generate cryptographically safe UUIDv4 string."""
    return uuid.uuid4().hex


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing request ID and correlation ID tracing and context isolation."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Process incoming HTTP request, managing request-scoped context variables."""
        # 1. Request ID resolution
        raw_request_id = request.headers.get("X-Request-ID")
        request_id: str = (
            raw_request_id
            if raw_request_id and is_valid_identifier(raw_request_id)
            else generate_secure_id()
        )

        # 2. Correlation ID resolution
        raw_correlation_id = request.headers.get("X-Correlation-ID")
        correlation_id: str = (
            raw_correlation_id
            if raw_correlation_id and is_valid_identifier(raw_correlation_id)
            else request_id
        )

        # 3. Bind contextvars for the duration of this request task
        req_token = request_id_var.set(request_id)
        corr_token = correlation_id_var.set(correlation_id)

        # Store on request state as well for convenient route access
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id

        try:
            response = await call_next(request)
            # Inject headers into outgoing response
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Correlation-ID"] = correlation_id
            return response
        finally:
            # Reset contextvars to prevent leaks across reused threads/tasks
            request_id_var.reset(req_token)
            correlation_id_var.reset(corr_token)
