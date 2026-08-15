"""NETRA Security Headers Middleware.

Applies API-appropriate HTTP security headers to protect against MIME-sniffing,
clickjacking, and header injection.
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware attaching security headers to all HTTP API responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Add security headers to response."""
        response = await call_next(request)

        # 1. Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 2. Prevent frame embedding / clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # 3. Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 4. Content Security Policy for API endpoint responses
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

        # 5. Disable caching for sensitive API responses (optional/standard for APIs)
        response.headers["X-XSS-Protection"] = "0"

        return response
