"""NETRA Centralized Error Handler Middleware.

Implements the standard machine-readable error envelope contract across all API endpoints:
{
  "success": false,
  "error": {
    "code": "CODE_NAME",
    "message": "Human readable description",
    "request_id": "...",
    "timestamp": "..."
  }
}
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from netra_backend.logging import get_logger
from netra_backend.middleware.request_id import request_id_var

logger = get_logger(__name__)


def create_error_response(
    status_code: int,
    code: str,
    message: str,
    request_id: str | None = None,
    details: Any = None,
) -> JSONResponse:
    """Construct a standardized error JSON response."""
    if not request_id:
        request_id = request_id_var.get() or "unknown"

    content: dict[str, Any] = {
        "success": False,
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
            "timestamp": datetime.now(UTC).isoformat(),
        },
    }
    if details is not None and not isinstance(details, Exception):
        content["error"]["details"] = details

    return JSONResponse(status_code=status_code, content=content)


def sanitize_validation_errors(errors: Sequence[Any]) -> list[dict[str, Any]]:
    """Sanitize Pydantic validation errors to remove sensitive field values or raw inputs."""
    sanitized = []
    for err in errors:
        if isinstance(err, dict):
            item = {
                "loc": [str(loc) for loc in err.get("loc", [])],
                "msg": err.get("msg", "Invalid input"),
                "type": err.get("type", "value_error"),
            }
            sanitized.append(item)
    return sanitized


def add_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers on the FastAPI application."""

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Handle HTTP status exceptions (404, 405, 403, etc.)."""
        req_id = getattr(request.state, "request_id", request_id_var.get())

        if exc.status_code == status.HTTP_404_NOT_FOUND:
            code = "NOT_FOUND"
            message = "Resource not found"
        elif exc.status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
            code = "METHOD_NOT_ALLOWED"
            message = f"Method {request.method} not allowed for endpoint"
        elif exc.status_code == status.HTTP_401_UNAUTHORIZED:
            code = "UNAUTHORIZED"
            message = str(exc.detail) if exc.detail else "Unauthorized access"
        elif exc.status_code == status.HTTP_403_FORBIDDEN:
            code = "FORBIDDEN"
            message = str(exc.detail) if exc.detail else "Forbidden access"
        else:
            code = "HTTP_ERROR"
            message = str(exc.detail) if exc.detail else "HTTP request error"

        return create_error_response(
            status_code=exc.status_code,
            code=code,
            message=message,
            request_id=req_id,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle 422 request validation errors safely."""
        req_id = getattr(request.state, "request_id", request_id_var.get())
        sanitized_details = sanitize_validation_errors(exc.errors())

        return create_error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            code="VALIDATION_ERROR",
            message="Request validation failed",
            request_id=req_id,
            details=sanitized_details,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle unhandled 500 internal server exceptions safely without leaking tracebacks."""
        req_id = getattr(request.state, "request_id", request_id_var.get())

        # Log complete stack trace internally for ops/debugging
        logger.error(
            "unhandled_server_exception",
            exception_type=type(exc).__name__,
            exc_info=exc,
            request_id=req_id,
            path=request.url.path,
            method=request.method,
        )

        return create_error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="INTERNAL_ERROR",
            message="An internal server error occurred",
            request_id=req_id,
        )
