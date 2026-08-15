"""NETRA Structured Logging Module.

Configures structlog for structured JSON logging with contextvar tracing and secret redaction.
"""

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor

from netra_backend.config import Settings
from netra_backend.middleware.request_id import correlation_id_var, request_id_var

SENSITIVE_KEYS = {
    "password",
    "passphrase",
    "authorization",
    "auth",
    "token",
    "jwt",
    "secret",
    "private_key",
    "api_key",
    "secret_key",
    "credentials",
}


def redact_sensitive_processor(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Redact sensitive keys from log event dictionaries."""
    for key in list(event_dict.keys()):
        key_lower = key.lower()
        if any(sensitive in key_lower for sensitive in SENSITIVE_KEYS):
            event_dict[key] = "[REDACTED]"
    return event_dict


def add_contextvars_processor(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Inject service tag, request_id, and correlation_id from contextvars."""
    event_dict["service"] = "netra-backend"
    req_id = request_id_var.get()
    if req_id is not None:
        event_dict["request_id"] = req_id
    corr_id = correlation_id_var.get()
    if corr_id is not None:
        event_dict["correlation_id"] = corr_id
    return event_dict


def setup_logging(settings: Settings) -> None:
    """Configure structlog and standard logging based on application settings."""
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        add_contextvars_processor,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        redact_sensitive_processor,
    ]

    # Standard logging configuration
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
        force=True,
    )

    renderer: Processor = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Attach structlog renderer to standard logging handler
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.setFormatter(formatter)
        handler.setLevel(log_level)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance."""
    return structlog.get_logger(name)
