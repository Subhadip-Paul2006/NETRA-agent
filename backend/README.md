# NETRA Backend Central Security Engine (`netra-backend`)

The **NETRA Backend** (`backend/`) is the central control, orchestration, multi-tenant database owner, and telemetry processing engine of the NETRA security toolkit.

---

## 1. Architecture & Position

In the NETRA monorepo, `backend/` serves as the core authority:
- **FastAPI / Uvicorn**: High-performance asynchronous REST API framework.
- **Pydantic v2 Settings**: Strongly-typed environment validation and configuration.
- **Structlog**: Structured JSON logging with request tracing and credential redaction.
- **`src/` Layout**: Packaged cleanly under `src/netra_backend` for editable package installation without modifying `PYTHONPATH`.

```
NETRA-agent/
├── backend/
│   ├── pyproject.toml
│   ├── README.md
│   ├── src/
│   │   └── netra_backend/
│   │       ├── __init__.py
│   │       ├── main.py
│   │       ├── config.py
│   │       ├── logging.py
│   │       ├── middleware/
│   │       │   ├── request_id.py
│   │       │   ├── error_handler.py
│   │       │   └── security_headers.py
│   │       └── api/
│   │           └── v1/
│   │               └── health.py
│   └── tests/
│       ├── conftest.py
│       └── unit/
```

---

## 2. Prerequisites & Setup

### Prerequisites
- Python **3.11+**

### Installation
From the repository root or `backend/` directory, install in editable mode with development dependencies:

```bash
pip install -e backend/.[dev]
```

`pyproject.toml` is the **single source of truth** for all runtime and development dependencies.

---

## 3. Environment Configuration

All environment variables use the `NETRA_` prefix:

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `NETRA_ENV` | `development` | Environment mode (`development`, `staging`, `production`, `test`) |
| `NETRA_HOST` | `127.0.0.1` | Server bind host address |
| `NETRA_PORT` | `4000` | Server bind port (1 - 65535) |
| `NETRA_LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `NETRA_API_PREFIX` | `/api/v1` | Base API router prefix |
| `NETRA_ALLOWED_ORIGINS` | `[]` | Comma-separated list or JSON array of allowed CORS origins |

> [!IMPORTANT]
> Setting `NETRA_ENV=production` enforces strict security constraints: wildcard CORS origins (`*`) are prohibited and raise immediate boot-time validation errors.

---

## 4. Running the Server

Start the backend server using the module entrypoint:

```bash
python -m netra_backend.main
```

Or run directly via Uvicorn:

```bash
uvicorn netra_backend.main:app --host 127.0.0.1 --port 4000 --reload
```

---

## 5. Probes: Liveness vs. Readiness

NETRA backend differentiates clearly between liveness and readiness probes:

### Liveness Probe (`GET /api/v1/health`)
- **Purpose**: Process health check. Confirms the backend server process is alive and responding.
- **Response**:
```json
{
  "status": "UP",
  "service": "netra-backend"
}
```

### Readiness Probe (`GET /api/v1/readiness`)
- **Purpose**: Subsystem readiness check. Confirms the service and registered downstream dependencies are ready to process traffic.
- **Architecture**: Backed by an extensible `ReadinessCheckManager` registry prepared for future infrastructure health hooks (PostgreSQL 16, Redis, Agent WSS gateway).
- **Response**:
```json
{
  "status": "READY",
  "service": "netra-backend",
  "checks": {
    "app": "ok"
  }
}
```

---

## 6. Request ID vs. Correlation ID Architecture

Every HTTP request is assigned request-scoped metadata maintained inside Python `contextvars` to ensure complete concurrency isolation across asynchronous tasks:

- **`X-Request-ID` (`request_id`)**: Unique identifier for an individual HTTP request transaction. If supplied by client, it is validated (alphanumeric/hyphen/underscore, max 128 chars); if absent or malformed, a secure UUIDv4 is generated.
- **`X-Correlation-ID` (`correlation_id`)**: Identifier tracing a multi-service transaction chain (e.g. Discord slash command $\rightarrow$ Backend API $\rightarrow$ Agent execution). Defaults to `request_id` when omitted.

Both IDs are injected into response headers, error envelopes, and structured log contexts.

---

## 7. Machine-Readable Standard Error Contract

All error responses adhere strictly to the unified envelope:

```json
{
  "success": false,
  "error": {
    "code": "NOT_FOUND",
    "message": "Resource not found",
    "request_id": "8f3d1a9b2c...",
    "timestamp": "2026-08-15T11:00:00.000000+00:00"
  }
}
```

- **Supported Codes**: `NOT_FOUND` (404), `METHOD_NOT_ALLOWED` (405), `VALIDATION_ERROR` (422), `INTERNAL_ERROR` (500).
- **Security Guarantee**: Unhandled exceptions (500) log complete stack traces internally while returning sanitized generic messages to clients. Tracebacks, credentials, and environment details are **never** exposed.

---

## 8. Security Headers

API responses are hardened with API-appropriate security headers:
- `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing.
- `X-Frame-Options: DENY`: Prevents embedding in frames / clickjacking.
- `Referrer-Policy: strict-origin-when-cross-origin`: Controls referrer header transmission.
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`: Restricts response resource execution and framing.

---

## 9. Testing & Code Quality

Run the test suite and quality checks:

```bash
# Run pytest with coverage enforcement (min 80%)
pytest backend/tests -v --cov=netra_backend --cov-fail-under=80

# Run Ruff linter & format check
ruff check backend
ruff format --check backend

# Run MyPy type check
mypy backend/src
```

---

## 10. Phase 1 Scope & Boundary

### Implemented in Phase 1:
- [x] Package structure (`src/netra_backend`) & `pyproject.toml`
- [x] Application factory (`create_app`) & Lifespan manager
- [x] Pydantic Settings configuration validator
- [x] Structlog structured JSON logging with contextvars & secret redaction
- [x] Request ID & Correlation ID middleware with isolation guarantees
- [x] Centralized error contract & exception handlers
- [x] Liveness (`/api/v1/health`) & Readiness (`/api/v1/readiness`) endpoints
- [x] Security headers & CORS policy
- [x] Comprehensive Pytest unit and concurrency test suite
- [x] GitHub Actions CI workflow

### Intentionally Unimplemented (Future Phases):
- PostgreSQL 16 & SQLAlchemy 2.0 Async ORM (Phase 2)
- Alembic database migrations & Row-Level Security (RLS) (Phase 2)
- JWT Authentication & User/Tenant management (Phase 2)
- Device enrollment & Ed25519 asymmetric identity (Phase 3)
- Outbound WSS gateway & HTTPS agent polling (Phase 4)
- Task engine queue & Scanner capabilities (Phases 5-7)
- Discord Bot control plane (Phase 8)
