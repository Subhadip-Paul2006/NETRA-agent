# NETRA Comprehensive Development Roadmap & Implementation Blueprint

## Phase 0: Architecture & Foundation Planning (Architecture Draft)
- **Goal**: Finalize Python Monorepo design (`backend/`, `agent/`, `discord/`, `shared/`, `docs/`, `.github/`), multi-tenant isolation, Ed25519 device auth, 14 DB entities, 7 capability specs, and monorepo CI/CD blueprints.
- **Scope**: Documentation audit across all 11 specification files in workspace (`docs/`).
- **Target Architecture**: **Unified Python Monorepo** (`NETRA/`)
- **Components**: `ARCHITECTURE.md`, `SYSTEM_DESIGN.md`, `DATABASE_DESIGN.md`, `API_BOUNDARY.md`, `SECURITY_MODEL.md`, `CI_CD_STRATEGY.md`, `DEVELOPMENT_ROADMAP.md`, `REPOSITORY_STRUCTURE.md`, `GITHUB_WORKFLOW.md`, `OBSERVABILITY.md`, `THREAT_MODEL.md`, `.env.example`.
- **Dependencies**: None (Foundation baseline).
- **Security Considerations**: Zero trust, Ed25519 asymmetric auth, defense-in-depth PostgreSQL RLS, Ephemeral slash acks + DM result delivery, 12-threat matrix.
- **Acceptance Criteria**: All 11 documents internally consistent, zero contradictions, Phase 0 set to `UNDER REVIEW`.
- **Rollback Considerations**: N/A (Documentation phase).

> [!IMPORTANT]
> **PHASE 0 GATE**: **DO NOT PROCEED until Phase 0 architecture receives explicit user review and approval.**  
> **Phase 0 Status**: **UNDER REVIEW**

---

## Phase 1: NETRA Backend Core Foundation (`backend/`)
- **Goal**: Initialize `backend/` directory baseline, FastAPI web server, Pydantic v2 environment variable validation, structured JSON logging, global exception handling, health/readiness probes, and Pytest test infrastructure.
- **STRICT SCOPE BOUNDARY**: Phase 1 MUST NOT implement PostgreSQL database connections, SQLAlchemy/Alembic models, Row-Level Security (RLS) policies, authentication endpoints, device enrollment, task queue execution, or WebSocket gateway logic. Phase 1 is strictly restricted to HTTP server baseline, configuration framework, and test baseline.
- **Target Repository Component**: **`backend/`** (Python 3.11+ / FastAPI / Uvicorn / Pydantic v2 / Structlog / Pytest)
- **Files/Components**:
  - `backend/pyproject.toml`
  - `backend/requirements.txt`
  - `backend/src/main.py` (FastAPI app factory & runner)
  - `backend/src/config.py` (Pydantic v2 Settings validator)
  - `backend/src/utils/logger.py` (Structlog JSON logger)
  - `backend/src/middleware/error_handler.py` (Global exception handler & standard error envelope)
  - `backend/src/api/v1/health.py` (`GET /api/v1/health` and `GET /api/v1/readiness`)
  - `backend/tests/unit/test_health.py`
  - `.github/workflows/ci.yml`
- **Dependencies**: Python 3.11+, FastAPI, Uvicorn, Pydantic v2, Structlog, Pytest.
- **Security Considerations**: Strict Pydantic environment variable parsing at boot time, secure HTTP headers, CORS restriction.
- **Tests**: Pytest unit tests for environment config validator and health probe endpoints.
- **Manual Verification**: Launch server (`uvicorn backend.src.main:app`) $\rightarrow$ `curl http://localhost:4000/api/v1/health` returns `200 OK` with status `"UP"`.
- **Acceptance Criteria**: FastAPI server boots cleanly, missing environment variables trigger immediate startup exit with descriptive Pydantic error, health probes pass.
- **Rollback Considerations**: Revert commit baseline on failure.

> [!IMPORTANT]
> **PHASE 1 GATE**: **DO NOT PROCEED until all Phase 1 verification criteria pass.**

---

## Phase 2: Database, RLS, Identity & Tenancy (`backend/` & `shared/`)
- **Goal**: Implement SQLAlchemy 2.0 ORM entities (all 14 models + `NonceCache`), Alembic migrations in `backend/alembic/`, PostgreSQL 16 RLS policies, `with_tenant_context` async session context manager, Argon2 password hashing, and JWT authentication.
- **Target Repository Components**: **`backend/`** & **`shared/`** (Python 3.11+ / SQLAlchemy 2.0 / AsyncPG / Alembic / PostgreSQL 16 / Argon2 / PyJWT)
- **Files/Components**:
  - `backend/src/models/` (14 entities: `Tenant`, `User`, `TenantMembership`, `Device`, `DeviceCredential`, `AgentSession`, `Task`, `TaskExecution`, `Finding`, `FindingEvidence`, `DiscordBinding`, `DiscordSession`, `AuditEvent`, `EnrollmentCode`, `NonceCache`)
  - `backend/alembic/versions/` (PostgreSQL RLS DDL migration scripts)
  - `backend/src/rls.py` (`with_tenant_context` context manager executing `SELECT set_config('app.current_tenant_id', :tenant_id, true)`)
  - `backend/src/api/v1/auth.py` (`POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`)
  - `backend/tests/integration/test_rls.py`
- **Dependencies**: PostgreSQL 16, SQLAlchemy 2.0, AsyncPG, Alembic, Argon2, PyJWT.
- **Security Considerations**: RLS policies enforce `tenant_id = current_setting('app.current_tenant_id', true)`. Runtime user `netra_app_user` lacks `BYPASSRLS`.
- **Tests**: Pytest integration tests with ephemeral PostgreSQL 16 container asserting zero data leakage when querying without tenant context.
- **Manual Verification**: Run `alembic upgrade head` and execute SQL query as `netra_app_user` without context $\rightarrow$ 0 rows returned.
- **Acceptance Criteria**: All 14 entities created, RLS enforced, JWT auth & tenant isolation verified.
- **Rollback Considerations**: Execute `alembic downgrade base`.

> [!IMPORTANT]
> **PHASE 2 GATE**: **DO NOT PROCEED until all Phase 2 verification criteria pass.**

---

## Phase 3: Agent Enrollment & Ed25519 Device Identity (`backend/` & `agent/`)
- **Goal**: Implement `EnrollmentCode` generator, CLI `netra enroll`, local Ed25519 keypair generation, OS protected key storage, and public key registration.
- **Target Repository Components**: **`backend/`** & **`agent/`** (Python 3.11+ / Typer / cryptography / keyring)
- **Files/Components**:
  - `backend/src/api/v1/devices.py` (`POST /api/v1/control/enrollment-codes`, `POST /api/v1/agent/enroll`)
  - `agent/netra/auth/keyring.py` (Local Ed25519 generation + OS keyring storage via DPAPI / Secret Service API / Keychain)
  - `agent/netra/cli/enroll.py` (`netra enroll <code>` command handler)
  - `agent/tests/test_keyring.py`
  - `backend/tests/integration/test_enrollment.py`
- **Dependencies**: `cryptography` (Python), `keyring` (Python), `typer` (Python).
- **Security Considerations**: Single-use 15-min enrollment code, private key stored strictly in OS protected storage (NEVER sent over network or stored on backend), public key registered in PostgreSQL `DeviceCredential.publicKey`.
- **Tests**: Pytest unit tests for keyring generation; integration tests for enrollment code single-use enforcement.
- **Manual Verification**: Run `netra enroll ABCD-1234` on test host $\rightarrow$ `DeviceCredential.publicKey` saved in DB, private key saved in Windows Credential Manager.
- **Acceptance Criteria**: Single-use enrollment code verified, public key stored, device registered.
- **Rollback Considerations**: Revoke test device via `DELETE /api/v1/devices/:id`.

> [!IMPORTANT]
> **PHASE 3 GATE**: **DO NOT PROCEED until all Phase 3 verification criteria pass.**

---

## Phase 4: Agent WSS Gateway & Transport Protocol (`backend/` & `agent/`)
- **Goal**: Build persistent outbound WSS gateway (`/api/v1/agent/connect`) with Ed25519 signature verification, heartbeat loop, and REST polling fallback.
- **Target Repository Components**: **`backend/`** & **`agent/`** (Python 3.11+ / FastAPI WebSockets / websockets / httpx)
- **Files/Components**:
  - `backend/src/api/wss/gateway.py` (WSS connection manager & Ed25519 handshake validator)
  - `agent/netra/connection/wss_client.py` (Outbound WSS client with exponential backoff reconnect)
  - `agent/netra/connection/rest_client.py` (Fallback HTTP polling client `GET /api/v1/agent/tasks`)
- **Dependencies**: FastAPI WebSockets, `websockets` (Python), `httpx` (Python).
- **Security Considerations**: Ed25519 signature verified on handshake (`X-NETRA-Signature`). 5-min timestamp window & `NonceCache` deduplication.
- **Tests**: Pytest mock tests for WSS gateway; Pytest reconnect & polling fallback tests.
- **Manual Verification**: Start backend & agent $\rightarrow$ WSS connection established, heartbeat ping/pong logged every 30s. Disconnect network $\rightarrow$ Agent retries with backoff & falls back to REST poll.
- **Acceptance Criteria**: WSS stream active, Ed25519 verified, auto-reconnect functional.
- **Rollback Considerations**: Fallback to REST polling mode.

> [!IMPORTANT]
> **PHASE 4 GATE**: **DO NOT PROCEED until all Phase 4 verification criteria pass.**

---

## Phase 5: Task Queue Engine & State Machine (`backend/`)
- **Goal**: Implement Task Queue Engine (`CREATED` $\rightarrow$ `QUEUED` $\rightarrow$ `DELIVERED` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RUNNING` $\rightarrow$ `COMPLETED`), idempotency check, and lease timeouts.
- **INFRASTRUCTURE REQUIREMENT**: PostgreSQL `TaskExecution` and `NonceCache` tables provide durable idempotency and nonce persistence. Redis is OPTIONAL and deferred for future high-scale performance phases.
- **Target Repository Component**: **`backend/`** (Python 3.11+ / FastAPI / SQLAlchemy 2.0)
- **Files/Components**:
  - `backend/src/services/task_engine.py` (`POST /api/v1/control/tasks`, task dispatcher)
  - `backend/src/services/task_sweeper.py` (Lease sweeper worker for timeout tasks)
  - `backend/src/api/v1/tasks.py` (`POST /api/v1/agent/tasks/:id/results`)
  - `backend/src/services/finding_ingest.py` (Finding & Evidence ingestion)
- **Dependencies**: SQLAlchemy 2.0, FastAPI.
- **Security Considerations**: `X-Idempotency-Key` deduplication (`unique(task_id, execution_id)`), Ed25519 signature on result submission.
- **Tests**: Integration tests for task state transitions, idempotency duplicate submission rejection, and timeout sweeps.
- **Manual Verification**: Dispatch task $\rightarrow$ transitions `CREATED` $\rightarrow$ `QUEUED` $\rightarrow$ `DELIVERED` $\rightarrow$ `RUNNING` $\rightarrow$ `COMPLETED`. Post duplicate result $\rightarrow$ returns cached ACK without duplicate findings.
- **Acceptance Criteria**: State machine transitions verified, idempotency enforced, findings stored.
- **Rollback Considerations**: Reset stuck task states via recovery worker.

> [!IMPORTANT]
> **PHASE 5 GATE**: **DO NOT PROCEED until all Phase 5 verification criteria pass.**

---

## Phase 6: Controlled Security Capabilities Suite (`agent/`)
- **Goal**: Implement pre-compiled Python scanner modules for all 7 controlled capabilities (`SCAN_NETWORK`, `SCAN_PROCESSES`, `SCAN_CONNECTIONS`, `SCAN_FIREWALL`, `SCAN_USERS`, `SCAN_STARTUP`, `SCAN_FILE_INTEGRITY`).
- **Target Repository Component**: **`agent/`** (Python 3.11+ / Typer / psutil / pydantic / cryptography)
- **Files/Components**:
  - `agent/netra/modules/base.py` (Base scanner module class with CPU/RAM resource caps)
  - `agent/netra/modules/network_scan.py`
  - `agent/netra/modules/process_scan.py`
  - `agent/netra/modules/connections_scan.py`
  - `agent/netra/modules/firewall_scan.py`
  - `agent/netra/modules/users_scan.py`
  - `agent/netra/modules/startup_scan.py`
  - `agent/netra/modules/file_integrity_scan.py`
  - `agent/tests/test_modules.py`
- **Dependencies**: `psutil`, `pydantic`, `cryptography`, `pytest`.
- **Security Considerations**: Zero shell string execution (`exec`/`eval` strictly prohibited). Pre-defined file path manifests ONLY for file integrity scanning.
- **Tests**: Pytest unit tests for all 7 scanner modules on Windows/Linux platform mocks.
- **Manual Verification**: Execute `netra run --capability SCAN_NETWORK` locally $\rightarrow$ returns validated JSON finding payload within 5s.
- **Acceptance Criteria**: All 7 capabilities execute cleanly, Pydantic schemas validated, zero shell injection risk.
- **Rollback Considerations**: Disable failing capability module in agent configuration.

> [!IMPORTANT]
> **PHASE 6 GATE**: **DO NOT PROCEED until all Phase 6 verification criteria pass.**

---

## Phase 7: Discord Control Plane & Async DM Delivery (`discord/`)
- **Goal**: Initialize `discord/` bot, implement Slash Commands (`/panel`, `/scan`, `/devices`, `/findings`), ephemeral slash command acks (`ephemeral: true`), and Direct Message (DM) result delivery.
- **Target Repository Component**: **`discord/`** (Python 3.11+ / discord.py / httpx)
- **Files/Components**:
  - `discord/bot/main.py` (discord.py bot runner)
  - `discord/bot/cogs/` (Slash command routers: `scan.py`, `panel.py`, `devices.py`, `findings.py`)
  - `discord/bot/services/backend_client.py` (HTTP client for `backend/` REST API)
  - `discord/bot/services/dm_delivery.py` (Asynchronous event listener for `TASK_RESULT_DELIVERY` and `SECURITY_ALERT_DELIVERY` events)
  - `discord/bot/formatters/embeds.py` (Rich Discord embed formatters)
  - `discord/tests/test_cogs.py`
- **Dependencies**: Python 3.11+, discord.py, httpx, Pytest.
- **Security Considerations**: Zero direct DB access in Discord bot. Ephemeral slash command responses (`ephemeral: true`). Results delivered strictly via private DMs. Catches Discord error `50007` when DMs are disabled and flags results for dashboard retrieval.
- **Tests**: Pytest mock tests for Discord slash command handlers and DM renderer.
- **Manual Verification**: Type `/scan` in Discord channel $\rightarrow$ receive immediate ephemeral ack ("Task queued..."). Upon scan completion $\rightarrow$ receive private Discord DM with rich visual embed of scan findings.
- **Acceptance Criteria**: Slash commands functional, ephemeral acks working, DM delivery successful, channel remains clean.
- **Rollback Considerations**: Disable bot commands or restart bot gateway session.

> [!IMPORTANT]
> **PHASE 7 GATE**: **DO NOT PROCEED until all Phase 7 verification criteria pass.**

---

## Phase 8: Observability, Resilience & Fault Recovery (Monorepo)
- **Goal**: Implement JSON log redactor, correlation ID propagation (`request_id`, `task_id`, `execution_id`, `device_id`, `tenant_id`), Prometheus metrics, and automated fault recovery.
- **Target Repository Components**: `backend/`, `discord/`, `agent/`, `shared/`.
- **Files/Components**:
  - `backend/src/utils/logger.py`
  - `discord/bot/utils/logger.py`
  - `agent/netra/utils/logger.py`
  - `shared/netra_shared/errors/`
- **Dependencies**: `prometheus-fastapi-instrumentator`, `structlog`, `logging` (Python).
- **Security Considerations**: Mandatory redaction of `password`, `token`, `jwt`, `private_key`, `DISCORD_BOT_TOKEN`, `signature`, and raw evidence payloads.
- **Tests**: Pytest unit tests for log secret redactor regex; integration tests for correlation ID propagation across HTTP/WSS headers.
- **Manual Verification**: Trigger task $\rightarrow$ verify matching `request_id`, `task_id`, `execution_id` across Backend, Discord, and Agent JSON logs. Verify secrets replaced with `"[REDACTED]"`.
- **Acceptance Criteria**: Correlation IDs propagated, secret redaction 100% effective, Prometheus metrics exported.
- **Rollback Considerations**: N/A (Observability layer).

> [!IMPORTANT]
> **PHASE 8 GATE**: **DO NOT PROCEED until all Phase 8 verification criteria pass.**

---

## Phase 9: Monorepo CI/CD Automation & Deployment (`.github/workflows`)
- **Goal**: Configure matrixed GitHub Actions CI pipeline (`.github/workflows/ci.yml`), container builds for backend and discord bot, and PyPI package build for agent.
- **Target Repository Component**: `.github/workflows/`
- **Files/Components**: `.github/workflows/ci.yml`
- **Dependencies**: GitHub Actions, Docker, Trivy, Ruff, Mypy, Bandit.
- **Security Considerations**: Bandit SAST secret scanning, Trivy image vulnerability scan (fail on CRITICAL/HIGH), dependency audit.
- **Tests**: Execution of CI matrix pipeline on PR and push events.
- **Manual Verification**: Push PR $\rightarrow$ GitHub Actions triggers matrix pipeline across `shared`, `backend`, `agent`, and `discord` and passes all gates.
- **Acceptance Criteria**: CI pipeline passing, 0 security vulnerabilities, Docker/PyPI artifacts built cleanly.
- **Rollback Considerations**: Revert workflow file changes.

> [!IMPORTANT]
> **PHASE 9 GATE**: **DO NOT PROCEED until all Phase 9 verification criteria pass.**

---

## Phase 10: Production Hardening, Load Testing & Release Tagging
- **Goal**: Conduct end-to-end multi-tenant penetration testing, high-concurrency WSS load testing (1,000 req/sec), production container image publishing, and tag `v1.0.0` release.
- **Target Repository Components**: `backend/`, `discord/`, `agent/`, `shared/`.
- **Files/Components**: Performance test suites, release tagging across monorepo.
- **Dependencies**: Locust / k6, Docker Registry, PyPI.
- **Security Considerations**: Final IDOR penetration audit, verifying zero cross-tenant data leakage under load.
- **Tests**: Load test suite simulating 100 concurrent agents and 50 concurrent Discord users.
- **Manual Verification**: Run load test $\rightarrow$ WSS gateway maintains 1,000 req/sec, zero database connection pool exhaustion, zero cross-tenant leakage.
- **Acceptance Criteria**: Load test passed, security audit clean, official `v1.0.0` tagged.
- **Rollback Considerations**: Revert release tags if production smoke test fails.

> [!IMPORTANT]
> **PHASE 10 GATE**: **DO NOT PROCEED until all Phase 10 verification criteria pass.**




