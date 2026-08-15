# NETRA Comprehensive Development Roadmap & Implementation Blueprint

## Phase 0: Architecture & Foundation Planning (Architecture Draft)
- **Goal**: Finalize 3-repository design, multi-tenant isolation, Ed25519 device auth, 14 DB entities, 7 capability specs, and CI/CD blueprints.
- **Scope**: Documentation audit across all 12 specification files in workspace.
- **Target Repositories**: `netra-backend`, `netra-discord`, `netra-agent`.
- **Components**: `ARCHITECTURE.md`, `SYSTEM_DESIGN.md`, `DATABASE_DESIGN.md`, `API_BOUNDARY.md`, `SECURITY_MODEL.md`, `CI_CD_STRATEGY.md`, `DEVELOPMENT_ROADMAP.md`, `REPOSITORY_STRUCTURE.md`, `GITHUB_WORKFLOW.md`, `OBSERVABILITY.md`, `THREAT_MODEL.md`, `.env.example`.
- **Dependencies**: None (Foundation baseline).
- **Security Considerations**: Zero trust, Ed25519 asymmetric auth, defense-in-depth PostgreSQL RLS, Ephemeral slash acks + DM result delivery, 12-threat matrix.
- **Acceptance Criteria**: All 12 documents internally consistent, zero contradictions, Phase 0 set to `UNDER REVIEW`.
- **Rollback Considerations**: N/A (Documentation phase).

> [!IMPORTANT]
> **PHASE 0 GATE**: **DO NOT PROCEED until Phase 0 architecture receives explicit user review and approval.**  
> **Phase 0 Status**: **UNDER REVIEW**

---

## Phase 1: NETRA Backend Core Foundation (`netra-backend`)
- **Goal**: Initialize `netra-backend` repository baseline, Fastify web server, environment variable validation, structured logging, global error handling, health/readiness probes, and test infrastructure.
- **STRICT SCOPE BOUNDARY**: Phase 1 MUST NOT implement PostgreSQL database connections, Prisma ORM models, Row-Level Security (RLS) policies, authentication endpoints, device enrollment, task queue execution, or WebSocket gateway logic. Phase 1 is strictly restricted to HTTP server baseline and configuration framework.
- **Target Repository**: **`netra-backend`** (Node.js 20 / TypeScript / Fastify / Pino / Zod / Jest)
- **Files/Components**:
  - `netra-backend/package.json`
  - `netra-backend/tsconfig.json`
  - `netra-backend/src/server.ts`
  - `netra-backend/src/app.ts`
  - `netra-backend/src/config/env.ts` (Zod environment variable schema validator)
  - `netra-backend/src/utils/logger.ts` (Pino JSON logger)
  - `netra-backend/src/middleware/error-handler.ts` (Global Fastify error handler & envelope)
  - `netra-backend/src/routes/health.ts` (`GET /api/v1/health` and `GET /api/v1/readiness`)
  - `netra-backend/tests/unit/health.test.ts`
  - `netra-backend/.github/workflows/ci.yml`
- **Dependencies**: Node.js 20, TypeScript, Fastify, Zod, Pino, Jest.
- **Security Considerations**: Strict Zod environment variable parsing at boot time, Helmet secure HTTP headers, CORS restriction.
- **Tests**: Jest unit tests for environment config validator and health probe endpoints.
- **Manual Verification**: Launch server (`npm run dev`) $\rightarrow$ `curl http://localhost:4000/api/v1/health` returns `200 OK` with status `"UP"`.
- **Acceptance Criteria**: Fastify server boots cleanly, missing environment variables trigger immediate startup exit with descriptive Zod error, health probes pass.
- **Rollback Considerations**: Revert commit baseline on failure.

> [!IMPORTANT]
> **PHASE 1 GATE**: **DO NOT PROCEED until all Phase 1 verification criteria pass.**

---

## Phase 2: Database, RLS, Identity & Tenancy (`netra-backend`)
- **Goal**: Implement Prisma ORM schema with all 14 entities, PostgreSQL 16 migrations, RLS policies, `withTenantContext` interactive transaction wrapper, Argon2 password hashing, and JWT authentication.
- **Target Repository**: **`netra-backend`** (Node.js 20 / TypeScript / Prisma / PostgreSQL 16 / Argon2 / JWT)
- **Files/Components**:
  - `netra-backend/prisma/schema.prisma` (14 entities: `Tenant`, `User`, `TenantMembership`, `Device`, `DeviceCredential`, `AgentSession`, `Task`, `TaskExecution`, `Finding`, `FindingEvidence`, `DiscordBinding`, `DiscordSession`, `AuditEvent`, `EnrollmentCode`, `NonceCache`)
  - `netra-backend/prisma/migrations/` (PostgreSQL RLS DDL policies)
  - `netra-backend/src/middleware/tenant-context.ts` (`withTenantContext` wrapper with `SET LOCAL app.current_tenant_id`)
  - `netra-backend/src/modules/auth/` (`POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`)
  - `netra-backend/src/modules/tenant/`
  - `netra-backend/tests/integration/rls.test.ts`
- **Dependencies**: PostgreSQL 16, Prisma ORM, Argon2, jsonwebtoken.
- **Security Considerations**: RLS policies enforce `tenant_id = current_setting('app.current_tenant_id', true)`. Runtime user `netra_app_user` lacks `BYPASSRLS`.
- **Tests**: Integration tests with PostgreSQL 16 container asserting zero data leakage when querying without tenant context.
- **Manual Verification**: Run `npx prisma migrate deploy` and execute SQL query as `netra_app_user` without context $\rightarrow$ 0 rows returned.
- **Acceptance Criteria**: All 14 entities created, RLS enforced, JWT auth & tenant isolation verified.
- **Rollback Considerations**: Execute `npx prisma migrate reset` or down-migration SQL.

> [!IMPORTANT]
> **PHASE 2 GATE**: **DO NOT PROCEED until all Phase 2 verification criteria pass.**

---

## Phase 3: Agent Enrollment & Ed25519 Device Identity (`netra-backend` & `netra-agent`)
- **Goal**: Implement `EnrollmentCode` generator, CLI `netra enroll`, local Ed25519 keypair generation, OS protected key storage, and public key registration.
- **Target Repositories**: **`netra-backend`** (TypeScript) & **`netra-agent`** (Python 3.11+)
- **Files/Components**:
  - `netra-backend/src/modules/device/enrollment.ts` (`POST /api/v1/control/enrollment-codes`, `POST /api/v1/agent/enroll`)
  - `netra-agent/netra/auth/keyring.py` (Local Ed25519 generation + OS keyring storage via DPAPI / Secret Service API / Keychain)
  - `netra-agent/netra/cli/enroll.py` (`netra enroll <code>` command handler)
  - `netra-agent/tests/test_keyring.py`
  - `netra-backend/tests/integration/enrollment.test.ts`
- **Dependencies**: `cryptography` (Python), `keyring` (Python), `crypto` (Node.js).
- **Security Considerations**: Single-use 15-min enrollment code, private key stored strictly in OS protected storage (NEVER sent over network or stored on backend), public key registered in PostgreSQL `DeviceCredential.publicKey`.
- **Tests**: Pytest unit tests for keyring generation; Jest integration tests for enrollment code single-use enforcement.
- **Manual Verification**: Run `netra enroll ABCD-1234` on test host $\rightarrow$ `DeviceCredential.publicKey` saved in DB, private key saved in Windows Credential Manager.
- **Acceptance Criteria**: Single-use enrollment code verified, public key stored, device registered.
- **Rollback Considerations**: Revoke test device via `DELETE /api/v1/devices/:id`.

> [!IMPORTANT]
> **PHASE 3 GATE**: **DO NOT PROCEED until all Phase 3 verification criteria pass.**

---

## Phase 4: Agent WSS Gateway & Transport Protocol (`netra-backend` & `netra-agent`)
- **Goal**: Build persistent outbound WSS gateway (`/api/v1/agent/connect`) with Ed25519 signature verification, heartbeat loop, and REST polling fallback.
- **Target Repositories**: **`netra-backend`** (TypeScript) & **`netra-agent`** (Python 3.11+)
- **Files/Components**:
  - `netra-backend/src/gateway/wss.ts` (WSS connection manager & Ed25519 handshake validator)
  - `netra-agent/netra/connection/wss_client.py` (Outbound WSS client with exponential backoff reconnect)
  - `netra-agent/netra/connection/rest_client.py` (Fallback HTTP polling client `GET /api/v1/agent/tasks`)
- **Dependencies**: `@fastify/websocket`, `websockets` (Python), `httpx` (Python).
- **Security Considerations**: Ed25519 signature verified on handshake (`X-NETRA-Signature`). 5-min timestamp window & `NonceCache` deduplication.
- **Tests**: Jest mock tests for WSS gateway; Pytest reconnect & polling fallback tests.
- **Manual Verification**: Start backend & agent $\rightarrow$ WSS connection established, heartbeat ping/pong logged every 30s. Disconnect network $\rightarrow$ Agent retries with backoff & falls back to REST poll.
- **Acceptance Criteria**: WSS stream active, Ed25519 verified, auto-reconnect functional.
- **Rollback Considerations**: Fallback to REST polling mode.

> [!IMPORTANT]
> **PHASE 4 GATE**: **DO NOT PROCEED until all Phase 4 verification criteria pass.**

---

## Phase 5: Task Queue Engine & State Machine (`netra-backend`)
- **Goal**: Implement Task Queue Engine (`CREATED` $\rightarrow$ `QUEUED` $\rightarrow$ `DELIVERED` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RUNNING` $\rightarrow$ `COMPLETED`), idempotency check, and lease timeouts.
- **INFRASTRUCTURE REQUIREMENT**: PostgreSQL `TaskExecution` and `NonceCache` tables provide durable idempotency and nonce persistence. Redis is OPTIONAL and deferred for future high-scale performance phases.
- **Target Repository**: **`netra-backend`** (Node.js 20 / TypeScript / Fastify / Prisma)
- **Files/Components**:
  - `netra-backend/src/modules/task/engine.ts` (`POST /api/v1/control/tasks`, task dispatcher)
  - `netra-backend/src/modules/task/sweeper.ts` (Lease sweeper worker for timeout tasks)
  - `netra-backend/src/modules/task/results.ts` (`POST /api/v1/agent/tasks/:id/results`)
  - `netra-backend/src/modules/finding/ingest.ts` (Finding & Evidence ingestion)
- **Dependencies**: Prisma ORM, Fastify.
- **Security Considerations**: `X-Idempotency-Key` deduplication (`@@unique([taskId, executionId])`), Ed25519 signature on result submission.
- **Tests**: Integration tests for task state transitions, idempotency duplicate submission rejection, and timeout sweeps.
- **Manual Verification**: Dispatch task $\rightarrow$ transitions `CREATED` $\rightarrow$ `QUEUED` $\rightarrow$ `DELIVERED` $\rightarrow$ `RUNNING` $\rightarrow$ `COMPLETED`. Post duplicate result $\rightarrow$ returns cached ACK without duplicate findings.
- **Acceptance Criteria**: State machine transitions verified, idempotency enforced, findings stored.
- **Rollback Considerations**: Reset stuck task states via recovery worker.

> [!IMPORTANT]
> **PHASE 5 GATE**: **DO NOT PROCEED until all Phase 5 verification criteria pass.**

---

## Phase 6: Controlled Security Capabilities Suite (`netra-agent`)
- **Goal**: Implement pre-compiled Python scanner modules for all 7 controlled capabilities (`SCAN_NETWORK`, `SCAN_PROCESSES`, `SCAN_CONNECTIONS`, `SCAN_FIREWALL`, `SCAN_USERS`, `SCAN_STARTUP`, `SCAN_FILE_INTEGRITY`).
- **Target Repository**: **`netra-agent`** (Python 3.11+ / Typer / psutil / pydantic / cryptography)
- **Files/Components**:
  - `netra-agent/netra/modules/base.py` (Base scanner module class with CPU/RAM resource caps)
  - `netra-agent/netra/modules/network_scan.py`
  - `netra-agent/netra/modules/process_scan.py`
  - `netra-agent/netra/modules/connections_scan.py`
  - `netra-agent/netra/modules/firewall_scan.py`
  - `netra-agent/netra/modules/users_scan.py`
  - `netra-agent/netra/modules/startup_scan.py`
  - `netra-agent/netra/modules/file_integrity_scan.py`
  - `netra-agent/tests/test_modules.py`
- **Dependencies**: `psutil`, `pydantic`, `cryptography`, `pytest`.
- **Security Considerations**: Zero shell string execution (`exec`/`eval` strictly prohibited). Pre-defined file path manifests ONLY for file integrity scanning.
- **Tests**: Pytest unit tests for all 7 scanner modules on Windows/Linux platform mocks.
- **Manual Verification**: Execute `netra run --capability SCAN_NETWORK` locally $\rightarrow$ returns validated JSON finding payload within 5s.
- **Acceptance Criteria**: All 7 capabilities execute cleanly, Pydantic schemas validated, zero shell injection risk.
- **Rollback Considerations**: Disable failing capability module in agent configuration.

> [!IMPORTANT]
> **PHASE 6 GATE**: **DO NOT PROCEED until all Phase 6 verification criteria pass.**

---

## Phase 7: Discord Control Plane & Async DM Delivery (`netra-discord`)
- **Goal**: Initialize `netra-discord` bot, implement Slash Commands (`/panel`, `/scan`, `/devices`, `/findings`), ephemeral slash command acks (`ephemeral: true`), and Direct Message (DM) result delivery.
- **Target Repository**: **`netra-discord`** (Node.js 20 / TypeScript / Discord.js v14)
- **Files/Components**:
  - `netra-discord/src/bot.ts` (Discord client initialization)
  - `netra-discord/src/commands/` (Slash command routers: `scan.ts`, `panel.ts`, `devices.ts`, `findings.ts`)
  - `netra-discord/src/services/backend-client.ts` (HTTP client for `netra-backend` REST API)
  - `netra-discord/src/services/dm-delivery.ts` (Asynchronous event listener for `TASK_RESULT_DELIVERY` and `SECURITY_ALERT_DELIVERY` events)
  - `netra-discord/src/formatters/embeds.ts` (Rich Discord embed formatters)
  - `netra-discord/tests/unit/commands.test.ts`
- **Dependencies**: Node.js 20, Discord.js v14, Axios/Fetch, Jest.
- **Security Considerations**: Zero direct DB access in Discord bot. Ephemeral slash command responses (`ephemeral: true`). Results delivered strictly via private DMs. Catches Discord error `50007` when DMs are disabled and flags results for dashboard retrieval.
- **Tests**: Jest mock tests for Discord slash command handlers and DM renderer.
- **Manual Verification**: Type `/scan` in Discord channel $\rightarrow$ receive immediate ephemeral ack ("Task queued..."). Upon scan completion $\rightarrow$ receive private Discord DM with rich visual embed of scan findings.
- **Acceptance Criteria**: Slash commands functional, ephemeral acks working, DM delivery successful, channel remains clean.
- **Rollback Considerations**: Disable bot commands or restart bot gateway session.

> [!IMPORTANT]
> **PHASE 7 GATE**: **DO NOT PROCEED until all Phase 7 verification criteria pass.**

---

## Phase 8: Observability, Resilience & Fault Recovery (All Repositories)
- **Goal**: Implement JSON log redactor, correlation ID propagation (`request_id`, `task_id`, `execution_id`, `device_id`, `tenant_id`), Prometheus metrics, and automated fault recovery.
- **Target Repositories**: `netra-backend`, `netra-discord`, `netra-agent`.
- **Files/Components**:
  - `netra-backend/src/middleware/logging.ts`
  - `netra-discord/src/utils/logger.ts`
  - `netra-agent/netra/utils/logging.py`
- **Dependencies**: `prom-client` (Node.js), `pino` (Node.js), `logging` (Python).
- **Security Considerations**: Mandatory redaction of `password`, `token`, `jwt`, `privateKey`, `DISCORD_BOT_TOKEN`, `signature`, and raw evidence payloads.
- **Tests**: Unit tests for log secret redactor regex; integration tests for correlation ID propagation across HTTP/WSS headers.
- **Manual Verification**: Trigger task $\rightarrow$ verify matching `request_id`, `task_id`, `execution_id` across Backend, Discord, and Agent JSON logs. Verify secrets replaced with `"[REDACTED]"`.
- **Acceptance Criteria**: Correlation IDs propagated, secret redaction 100% effective, Prometheus metrics exported.
- **Rollback Considerations**: N/A (Observability layer).

> [!IMPORTANT]
> **PHASE 8 GATE**: **DO NOT PROCEED until all Phase 8 verification criteria pass.**

---

## Phase 9: Multi-Repo CI/CD Automation & Deployment (`.github/workflows`)
- **Goal**: Configure independent GitHub Actions CI/CD pipelines across `netra-backend`, `netra-discord`, and `netra-agent`, container builds, and PyPI release workflows.
- **Target Repositories**: `netra-backend`, `netra-discord`, `netra-agent`.
- **Files/Components**:
  - `netra-backend/.github/workflows/ci.yml`
  - `netra-discord/.github/workflows/ci.yml`
  - `netra-agent/.github/workflows/ci.yml`
- **Dependencies**: GitHub Actions, Docker, Trivy, Hatch, Gitleaks.
- **Security Considerations**: Gitleaks secret scanning, Trivy image vulnerability scan (fail on CRITICAL/HIGH), dependency audit.
- **Tests**: Execution of CI pipelines on PR and push events across all 3 repos.
- **Manual Verification**: Push PR in each repo $\rightarrow$ GitHub Actions triggers correct stack pipeline (Node vs Python) and passes all gates.
- **Acceptance Criteria**: 3 independent CI pipelines passing, 0 security vulnerabilities, Docker/PyPI artifacts built cleanly.
- **Rollback Considerations**: Revert workflow file changes.

> [!IMPORTANT]
> **PHASE 9 GATE**: **DO NOT PROCEED until all Phase 9 verification criteria pass.**

---

## Phase 10: Production Hardening, Load Testing & Release Tagging
- **Goal**: Conduct end-to-end multi-tenant penetration testing, high-concurrency WSS load testing (1,000 req/sec), production container image publishing, and tag `v1.0.0` release.
- **Target Repositories**: `netra-backend`, `netra-discord`, `netra-agent`.
- **Files/Components**: Performance test suites, release tagging across all 3 repositories.
- **Dependencies**: k6, Locust, Docker Registry, PyPI.
- **Security Considerations**: Final IDOR penetration audit, verifying zero cross-tenant data leakage under load.
- **Tests**: Load test suite simulating 100 concurrent agents and 50 concurrent Discord users.
- **Manual Verification**: Run load test $\rightarrow$ WSS gateway maintains 1,000 req/sec, zero database connection pool exhaustion, zero cross-tenant leakage.
- **Acceptance Criteria**: Load test passed, security audit clean, official `v1.0.0` tagged across all 3 repositories.
- **Rollback Considerations**: Revert release tags if production smoke test fails.

> [!IMPORTANT]
> **PHASE 10 GATE**: **DO NOT PROCEED until all Phase 10 verification criteria pass.**



