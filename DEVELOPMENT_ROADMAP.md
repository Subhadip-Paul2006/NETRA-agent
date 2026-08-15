# NETRA Comprehensive Development Roadmap & Implementation Blueprint

## Phase 0: Architecture & Foundation Planning (Architecture Draft)
- **Goal**: Finalize 3-repository design, multi-tenant isolation, Ed25519 device auth, 14 DB entities, 7 capability specs, and CI/CD blueprints.
- **Scope**: Documentation audit across all 12 specification files in workspace.
- **Components**: `ARCHITECTURE.md`, `SYSTEM_DESIGN.md`, `DATABASE_DESIGN.md`, `API_BOUNDARY.md`, `SECURITY_MODEL.md`, `CI_CD_STRATEGY.md`, `DEVELOPMENT_ROADMAP.md`, `REPOSITORY_STRUCTURE.md`, `GITHUB_WORKFLOW.md`, `OBSERVABILITY.md`, `THREAT_MODEL.md`, `.env.example`.
- **Dependencies**: None (Foundation baseline).
- **Security Considerations**: Zero trust, Ed25519 asymmetric auth, defense-in-depth PostgreSQL RLS, Ephemeral slash acks + DM result delivery, 12-threat matrix.
- **Acceptance Criteria**: All 12 documents internally consistent, zero contradictions, Phase 0 set to `UNDER REVIEW`.
- **Rollback Considerations**: N/A (Documentation phase).

> [!IMPORTANT]
> **PHASE 0 GATE**: **DO NOT PROCEED until Phase 0 architecture receives explicit user review and approval.**
> **Phase 0 Status**: **UNDER REVIEW**

---

## Phase 1: NETRA Backend Core Engine (`netra-backend`)
- **Goal**: Initialize `netra-backend` repository, Fastify web server, environment validation, logging, and health probe endpoints.
- **Scope**: Repository 1 setup, Zod config validator, Fastify error handler, JSON logger, `/api/v1/health` and `/api/v1/readiness`.
- **Files/Components**: `package.json`, `tsconfig.json`, `src/app.ts`, `src/server.ts`, `src/config/`, `src/middleware/`.
- **Dependencies**: Node.js 20, TypeScript, Fastify, Zod, Pino.
- **Security Considerations**: Environment variable validation, secure HTTP response headers (Helmet), CORS restriction.
- **Tests**: Jest unit tests for config validator and health endpoints.
- **Manual Verification**: `curl http://localhost:3000/api/v1/health` returns `200 OK`.
- **Acceptance Criteria**: Fastify server starts cleanly, Zod rejects missing env vars, health probes pass.
- **Rollback Considerations**: Revert commit baseline on failure.

> [!IMPORTANT]
> **PHASE 1 GATE**: **DO NOT PROCEED until all Phase 1 verification criteria pass.**

---

## Phase 2: Database, RLS, Identity & Tenancy (`netra-backend`)
- **Goal**: Implement Prisma schema with all 14 entities, PostgreSQL RLS migrations, `withTenantContext` wrapper, and User/Tenant auth.
- **Scope**: `prisma/schema.prisma`, Prisma migrations, RLS policies on 10 tables, Argon2 password hashing, JWT access/refresh token rotation.
- **Files/Components**: `prisma/schema.prisma`, `prisma/migrations/`, `src/middleware/tenant-context.ts`, `src/modules/auth/`, `src/modules/tenant/`.
- **Dependencies**: PostgreSQL 16, Prisma ORM, Argon2, jsonwebtoken.
- **Security Considerations**: RLS policies enforce `tenant_id = current_setting('app.current_tenant_id', true)`. Runtime role `netra_app_user` lacks `BYPASSRLS`.
- **Tests**: Integration tests with ephemeral PostgreSQL 16 container validating RLS zero-data leak guarantee.
- **Manual Verification**: Run `npx prisma migrate deploy` and execute raw SQL query as `netra_app_user` without context -> 0 rows returned.
- **Acceptance Criteria**: All 14 entities created, RLS enforced, JWT auth & tenant isolation verified.
- **Rollback Considerations**: Execute `npx prisma migrate reset` or down-migration SQL.

> [!IMPORTANT]
> **PHASE 2 GATE**: **DO NOT PROCEED until all Phase 2 verification criteria pass.**

---

## Phase 3: Agent Enrollment & Ed25519 Device Identity (`netra-backend` & `netra-agent`)
- **Goal**: Implement `EnrollmentCode` generator, CLI `netra enroll`, local Ed25519 keypair generation, OS protected key storage, and public key registration.
- **Scope**: Enrollment code API (`POST /api/v1/control/enrollment-codes`), Agent enrollment client (`POST /api/v1/agent/enroll`), keyring integration.
- **Files/Components**: `netra-backend/src/modules/device/`, `netra-agent/netra/auth/keyring.py`, `netra-agent/netra/cli/enroll.py`.
- **Dependencies**: `cryptography` (Python), `keyring` (DPAPI/SecretService/Keychain), `crypto` (Node.js).
- **Security Considerations**: Single-use 15-min enrollment code, private key stored strictly in OS protected storage, public key registered in PostgreSQL `DeviceCredential`.
- **Tests**: Pytest unit tests for keyring generation; Jest integration tests for enrollment code single-use enforcement.
- **Manual Verification**: Run `netra enroll ABCD-1234` on test host -> `DeviceCredential.publicKey` saved in DB, private key saved in Windows Credential Manager.
- **Acceptance Criteria**: enrollment code single-use verified, public key stored, device registered.
- **Rollback Considerations**: Revoke test device via `DELETE /api/v1/devices/:id`.

> [!IMPORTANT]
> **PHASE 3 GATE**: **DO NOT PROCEED until all Phase 3 verification criteria pass.**

---

## Phase 4: Agent WSS Gateway & Transport Protocol (`netra-backend` & `netra-agent`)
- **Goal**: Build persistent outbound WSS gateway (`/api/v1/agent/connect`) with Ed25519 signature verification, heartbeat loop, and REST polling fallback.
- **Scope**: WSS connection manager, handshake signature validation, exponential backoff reconnect, REST fallback (`GET /api/v1/agent/tasks`).
- **Files/Components**: `netra-backend/src/gateway/wss.ts`, `netra-agent/netra/connection/wss_client.py`.
- **Dependencies**: `@fastify/websocket`, `websockets` (Python), `httpx`.
- **Security Considerations**: Ed25519 signature verified on handshake (`X-NETRA-Signature`). 5-min timestamp window & nonce tracking.
- **Tests**: Jest mock tests for WSS gateway; Pytest reconnect & polling fallback tests.
- **Manual Verification**: Start backend & agent -> WSS connection established, heartbeat ping/pong logged every 30s. Disconnect network -> Agent retries with backoff & falls back to REST poll.
- **Acceptance Criteria**: WSS stream active, Ed25519 verified, auto-reconnect functional.
- **Rollback Considerations**: Fallback to REST polling mode.

> [!IMPORTANT]
> **PHASE 4 GATE**: **DO NOT PROCEED until all Phase 4 verification criteria pass.**

---

## Phase 5: Task Queue Engine & State Machine (`netra-backend`)
- **Goal**: Implement Task Queue Engine (`CREATED` -> `QUEUED` -> `DELIVERED` -> `ACKNOWLEDGED` -> `RUNNING` -> `COMPLETED`), idempotency check, and lease timeouts.
- **Scope**: `POST /api/v1/control/tasks`, task dispatcher, lease sweeper worker, result ingestion endpoint (`POST /api/v1/agent/tasks/:id/results`).
- **Files/Components**: `netra-backend/src/modules/task/`, `netra-backend/src/modules/finding/`.
- **Dependencies**: Prisma ORM, Fastify, Redis (for nonce cache).
- **Security Considerations**: `X-Idempotency-Key` deduplication (`@@unique([taskId, executionId])`), Ed25519 signature on result submission.
- **Tests**: Integration tests for task state transitions, idempotency duplicate submission rejection, and timeout sweeps.
- **Manual Verification**: Dispatch task -> transitions `CREATED` -> `QUEUED` -> `DELIVERED` -> `RUNNING` -> `COMPLETED`. Post duplicate result -> returns cached ACK without duplicate findings.
- **Acceptance Criteria**: State machine transitions verified, idempotency enforced, findings stored.
- **Rollback Considerations**: Reset stuck task states via recovery worker.

> [!IMPORTANT]
> **PHASE 5 GATE**: **DO NOT PROCEED until all Phase 5 verification criteria pass.**

---

## Phase 6: Controlled Security Capabilities Suite (`netra-agent`)
- **Goal**: Implement pre-compiled Python scanner modules for all 7 controlled capabilities (`SCAN_NETWORK`, `SCAN_PROCESSES`, `SCAN_CONNECTIONS`, `SCAN_FIREWALL`, `SCAN_USERS`, `SCAN_STARTUP`, `SCAN_FILE_INTEGRITY`).
- **Scope**: `netra-agent/netra/modules/` scanner classes, resource caps (CPU/RAM limits), execution timeouts (max 45s), Pydantic output schemas.
- **Files/Components**: `netra-agent/netra/modules/base.py`, `network_scan.py`, `process_scan.py`, `connections_scan.py`, `firewall_scan.py`, `users_scan.py`, `startup_scan.py`, `file_integrity_scan.py`.
- **Dependencies**: `psutil`, `pydantic`, `cryptography`.
- **Security Considerations**: Zero shell string execution (`exec`/`eval` strictly prohibited). Pre-defined file path manifests ONLY for file integrity.
- **Tests**: Pytest unit tests for all 7 scanner modules on Windows/Linux platform mocks.
- **Manual Verification**: Execute `netra run --capability SCAN_NETWORK` locally -> returns validated JSON finding payload within 5s.
- **Acceptance Criteria**: All 7 capabilities execute cleanly, Pydantic schemas validated, zero shell injection risk.
- **Rollback Considerations**: Disable failing capability module in agent configuration.

> [!IMPORTANT]
> **PHASE 6 GATE**: **DO NOT PROCEED until all Phase 6 verification criteria pass.**

---

## Phase 7: Discord Control Plane & Async DM Delivery (`netra-discord`)
- **Goal**: Initialize `netra-discord` bot, implement Slash Commands (`/panel`, `/scan`, `/devices`, `/findings`), ephemeral slash command acks, and Direct Message (DM) result delivery.
- **Scope**: Repository 2 setup, Discord.js client, slash command router, Backend REST client, DM delivery service.
- **Files/Components**: `netra-discord/src/bot.ts`, `src/commands/`, `src/formatters/`, `src/services/dm_delivery.ts`.
- **Dependencies**: Node.js 20, Discord.js v14, Axios/Fetch.
- **Security Considerations**: Zero direct DB access in Discord bot. Zero business logic. Ephemeral slash command responses (`ephemeral: true`). Results delivered strictly via private DMs.
- **Tests**: Jest mock tests for Discord slash command handlers and DM renderer.
- **Manual Verification**: Type `/scan` in Discord channel -> receive immediate ephemeral ack ("Task queued..."). Upon scan completion -> receive private Discord DM with rich visual embed of scan findings.
- **Acceptance Criteria**: Slash commands functional, ephemeral acks working, DM delivery successful, channel remains clean.
- **Rollback Considerations**: Disable bot commands or restart bot gateway session.

> [!IMPORTANT]
> **PHASE 7 GATE**: **DO NOT PROCEED until all Phase 7 verification criteria pass.**

---

## Phase 8: Observability, Resilience & Fault Recovery (All Repositories)
- **Goal**: Implement JSON log redactor, correlation ID propagation (`request_id`, `task_id`, `execution_id`, `device_id`, `tenant_id`), Prometheus metrics, and automated fault recovery.
- **Scope**: Logging middleware, Prometheus metrics endpoint (`/metrics`), backend/discord/agent crash recovery loops.
- **Files/Components**: `netra-backend/src/middleware/logging.ts`, `netra-discord/src/utils/logger.ts`, `netra-agent/netra/utils/logging.py`.
- **Dependencies**: `prom-client`, `pino`.
- **Security Considerations**: Mandatory redaction of `password`, `token`, `jwt`, `privateKey`, `DISCORD_BOT_TOKEN`, `signature`, and raw evidence.
- **Tests**: Unit tests for log secret redactor regex; integration tests for correlation ID propagation across HTTP/WSS headers.
- **Manual Verification**: Trigger task -> verify matching `request_id`, `task_id`, `execution_id` across Backend, Discord, and Agent JSON logs. Verify secrets replaced with `"[REDACTED]"`.
- **Acceptance Criteria**: Correlation IDs propagated, secret redaction 100% effective, Prometheus metrics exported.
- **Rollback Considerations**: N/A (Observability layer).

> [!IMPORTANT]
> **PHASE 8 GATE**: **DO NOT PROCEED until all Phase 8 verification criteria pass.**

---

## Phase 9: Multi-Repo CI/CD Automation & Deployment (`.github/workflows`)
- **Goal**: Configure independent GitHub Actions CI/CD pipelines across `netra-backend`, `netra-discord`, and `netra-agent`, container builds, and PyPI release workflows.
- **Scope**: `.github/workflows/ci.yml` in all 3 repositories, Trivy vulnerability scans, Hatch package build verification.
- **Files/Components**: `netra-backend/.github/workflows/ci.yml`, `netra-discord/.github/workflows/ci.yml`, `netra-agent/.github/workflows/ci.yml`.
- **Dependencies**: GitHub Actions, Docker, Trivy, Hatch, Gitleaks.
- **Security Considerations**: Gitleaks secret scanning, Trivy image vulnerability scan (fail on CRITICAL/HIGH), dependency audit.
- **Tests**: Execution of CI pipelines on PR and push events across all 3 repos.
- **Manual Verification**: Push PR in each repo -> GitHub Actions triggers correct stack pipeline (Node vs Python) and passes all gates.
- **Acceptance Criteria**: 3 independent CI pipelines passing, 0 security vulnerabilities, Docker/PyPI artifacts built cleanly.
- **Rollback Considerations**: Revert workflow file changes.

> [!IMPORTANT]
> **PHASE 9 GATE**: **DO NOT PROCEED until all Phase 9 verification criteria pass.**

---

## Phase 10: Production Hardening, Load Testing & Release Tagging
- **Goal**: Conduct end-to-end multi-tenant penetration testing, high-concurrency WSS load testing (1,000 req/sec), production container image publishing, and tag `v1.0.0` release.
- **Scope**: Load testing scripts (k6 / Locust), security audit, container registry push, PyPI package publication, Git tagging.
- **Files/Components**: Performance test suites, release tagging across `netra-backend`, `netra-discord`, `netra-agent`.
- **Dependencies**: k6, Locust, Docker Registry, PyPI.
- **Security Considerations**: Final IDOR penetration audit, verifying zero cross-tenant data leakage under load.
- **Tests**: Load test suite simulating 100 concurrent agents and 50 concurrent Discord users.
- **Manual Verification**: Run load test -> WSS gateway maintains 1,000 req/sec, zero database connection pool exhaustion, zero cross-tenant leakage.
- **Acceptance Criteria**: Load test passed, security audit clean, official `v1.0.0` tagged across all 3 repositories.
- **Rollback Considerations**: Revert release tags if production smoke test fails.

> [!IMPORTANT]
> **PHASE 10 GATE**: **DO NOT PROCEED until all Phase 10 verification criteria pass.**


