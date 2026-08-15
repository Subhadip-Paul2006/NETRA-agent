# NETRA Comprehensive Development Roadmap

## Phase 0: Architecture & Foundation Planning (Architecture Draft)
- [x] **Repository Inspection**: Verified empty codebase state.
- [x] **3-Repository Architecture**: Defined boundaries for `netra-backend`, `netra-discord`, and `netra-agent` (`ARCHITECTURE.md`).
- [x] **System Design**: Documented directional flow (Discord $\leftrightarrow$ Backend $\leftrightarrow$ Agent), explicit state machine (`CREATED` $\rightarrow$ `COMPLETED`), enrollment sequence, 10 concurrency/recovery scenarios, and idempotency (`SYSTEM_DESIGN.md`).
- [x] **Repository Structure**: Detailed file layouts for all 3 repos (`REPOSITORY_STRUCTURE.md`).
- [x] **Security Model**: Designed Ed25519 asymmetric signature protocol, OS protected key storage, key lifecycle, replay protection, and controlled capabilities (`SECURITY_MODEL.md`).
- [x] **API Boundary**: Defined OpenAPI REST & WSS specifications, enrollment contracts with public key registration, and status codes (`API_BOUNDARY.md`).
- [x] **Database Design**: Drafted Prisma schema with `TenantMembership`, `DeviceCredential` (Ed25519 `publicKey`), `TaskExecution`, RLS transaction pattern, and formal `DATABASE_INVARIANTS` (`DATABASE_DESIGN.md`).
- [x] **GitHub & CI/CD Workflows**: Defined branch strategy, conventional commits, and 3 repository-specific CI/CD pipelines (`GITHUB_WORKFLOW.md`, `CI_CD_STRATEGY.md`).
- [x] **Threat Model**: Documented threat matrix and security mitigations (`THREAT_MODEL.md`).
- [x] **Observability**: Defined JSON log schemas, correlation IDs (`request_id`, `task_id`), and metrics (`OBSERVABILITY.md`).
- [x] **Environment Security**: Created categorized `.env.example` template and production `.gitignore`.

> [!IMPORTANT]
> **Phase 0 Status**: **UNDER REVIEW**
> *Note: Phase 0 will be marked **PASS / APPROVED** only after full user review and explicit approval of all architecture documentation.*

---

## Phase 1: NETRA Backend Core Engine (`netra-backend`)
- [ ] Initialize `netra-backend` Node.js / TypeScript repository.
- [ ] Setup Fastify/Express web framework with global error handlers and Zod environment validator.
- [ ] Integrate Prisma Client and execute initial PostgreSQL database migration with RLS policies and `DATABASE_INVARIANTS`.
- [ ] Implement Tenant, User, TenantMembership, and DeviceCredential (Ed25519 public key) management modules.
- [ ] Implement JWT access tokens, refresh token rotation, and password hashing (`argon2`).
- [ ] Build `withTenantContext` transaction wrapper for PostgreSQL RLS execution context (`SET LOCAL app.current_tenant_id`).
- [ ] Implement Task Queue Engine (`CREATED` $\rightarrow$ `QUEUED` $\rightarrow$ `DELIVERED` $\rightarrow$ `RUNNING` $\rightarrow$ `COMPLETED`).
- [ ] Implement WSS Gateway for agent connection, task dispatching, and Ed25519 verification.
- [ ] Build immutable Audit Logger module.
- [ ] Write Jest unit and integration tests with test PostgreSQL database.

---

## Phase 2: NETRA Agent Package (`netra-agent`)
- [ ] Initialize `netra-agent` Python package repository (`pyproject.toml`).
- [ ] Implement CLI entrypoint (`netra`) with argument parser (`netra enroll`, `netra run`).
- [ ] Implement Device Enrollment client flow with local Ed25519 keypair generation (`netra enroll <code>`).
- [ ] Implement OS protected storage key manager (Windows Credential Manager / Secret Service API / macOS Keychain).
- [ ] Implement secure Ed25519 signature generator for `httpx` and `websockets`.
- [ ] Build persistent WSS client connection loop with automatic reconnect and HTTPS polling fallback.
- [ ] Implement Worker Execution Engine for controlled scanner modules (`SCAN_NETWORK`, `SCAN_PROCESSES`, `SCAN_FIREWALL`).
- [ ] Build encrypted local SQLite result queue for offline resilience and retry safety.
- [ ] Write Pytest test suite for local agent execution.

---

## Phase 3: NETRA Discord Control Plane (`netra-discord`)
- [ ] Initialize `netra-discord` Node.js / TypeScript bot repository.
- [ ] Setup Discord.js client with Slash Command router.
- [ ] Build Discord OAuth2 Account Link flow (`/link`, `/panel`).
- [ ] Implement Discord slash command handlers (`/devices`, `/scan`, `/findings`).
- [ ] Implement initial ephemeral slash command acknowledgments (`ephemeral: true`).
- [ ] Implement Direct Message (DM) delivery service for asynchronous scan results and high/critical alerts.
- [ ] Implement rich Discord embed formatters with ANSI code block formatting.

---

## Phase 4: Production Hardening, Advanced Scanning & Release
- [ ] Expand security audit modules in `netra-agent` (file integrity, docker audit, startup process monitor).
- [ ] Conduct end-to-end multi-tenant penetration testing (verify zero cross-tenant IDOR leakage).
- [ ] Perform load testing on WSS task gateway and Ed25519 authentication endpoints (1,000 requests/sec).
- [ ] Finalize Docker containerization and publish production images to Container Registry.
- [ ] Publish `netra` Python package to PyPI.
- [ ] Tag official `v1.0.0` production release.

