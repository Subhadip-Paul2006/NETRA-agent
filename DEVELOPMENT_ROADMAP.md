# NETRA Comprehensive Development Roadmap

## Phase 0: Architecture & Foundation Planning (COMPLETED)
- [x] **Repository Inspection**: Verified empty codebase state.
- [x] **3-Repository Architecture**: Defined boundaries for `netra-backend`, `netra-discord`, and `netra-agent` (`ARCHITECTURE.md`).
- [x] **System Design**: Documented directional flow (Discord $\leftrightarrow$ Backend $\leftrightarrow$ Agent), explicit state machine (`CREATED` $\rightarrow$ `COMPLETED`), enrollment sequence, and idempotency (`SYSTEM_DESIGN.md`).
- [x] **Repository Structure**: Detailed file layouts for all 3 repos (`REPOSITORY_STRUCTURE.md`).
- [x] **Security Model**: Designed HMAC SHA-256 protocol, credential lifecycle, replay protection, and controlled capabilities (`SECURITY_MODEL.md`).
- [x] **API Boundary**: Defined OpenAPI REST & WSS specifications, enrollment contracts, and status codes (`API_BOUNDARY.md`).
- [x] **Database Design**: Drafted Prisma schema with `TenantMembership`, `DeviceCredential`, `TaskExecution`, and PostgreSQL RLS transaction pattern (`DATABASE_DESIGN.md`).
- [x] **GitHub & CI/CD Workflows**: Defined branch strategy, conventional commits, and SAST/container scan pipelines (`GITHUB_WORKFLOW.md`, `CI_CD_STRATEGY.md`).
- [x] **Threat Model**: Documented threat matrix and security mitigations (`THREAT_MODEL.md`).
- [x] **Observability**: Defined JSON log schemas, correlation IDs (`request_id`, `task_id`), and metrics (`OBSERVABILITY.md`).
- [x] **Environment Security**: Created categorized `.env.example` template and production `.gitignore`.

**Phase 0 Status**: **PASS** (Ready for Phase 1 approval).

---

## Phase 1: NETRA Backend Core Engine (`netra-backend`)
- [ ] Initialize `netra-backend` Node.js / TypeScript repository.
- [ ] Setup Fastify/Express web framework with global error handlers and Zod environment validator.
- [ ] Integrate Prisma Client and execute initial PostgreSQL database migration with RLS policies.
- [ ] Implement Tenant, User, TenantMembership, and DeviceCredential management modules.
- [ ] Implement JWT access tokens, refresh token rotation, and password hashing (`argon2`).
- [ ] Build `withTenantContext` transaction wrapper for PostgreSQL RLS execution context (`SET LOCAL app.current_tenant_id`).
- [ ] Implement Task Queue Engine (`CREATED` $\rightarrow$ `QUEUED` $\rightarrow$ `DELIVERED` $\rightarrow$ `RUNNING` $\rightarrow$ `COMPLETED`).
- [ ] Implement WSS Gateway for agent connection and task dispatching.
- [ ] Build immutable Audit Logger module.
- [ ] Write Jest unit and integration tests with test PostgreSQL database.

---

## Phase 2: NETRA Agent Package (`netra-agent`)
- [ ] Initialize `netra-agent` Python package repository (`pyproject.toml`).
- [ ] Implement CLI entrypoint (`netra`) with argument parser (`netra enroll`, `netra run`).
- [ ] Implement Device Enrollment client flow (`netra enroll <code>`).
- [ ] Implement secure HMAC SHA-256 signature generator for `httpx` and `websockets`.
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
- [ ] Implement rich Discord embed formatters with ANSI code block formatting.
- [ ] Ensure all finding output embeds use `ephemeral: true` to prevent channel data leaks.

---

## Phase 4: Production Hardening, Advanced Scanning & Release
- [ ] Expand security audit modules in `netra-agent` (file integrity, docker audit, startup process monitor).
- [ ] Conduct end-to-end multi-tenant penetration testing (verify zero cross-tenant IDOR leakage).
- [ ] Perform load testing on WSS task gateway and HMAC authentication endpoints (1,000 requests/sec).
- [ ] Finalize Docker containerization and publish production images to Container Registry.
- [ ] Publish `netra` Python package to PyPI.
- [ ] Tag official `v1.0.0` production release.
