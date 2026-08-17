# NETRA System Memory & Development Log

## Project Summary
**NETRA** (Network & Enterprise Threat Reconnaissance Agent) is an enterprise-grade, multi-tenant defensive security monitoring, agent orchestration, and threat intelligence platform.

- **Monorepo Architecture**: `backend/` (FastAPI / SQLAlchemy 2.0 / PostgreSQL RLS), `agent/` (Python Typer CLI / Scanner Engine / Ed25519 Keyring), `shared/` (Pydantic schemas / Enums / Shared Utilities).
- **Primary Security Model**: Ed25519 asymmetric cryptographic device auth, PostgreSQL Row-Level Security (RLS) multi-tenancy, nonces/timestamps replay defense, zero arbitrary shell string execution (`exec`/`eval` prohibited).

---

## Phase Execution History & Completed Milestones

### Phase 0: Architecture & Foundation Planning — [COMPLETED]
- Defined 11 blueprint documents (`ARCHITECTURE.md`, `SYSTEM_DESIGN.md`, `DATABASE_DESIGN.md`, `API_BOUNDARY.md`, `SECURITY_MODEL.md`, `CI_CD_STRATEGY.md`, `DEVELOPMENT_ROADMAP.md`, `REPOSITORY_STRUCTURE.md`, `GITHUB_WORKFLOW.md`, `OBSERVABILITY.md`, `THREAT_MODEL.md`).
- Designed 14 PostgreSQL database entities, Ed25519 authentication flows, task queue state machine, and 7 defensive scanner capabilities.

### Phase 1: Backend Core Foundation (`backend/`) — [COMPLETED]
- Initialized FastAPI server baseline with Pydantic v2 settings management (`src/config.py`).
- Structured JSON logging (`structlog`) with automatic sensitive token/password redactor.
- Global exception handler middleware (`middleware/error_handler.py`).
- Health and readiness endpoints (`GET /api/v1/health`, `GET /api/v1/readiness`).

### Phase 2: Database, RLS, Identity & Tenancy — [COMPLETED]
- Implemented 14 SQLAlchemy 2.0 ORM models: `Tenant`, `User`, `TenantMembership`, `Device`, `DeviceCredential`, `AgentSession`, `Task`, `TaskExecution`, `Finding`, `FindingEvidence`, `DiscordBinding`, `DiscordSession`, `AuditEvent`, `EnrollmentCode`, `NonceCache`.
- Created Alembic DDL migration `001_initial_schema.py`.
- Enforced PostgreSQL 16 Row-Level Security (RLS) via `with_tenant_context` context manager (`SET LOCAL app.current_tenant_id = :tenant_id`).
- Implemented JWT authentication (`POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`) with Argon2 password hashing.

### Phase 3: Agent Enrollment & Ed25519 Device Identity — [COMPLETED]
- Created single-use 15-minute `EnrollmentCode` generator (`POST /api/v1/control/enrollment-codes`).
- Implemented agent CLI enrollment handler (`netra enroll <code>`).
- Integrated local Ed25519 keypair generation and secure OS keyring storage (Windows Credential Manager / macOS Keychain / Linux Secret Service).
- Implemented device registration & public key validation endpoint (`POST /api/v1/agent/enroll`).

### Phase 4: Agent WSS Gateway & Transport Protocol — [COMPLETED]
- Built WSS gateway endpoint (`/api/v1/agent/connect`) enforcing `X-NETRA-Signature` Ed25519 handshake validation.
- Implemented timestamp drift checks (5-min window) and `NonceCache` deduplication.
- Built robust client (`wss_client.py`) with exponential backoff reconnect and REST polling fallback (`rest_client.py`).

### Phase 5: Durable Task Queue Engine & Execution Lifecycle — [COMPLETED]
- Implemented explicit task state machine:
  `CREATED` $\rightarrow$ `QUEUED` $\rightarrow$ `DELIVERED` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RUNNING` $\rightarrow$ `COMPLETED` (or `FAILED` / `CANCELLED` / `TIMEOUT`).
- Developed atomic task claiming (`claim_next_task_for_device`) guaranteeing single-worker delivery under high concurrency (`UPDATE tasks SET status = 'DELIVERED' WHERE status = 'QUEUED'`).
- Added `X-Idempotency-Key` deduplication on task result submissions.
- Created Alembic migration `002_task_orchestration.py`.

### Phase 6: Controlled Security Capabilities Suite & Local Scanner Engine — [COMPLETED]
- Implemented abstract `BaseScanner` with safety bounds (`execute_with_safety_limits` for CPU/memory limits, timeouts, and error isolation).
- Built 7 cross-platform host security posture scanners in `agent/src/netra_agent/scanners/`:
  1. `SCAN_NETWORK`: Network interfaces, IP addresses, netmasks, DNS.
  2. `SCAN_PROCESSES`: Process table, PIDs, `/tmp` execution checks.
  3. `SCAN_CONNECTIONS`: Open sockets, unencrypted/high-risk listening ports (21, 23, 445).
  4. `SCAN_FIREWALL`: Windows Defender, UFW, pfctl firewall profile status.
  5. `SCAN_USERS`: Interactive sessions, default admin user checks.
  6. `SCAN_STARTUP`: Autorun registry keys, systemd, cron startup items.
  7. `SCAN_FILE_INTEGRITY`: SHA-256 file hashing with strict path traversal & file count limits.
- Built `ScannerRegistry` singleton and integrated task executor (`task_executor.py`).

### Phase 7: Findings Security Domain & Control-Plane Intelligence — [COMPLETED]
- Created Alembic migration `003_phase_7_findings.py` adding schema enhancements (`device_id`, `task_id`, `execution_id`, `capability`, `description`, `remediation`, indexes, and FK constraints).
- Implemented finding management engine (`finding_engine.py`) for querying paginated findings, retrieving evidence history, and mutating finding status (`ACKNOWLEDGED`, `RESOLVED`, `REOPENED`, `MUTED`).
- Implemented REST API endpoints (`GET /api/v1/control/findings`, `GET /api/v1/control/findings/{id}`, `POST /api/v1/control/findings/{id}/status`).

---

## Directory Map

```text
NETRA-agent/
├── MEMORY.md                          # Current system memory & work log
├── DEVELOPMENT_ROADMAP.md             # Master phase roadmap & acceptance gates
├── ARCHITECTURE.md                    # Core architectural specification
├── DATABASE_DESIGN.md                 # Schema & RLS policy specifications
├── SECURITY_MODEL.md                  # Threat model & zero-trust security controls
├── API_BOUNDARY.md                    # REST, WSS & payload contracts
├── agent/                             # Agent Monorepo Package (Python Typer CLI)
│   ├── src/netra_agent/
│   │   ├── cli/                       # CLI commands (enroll, run, etc.)
│   │   ├── connection/                # WSS gateway client & REST polling fallback
│   │   ├── executor/                  # Task execution engine & scanner dispatcher
│   │   ├── scanners/                  # 7 Capability scanner engines + BaseScanner + Registry
│   │   └── security/                  # Ed25519 signing, keyring storage, nonces
│   └── tests/                         # Agent unit & security boundary test suite
├── backend/                           # Backend Control-Plane (FastAPI)
│   ├── alembic/                       # Database DDL migrations (001, 002, 003)
│   ├── src/netra_backend/
│   │   ├── api/v1/                    # Control & Agent REST API endpoints
│   │   ├── database/                   # SQLAlchemy async engine & session management
│   │   ├── models/                    # 14 SQLAlchemy ORM models
│   │   ├── rls/                       # Row-Level Security session context manager
│   │   ├── security/                  # Argon2, JWT, Ed25519 signature validation
│   │   └── services/                  # Task engine, finding engine, device manager
│   └── tests/                         # Backend unit & integration test suite
└── shared/                            # Monorepo Shared Package
    └── src/netra_shared/
        ├── enums/                     # Shared capability, status, severity, role enums
        ├── errors/                    # Standardized error definitions
        └── schemas/                   # Pydantic v2 schemas for tasks, findings, auth
```

---

## Key Technical Decisions & Security Contracts

1. **Zero-Trust Multi-Tenancy**: All backend database queries run inside `with_tenant_context(session, tenant_id)`, which executes `SET LOCAL app.current_tenant_id = :tenant_id`. PostgreSQL RLS policies enforce isolation even if application code omits a `WHERE tenant_id = ...` filter.
2. **Ed25519 Device Authentication**: Agents sign every WSS connection request and HTTP body with Ed25519 private key stored in local OS protected storage. Backend authenticates signatures using registered public key (`DeviceCredential`).
3. **Strict Capability Sandbox**: Scanner modules perform read-only inspection. Command injection is prevented by prohibiting arbitrary shell string execution (`exec`/`eval`), using hardcoded array arguments for system utilities, and validating all input via Pydantic.
4. **Idempotent Task Processing**: Task completion requests accept an `X-Idempotency-Key` header mapped to `TaskExecution` records to prevent duplicate finding creation during network retries.
