# NETRA Monorepo Structure & Service Boundaries

## 1. Unified Python Monorepo Architecture

NETRA consolidates all services, agent packages, control planes, and shared domain libraries into a **Unified Python Monorepo** (`NETRA/`) powered by **Python 3.11+**:

```
NETRA/
├── backend/                    # Python Backend Central Service (FastAPI / SQLAlchemy 2.0 / Alembic)
├── agent/                      # Python Client Agent Package (Typer CLI / httpx / websockets / keyring)
├── discord/                    # Python Discord Control Plane (discord.py / httpx)
├── shared/                     # Common Domain Package (netra_shared: Pydantic v2 schemas / crypto / errors)
├── docs/                       # Central Architecture Specifications
└── .github/                    # Unified GitHub Actions Workflows
```

---

## 2. Directory Layout Breakdown

```
NETRA/
├── backend/                    # Central Security Engine Service
│   ├── alembic/                # Alembic database schema migrations
│   │   ├── versions/           # Versioned SQL migration scripts
│   │   └── env.py              # Alembic migration environment config
│   ├── src/
│   │   ├── config.py           # Pydantic v2 Settings validator
│   │   ├── database.py         # SQLAlchemy 2.0 async engine & session maker
│   │   ├── rls.py              # PostgreSQL RLS session wrapper (`SET LOCAL app.current_tenant_id`)
│   │   ├── main.py             # FastAPI app initialization & route registration
│   │   ├── api/
│   │   │   ├── v1/
│   │   │   │   ├── auth.py     # Login, refresh token, password hashing (Argon2)
│   │   │   │   ├── devices.py  # Enrollment, public key registration, revocation
│   │   │   │   ├── tasks.py    # Task queue engine, status query, result ingestion
│   │   │   │   ├── findings.py # Vulnerability findings & evidence query endpoints
│   │   │   │   ├── events.py   # Internal Discord async result event bridge
│   │   │   │   └── health.py   # Health & readiness probes (`/api/v1/health`, `/api/v1/readiness`)
│   │   │   └── wss/
│   │   │       └── gateway.py  # Outbound Agent WSS gateway & Ed25519 signature validator
│   │   ├── services/           # Domain business logic (Task Engine, Finding Ingestion, Audit)
│   │   └── models/             # SQLAlchemy 2.0 database entity models (14 entities)
│   ├── tests/
│   │   ├── unit/
│   │   └── integration/        # Ephemeral PostgreSQL 16 RLS tests
│   ├── Dockerfile
│   ├── pyproject.toml
│   └── requirements.txt
│
├── agent/                      # Standalone Client Host Agent Package
│   ├── netra/
│   │   ├── __init__.py
│   │   ├── __main__.py         # CLI entrypoint (`netra`)
│   │   ├── cli/                # Typer CLI commands (`netra enroll`, `netra run`)
│   │   ├── auth/               # Local Ed25519 keypair generator & OS keyring storage (DPAPI/SecretService/Keychain)
│   │   ├── connection/         # Outbound WSS client & REST polling fallback client
│   │   ├── worker/             # Task execution loop & worker thread pool
│   │   ├── modules/            # Pre-compiled security capabilities
│   │   │   ├── base.py         # Base scanner interface with CPU/RAM caps & timeouts
│   │   │   ├── network_scan.py
│   │   │   ├── process_scan.py
│   │   │   ├── connections_scan.py
│   │   │   ├── firewall_scan.py
│   │   │   ├── users_scan.py
│   │   │   ├── startup_scan.py
│   │   │   └── file_integrity_scan.py
│   │   └── storage/            # Encrypted local SQLite offline queue
│   ├── tests/
│   ├── pyproject.toml          # Hatch / Flit build specification
│   └── requirements.txt
│
├── discord/                    # Discord Control Plane & Alerting Service
│   ├── bot/
│   │   ├── main.py             # discord.py bot runner
│   │   ├── cogs/               # Slash command cog routers (`scan`, `panel`, `devices`, `findings`)
│   │   ├── formatters/         # Rich embed formatters & ANSI renderers
│   │   └── services/           # Backend REST API client & async DM delivery listener
│   ├── tests/
│   ├── Dockerfile
│   ├── pyproject.toml
│   └── requirements.txt
│
├── shared/                     # Common Domain Library (`netra_shared`)
│   ├── netra_shared/
│   │   ├── __init__.py
│   │   ├── schemas/            # Pydantic v2 models (Task, Execution, Finding, Device, Error Envelope)
│   │   ├── capabilities/       # Capability enums, input schemas & output schemas
│   │   ├── crypto/             # Ed25519 key verification helpers & canonical payload signers
│   │   └── errors/             # 10 Standard error codes & custom exception classes
│   ├── pyproject.toml
│   └── requirements.txt
│
├── docs/                       # Architecture Specifications & Specifications
│   ├── ARCHITECTURE.md
│   ├── SYSTEM_DESIGN.md
│   ├── DATABASE_DESIGN.md
│   ├── API_BOUNDARY.md
│   ├── SECURITY_MODEL.md
│   ├── CI_CD_STRATEGY.md
│   ├── DEVELOPMENT_ROADMAP.md
│   ├── REPOSITORY_STRUCTURE.md
│   ├── GITHUB_WORKFLOW.md
│   ├── OBSERVABILITY.md
│   └── THREAT_MODEL.md
│
├── .github/
│   └── workflows/
│       ├── ci.yml              # Matrix CI workflow testing backend, agent, discord, shared
│       └── release.yml         # Container build & PyPI publishing pipeline
│
├── .env.example
├── .gitignore
└── README.md
```

---

## 3. Strict Service Boundary & Code Reuse Rules

1. **Shared Code via `shared/` (`netra_shared`)**: Domain schemas, capability definitions, Ed25519 signature verification functions, and standard error envelopes live strictly in `shared/`. Both `backend/`, `agent/`, and `discord/` import from `netra_shared`.
2. **PostgreSQL Owner**: `backend/` is the **ONLY** service that connects to PostgreSQL 16 and manages Alembic migrations. Neither `agent/` nor `discord/` have database drivers or credentials.
3. **Control Plane Isolation**: `discord/` communicates strictly with `backend/` via REST APIs (`/api/v1/...`). It contains zero scanning logic, zero database access, and zero tenant business logic.
4. **Agent Isolation**: `agent/` communicates strictly with `backend/` over outbound WSS or REST polling. It has zero knowledge of Discord APIs.


