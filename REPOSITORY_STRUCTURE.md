# NETRA Repository Structure & Boundaries

## 1. Three-Repository Architectural Boundary

NETRA cleanly segregates code, dependencies, and execution contexts across three independent repositories:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. NETRA Backend Repository (netra-backend) [Repo 1]                       │
│    - Technology: Node.js / TypeScript / Prisma ORM / Fastify                │
│    - Responsibilities: API Gateway, Identity Provider, Tenant Isolation,    │
│      PostgreSQL Database Schema, Task State Engine, Agent WSS Gateway,      │
│      Audit Trail Engine.                                                    │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. NETRA Discord Control Plane Repository (netra-discord) [Repo 2]         │
│    - Technology: Node.js / TypeScript / Discord.js                          │
│    - Responsibilities: Discord Bot Service, Slash Command Router, Embed     │
│      Formatter, Discord OAuth2 Identity Verification, Calling Core API.     │
│    - STRICT RULE: Zero business logic, scanning code, or direct DB access.  │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. NETRA Agent Repository (netra-agent) [Repo 3 - Standalone Package]       │
│    - Technology: Python 3.10+ / Hatch / Pytest / httpx / websockets         │
│    - Responsibilities: Python CLI (`netra`), Device Enrollment Client,      │
│      Outbound WSS / HTTPS Polling Worker, Local Pre-compiled Scanners,       │
│      Encrypted SQLite Offline Queue, OS Keyring Credential Vault.           │
│    - STRICT RULE: Zero awareness or direct coupling to Discord APIs.        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Repository 1 Layout (`netra-backend`)

```
netra-backend/
├── .github/workflows/
│   ├── ci.yml                  # Lint, test, typecheck, Prisma validation, SAST
│   └── release.yml             # Container build & release tagging
├── prisma/
│   ├── schema.prisma           # Canonical database schema definition
│   └── migrations/             # Versioned SQL migration scripts
├── src/
│   ├── config/                 # Zod validated environment configuration
│   ├── gateway/                # WebSocket & REST protocol handlers
│   ├── middleware/             # Auth, TenantContext, RLS transaction setup, RateLimit
│   ├── modules/                # Domain modules
│   │   ├── auth/               # User authentication & JWT management
│   │   ├── tenant/             # Tenant context & TenantMembership management
│   │   ├── device/             # Device registration, key vault, WSS session tracker
│   │   ├── task/               # Task lifecycle state machine & queue manager
│   │   ├── finding/            # Security finding ingest & deduplication engine
│   │   ├── discord-link/       # Discord OAuth2 identity linking API
│   │   └── audit/              # Immutable audit logging engine
│   ├── app.ts                  # Application setup
│   └── server.ts               # HTTP & WSS server entrypoint
├── tests/
│   ├── unit/
│   └── integration/
├── .env.example
├── .gitignore
├── Dockerfile
├── package.json
└── tsconfig.json
```

---

## 3. Repository 2 Layout (`netra-discord`)

```
netra-discord/
├── .github/workflows/
│   └── ci.yml                  # Discord bot linting & unit testing
├── src/
│   ├── config/                 # Bot environment loading
│   ├── client/                 # Core API HTTP client (Axios/Fetch with retry)
│   ├── commands/               # Slash command handlers
│   │   ├── auth/               # /link, /unlink, /panel
│   │   ├── device/             # /devices list, /device info
│   │   ├── scan/               # /scan start, /scan status
│   │   └── findings/           # /findings list, /finding view
│   ├── formatters/             # Rich embed formatters & ANSI color renderers
│   ├── bot.ts                  # Discord.js client initialization
│   └── index.ts                # Bot entrypoint
├── tests/
├── .env.example
├── .gitignore
├── Dockerfile
├── package.json
└── tsconfig.json
```

---

## 4. Repository 3 Layout (`netra-agent`)

```
netra-agent/
├── .github/workflows/
│   └── publish.yml             # PyPI automated package build & release
├── netra/
│   ├── __init__.py
│   ├── __main__.py             # CLI entrypoint (`netra`)
│   ├── cli/                    # Argument parser (`netra enroll`, `netra run`)
│   ├── auth/                   # OS Keyring manager & HMAC SHA-256 signing engine
│   ├── connection/             # Outbound WSS client with exponential backoff & HTTPS fallback
│   ├── worker/                 # Task queue consumer & execution loop
│   ├── modules/                # Controlled local security audit capabilities
│   │   ├── base.py             # Base scanner interface
│   │   ├── network_scan.py     # Local network & port inspector
│   │   ├── process_scan.py     # Running process threat analyzer
│   │   ├── firewall_scan.py    # Local firewall configuration checker
│   │   └── file_scan.py        # System file baseline auditor
│   ├── storage/                # Encrypted SQLite offline result buffer
│   └── utils/                  # System metadata, logging
├── tests/
├── pyproject.toml              # Packaging config (Hatch/Poetry)
├── .env.example
├── .gitignore
└── README.md
```

---

## 5. Strict Code Duplication Prevention Rules

1. **No Shared Code Files**: Repositories maintain strict autonomy. Shared API contracts are defined via OpenAPI specifications.
2. **Prisma Single-Sourcing**: Database migrations and `schema.prisma` reside **ONLY** in `netra-backend`.
3. **No Direct Security Engine Code in Control Plane**: Scanning logic resides in `netra-agent`; result normalization resides in `netra-backend`. Neither exists in `netra-discord`.
