# NETRA Core Architecture

## 1. System Vision & Objective

**NETRA** (Network & Enterprise Threat Reconnaissance Agent) is a production-grade, multi-tenant security operations toolkit designed for distributed vulnerability assessment, local machine security enforcement, and centralized threat management.

### 1.1 Repository Scope & Phase 0 Workspace Context
- **Current Repository (`Subhadip-Paul2006/NETRA-agent`)**: Acts as the Phase 0 architecture design baseline and repository workspace for the entire NETRA system.
- **Target Multi-Repository Architecture**:
  - **Repository 1: NETRA Backend** (`netra-backend`) — Centralized security engine, multi-tenant database owner, identity provider, command orchestration broker, agent gateway, and audit vault.
  - **Repository 2: NETRA Discord Control Plane** (`netra-discord`) — Interactive management and alerting interface operating strictly as an API client to the Backend.
  - **Repository 3: NETRA Agent** (`netra-agent`) — Standalone Python agent package running on user client host machines that executes authorized security capabilities and reports telemetry back to the Backend.

The final repository ownership and code layout are governed by Phase 0 architecture documentation before implementation begins.

---

## 2. High-Level Internet Topology

```
                                  INTERNET
                                     │
                       ┌─────────────┴─────────────┐
                       │                           │
                       ▼                           ▼
                Discord Control              REST/API Clients
                   Plane Repo 2                   │
                       │                           │
                       └─────────────┬─────────────┘
                                     ▼
                          ┌─────────────────────┐
                          │    NETRA BACKEND    │
                          │       REPO 1        │
                          │                     │
                          │ Auth                │
                          │ Tenant Management   │
                          │ Device Management   │
                          │ Task Engine         │
                          │ Findings            │
                          │ Audit               │
                          │ Agent Gateway       │
                          └──────────┬──────────┘
                                     │
                              PostgreSQL
                                     │
                          ┌──────────┴──────────┐
                          │                     │
                          ▼                     ▼
                   NETRA Agent A          NETRA Agent B
                   User PC #1             User PC #2
                   Repo 3                 Repo 3
```

---

## 3. Directional Communication Flow

Discord and Local Agents **NEVER** communicate directly with each other. All control signals and telemetry flow strictly through the Backend:

```
[ Discord User ] ──> [ Discord Control Plane (Repo 2) ] ──> [ NETRA Backend (Repo 1) ] ──> [ NETRA Agent (Repo 3) ]
        │                                                                                           │
        │ (4. Immediate Ephemeral Ack)                                                              │
        ▼                                                                                           ▼
[ Discord Channel ] <── [ Discord Bot Response ]                                          [ Local Security Scan ]
        ▲                                                                                           │
        │                                                                                           ▼
        └────────────── [ Discord Direct Message (DM) ] <── [ NETRA Discord ] <── [ NETRA Backend ] ┘
```

1. **Control Phase**: User triggers slash command in Discord $\rightarrow$ Bot posts to Backend $\rightarrow$ Backend returns instant queue acknowledgment $\rightarrow$ Bot renders `ephemeral: true` message ("Task queued...").
2. **Execution Phase**: Backend dispatches task over outbound WSS $\rightarrow$ Agent executes pre-compiled scanner $\rightarrow$ Agent posts Ed25519 signed result payload to Backend.
3. **Delivery Phase**: Backend verifies Ed25519 signature, persists findings inside PostgreSQL transaction, and emits event $\rightarrow$ Discord bot delivers full visual result embed directly to the user's **Discord Direct Messages (DMs)**.

---

## 4. Core Architectural Principles

1. **Multi-Tenant Isolation from Day 1**: Every query, task, device registration, finding, and audit record is strictly bound to a `tenant_id`. User A can never discover, control, or read data belonging to User B.
2. **Stateless Backend Processing**: All application state resides in PostgreSQL. Backend web/API nodes remain stateless to allow immediate horizontal scaling behind a load balancer.
3. **Decoupled 3-Repository Boundaries**:
   - The local Python agent has zero awareness of Discord APIs.
   - The Discord bot has zero direct database connections and zero security scanning logic.
   - The Backend acts as the single source of truth, authorization layer, and coordination gateway.
4. **Agent Communication Protocol & Ed25519 Asymmetric Identity**:
   - **Primary**: Outbound persistent WSS (WebSocket) connection from Agent to Backend (`netra-agent` $\rightarrow$ `netra-backend`). Requires no open inbound ports on the user's PC.
   - **Fallback**: Authenticated HTTPS REST polling (`GET /tasks`, execute, `POST /results`) for restrictive network environments.
   - **Identity**: Every payload signed with local Ed25519 private key (stored in OS protected storage); verified against PostgreSQL `DeviceCredential.publicKey`.
5. **Controlled Capability Model**: No arbitrary remote shell command execution (`exec`/`eval` strictly prohibited). Control plane triggers pre-compiled, type-checked security audit capabilities (`SCAN_NETWORK`, `SCAN_PROCESSES`, `SCAN_FIREWALL`, etc.).
6. **Asynchronous Discord Result Separation**: Initial slash command response is rendered strictly as `ephemeral: true` (acknowledgement only). Full scan results and security alerts are delivered directly to requesting users via Discord Direct Messages (DMs).
7. **Pragmatic Production Design**: Minimal operational complexity. No premature addition of Kafka, Kubernetes, or microservices until concrete scale requirements demand it.

---

## 5. Architectural Decision Records (ADRs)

### ADR-01: Three-Repository Architecture vs. Monorepo / Combined Repo
- **Decision**: Explicitly split into **3 Repositories** (`netra-backend`, `netra-discord`, `netra-agent`).
- **Why**: `netra-backend` (Node.js/TypeScript/Prisma), `netra-discord` (Node.js/Discord.js), and `netra-agent` (Python/PyPI) have fundamentally different technology stacks, deployment lifecycles, and security boundaries.
- **Alternatives Considered**: Monorepo or bundling agent into backend repo.
- **Why Rejected**: Bundling agent code with the backend creates confusion between central server code and distributed host client code, increasing security vulnerability surface area.

### ADR-02: Agent Communication Protocol — Outbound WebSocket (Primary) + HTTPS Polling (Fallback)
- **Decision**: Choose **Outbound Persistent WSS (WebSocket) as Primary**, with **HTTPS Polling as Fallback**.
- **Why**: Outbound WebSocket allows immediate real-time task dispatch from Backend to Agent without requiring the user to open inbound firewall ports or configure NAT routing. HTTPS polling serves as an automatic fallback on networks where WebSocket proxies are blocked.
- **Alternatives Considered**: Inbound REST server on Agent, Server-Sent Events (SSE).
- **Why Rejected**: Inbound REST on Agent requires open firewall ports on client PCs (unacceptable security risk). SSE is unidirectional and requires an auxiliary channel for result posting.

### ADR-03: Primary Data Store — PostgreSQL with Prisma ORM & RLS
- **Decision**: Choose **PostgreSQL 16** with **Prisma ORM** using interactive transaction `SET LOCAL` context scoping for PostgreSQL Row-Level Security (RLS).
- **Why**: Relational schema guarantees, strong ACID transactions for audit logs, and PostgreSQL RLS support for database-level multi-tenant isolation.
- **Alternatives Considered**: MongoDB, MySQL.
- **Why Rejected**: MongoDB lacks strict relational integrity and cascading deletes needed for hierarchical tenant isolation (`Tenant` $\rightarrow$ `TenantMembership` $\rightarrow$ `Device` $\rightarrow$ `Task` $\rightarrow$ `Finding`).

### ADR-04: Controlled Task Capability Model vs. Arbitrary Shell Execution
- **Decision**: Enforce **Controlled Task Capability Model**.
- **Why**: Allowing arbitrary remote shell execution from Discord or API controls introduces massive Remote Code Execution (RCE) vulnerabilities.
- **Alternatives Considered**: Arbitrary shell command execution over SSH/Agent.
- **Why Rejected**: High risk of command injection, privilege escalation, and host compromise if Discord bot or API credentials are breached.

### ADR-05: Ed25519 Asymmetric Device Identity vs Shared-Secret HMAC
- **Decision**: Enforce **Ed25519 Asymmetric Device Signatures**. Private key stored in client OS protected storage (Windows Credential Manager / Secret Service API / macOS Keychain); public key stored in PostgreSQL (`DeviceCredential.publicKey`).
- **Why**: Prevents shared-secret server-side leakage, enforces non-repudiation, and guarantees that server-side database compromise cannot compromise client host private keys.
- **Alternatives Considered**: Shared-secret HMAC-SHA256, RSA 4096.
- **Why Rejected**: Shared secrets present server-side leakage risks if database backups are exposed. RSA 4096 signature creation/verification is significantly slower and generates large payloads compared to compact, ultra-fast 64-byte Ed25519 signatures.
