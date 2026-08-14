# NETRA System Design & Concurrency Architecture

## 1. Multi-User Concurrency Design Principles

NETRA is built from Day 1 to handle high-concurrency multi-tenant operations cleanly across 10+ simultaneous users, hundreds of enrolled agent devices, and concurrent Discord command triggers.

### 1.1 State Isolation Scopes Table

To guarantee that a failure or state corruption in User A's session never impacts User B, state is strictly scoped and decoupled from process-local global variables:

| Scope | Managed Entities | Storage / Lifecycle | Concurrency & Boundary Enforcement |
| :--- | :--- | :--- | :--- |
| **Shared Platform State** | Global DB Schema, Enum Definitions, Audit Vault | PostgreSQL 16 DB | Transaction isolation, Row-Level Security (`app.current_tenant_id`), ACID constraints. |
| **User-Scoped State** | User JWTs, `TenantMembership`, User Session | DB `user_sessions`, JWT payload | Cryptographically signed JWT claims; verified on every API request. |
| **Device-Scoped State** | `DeviceCredential`, Active WSS Connection | DB `device_credentials`, In-Memory WSS Connection Registry (`connectionId` mapped to `deviceId` + `tenantId`) | Isolated connection streams; disconnect on device A does not affect device B. |
| **Request-Scoped State** | `request_id`, `TenantContext`, Route Params | Node.js Fastify AsyncLocalStorage (`RequestStore`) | Immutable per-request object; created at Gateway entry, destroyed on HTTP/WSS response. |
| **Locking Boundaries** | Task Queue Claims (`QUEUED` $\rightarrow$ `DELIVERED`) | PostgreSQL `FOR UPDATE SKIP LOCKED` | Database-level row locking prevents duplicate task claims under concurrent polling/WSS pushes. |
| **Idempotency Boundaries** | Task Execution Results Ingestion | DB `task_executions` (`executionId` + `X-Idempotency-Key`) | Idempotent transaction guard; retried result submissions return cached ACK without duplicate writes. |
| **Queue Boundaries** | Pending Task Queue | PostgreSQL `tasks` table (`status = QUEUED`) | Multi-tenant compound index `(tenantId, status)`; tasks isolated per tenant slice. |

---

## 2. Three-User Simultaneous Execution Sequence Diagram

The following sequence diagram demonstrates **three independent users (User A, User B, User C)** operating concurrently across different tenants and devices without cross-tenant state leakage or queue blocking:

```mermaid
sequenceDiagram
    autonumber
    actor UserA as User A (Tenant Alpha)
    actor UserB as User B (Tenant Beta)
    actor UserC as User C (Tenant Gamma)
    
    participant Discord as NETRA Discord (Repo 2)
    participant Backend as NETRA Backend (Repo 1)
    participant AgentA as Agent A (User A Laptop)
    participant AgentB as Agent B (User B Server)
    participant AgentC as Agent C (User C PC)

    Note over UserA, AgentC: Concurrent Initialization & Task Requests
    par User A Action
        UserA->>Discord: `/scan device:laptop-a capability:SCAN_NETWORK`
        Discord->>Backend: POST /api/v1/control/tasks (Tenant Alpha JWT)
        Backend->>Backend: Validate AuthZ, Insert Task A1 (Tenant Alpha, QUEUED)
    and User B Action
        UserB->>Discord: `/scan device:server-b capability:SCAN_PROCESSES`
        Discord->>Backend: POST /api/v1/control/tasks (Tenant Beta JWT)
        Backend->>Backend: Validate AuthZ, Insert Task B1 (Tenant Beta, QUEUED)
    and User C Action
        UserC->>Discord: `/scan device:pc-c capability:SCAN_FIREWALL`
        Discord->>Backend: POST /api/v1/control/tasks (Tenant Gamma JWT)
        Backend->>Backend: Validate AuthZ, Insert Task C1 (Tenant Gamma, QUEUED)
    end

    Note over Backend, AgentC: Concurrent Task Dispatch & WSS Streams
    par Dispatch to Agent A
        Backend->>AgentA: Push TASK_DISPATCH A1 over WSS Stream (Conn 101)
        AgentA-->>Backend: ACK TASK A1 (Status -> RUNNING)
    and Dispatch to Agent B
        Backend->>AgentB: Push TASK_DISPATCH B1 over WSS Stream (Conn 202)
        AgentB-->>Backend: ACK TASK B1 (Status -> RUNNING)
    and Dispatch to Agent C
        Backend->>AgentC: Push TASK_DISPATCH C1 over WSS Stream (Conn 303)
        AgentC-->>Backend: ACK TASK C1 (Status -> RUNNING)
    end

    Note over AgentA, Backend: Local Module Execution & Parallel Result Ingestion
    par Agent A Execution
        AgentA->>AgentA: Execute `SCAN_NETWORK` locally
        AgentA->>Backend: POST /results (HMAC Signed, Tenant Alpha)
        Backend->>Backend: RLS SET LOCAL 'tenant_alpha' -> Store Finding A1
        Backend-->>Discord: Push Result Embed A1 (Ephemeral to User A)
        Discord-->>UserA: Renders Findings Embed A1
    and Agent B Execution (Simulated Network Retry)
        AgentB->>AgentB: Execute `SCAN_PROCESSES` locally
        AgentB->>Backend: POST /results (Idempotency Key B1) [Network Dropped]
        AgentB->>Backend: Retry POST /results (Idempotency Key B1)
        Backend->>Backend: Deduplicate Key B1 -> Return Cached ACK
        Backend-->>Discord: Push Result Embed B1 (Ephemeral to User B)
        Discord-->>UserB: Renders Findings Embed B1
    and Agent C Execution
        AgentC->>AgentC: Execute `SCAN_FIREWALL` locally
        AgentC->>Backend: POST /results (HMAC Signed, Tenant Gamma)
        Backend->>Backend: RLS SET LOCAL 'tenant_gamma' -> Store Finding C1
        Backend-->>Discord: Push Result Embed C1 (Ephemeral to User C)
        Discord-->>UserC: Renders Findings Embed C1
    end
```

---

## 3. Directional Data & Control Flow

NETRA enforces strict directional isolation. The Discord Control Plane and NETRA Agents NEVER interact directly:

```
[ User in Discord ]
        │
        │ 1. /scan target:laptop-01 capability:SCAN_NETWORK
        ▼
[ NETRA Discord (Repo 2) ]
        │
        │ 2. POST /api/v1/control/tasks (Bearer Tenant JWT)
        ▼
[ NETRA Backend (Repo 1) ]
        │
        │ 3. Validate AuthZ & Queue Task (CREATED -> QUEUED)
        │ 4. Dispatch via WSS (Primary) or Poll Response (Fallback)
        ▼
[ NETRA Agent (Repo 3) ]
        │
        │ 5. Execute Approved Local Scanner Module
        │ 6. Send Signed Payload (HMAC SHA-256)
        ▼
[ NETRA Backend (Repo 1) ]
        │
        │ 7. Validate Signature, Idempotency, Store Findings & Audit
        │ 8. Emit Event Notification
        ▼
[ NETRA Discord (Repo 2) ]
        │
        │ 9. Render Ephemeral Visual Embed Output
        ▼
[ User in Discord ]
```

---

## 4. Explicit Task Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> CREATED: Task requested by control plane
    CREATED --> QUEUED: Validated & inserted into DB queue
    QUEUED --> DELIVERED: Pushed over WebSocket or claimed via poll
    DELIVERED --> ACKNOWLEDGED: Agent confirms task receipt & signature
    ACKNOWLEDGED --> RUNNING: Local scanner subprocess started
    RUNNING --> COMPLETED: Results validated & findings stored
    
    QUEUED --> EXPIRED: TTL exceeded (Agent offline > 24h)
    DELIVERED --> TIMEOUT: Agent failed to ACK within 30s
    RUNNING --> TIMEOUT: Heartbeat missing > 120s
    RUNNING --> FAILED: Local execution error / non-zero exit
    RUNNING --> CANCELLED: Tenant admin sent abort signal
    
    COMPLETED --> [*]
    EXPIRED --> [*]
    TIMEOUT --> [*]
    FAILED --> [*]
    CANCELLED --> [*]
```

### 4.1 State Definitions & Transition Rules

| State | Scope | Description & Trigger Conditions |
| :--- | :--- | :--- |
| `CREATED` | Backend | Task payload validated against schema; permissions verified against requesting tenant. |
| `QUEUED` | Backend DB | Transactionally persisted in PostgreSQL task queue; ready for agent dispatch. |
| `DELIVERED` | Transport | Pushed to active Agent WSS stream or returned in agent poll response. Lease clock starts. |
| `ACKNOWLEDGED`| Transport | Agent sends cryptographic ACK receipt (`X-Execution-ID`). Cancels delivery timeout timer. |
| `RUNNING` | Agent Host | Agent launched pre-compiled scanner module in isolated worker thread/subprocess. |
| `COMPLETED` | Backend DB | Terminal state. Results verified via HMAC, deduplicated, and committed to tenant findings vault. |
| `EXPIRED` | Backend DB | Terminal state. Task remained `QUEUED` past maximum TTL (default: 24 hours). |
| `TIMEOUT` | Backend DB | Terminal state. Agent stopped sending heartbeats or failed to report completion within lease window. |
| `FAILED` | Backend DB | Terminal state. Local scanner returned non-zero exit code or payload validation failed. |
| `CANCELLED` | Backend DB | Terminal state. Task aborted manually by authorized tenant administrator. |

---

## 5. Device Enrollment Architecture & Sequence

```mermaid
sequenceDiagram
    autonumber
    actor User as Tenant Admin / User
    participant Discord as NETRA Discord (Repo 2)
    participant Backend as NETRA Backend (Repo 1)
    participant Agent as NETRA Agent CLI (Repo 3)

    User->>Discord: Type `/panel enroll`
    Discord->>Backend: POST /api/v1/control/enrollment-codes (Tenant JWT)
    Backend-->>Discord: Return short-lived code (e.g. `ABCD-1234`, TTL: 15 min)
    Discord-->>User: Display code ephemerally

    User->>Agent: Run `netra enroll ABCD-1234`
    Agent->>Backend: POST /api/v1/agent/enroll (Code + Host Metadata + Public Key)
    Backend->>Backend: Validate Code, Create Device Record, Generate `device_id` & `device_secret`
    Backend-->>Agent: Return `device_id`, `device_secret`, Tenant Context
    Agent->>Agent: Save credentials encrypted in OS Keyring / `credentials.json`
    Agent-->>Backend: Establish Primary WebSocket Connection (WSS)
    Backend->>Backend: Mark Device Status = `ACTIVE`
```
