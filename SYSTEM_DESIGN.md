# NETRA System Design & Concurrency Architecture

## 1. Multi-User Concurrency Design Principles

NETRA is built from Day 1 to handle high-concurrency multi-tenant operations cleanly across 10+ simultaneous users, hundreds of enrolled agent devices, and concurrent Discord command triggers.

### 1.1 State Isolation Scopes Table

To guarantee that a failure or state corruption in User A's session never impacts User B, state is strictly scoped and decoupled from process-local global variables:

| Scope | Managed Entities | Storage / Lifecycle | Concurrency & Boundary Enforcement |
| :--- | :--- | :--- | :--- |
| **Shared Platform State** | Global DB Schema, Enum Definitions, Audit Vault | PostgreSQL 16 DB | Transaction isolation, Row-Level Security (`app.current_tenant_id`), ACID constraints. |
| **User-Scoped State** | User JWTs, `TenantMembership`, User Session | DB `user_sessions`, JWT payload | Cryptographically signed JWT claims; verified on every API request. |
| **Device-Scoped State** | `DeviceCredential` (Public Key), Active WSS Connection | DB `device_credentials`, In-Memory WSS Connection Registry (`connectionId` mapped to `deviceId` + `tenantId`) | Isolated connection streams; Ed25519 public key in DB; private key strictly in Agent OS protected storage. |
| **Request-Scoped State** | `request_id`, `TenantContext`, Route Params | Node.js Fastify AsyncLocalStorage (`RequestStore`) | Immutable per-request object; created at Gateway entry, destroyed on HTTP/WSS response. |
| **Locking Boundaries** | Task Queue Claims (`QUEUED` $\rightarrow$ `DELIVERED`) | PostgreSQL `FOR UPDATE SKIP LOCKED` | Database-level row locking prevents duplicate task claims under concurrent polling/WSS pushes. |
| **Idempotency Boundaries** | Task Execution Results Ingestion | DB `task_executions` (`executionId` + `X-Idempotency-Key`) | Idempotent transaction guard; retried result submissions return cached ACK without duplicate writes. |
| **Queue Boundaries** | Pending Task Queue | PostgreSQL `tasks` table (`status = QUEUED`) | Multi-tenant compound index `(tenantId, status)`; tasks isolated per tenant slice. |

---

## 2. Three-User Simultaneous Execution Sequence Diagram

The following sequence diagram demonstrates **three independent users (User A, User B, User C)** operating concurrently across different tenants and devices without cross-tenant state leakage or queue blocking, using Ed25519 signature validation and Ephemeral Ack + Direct Message (DM) result delivery:

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
        Backend-->>Discord: Return Task A1 Queue Confirmation
        Discord-->>UserA: Ephemeral Slash Ack ("Task A1 queued for laptop-a...")
    and User B Action
        UserB->>Discord: `/scan device:server-b capability:SCAN_PROCESSES`
        Discord->>Backend: POST /api/v1/control/tasks (Tenant Beta JWT)
        Backend->>Backend: Validate AuthZ, Insert Task B1 (Tenant Beta, QUEUED)
        Backend-->>Discord: Return Task B1 Queue Confirmation
        Discord-->>UserB: Ephemeral Slash Ack ("Task B1 queued for server-b...")
    and User C Action
        UserC->>Discord: `/scan device:pc-c capability:SCAN_FIREWALL`
        Discord->>Backend: POST /api/v1/control/tasks (Tenant Gamma JWT)
        Backend->>Backend: Validate AuthZ, Insert Task C1 (Tenant Gamma, QUEUED)
        Backend-->>Discord: Return Task C1 Queue Confirmation
        Discord-->>UserC: Ephemeral Slash Ack ("Task C1 queued for pc-c...")
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
        AgentA->>Backend: POST /results (Ed25519 Signed, Tenant Alpha)
        Backend->>Backend: Verify Ed25519 Sig -> RLS SET LOCAL 'tenant_alpha' -> Store Finding A1
        Backend-->>Discord: Emit Asynchronous Task Result Event A1
        Discord-->>UserA: Delivers Direct Message (DM) with Visual Finding Embed A1
    and Agent B Execution (Simulated Network Retry)
        AgentB->>AgentB: Execute `SCAN_PROCESSES` locally
        AgentB->>Backend: POST /results (Ed25519 Signed, Idempotency Key B1) [Network Dropped]
        AgentB->>Backend: Retry POST /results (Ed25519 Signed, Idempotency Key B1)
        Backend->>Backend: Deduplicate Key B1 -> Return Cached ACK
        Backend-->>Discord: Emit Asynchronous Task Result Event B1
        Discord-->>UserB: Delivers Direct Message (DM) with Visual Finding Embed B1
    and Agent C Execution
        AgentC->>AgentC: Execute `SCAN_FIREWALL` locally
        AgentC->>Backend: POST /results (Ed25519 Signed, Tenant Gamma)
        Backend->>Backend: Verify Ed25519 Sig -> RLS SET LOCAL 'tenant_gamma' -> Store Finding C1
        Backend-->>Discord: Emit Asynchronous Task Result Event C1
        Discord-->>UserC: Delivers Direct Message (DM) with Visual Finding Embed C1
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
[ NETRA Backend (Repo 1) ] ── (3. Return Ephemeral Confirmation) ──> [ Discord ] ──> (4. Ephemeral Ack) ──> [ User ]
        │
        │ 5. Queue Task (CREATED -> QUEUED)
        │ 6. Dispatch via WSS (Primary) or Poll Response (Fallback)
        ▼
[ NETRA Agent (Repo 3) ]
        │
        │ 7. Execute Approved Local Scanner Module
        │ 8. Send Payload Signed with Local Ed25519 Private Key
        ▼
[ NETRA Backend (Repo 1) ]
        │
        │ 9. Verify Ed25519 Signature against DB Public Key, Check Idempotency, Store Findings & Audit
        │ 10. Emit Async Event Notification to Control Plane
        ▼
[ NETRA Discord (Repo 2) ]
        │
        │ 11. Render & Send Direct Message (DM) Embed Output
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

| State | Scope | Trigger / Transitioning Entity | Valid Previous States | Next Valid States | Description & Behavioral Rules |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `CREATED` | Backend | Discord / REST Control Plane | None (Initial) | `QUEUED` | Payload schema validated via Zod; requesting user identity and tenant scope verified. |
| `QUEUED` | Backend DB | Backend Task Engine | `CREATED` | `DELIVERED`, `EXPIRED` | Persisted in PostgreSQL task queue inside `withTenantContext`. TTL timer starts (24h). |
| `DELIVERED` | Transport | WSS Gateway / REST Poll | `QUEUED` | `ACKNOWLEDGED`, `TIMEOUT` | Dispatched to active agent WSS connection or poll response. 30-second ACK lease timer starts. |
| `ACKNOWLEDGED`| Transport | Agent CLI (Ed25519) | `DELIVERED` | `RUNNING`, `TIMEOUT` | Agent verifies dispatch payload, signs ACK receipt with local private key, and cancels ACK lease timer. |
| `RUNNING` | Agent Host | Agent Worker Engine | `ACKNOWLEDGED` | `COMPLETED`, `FAILED`, `CANCELLED`, `TIMEOUT` | Scanner module initiated in worker thread. 120s heartbeat lease timer active. |
| `COMPLETED` | Backend DB | Agent Results Ingest | `RUNNING` | Terminal | Results signed with Ed25519, verified against DB public key, deduplicated, and stored. Async DM event emitted. |
| `EXPIRED` | Backend DB | Expiration Worker | `QUEUED` | Terminal | Task remained `QUEUED` past maximum TTL (24 hours) without agent claiming. |
| `TIMEOUT` | Backend DB | Lease Sweeper Worker | `DELIVERED`, `RUNNING` | Terminal | Agent failed to ACK within 30s or stopped emitting heartbeats (>120s) during execution. |
| `FAILED` | Backend DB | Agent / Backend Ingest | `RUNNING` | Terminal | Scanner module experienced non-zero exit code or payload validation failure. |
| `CANCELLED` | Backend DB | Tenant Admin | `QUEUED`, `DELIVERED`, `RUNNING` | Terminal | Abort command issued by authorized tenant admin via Discord (`/scan cancel`) or REST API. |

### 4.2 Correlation Identifiers & Idempotency Rules
- **`task_id`**: Identifies the overall user-requested security audit operation across its entire lifecycle.
- **`execution_id`**: Identifies a specific execution attempt by a target device. A retried task execution generates a new `execution_id`.
- **`request_id`**: Identifies individual HTTP/WSS network payload transactions for gateway tracing.
- **`X-Idempotency-Key`**: Formatted as `task_id:execution_id`. The backend checks `TaskExecution` uniqueness `@@unique([taskId, executionId])`. Duplicate result submissions return the cached HTTP 200 ACK without duplicate finding entries or audit logs.

---

## 5. Controlled Task Capability Model Specifications

To completely eliminate Remote Code Execution (RCE) and unauthorized data exfiltration risks, NETRA strictly prohibits arbitrary shell string execution (`exec`/`eval` prohibited) and arbitrary file system browsing. Every capability is pre-compiled into the `netra-agent` package and governed by strict schemas:

### 5.1 Capability 1: `SCAN_NETWORK`
- **Capability ID**: `SCAN_NETWORK`
- **Purpose**: Audits local network interfaces, active IPv4/IPv6 addresses, and listening TCP/UDP ports.
- **Input Parameters**: `{"ports": "1-1024", "include_loopback": false}` (Validated via Pydantic).
- **Output Schema**: `{"interfaces": [...], "open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}]}`.
- **Privilege Requirement**: Standard User (No elevated privileges required).
- **Resource Caps**: Max 30 seconds execution time, CPU cap 25%, RAM cap 100MB.
- **Security Restrictions**: Scans only local machine sockets (`localhost` / local interfaces); no external network port scanning or packet injection.
- **Audit Event**: `CAPABILITY_EXEC_SCAN_NETWORK`
- **Allowed Caller Roles**: `OPERATOR`, `ADMIN`

### 5.2 Capability 2: `SCAN_PROCESSES`
- **Capability ID**: `SCAN_PROCESSES`
- **Purpose**: Inspects running process tree, process ownership, command line parameters, and executable SHA-256 hashes.
- **Input Parameters**: `{"min_cpu_percent": 0.0, "verify_signatures": true}`.
- **Output Schema**: `{"processes": [{"pid": 1234, "name": "svc.exe", "user": "SYSTEM", "sha256": "e3b0c4..."}]}`.
- **Privilege Requirement**: Standard User (Elevated admin required for full system process hashes on Windows).
- **Resource Caps**: Max 30 seconds execution time, CPU cap 30%, RAM cap 150MB.
- **Security Restrictions**: Inspects process metadata only; memory reading (`ptrace`/`OpenProcess`) strictly forbidden.
- **Audit Event**: `CAPABILITY_EXEC_SCAN_PROCESSES`
- **Allowed Caller Roles**: `OPERATOR`, `ADMIN`

### 5.3 Capability 3: `SCAN_CONNECTIONS`
- **Capability ID**: `SCAN_CONNECTIONS`
- **Purpose**: Inspects active established TCP/UDP network connections and remote endpoints.
- **Input Parameters**: `{"state": "ESTABLISHED", "resolve_dns": false}`.
- **Output Schema**: `{"connections": [{"local_addr": "192.168.1.5:49152", "remote_addr": "198.51.100.1:443", "pid": 1234}]}`.
- **Privilege Requirement**: Standard User.
- **Resource Caps**: Max 20 seconds execution time, CPU cap 20%, RAM cap 100MB.
- **Security Restrictions**: Reads OS socket tables only; packet capturing (`libpcap`/`WinPcap`) forbidden.
- **Audit Event**: `CAPABILITY_EXEC_SCAN_CONNECTIONS`
- **Allowed Caller Roles**: `OPERATOR`, `ADMIN`

### 5.4 Capability 4: `SCAN_FIREWALL`
- **Capability ID**: `SCAN_FIREWALL`
- **Purpose**: Audits local OS firewall state (Windows Defender Firewall / `ufw` / `iptables`) and active inbound policies.
- **Input Parameters**: `{"profile": "all"}`.
- **Output Schema**: `{"firewall_enabled": true, "profiles": [{"name": "Public", "inbound_policy": "BLOCK"}]}`.
- **Privilege Requirement**: Standard User (Admin required to list full `netsh` / `iptables` rule dump).
- **Resource Caps**: Max 15 seconds execution time, CPU cap 15%, RAM cap 80MB.
- **Security Restrictions**: Read-only configuration query; firewall rule modification strictly forbidden.
- **Audit Event**: `CAPABILITY_EXEC_SCAN_FIREWALL`
- **Allowed Caller Roles**: `OPERATOR`, `ADMIN`

### 5.5 Capability 5: `SCAN_USERS`
- **Capability ID**: `SCAN_USERS`
- **Purpose**: Audits local OS user accounts, privileged group memberships (Administrators, `sudo`, `wheel`), and stale accounts.
- **Input Parameters**: `{"check_disabled": true}`.
- **Output Schema**: `{"users": [{"username": "admin", "is_active": true, "groups": ["Administrators"]}]}`.
- **Privilege Requirement**: Administrator / Root privilege required for local shadow/SAM security queries.
- **Resource Caps**: Max 15 seconds execution time, CPU cap 15%, RAM cap 80MB.
- **Security Restrictions**: User account metadata query only; password hashes or SAM database contents NEVER returned.
- **Audit Event**: `CAPABILITY_EXEC_SCAN_USERS`
- **Allowed Caller Roles**: `ADMIN`

### 5.6 Capability 6: `SCAN_STARTUP`
- **Capability ID**: `SCAN_STARTUP`
- **Purpose**: Audits autorun entries, startup folder items, Windows Registry Run keys, systemd services, and scheduled tasks.
- **Input Parameters**: `{"include_services": true}`.
- **Output Schema**: `{"startup_items": [{"name": "Updater", "path": "C:\\Program Files\\...", "publisher": "Verified"}]}`.
- **Privilege Requirement**: Standard User.
- **Resource Caps**: Max 20 seconds execution time, CPU cap 20%, RAM cap 100MB.
- **Security Restrictions**: Autorun entry metadata inspection only; registry modification or service control forbidden.
- **Audit Event**: `CAPABILITY_EXEC_SCAN_STARTUP`
- **Allowed Caller Roles**: `OPERATOR`, `ADMIN`

### 5.7 Capability 7: `SCAN_FILE_INTEGRITY`
- **Capability ID**: `SCAN_FILE_INTEGRITY`
- **Purpose**: Validates cryptographic SHA-256 hashes of critical system binaries against pre-defined baseline manifests.
- **Input Parameters**: `{"target_manifest": "system32_core"}` (Selects approved system file path list).
- **Output Schema**: `{"files_scanned": 45, "integrity_violations": [{"path": "C:\\Windows\\System32\\driver.sys", "expected_hash": "a1...", "actual_hash": "b2..."}]}`.
- **Privilege Requirement**: Administrator / Root.
- **Resource Caps**: Max 45 seconds execution time, CPU cap 35%, RAM cap 200MB.
- **Security Restrictions**: Pre-defined file path manifests ONLY. Arbitrary file path parameter input strictly prohibited to prevent arbitrary file reading or privacy breaches.
- **Audit Event**: `CAPABILITY_EXEC_SCAN_FILE_INTEGRITY`
- **Allowed Caller Roles**: `ADMIN`

---

## 6. Device Enrollment Architecture & Sequence

```mermaid
sequenceDiagram
    autonumber
    actor User as Tenant Admin / User
    participant Discord as NETRA Discord (Repo 2)
    participant Backend as NETRA Backend (Repo 1)
    participant Agent as NETRA Agent CLI (Repo 3)

    User->>Discord: Type `/panel enroll`
    Discord->>Backend: POST /api/v1/control/enrollment-codes (Tenant JWT)
    Backend->>Backend: Create `EnrollmentCode` (Single-use, TTL: 15 min, cryptographically random string)
    Backend-->>Discord: Return short-lived code (e.g. `ABCD-1234`)
    Discord-->>User: Display code ephemerally

    User->>Agent: Run `netra enroll ABCD-1234`
    Agent->>Agent: Generate Ed25519 Keypair locally<br>Save Private Key in OS Protected Storage (Windows Credential Manager / Secret Service API / Keychain)
    Agent->>Backend: POST /api/v1/agent/enroll (Code + Host Metadata + Ed25519 Public Key)
    Backend->>Backend: Validate Code (Check TTL & `isRevoked`), Create `Device` record, Register `publicKey` in `DeviceCredential`, Mark `EnrollmentCode` as used (`usedAt`, `usedByDeviceId`)
    Backend-->>Agent: Return `device_id`, Tenant Slug & Scoping Details
    Agent-->>Backend: Establish Primary WebSocket Connection (WSS) signed with Ed25519
    Backend->>Backend: Mark Device Status = `ACTIVE`
```

### 6.1 Enrollment Code Security Rules
- **Single-Use**: Once validated, `usedAt` and `usedByDeviceId` are set. Subsequent enrollment attempts with the same code fail with `409 Conflict`.
- **Short-Lived**: Automatically expires 15 minutes after generation (`expiresAt`). Expired codes fail with `410 Gone`.
- **Non-Guessable**: Generated using CSPRNG (`crypto.randomBytes`) with high entropy (128-bit).
- **Revocable**: Tenant Admin can revoke active enrollment codes immediately via `/panel revoke-code`.

---

## 7. Multi-Tenant Concurrency Matrix & Fault Recovery Architecture

NETRA explicitly handles 10 real-world concurrency scenarios and system restart edge cases to ensure data isolation, idempotency, and zero state corruption:

### 7.1 Scenario 1: 3 Users / Same Tenant
- **Behavior**: User A, User B, User C belong to Tenant Alpha and trigger concurrent scans.
- **Handling**: Tasks are inserted under `tenantId = tenant_alpha`. Database RLS scopes queries to `tenant_alpha`. PostgreSQL row locks (`FOR UPDATE SKIP LOCKED`) prevent workers from double-claiming tasks. All 3 users see results for Tenant Alpha devices, delivered to each requesting user via personal Discord DM.

### 7.2 Scenario 2: 3 Users / Different Tenants
- **Behavior**: User A (Tenant Alpha), User B (Tenant Beta), User C (Tenant Gamma) dispatch tasks simultaneously.
- **Handling**: Strict tenant boundary isolation. Fastify `AsyncLocalStorage` sets `app.current_tenant_id` per request transaction. PostgreSQL RLS prevents cross-tenant data visibility. Zero shared memory or global state leakage between tenants.

### 7.3 Scenario 3: Multiple Devices / Same User
- **Behavior**: User A triggers `/scan` across `device-01`, `device-02`, and `device-03` at the same time.
- **Handling**: Backend creates 3 distinct `Task` records (`task_01`, `task_02`, `task_03`). Each task is dispatched to the corresponding device's WSS stream independently. Results are processed in parallel and delivered as separate DMs to User A.

### 7.4 Scenario 4: Simultaneous Commands Processing
- **Behavior**: Rapid burst of 50 incoming Discord slash commands within 1 second.
- **Handling**: Non-blocking Node.js async event loop handles REST API requests. Fastify processes incoming HTTP tasks asynchronously, validating Zod schemas and inserting `QUEUED` task rows in bulk database transactions.

### 7.5 Scenario 5: Simultaneous Task Results Ingestion
- **Behavior**: 20 agents post scan results (`POST /api/v1/agent/tasks/:id/results`) simultaneously.
- **Handling**: Each result ingestion request runs inside a dedicated database transaction with `SET LOCAL app.current_tenant_id`. Ed25519 signatures are verified in parallel using Node's `crypto.verify`. Findings are bulk-inserted with `ON CONFLICT DO NOTHING` for deduplication.

### 7.6 Scenario 6: Duplicate Deliveries & Network Retries
- **Behavior**: Agent posts scan results, but network drops before receiving HTTP 200 ACK. Agent retries posting identical result payload.
- **Handling**: Ingestion endpoint validates `X-Idempotency-Key: task_id:execution_id`. The compound unique constraint `@@unique([taskId, executionId])` in `TaskExecution` detects duplicate submissions, skips redundant finding writes, and returns the cached HTTP 200 ACK.

### 7.7 Scenario 7: WSS Disconnections & Automatic Reconnection
- **Behavior**: Flaky network disconnects Agent WSS stream during idle state.
- **Handling**: Agent detects WSS closure, initiates exponential backoff reconnect (1s, 2s, 4s, 8s... max 60s) with jitter. During WSS outage, Agent polls fallback REST endpoint `GET /api/v1/agent/tasks` every 15s. Upon WSS reconnect, Agent signs WSS handshake with Ed25519 private key and resumes real-time stream.

### 7.8 Scenario 8: Backend Service Restart & Task Recovery
- **Behavior**: `backend/` service container restarts while tasks are in `QUEUED` or `DELIVERED` state.
- **Handling**: State machine recovery job executes on Backend startup. Tasks stuck in `DELIVERED` without an ACK past lease expiration (30s) are reset to `QUEUED`. Connected agents automatically reconnect WSS streams and re-fetch pending tasks.

### 7.9 Scenario 9: Discord Bot Service Restart
- **Behavior**: `netra-discord` container restarts while user commands are in flight.
- **Handling**: Discord gateway automatically resumes session using session ID and sequence number. The bot re-registers slash commands if needed. Ongoing task execution in Backend is completely unaffected because task state is persisted in PostgreSQL, not in Discord bot memory. When results complete, Backend emits event and Discord bot sends DMs upon reconnect.

### 7.10 Scenario 10: Agent Host Restart & Local Worker Recovery
- **Behavior**: User PC reboots or agent process crashes while task is in `RUNNING` state.
- **Handling**: On agent startup, `netra-agent` daemon checks its encrypted local SQLite queue buffer. Unfinished local scanner executions are marked `FAILED` or retried depending on task parameters. If execution timed out on Backend (>120s missing heartbeat), Backend marks task `TIMEOUT`. Next status check informs the user.

