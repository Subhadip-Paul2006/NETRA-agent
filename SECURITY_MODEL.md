# NETRA Security Model & Threat Protection Architecture

## 1. Security Principles & Threat Posture

NETRA is designed with a zero-trust architecture. Access to any system resource requires explicit authentication, fine-grained authorization, cryptographic payload verification, and database-enforced tenant context isolation.

---

## 2. Agent Cryptographic Signature Protocol (Ed25519 Asymmetric Identity)

Every HTTP or WebSocket payload sent by a local NETRA agent to the Backend is cryptographically signed using **Ed25519 asymmetric signatures**. Shared-secret HMAC is explicitly rejected to ensure non-repudiation and eliminate shared-secret leakage vulnerabilities.

### 2.1 Key Location & Storage Boundaries
- **Agent Host (Client)**: Private key (`Ed25519 Private Key`) is generated locally on device enrollment and persisted **strictly in OS protected storage**:
  - **Windows**: Windows Credential Manager (`CryptProtectData` / DPAPI via `keyring`).
  - **Linux**: Secret Service API (Freedesktop SecretService via D-Bus).
  - **macOS**: macOS Keychain (`SecItemAdd`).
  *The private key NEVER leaves the local machine host and is NEVER transmitted over the network.*
- **NETRA Backend (Server)**: Public key (`Ed25519 Public Key`) is transmitted once during device enrollment and stored in PostgreSQL (`DeviceCredential.publicKey`).

### 2.2 String-to-Sign Construction
```text
canonical_payload = HTTP_METHOD + "\n" +
                    REQUEST_PATH + "\n" +
                    TIMESTAMP + "\n" +
                    NONCE + "\n" +
                    REQUEST_ID + "\n" +
                    SHA256(REQUEST_BODY)

signature = Ed25519_Sign(private_key, canonical_payload)
```

### 2.3 Transmitted Security Headers
```http
X-NETRA-Device-ID: dev_7f8a9b1c2d3e
X-NETRA-Timestamp: 1776189500
X-NETRA-Nonce: a9f8e7d6-c5b4-4a3b-2a1f-0e9d8c7b6a5f
X-NETRA-Request-ID: req_1122334455667788
X-NETRA-Signature: 6f8b9e... (128-char hex or base64-encoded Ed25519 signature)
```

### 2.4 Signature & Replay Protection Pipeline
1. **Timestamp Window Check**: Rejects request if `|CurrentTime - Timestamp| > 300 seconds` (5-minute expiration window).
2. **Nonce Tracking**: Checks Redis / in-memory cache for `(device_id, nonce)` pairs within the 5-minute window; rejects duplicate nonces.
3. **Request ID Tracking**: Verifies `request_id` to prevent network layer replay.
4. **Ed25519 Public Key Verification**: Fetches stored `publicKey` for `device_id` from PostgreSQL / cache and verifies:
   `Ed25519_Verify(public_key, canonical_payload, signature) == TRUE`.

---

## 3. Credential Lifecycle Management

### 3.1 Device Enrollment
1. User triggers single-use enrollment code via Discord (`/panel enroll`) or Web UI. Code expires in 15 minutes.
2. Agent executes `netra enroll <code>`.
3. Agent generates a fresh **Ed25519 keypair** locally using CSPRNG.
4. Agent stores the **private key** inside OS Protected Storage (Windows Credential Manager / Secret Service API / macOS Keychain).
5. Agent sends `POST /api/v1/agent/enroll` containing enrollment code, device metadata, and the **public key**.
6. Backend verifies enrollment code, creates `Device` record, registers `DeviceCredential` (`publicKey`), and returns `device_id` and tenant scoping details.

### 3.2 Credential Rotation Protocol
1. Agents automatically request credential rotation every 30 days via `POST /api/v1/agent/credentials/rotate`.
2. Agent generates a new Ed25519 keypair locally.
3. Agent signs the rotation request using its **current (active) private key**, transmitting `new_public_key` in the request body.
4. Backend updates PostgreSQL `DeviceCredential` with the new public key. The previous public key remains valid for a **1-hour grace window** to allow in-flight async request completion during transition.

### 3.4 Compromised Device Recovery & Emergency Purge Protocol
1. **Emergency Revocation Trigger**: When an administrator triggers `/device revoke id:<device_id>` or revokes via REST API, the Backend immediately sets `Device.isPaired = false`, updates PostgreSQL `DeviceCredential`, and adds `device_id` to Redis bloom filter revocation list.
2. **Immediate Stream Termination**: Backend actively drops active WSS TCP connection associated with `device_id`.
3. **Pending Task Eviction**: Tasks for `device_id` in `QUEUED`, `DELIVERED`, or `RUNNING` states are transitioned to `CANCELLED` with audit event `DEVICE_REVOCATION_TASK_CANCEL`.
4. **Client Recovery & Re-enrollment**: To re-pair a compromised or re-imaged device, the user must wipe local keyring credentials, generate a fresh `EnrollmentCode` via `/panel enroll`, execute `netra enroll <code>` with a newly generated Ed25519 keypair, and register a new `Device` entity. Old public keys cannot be reused.

---

## 4. Controlled Task Capability Model

To eliminate Remote Code Execution (RCE) and host compromise risks, NETRA strictly prohibits arbitrary shell string execution (`exec`/`eval` prohibited) and unconstrained file browsing.

### 4.1 Approved Capability List & Authorization Scopes

| Capability Enum | Purpose | Privilege Scope | Resource Limits | Audit Event | Authorization Scope |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SCAN_NETWORK` | Inspects local interfaces, listening ports, and socket state | Standard User | 30s / 25% CPU / 100MB RAM | `CAPABILITY_EXEC_SCAN_NETWORK` | `OPERATOR`, `ADMIN` |
| `SCAN_PROCESSES` | Analyzes running process tree and executable SHA-256 hashes | Standard / Admin | 30s / 30% CPU / 150MB RAM | `CAPABILITY_EXEC_SCAN_PROCESSES` | `OPERATOR`, `ADMIN` |
| `SCAN_CONNECTIONS` | Audits active established network sockets & remote IPs | Standard User | 20s / 20% CPU / 100MB RAM | `CAPABILITY_EXEC_SCAN_CONNECTIONS` | `OPERATOR`, `ADMIN` |
| `SCAN_FIREWALL` | Checks local OS firewall status and active rules | Standard / Admin | 15s / 15% CPU / 80MB RAM | `CAPABILITY_EXEC_SCAN_FIREWALL` | `OPERATOR`, `ADMIN` |
| `SCAN_USERS` | Audits local user accounts and privileged group memberships | Admin / Root | 15s / 15% CPU / 80MB RAM | `CAPABILITY_EXEC_SCAN_USERS` | `ADMIN` |
| `SCAN_STARTUP` | Checks autorun entries, services, and scheduled tasks | Standard User | 20s / 20% CPU / 100MB RAM | `CAPABILITY_EXEC_SCAN_STARTUP` | `OPERATOR`, `ADMIN` |
| `SCAN_FILE_INTEGRITY` | Audits SHA-256 hashes of system binaries against manifests | Admin / Root | 45s / 35% CPU / 200MB RAM | `CAPABILITY_EXEC_SCAN_FILE_INTEGRITY` | `ADMIN` |

---

## 5. Structured Threat Matrix & Defense-in-Depth Mitigations (T-01 to T-12)

| Threat ID & Title | Attack Surface | Impact Level | Architectural Prevention | Operational Detection | Incident Response |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **T-01: Stolen Discord Account** | Discord Slash Command Interface | **HIGH** | Slash commands execute only pre-approved capabilities (`SCAN_NETWORK`); no shell access. Ephemeral slash acks + private DM delivery prevents data exposure. | Audit log tracks unusual Discord command volume or unexpected user IDs. | Revoke Discord binding via `/unlink` or Backend API; invalidate active `DiscordSession`. |
| **T-02: Compromised Discord Bot Token** | Discord Bot Gateway Service | **CRITICAL** | Bot service has ZERO database credentials and ZERO direct DB access. Operates strictly as a scoped Backend REST client. | Backend API monitoring flags anomalous API call patterns from Discord bot IP. | Immediately revoke `DISCORD_SERVICE_SECRET` in Backend environment without restarting core DB/agent nodes. |
| **T-03: Stolen Agent Private Key** | Client Host Machine | **HIGH** | Agent private key stored in OS protected storage (Windows DPAPI / Secret Service API / Keychain); non-exportable over network. Backend verifies Ed25519 sigs against DB public key. | Signature verification failure alerts; unexpected IP address changes for `device_id`. | Admin revokes device (`/device revoke`). Backend revokes `publicKey` and drops active WSS streams immediately. |
| **T-04: Malicious Tenant Cross-Access (IDOR)** | REST API Endpoints | **CRITICAL** | Dual-layer isolation: Fastify `TenantContext` middleware AND PostgreSQL Row-Level Security (`SET LOCAL app.current_tenant_id`). | Automated RLS integration tests; audit log alerts on 404/403 cross-tenant queries. | Offending JWT token immediately revoked; IP address added to API Gateway blocklist. |
| **T-05: Replay Attacks** | WSS & REST Network Stream | **MEDIUM** | 5-minute timestamp window (`\|T_req - T_now\| <= 300s`) + Redis Nonce cache tracking + `request_id` + `X-Idempotency-Key` deduplication. | Redis nonce collision log alerts; HTTP 409 `IDEMPOTENCY_CONFLICT` metric spikes. | Drop replayed packets automatically; temporarily ban IP if high-frequency replay detected. |
| **T-06: Malicious Capability Parameters** | Slash Command Parameters | **HIGH** | Strict parameter validation via Zod (Backend) & Pydantic (Agent). Capability parameters use strict enums; arbitrary path/shell input rejected. | Validation failure metrics (`VALIDATION_ERROR` counter spike). | Reject invalid payload at REST Gateway before task queue insertion. |
| **T-07: Enrollment Code Theft** | Discord Channel / Command Output | **HIGH** | Enrollment codes rendered strictly as `ephemeral: true`, single-use (`usedAt`), short-lived (15-min TTL), 128-bit CSPRNG generated. | Multi-use attempt alerts; expired code submission metrics. | Admin revokes enrollment code immediately via `/panel revoke-code`. |
| **T-08: Backend Infrastructure Compromise** | Central Application Server | **CRITICAL** | Database runtime role (`netra_app_user`) lacks `BYPASSRLS`. Database secrets stored in vault/KMS. Agent private keys NEVER stored on backend. | Intrusion detection (Falco / Datadog), container drift detection, audit log checksum gaps. | Isolate container, rotate DB credentials, redeploy clean container images from immutable registry. |
| **T-09: Supply-Chain / Dependency Compromise** | npm / PyPI Package Dependencies | **CRITICAL** | Automated CI dependency auditing (`npm audit` / `Safety` / Snyk), lockfile pinning (`package-lock.json` / `hatch.toml`), container Trivy SAST scanning. | CI pipeline dependency vulnerability audit failures; Trivy security scan alerts. | Block PR merge; bump dependency version; release hotfix patch across affected repo. |
| **T-10: Denial of Service (DoS / API Abuse)** | REST / WSS Gateway Endpoints | **MEDIUM** | Fastify rate-limiting per IP and per tenant (`100 req/min`), maximum WSS frame size limits (1MB), bulk request throttling. | Prometheus `netra_rate_limited_total` metric spikes; HTTP 429 response monitoring. | Automated API Gateway rate-limit block; Cloudflare / WAF IP rate limiting. |
| **T-11: Malicious / Misconfigured Agent** | Local Client Host | **HIGH** | Agent processes pre-compiled capabilities in isolated worker threads with strict timeouts (max 45s) and CPU/RAM resource limits. | Agent heartbeat timeout metrics (`netra_tasks_failed_total` counter). | Backend marks task `FAILED` or `TIMEOUT`, logs audit event, and notifies admin. |
| **T-12: Compromised User PC** | User Client Machine | **HIGH** | Agent operates with minimal privileges required for capability scope. Non-elevated capabilities require standard user permissions only. | Host-based intrusion detection; unexpected host configuration drift. | User wipes local agent keyring and re-enrolls device with fresh Ed25519 keypair. |

---

## 6. Role-Based Access Control (RBAC) & Authorization Scope

NETRA enforces 3 fine-grained application roles defined in `Role` enum:

| Role | Permitted Capabilities & System Operations | Target User Base |
| :--- | :--- | :--- |
| `ADMIN` | All capabilities (`SCAN_NETWORK`, `SCAN_PROCESSES`, `SCAN_CONNECTIONS`, `SCAN_FIREWALL`, `SCAN_USERS`, `SCAN_STARTUP`, `SCAN_FILE_INTEGRITY`), Device enrollment code generation, Device revocation/deletion, Member role management, Tenant configuration. | Security Team Leads, Systems Administrators |
| `OPERATOR` | Standard capabilities (`SCAN_NETWORK`, `SCAN_PROCESSES`, `SCAN_CONNECTIONS`, `SCAN_FIREWALL`, `SCAN_STARTUP`), View devices, View findings, View scan status. | SOC Analysts, Security Operators |
| `AUDITOR` | Read-only access: View devices, View findings, View audit logs. Execution of security capabilities strictly forbidden. | Compliance Auditors, Executive Stakeholders |

---

## 7. Secrets Management & Data Exfiltration Prevention

1. **Zero Secret Persistence in Repos**: Plaintext passwords, private keys, bot tokens, and database URLs MUST NEVER exist in source code or documentation examples.
2. **Environment Variable Security**: Injected dynamically via platform secrets managers (AWS Secrets Manager / GCP Secret Manager / GitHub Environments).
3. **Data Masking in Telemetry**: Logging framework automatically redacts `password`, `passwordHash`, `token`, `jwt`, `privateKey`, `private_key`, `DISCORD_BOT_TOKEN`, `authorization`, `signature`, and raw evidence payloads before serialization.

