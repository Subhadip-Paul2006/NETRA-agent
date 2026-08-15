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

### 3.3 Credential Revocation & Deletion
1. Tenant Admin revokes or deletes a device via Discord (`/device revoke`) or Backend API.
2. Backend immediately sets `Device.isPaired = false`, updates `DeviceCredential`, and pushes `device_id` to an in-memory revocation cache / Redis bloom filter.
3. Active WSS stream for `device_id` is immediately terminated by the Backend.
4. Any subsequent HTTP or WSS request signed by the revoked device key fails instantly with `401 Unauthorized`.

---

## 4. Controlled Task Capability Model

To eliminate Remote Code Execution (RCE) risks, NETRA strictly prohibits arbitrary shell string execution (`exec`/`eval` prohibited).

### 4.1 Approved Capability List

| Capability Enum | Description | Authorization Scope |
| :--- | :--- | :--- |
| `SCAN_NETWORK` | Inspects local interfaces, open listening ports, active connections | `OPERATOR`, `ADMIN` |
| `SCAN_PROCESSES` | Analyzes running process tree and executable hashes | `OPERATOR`, `ADMIN` |
| `SCAN_FIREWALL` | Checks local OS firewall rules and active policies | `OPERATOR`, `ADMIN` |
| `SCAN_USERS` | Audits local user accounts, sudoers, and privilege groups | `ADMIN` |
| `SCAN_STARTUP` | Checks autorun entries, services, and scheduled tasks | `OPERATOR`, `ADMIN` |
| `SCAN_FILES` | Audits specific system file permissions against security baselines | `OPERATOR`, `ADMIN` |

---

## 5. Security Vector Mitigations Matrix

| Security Vector | Potential Impact | NETRA Architectural Mitigation |
| :--- | :--- | :--- |
| **Horizontal Privilege Escalation / IDOR** | User A accesses User B's device or findings | Every query scopes by `tenant_id` at application layer AND PostgreSQL Row-Level Security (RLS) layer. |
| **Command Injection** | Arbitrary shell execution on user PC | Pre-compiled Python scanner modules with Pydantic type-validated parameters; no shell invocation. |
| **Stale Session / Token Compromise** | Unauthorized long-term API access | Short 15-minute JWT access tokens, single-use refresh rotation, and instant revocation lists. |
| **Discord Channel Data Leak** | Findings exposed in public Discord channel | 1. Initial slash command response is rendered strictly as `ephemeral: true` (acknowledgement only).<br>2. Full asynchronous scan results and security alerts are delivered directly to the user via **Discord Direct Messages (DMs)**. |
| **Replay Attacks** | Old task results re-submitted by attacker | Nonce + timestamp 5-minute window check + `request_id` tracking + `X-Idempotency-Key` deduplication. |
