# NETRA Security Model & Threat Protection Architecture

## 1. Security Principles & Threat Posture

NETRA is designed with a zero-trust architecture. Access to any system resource requires explicit authentication, fine-grained authorization, cryptographic payload verification, and database-enforced tenant context isolation.

---

## 2. Agent Cryptographic Signature Protocol

Every HTTP or WebSocket payload sent by a local NETRA agent to the Backend is cryptographically signed using HMAC-SHA256.

### 2.1 String-to-Sign Construction
```text
string_to_sign = HTTP_METHOD + "\n" +
                 REQUEST_PATH + "\n" +
                 TIMESTAMP + "\n" +
                 NONCE + "\n" +
                 REQUEST_ID + "\n" +
                 SHA256(REQUEST_BODY)

signature = HMAC_SHA256(device_secret, string_to_sign)
```

### 2.2 Transmitted Security Headers
```http
X-NETRA-Device-ID: dev_7f8a9b1c2d3e
X-NETRA-Timestamp: 1776189500
X-NETRA-Nonce: a9f8e7d6-c5b4-4a3b-2a1f-0e9d8c7b6a5f
X-NETRA-Request-ID: req_1122334455667788
X-NETRA-Signature: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 2.3 Replay Protection Pipeline
1. **Timestamp Window Check**: Rejects request if `|CurrentTime - Timestamp| > 300 seconds` (5-minute expiration window).
2. **Nonce Tracking**: Checks in-memory cache / Redis for `(device_id, nonce)` pairs within the 5-minute window; rejects duplicate nonces.
3. **Request ID Tracking**: Verifies `request_id` to prevent network layer replay.
4. **Signature Verification**: Computes HMAC using constant-time string comparison (`crypto.timingSafeEqual`) to prevent timing side-channel attacks.

---

## 3. Credential Lifecycle Management

### 3.1 Device Enrollment
- User triggers 1-time enrollment code via Discord (`/panel enroll`) or Web UI. Code expires in 15 minutes.
- Agent executes `netra enroll <code>`.
- Backend verifies code, generates `device_id`, issues random 256-bit `device_secret`, and registers device under requesting tenant.
- Secret is returned **once** over TLS and stored locally in OS Keyring (Windows Credential Manager / Secret Service API).

### 3.2 Credential Rotation
- Agents automatically request credential rotation every 30 days via `POST /api/v1/agent/credentials/rotate`.
- Old key remains valid for a 1-hour grace window during transition.

### 3.3 Credential Revocation & Deletion
- Tenant Admin can revoke or delete a device via Discord or Backend API.
- Revocation immediately invalidates active WSS sessions and adds `device_id` to an in-memory revocation bloom filter/cache. Any subsequent request fails instantly with `401 Unauthorized`.

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
| **Discord Channel Data Leak** | Findings exposed in public Discord channel | Discord command output embeds rendered strictly as `ephemeral: true` so only the requesting user sees findings. |
| **Replay Attacks** | Old task results re-submitted by attacker | Nonce + timestamp 5-minute window check + `request_id` tracking + `X-Idempotency-Key` deduplication. |
