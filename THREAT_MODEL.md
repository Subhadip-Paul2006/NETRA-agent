# NETRA Threat Model & Security Analysis

## 1. Executive Security Overview

NETRA operates in high-risk threat environments involving host-level monitoring and remote control plane interfaces. This threat model documents identified threat vectors, attack surfaces, and architectural mitigations.

---

## 2. Threat Matrix & Architectural Mitigations

| Threat Vector | Attack Scenario | Risk Level | Architectural Mitigation |
| :--- | :--- | :--- | :--- |
| **T-01: Stolen Discord Account** | Attacker compromises a user's Discord account and attempts to execute malicious commands on victim's PC. | HIGH | 1. **No Arbitrary Shell Access**: Discord bot cannot send shell commands. Only pre-compiled security capabilities (`SCAN_NETWORK`, `SCAN_PROCESSES`) can be triggered.<br>2. **Tenant Scoping**: Commands execute strictly within the linked tenant's boundary.<br>3. **Host Non-Compromise**: Local agent executes pre-written Python code; attacker cannot write files or execute external binaries. |
| **T-02: Compromised Discord Bot Token** | Attacker extracts `DISCORD_BOT_TOKEN` or compromises `netra-discord` server. | CRITICAL | 1. **Zero DB Access**: Discord bot has no database credentials or direct DB connection.<br>2. **Service Account Scoping**: Bot uses a restricted service token with Backend API authorization checks.<br>3. **Instant Revocation**: Backend can immediately revoke the Discord bot service token without restarting core services or affecting local agents. |
| **T-03: Stolen Agent Credentials** | Attacker attempts to compromise agent identity or extract keying material from a user host machine. | HIGH | 1. **OS Protected Key Storage**: Private key is stored strictly inside OS protected storage (Windows Credential Manager / Secret Service API / macOS Keychain) and is non-exportable over network boundaries.<br>2. **Ed25519 Asymmetric Verification**: Backend verifies signatures using DB-stored public key (`DeviceCredential.publicKey`). Attacker cannot forge signatures without host OS credential store breach.<br>3. **Instant Revocation**: Tenant admin can revoke the device via Backend API, immediately terminating WSS streams and rejecting subsequent payloads with `401 Unauthorized`. |
| **T-04: Malicious Tenant Cross-Access** | User A attempts to read findings or dispatch tasks to User B's device (IDOR / Escalation). | CRITICAL | 1. **Dual Isolation Layer**: Application layer checks `TenantContext` on every route.<br>2. **PostgreSQL RLS**: Database Row-Level Security policies enforce `WHERE tenant_id = current_setting('app.current_tenant_id')` on raw database queries.<br>3. **Generic 404s**: Cross-tenant enumeration attempts return generic `404 Not Found`. |
| **T-05: Replay Attacks** | Attacker intercepts network traffic and re-transmits valid agent payloads or task submissions. | MEDIUM | 1. **5-Minute Expiration Window**: Timestamp skew checked (`|T_req - T_now| <= 300s`).<br>2. **Nonce Tracking**: Nonce cached per device ID; duplicates rejected.<br>3. **Idempotency Deduplication**: `X-Idempotency-Key` prevents duplicate task executions or duplicate finding entries. |
| **T-06: Compromised Discord Bot Code Injection** | Malicious actor injects shell code into Discord slash command parameters. | HIGH | 1. **Strict Parameter Validation**: Command parameters validated via Zod schemas.<br>2. **Controlled Capability Enums**: Backend accepts only approved capability enums (`SCAN_NETWORK`), rejecting arbitrary text strings. |
