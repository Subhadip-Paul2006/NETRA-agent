# NETRA Threat Model & Security Analysis

## 1. Executive Security Overview

NETRA operates in high-risk threat environments involving host-level monitoring and remote control plane interfaces. This threat model documents identified threat vectors, attack surfaces, and architectural mitigations.

---

## 2. Threat Matrix & Architectural Mitigations

| Threat ID & Vector | Attack Surface | Impact Level | Architectural Mitigation & Security Controls |
| :--- | :--- | :--- | :--- |
| **T-01: Stolen Discord Account** | Discord Slash Commands | **HIGH** | Commands trigger pre-approved capabilities only (`SCAN_NETWORK`). Ephemeral slash acks + Direct Message (DM) result delivery prevents channel leaks. Account link bound to backend identity. |
| **T-02: Stolen Discord Bot Token** | Discord Bot Gateway | **CRITICAL** | Discord bot has ZERO database credentials and ZERO direct DB access. Operates strictly as an API client to Backend. Service token can be revoked instantly. |
| **T-03: Stolen Agent Private Key** | Client Host Machine | **HIGH** | Private key stored in OS protected storage (Windows DPAPI / Secret Service / Keychain); non-exportable. Ed25519 signatures verified against DB `publicKey`. Instant key revocation drops WSS streams. |
| **T-04: Malicious Tenant Cross-Access (IDOR)** | REST API Endpoints | **CRITICAL** | Dual-layer isolation: Application Fastify `TenantContext` AND PostgreSQL Row-Level Security (`SET LOCAL app.current_tenant_id`). RLS policies return 0 rows on un-scoped queries. |
| **T-05: Replay Attacks** | Network Stream | **MEDIUM** | 5-minute timestamp window (`\|T_req - T_now\| <= 300s`) + Redis Nonce cache tracking + `request_id` + `X-Idempotency-Key` deduplication. |
| **T-06: Malicious Capability Parameters** | Slash Command Input | **HIGH** | Strict parameter validation via Zod (Backend) & Pydantic (Agent). Capability parameters use strict enums; arbitrary path/shell input rejected. |
| **T-07: Enrollment Code Theft** | Discord Output | **HIGH** | Enrollment codes rendered strictly as `ephemeral: true`, single-use (`usedAt`), short-lived (15-min TTL), 128-bit CSPRNG generated. Single-use code invalidation. |
| **T-08: Backend Infrastructure Compromise** | Central Application Server | **CRITICAL** | Database runtime role (`netra_app_user`) lacks `BYPASSRLS`. Secrets stored in vault/KMS. Client private keys NEVER exist on server. |
| **T-09: Supply-Chain / Dependency Compromise** | Package Dependencies | **CRITICAL** | Automated CI dependency auditing (`npm audit` / `Safety` / Snyk), lockfile pinning (`package-lock.json` / `hatch.toml`), container Trivy SAST scanning. |
| **T-10: Denial of Service (DoS / API Abuse)** | REST / WSS Gateway | **MEDIUM** | Fastify rate-limiting per IP and per tenant (`100 req/min`), maximum WSS frame size limits (1MB), bulk request throttling. |
| **T-11: Malicious / Misconfigured Agent** | Local Client Host | **HIGH** | Agent processes pre-compiled capabilities in isolated worker threads with strict timeouts (max 45s) and CPU/RAM resource limits. |
| **T-12: Compromised User PC** | User Client Machine | **HIGH** | Agent operates with minimal privileges required for capability scope. Non-elevated capabilities require standard user permissions only. User can wipe keyring and re-enroll with fresh keypair. |

