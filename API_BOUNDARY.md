# NETRA API Boundary & Contract Specifications

## 1. Protocol Overview & Versioning

- **Base REST URL**: `/api/v1`
- **Base WebSocket URL**: `/api/v1/agent/connect`
- **Protocol**: HTTPS / WSS (TLS 1.3 enforced in production)
- **Data Format**: JSON (`Content-Type: application/json`)
- **Headers**:
  - `X-Request-ID`: Unique tracking ID per payload
  - `X-Idempotency-Key`: `task_id:execution_id` for retry safety
  - `X-NETRA-Signature`: Ed25519 cryptographic signature (hex or base64 encoded)

### 1.1 Standardized Error Envelope & Error Code Registry

All API errors return `Content-Type: application/json` with a consistent error structure:

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters provided",
    "details": { "field": "ports", "issue": "Value out of range 1-65535" },
    "request_id": "req_8f7e6d5c4b3a2a1",
    "timestamp": "2026-08-15T10:00:00.000Z"
  }
}
```

| Error Code | HTTP Status | Description & Operational Condition |
| :--- | :--- | :--- |
| `VALIDATION_ERROR` | `400 Bad Request` | Body or query parameters failed Zod/Pydantic schema validation. |
| `UNAUTHORIZED` | `401 Unauthorized` | Invalid JWT token, expired session, or invalid Ed25519 signature. |
| `FORBIDDEN` | `403 Forbidden` | User/Agent lacks permission role or cross-tenant access attempted. |
| `NOT_FOUND` | `404 Not Found` | Target device, task, finding, or user resource does not exist. |
| `CONFLICT` | `409 Conflict` | Unique constraint violation or single-use enrollment code already used. |
| `RATE_LIMITED` | `429 Too Many Requests` | Request volume exceeded tenant or IP rate limit threshold. |
| `IDEMPOTENCY_CONFLICT` | `409 Conflict` | Conflicting execution parameters submitted for an existing `X-Idempotency-Key`. |
| `DEVICE_REVOKED` | `401 Unauthorized` | Target device key has been revoked by tenant admin. |
| `TASK_EXPIRED` | `410 Gone` | Task requested for cancellation or results submission past TTL expiration. |
| `INTERNAL_ERROR` | `500 Internal Error` | Unexpected backend runtime failure; request ID logged for auditing. |

### 1.2 API Versioning & Backwards Compatibility
- **Versioning Strategy**: Explicit URL prefix `/api/v1/`. Breaking changes require incrementing to `/api/v2/`.
- **Deprecation Policy**: Non-breaking field additions permitted within `v1`. Deprecated endpoints maintain 90-day sunset period before removal.

---

## 2. Agent Connection Protocols

### 2.1 Primary Channel: WebSocket Connection (`WSS`)
- **Endpoint**: `GET /api/v1/agent/connect`
- **Handshake Headers**:
  - `X-NETRA-Device-ID: dev_9a8b7c6d5e4f`
  - `X-NETRA-Timestamp: 1776189500`
  - `X-NETRA-Nonce: non_12345678`
  - `X-NETRA-Signature: <Ed25519_Signature>`
- **Behavior**: Persistent outbound WSS stream. Backend pushes `TASK_DISPATCH` events in real time. Agent responds with `TASK_ACK` and `TASK_RESULT` events over WSS frame.

### 2.2 Fallback Channel: HTTPS REST Polling
- **Endpoint**: `GET /api/v1/agent/tasks` (Polled every 15s when WSS disconnected)
- **Auth**: Ed25519 Signature Headers

---

## 3. Key Endpoint Contracts

### 3.1 `POST /api/v1/agent/enroll` (Agent Device Enrollment)
- **Request Body**:
  ```json
  {
    "enrollment_code": "ABCD-1234",
    "hostname": "workstation-01",
    "os": "windows",
    "architecture": "x86_64",
    "agent_version": "1.0.0",
    "public_key": "MCowBQYDK2VwAyEA7f8a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c="
  }
  ```
- **Response `201 Created`**:
  ```json
  {
    "success": true,
    "data": {
      "device_id": "dev_9a8b7c6d5e4f",
      "tenant_slug": "acme-corp",
      "registered_at": "2026-08-14T22:10:00.000Z"
    }
  }
  ```

### 3.2 `POST /api/v1/control/enrollment-codes` (Generate Enrollment Code)
- **Auth**: Tenant User JWT (Role: `ADMIN` or `OPERATOR`).
- **Response `201 Created`**: `{"success": true, "data": {"code": "ABCD-1234", "expires_at": "2026-08-14T22:15:00.000Z"}}`

### 3.3 `POST /api/v1/control/tasks` (Submit Task Request)
- **Auth**: Tenant User JWT.
- **Request Body**:
  ```json
  {
    "target_device_id": "dev_9a8b7c6d5e4f",
    "capability": "SCAN_NETWORK",
    "parameters": { "ports": "1-1024" }
  }
  ```
- **Response `201 Created`**: `{"success": true, "data": {"task_id": "task_11223344", "status": "QUEUED"}}`

### 3.4 `POST /api/v1/agent/tasks/:id/results` (Submit Execution Results)
- **Auth**: Ed25519 Signature Headers + `X-Idempotency-Key: task_11223344:exec_998877`.
- **Request Body**:
  ```json
  {
    "task_id": "task_11223344",
    "execution_id": "exec_998877",
    "status": "COMPLETED",
    "execution_time_ms": 840,
    "findings": [
      {
        "title": "Open Port Exposing Sensitive Service",
        "category": "NETWORK",
        "severity": "HIGH",
        "fingerprint": "a8f7e6d5c4b3a2a1",
        "details": { "port": 22, "service": "ssh" }
      }
    ]
  }
  ```
- **Response `200 OK`**: `{"success": true, "data": {"acknowledged": true}}`

### 3.5 `POST /api/v1/control/tasks/:id/cancel` (Cancel Pending Task)
- **Auth**: Tenant User JWT (Role: `ADMIN` or `OPERATOR`).
- **Response `200 OK`**: `{"success": true, "data": {"task_id": "task_11223344", "status": "CANCELLED"}}`

### 3.6 `GET /api/v1/devices` (List Enrolled Devices)
- **Auth**: Tenant User JWT.
- **Response `200 OK`**: `{"success": true, "data": [{"id": "dev_9a...", "hostname": "workstation-01", "os": "windows", "is_paired": true}]}`

### 3.7 `DELETE /api/v1/devices/:id` (Revoke Device)
- **Auth**: Tenant User JWT (Role: `ADMIN`).
- **Response `200 OK`**: `{"success": true, "data": {"revoked": true, "device_id": "dev_9a..."}}`

### 3.8 `GET /api/v1/findings` (List Security Findings)
- **Auth**: Tenant User JWT.
- **Response `200 OK`**: `{"success": true, "data": [{"id": "fin_01...", "title": "Open Port", "severity": "HIGH", "fingerprint": "a8f7..."}]}`

### 3.9 `POST /api/v1/control/discord/bind` (Link Discord Identity)
- **Auth**: Tenant User JWT.
- **Request Body**: `{"discord_user_id": "1234567890", "discord_guild_id": "9876543210"}`
- **Response `200 OK`**: `{"success": true, "data": {"bound": true, "discord_user_id": "1234567890"}}`

### 3.10 `GET /api/v1/health` & `GET /api/v1/readiness`
- **Auth**: None (Public healthcheck probes).
- **Response `200 OK`**: `{"status": "UP", "database": "CONNECTED", "redis": "CONNECTED", "timestamp": "2026-08-15T10:00:00.000Z"}`


