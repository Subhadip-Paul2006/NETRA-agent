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
    "parameters": {
      "ports": "1-1024"
    }
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

