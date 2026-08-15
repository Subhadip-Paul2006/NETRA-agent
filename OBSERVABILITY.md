# NETRA Observability & Telemetry Architecture

## 1. Structured Logging Standard

All NETRA services (`backend`, `discord`, `agent`, `shared`) emit structured JSON logs to standard output (`stdout`) to enable centralized log ingestion (Elasticsearch, Datadog, CloudWatch).

### 1.1 JSON Log Schema Blueprint
```json
{
  "timestamp": "2026-08-15T12:00:00.000Z",
  "level": "info",
  "service": "backend",
  "environment": "production",
  "context": {
    "tenant_id": "ten_01h23456789",
    "user_id": "usr_987654321",
    "device_id": "dev_9a8b7c6d5e4f",
    "task_id": "task_11223344",
    "execution_id": "exec_998877",
    "request_id": "req_8f7e6d5c4b3a2a1"
  },
  "message": "Task completed successfully by agent",
  "module": "task-engine",
  "duration_ms": 840
}
```

---

## 2. Distributed Correlation & Tracing

To trace an end-to-end operation from a Discord slash command trigger down to a local agent execution and back, four mandatory correlation identifiers are passed across all service boundaries:

```
[ Discord Command ] ──( request_id )──> [ Backend API ]
                                            │
                                       ( task_id )
                                       ( device_id )
                                            │
                                            ▼
[ Agent Execution ] ──( execution_id )──> [ Result Ingest ] ──> [ Discord Embed ]
```

- **`request_id`**: Generated per HTTP/WSS payload to trace API gateway routing.
- **`task_id`**: Identifies the overall user-requested security task.
- **`device_id`**: Identifies the target local NETRA agent machine.
- **`execution_id`**: Unique ID generated for each execution attempt of a task.

---

## 3. Operational Metrics

NETRA services expose Prometheus-compatible operational metrics for real-time monitoring and alerting.

### 3.1 Metric Definitions

| Metric Name | Type | Description & Labels |
| :--- | :--- | :--- |
| `netra_active_agents` | Gauge | Count of enrolled active agents (`tenant_id`, `os`). |
| `netra_connected_agents_wss` | Gauge | Count of active persistent WebSocket connections (`tenant_id`). |
| `netra_tasks_queued` | Gauge | Count of tasks currently in `QUEUED` state waiting for execution. |
| `netra_tasks_completed_total` | Counter | Total completed tasks (`tenant_id`, `capability`, `status`). |
| `netra_tasks_failed_total` | Counter | Total failed/timed-out tasks (`tenant_id`, `reason`). |
| `netra_scan_duration_seconds` | Histogram | Execution duration of security scans (`capability`). |
| `netra_findings_generated_total` | Counter | Total security findings generated (`tenant_id`, `severity`, `category`). |
| `netra_discord_commands_total` | Counter | Total slash commands executed in Discord (`command`, `status`). |

---

## 4. Secret Sanitization & Data Masking Rules

The logging framework strictly enforces automated redaction of sensitive fields prior to serialization:
- **Redacted Fields**: `password`, `passwordHash`, `token`, `jwt`, `privateKey`, `private_key`, `DISCORD_BOT_TOKEN`, `authorization`, `signature`, `cookie`.
- **Masking Mechanism**: Regex patterns replace sensitive keys with `"[REDACTED]"`.
