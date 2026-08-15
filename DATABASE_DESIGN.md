# NETRA Database Design & PostgreSQL RLS Strategy

## 1. PostgreSQL Engine & Schema Governance

NETRA uses **PostgreSQL 16** as its core relational data store, **SQLAlchemy 2.0 (AsyncPG)** for type-safe async query building, and **Alembic** for schema migrations.

- **Schema Single Source of Truth**: SQLAlchemy entity models live in `backend/src/models/` and Alembic migrations reside strictly in `backend/alembic/`.
- **No Direct DB Access in Services 2 & 3**: Neither `discord/` nor `agent/` connect to PostgreSQL directly.

---

## 2. Multi-Tenant Hierarchy & Identity Cardinality

### 2.1 Identity & Scoping Mapping Architecture

NETRA enforces explicit cardinality across Discord identities, central user identities, tenant memberships, and devices:

```
Discord Account (discordUserId)
      │ (1-to-1 Mapping)
      ▼
NETRA User Identity (User)
      │ (1-to-Many Memberships)
      ├── TenantMembership (Tenant Alpha, Role: ADMIN)
      ├── TenantMembership (Tenant Beta, Role: OPERATOR)
      └── TenantMembership (Tenant Gamma, Role: AUDITOR)
```

1. **1 Discord Identity $\leftrightarrow$ 1 NETRA User Identity**: A Discord account maps to exactly one central `User` identity globally (`User.discord_user_id` unique).
2. **1 NETRA User $\leftrightarrow$ Many `TenantMembership` Records**: A user can belong to multiple tenants with role-based permissions (`TenantMembership` `unique(tenant_id, user_id)`).
3. **1 Tenant $\leftrightarrow$ Many Users**: A tenant maintains multiple user members (`Tenant.memberships`).

---

### 2.2 Entity Relationship Diagram

```
                                 +-------------------+
                                 |      Tenant       |
                                 +-------------------+
             /             /            |            \             \
            v             v             v             v             v
  +------------------+ +--------+ +-----------+ +------------+ +---------------+
  | TenantMembership | | Device | |  Finding  | | Discord    | |  AuditEvent   |
  +------------------+ +--------+ +-----------+ | Binding    | +---------------+
           |                |           |       +------------+
           v                v           v             |
       +------+   +------------------+ +------------+ v
       | User |   | DeviceCredential | |  Finding   | +----------------+
       +------+   +------------------+ | Evidence   | | DiscordSession |
           |                |          +------------+ +----------------+
           v                v                 ^
  +----------------+    +--------+            |
  | EnrollmentCode |    |  Task  |------------+
  +----------------+    +--------+
                            |
                            v
                    +---------------+
                    | TaskExecution |
                    +---------------+
```

---

## 3. Deep Technical RLS Architecture & Async Session Context

### 3.1 SQLAlchemy Async Session Pattern (`with_tenant_context`)
SQLAlchemy AsyncSession does not automatically attach session configuration variables to raw queries. NETRA enforces RLS by wrapping all tenant-scoped database interactions inside an async context manager executing `SET LOCAL`:

```python
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import AsyncSession
import sqlalchemy

@asynccontextmanager
async def with_tenant_context(tenant_id: str, session: AsyncSession):
    if not tenant_id or not tenant_id.strip():
        raise ValueError(
            "SECURITY_FATAL: MissingTenantContextException - Cannot query database without resolved tenant_id"
        )

    # 1. Establish transaction-scoped GUC variable (SET LOCAL)
    await session.execute(
        sqlalchemy.text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
        {"tenant_id": tenant_id}
    )
    try:
        yield session
    finally:
        pass
```

### 3.2 Key RLS Technical Attributes & Operational Security Rules

#### A. Transaction Scope (`SET LOCAL`)
The `true` parameter in `set_config('app.current_tenant_id', val, true)` (equivalent to `SET LOCAL`) binds the variable strictly to the lifetime of the current database transaction. When the transaction commits or rolls back, PostgreSQL automatically clears the variable.

#### B. Connection Pooling & PgBouncer Compatibility
NETRA supports PgBouncer operating in **transaction pool mode**. Because `SET LOCAL` is bound to transaction boundaries and cleared upon transaction end, connections returned to the pool never retain dirty tenant context state.

#### C. Deterministic Failure Behavior on Missing Context
Every PostgreSQL table enforcing RLS defines policies using `current_setting('app.current_tenant_id', true)`:

```sql
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON findings
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true));
```
- **Missing Context Handling**: The second argument `true` ensures that if `app.current_tenant_id` is missing or uninitialized, `current_setting` returns `NULL`.
- **Zero-Data Leak Guarantee**: In SQL, `tenant_id = NULL` evaluates to `FALSE` for all rows. Therefore, if a developer mistakenly executes a query without initializing tenant context, PostgreSQL returns **0 rows** instead of leaking multi-tenant data!

#### D. Defense-in-Depth: Application AuthZ + Database RLS
PostgreSQL RLS acts as a secondary defense layer. Application middleware MUST STILL validate JWT tenant claims and resource ownership before dispatching queries. RLS guarantees that even if a developer omits a `WHERE tenant_id = ?` clause in Python, cross-tenant data access is physically impossible at the database engine layer.

#### E. Background Worker Tenant Context Resolution
Async background queue processors (e.g. task expiration sweepers, metric aggregators) MUST NOT run un-scoped global queries. Every worker task fetches the target `tenant_id` from the queue payload and wraps execution inside `async with with_tenant_context(tenant_id, session):`.

#### F. Database User Roles & Migration Strategy
- **Migration Role (`netra_migration_runner`)**: Granted `SUPERUSER` or `BYPASSRLS` privileges. Used strictly during deployment pipelines (`alembic upgrade head`) to alter DDL and execute schema migrations.
- **Application Runtime Role (`netra_app_user`)**: Restricted non-superuser role **WITHOUT** `BYPASSRLS` privileges. Used by the Python backend at runtime. RLS policies are strictly enforced on every query.

#### G. Automated Integration Test Strategy for RLS
The CI/CD test suite contains dedicated Pytest integration tests asserting zero data leakage when querying without tenant context.

---

## 4. Finding vs. FindingEvidence Model Semantics

To prevent developer confusion between vulnerability definitions and scan execution attempts, NETRA strictly separates vulnerability identity from individual scan observations:

### 4.1 Concept Definitions
- **`Finding`**: Represents a normalized, ongoing security condition / vulnerability definition scoped to a tenant (`unique(tenant_id, fingerprint)`). The `fingerprint` is a stable cryptographic SHA-256 hash derived from the vulnerability identity (e.g. `SHA-256(category + normalized_title + component)`).
- **`FindingEvidence`**: Represents an individual scan observation/occurrence of that condition on a specific target device during a specific execution attempt (`finding_id`, `device_id`, `task_id`, `execution_id`, `details`, `observed_at`).

### 4.2 Structural Relationship Tree
```
Finding (fingerprint = stable vulnerability identity per tenant)
     │
     ├── FindingEvidence (Device A, Execution 1, Timestamp T1)
     ├── FindingEvidence (Device A, Execution 2, Timestamp T2)
     ├── FindingEvidence (Device B, Execution 3, Timestamp T3)
     └── FindingEvidence (Device C, Execution 4, Timestamp T4)
```

### 4.3 Deduplication & State Transition Rules
1. **`first_seen_at`**: Timestamp recorded when the master `Finding` record is first created for a fingerprint within a tenant.
2. **`last_seen_at`**: Updated automatically whenever a new `FindingEvidence` observation arrives matching this fingerprint.
3. **`severity`**: Current vulnerability severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). If new evidence indicates an escalated severity, `severity` is updated on the master `Finding` and an audit log event (`FINDING_SEVERITY_ESCALATED`) is created.
4. **`evidence` Insertion**: Every scan attempt observing a vulnerability creates a new `FindingEvidence` record linking `device_id`, `task_id`, `execution_id`, and raw JSON details without modifying the master `Finding` identity.
5. **`status` Transitions**:
   - `OPEN`: Set on initial finding discovery.
   - `RESOLVED`: Set when a subsequent scan execution on all affected devices confirms the vulnerability condition no longer exists.
   - `REOPENED`: Set automatically if a previously `RESOLVED` finding is observed again in a new scan execution.
   - `MUTED`: Set manually by a tenant administrator to suppress alert notifications.

---

## 5. SQLAlchemy 2.0 Typed Declarative Blueprint (`backend/src/netra_backend/models/`)

```python
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from sqlalchemy import String, ForeignKey, JSON, Enum as SQLEnum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    pass

class Role(str, Enum):
    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    AUDITOR = "AUDITOR"

class TaskStatus(str, Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    DELIVERED = "DELIVERED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    EXPIRED = "EXPIRED"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class FindingStatus(str, Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    MUTED = "MUTED"

class Tenant(SQLModel, table=True):
    __tablename__ = "tenants"

    id: str = Field(default=None, primary_key=True)
    name: str = Field(sa_column=Column(String(100), nullable=False))
    slug: str = Field(sa_column=Column(String(100), unique=True, nullable=False, index=True))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class User(SQLModel, table=True):
    __tablename__ = "users"

    id: str = Field(default=None, primary_key=True)
    email: str = Field(sa_column=Column(String(255), unique=True, nullable=False, index=True))
    password_hash: str = Field(sa_column=Column(String(255), nullable=False))
    discord_user_id: Optional[str] = Field(sa_column=Column(String(64), unique=True, nullable=True, index=True))
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class TenantMembership(SQLModel, table=True):
    __tablename__ = "tenant_memberships"

    id: str = Field(default=None, primary_key=True)
    tenant_id: str = Field(foreign_key="tenants.id", index=True, nullable=False)
    user_id: str = Field(foreign_key="users.id", index=True, nullable=False)
    role: Role = Field(default=Role.OPERATOR)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserSession(SQLModel, table=True):
    __tablename__ = "user_sessions"

    id: str = Field(default=None, primary_key=True)
    user_id: str = Field(foreign_key="users.id", index=True, nullable=False)
    refresh_token: str = Field(sa_column=Column(String(512), unique=True, nullable=False, index=True))
    ip_address: str = Field(sa_column=Column(String(45), nullable=False))
    user_agent: str = Field(sa_column=Column(String(255), nullable=False))
    expires_at: datetime = Field(nullable=False)
    revoked_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Device(SQLModel, table=True):
    __tablename__ = "devices"

    id: str = Field(default=None, primary_key=True)
    tenant_id: str = Field(foreign_key="tenants.id", index=True, nullable=False)
    hostname: str = Field(sa_column=Column(String(255), nullable=False))
    os: str = Field(sa_column=Column(String(50), nullable=False))
    architecture: str = Field(sa_column=Column(String(50), nullable=False))
    agent_version: str = Field(sa_column=Column(String(20), nullable=False))
    is_paired: bool = Field(default=True)
    last_heartbeat_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class DeviceCredential(SQLModel, table=True):
    __tablename__ = "device_credentials"

    id: str = Field(default=None, primary_key=True)
    device_id: str = Field(foreign_key="devices.id", unique=True, index=True, nullable=False)
    public_key: str = Field(sa_column=Column(String(512), nullable=False))
    algorithm: str = Field(default="Ed25519")
    rotation_count: int = Field(default=0)
    last_rotated_at: datetime = Field(default_factory=datetime.utcnow)

class AgentSession(SQLModel, table=True):
    __tablename__ = "agent_sessions"

    id: str = Field(default=None, primary_key=True)
    device_id: str = Field(foreign_key="devices.id", index=True, nullable=False)
    connection_id: str = Field(sa_column=Column(String(128), unique=True, nullable=False, index=True))
    ip_address: str = Field(sa_column=Column(String(45), nullable=False))
    connected_at: datetime = Field(default_factory=datetime.utcnow)
    disconnected_at: Optional[datetime] = Field(default=None)

class Task(SQLModel, table=True):
    __tablename__ = "tasks"

    id: str = Field(default=None, primary_key=True)
    tenant_id: str = Field(foreign_key="tenants.id", index=True, nullable=False)
    device_id: str = Field(foreign_key="devices.id", index=True, nullable=False)
    capability: str = Field(sa_column=Column(String(100), nullable=False))
    parameters: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    status: TaskStatus = Field(default=TaskStatus.CREATED)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class TaskExecution(SQLModel, table=True):
    __tablename__ = "task_executions"

    id: str = Field(default=None, primary_key=True)
    task_id: str = Field(foreign_key="tasks.id", index=True, nullable=False)
    tenant_id: str = Field(foreign_key="tenants.id", index=True, nullable=False)
    execution_id: str = Field(sa_column=Column(String(128), unique=True, nullable=False, index=True))
    request_id: str = Field(sa_column=Column(String(128), nullable=False))
    status: TaskStatus = Field(nullable=False)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = Field(default=None)
    error_message: Optional[str] = Field(default=None)

class Finding(SQLModel, table=True):
    __tablename__ = "findings"

    id: str = Field(default=None, primary_key=True)
    tenant_id: str = Field(foreign_key="tenants.id", index=True, nullable=False)
    title: str = Field(sa_column=Column(String(255), nullable=False))
    category: str = Field(sa_column=Column(String(100), nullable=False))
    severity: Severity = Field(nullable=False)
    status: FindingStatus = Field(default=FindingStatus.OPEN)
    fingerprint: str = Field(sa_column=Column(String(64), nullable=False, index=True))
    first_seen_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen_at: datetime = Field(default_factory=datetime.utcnow)

class FindingEvidence(SQLModel, table=True):
    __tablename__ = "finding_evidences"

    id: str = Field(default=None, primary_key=True)
    tenant_id: str = Field(foreign_key="tenants.id", index=True, nullable=False)
    finding_id: str = Field(foreign_key="findings.id", index=True, nullable=False)
    device_id: str = Field(foreign_key="devices.id", index=True, nullable=False)
    task_id: str = Field(foreign_key="tasks.id", index=True, nullable=False)
    execution_id: str = Field(foreign_key="task_executions.execution_id", index=True, nullable=False)
    details: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    observed_at: datetime = Field(default_factory=datetime.utcnow)

class DiscordBinding(SQLModel, table=True):
    __tablename__ = "discord_bindings"

    id: str = Field(default=None, primary_key=True)
    tenant_id: str = Field(foreign_key="tenants.id", index=True, nullable=False)
    user_id: str = Field(foreign_key="users.id", index=True, nullable=False)
    discord_user_id: str = Field(sa_column=Column(String(64), unique=True, nullable=False, index=True))
    discord_guild_id: Optional[str] = Field(sa_column=Column(String(64), nullable=True))
    created_at: datetime = Field(default_factory=datetime.utcnow)

class DiscordSession(SQLModel, table=True):
    __tablename__ = "discord_sessions"

    id: str = Field(default=None, primary_key=True)
    tenant_id: str = Field(foreign_key="tenants.id", index=True, nullable=False)
    user_id: str = Field(foreign_key="users.id", index=True, nullable=False)
    discord_user_id: str = Field(sa_column=Column(String(64), nullable=False))
    session_token: str = Field(sa_column=Column(String(512), unique=True, nullable=False, index=True))
    expires_at: datetime = Field(nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AuditEvent(SQLModel, table=True):
    __tablename__ = "audit_events"

    id: str = Field(default=None, primary_key=True)
    tenant_id: str = Field(foreign_key="tenants.id", index=True, nullable=False)
    actor_id: str = Field(sa_column=Column(String(100), nullable=False))
    actor_type: str = Field(sa_column=Column(String(20), nullable=False))
    event: str = Field(sa_column=Column(String(100), nullable=False))
    details: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    ip_address: Optional[str] = Field(sa_column=Column(String(45), nullable=True))
    created_at: datetime = Field(default_factory=datetime.utcnow)

class EnrollmentCode(SQLModel, table=True):
    __tablename__ = "enrollment_codes"

    id: str = Field(default=None, primary_key=True)
    tenant_id: str = Field(foreign_key="tenants.id", index=True, nullable=False)
    created_by_id: str = Field(foreign_key="users.id", nullable=False)
    code: str = Field(sa_column=Column(String(32), unique=True, nullable=False, index=True))
    expires_at: datetime = Field(nullable=False)
    used_at: Optional[datetime] = Field(default=None)
    used_by_device_id: Optional[str] = Field(default=None)
    is_revoked: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class NonceCache(SQLModel, table=True):
    __tablename__ = "nonce_caches"

    id: str = Field(default=None, primary_key=True)
    device_id: str = Field(sa_column=Column(String(128), nullable=False, index=True))
    nonce: str = Field(sa_column=Column(String(128), nullable=False))
    expires_at: datetime = Field(nullable=False, index=True)
```


---

## 6. Formal DATABASE_INVARIANTS

The NETRA relational store strictly enforces 7 non-negotiable database invariants. Any application code, migration script, or manual database query that violates these rules is treated as a fatal security/integrity bug.

### INVARIANT 1: Tenant Context Isolation Guarantee
Every non-system entity table (`TenantMembership`, `Device`, `Task`, `TaskExecution`, `Finding`, `FindingEvidence`, `DiscordBinding`, `DiscordSession`, `AuditEvent`, `EnrollmentCode`) MUST contain a mandatory, non-null `tenantId String` column with a foreign key constraint pointing to `tenants(id)` ON DELETE CASCADE, and MUST participate in PostgreSQL Row-Level Security (RLS) policies.

### INVARIANT 2: Hierarchical Cascading Deletion Safety
Deleting a `Tenant` record MUST automatically cascade delete all associated memberships, devices, tasks, executions, findings, evidences, discord bindings, sessions, and audit logs. Deleting a `Device` record MUST cascade delete its `DeviceCredential`, `AgentSession` history, `Task` records, and `FindingEvidence` entries without orphan row accumulation.

### INVARIANT 3: Single Active Public Key Representation
Every enrolled `Device` MUST maintain exactly 1 `DeviceCredential` record (`deviceId @unique`). Shared-secret HMAC keys and raw plaintext secrets are strictly forbidden; only valid Ed25519 public key strings (`publicKey`) formatted in hex or base64 are permitted.

### INVARIANT 4: Idempotent Execution Uniqueness
Task execution ingestion MUST be strictly idempotent. The compound constraint `@@unique([taskId, executionId])` and globally unique `executionId` in `TaskExecution` prevent double-ingestion or double-counting of scan result attempts.

### INVARIANT 5: Finding Identity vs Observation Separation
The `Finding` entity enforces vulnerability definition identity per tenant slice (`@@unique([tenantId, fingerprint])`). Specific scan observations are recorded in `FindingEvidence` records referencing `deviceId`, `taskId`, and `executionId`. Multiple devices (or the same device over time) observing identical finding fingerprints link to the master `Finding` record without unique constraint collisions.

### INVARIANT 6: User-Tenant & Discord Identity Mapping Cardinality
A Discord account maps to exactly 1 `User` identity globally (`User.discordUserId @unique`). A `User` may belong to multiple tenants via `TenantMembership` (`@@unique([tenantId, userId])`). A `DiscordBinding` links a `Tenant` and a `User` (`@@unique([tenantId, userId])`).

### INVARIANT 7: Immutable Audit Event Append-Only Storage
`AuditEvent` records MUST NEVER be updated (`UPDATE` operations disallowed) or manually deleted (`DELETE` operations disallowed except via tenant cascade deletion). All audit logs remain append-only for enterprise compliance.

---

## 7. Data Retention & Archival Policies

1. **`AuditEvent` Retention**: Retained for 365 days in PostgreSQL main partition. Automated pg_cron partition pruning archives records older than 1 year to long-term cold storage before deletion.
2. **`TaskExecution` Logs**: Successful execution metadata retained for 90 days. Failed/timed-out execution logs retained for 180 days for operational debugging.
3. **`FindingEvidence` Observations**: Detailed evidence JSON details pruned after 180 days while preserving aggregate count, `status`, and `firstSeenAt`/`lastSeenAt` metadata on master `Finding` records.
4. **`NonceCache` Expiration**: Records in `nonce_caches` automatically cleaned up after 5-minute timestamp expiration window via background sweeper.

