# NETRA Database Design & PostgreSQL RLS Strategy

## 1. PostgreSQL Engine & Schema Governance

NETRA uses **PostgreSQL 16** as its core relational data store and **Prisma ORM** for type-safe query building and schema migration management.

- **Schema Single Source of Truth**: `prisma/schema.prisma` lives strictly in **Repository 1 (`netra-backend`)**.
- **No Direct DB Access in Repos 2 & 3**: Neither `netra-discord` nor `netra-agent` connect to PostgreSQL directly.

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

1. **1 Discord Identity $\leftrightarrow$ 1 NETRA User Identity**: A Discord account maps to exactly one central `User` identity globally (`User.discordUserId @unique`).
2. **1 NETRA User $\leftrightarrow$ Many `TenantMembership` Records**: A user can belong to multiple tenants with role-based permissions (`TenantMembership` `@@unique([tenantId, userId])`).
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

## 3. Deep Technical RLS Architecture & Prisma Validation

### 3.1 Prisma Interactive Transaction Pattern (`withTenantContext`)
Prisma does not natively attach session parameters to standard queries. NETRA enforces RLS by wrapping all tenant-scoped database interactions inside Prisma Interactive Transactions using `SET LOCAL`:

```typescript
export async function withTenantContext<T>(
  tenantId: string,
  fn: (tx: Prisma.TransactionClient) => Promise<T>
): Promise<T> {
  if (!tenantId || tenantId.trim() === '') {
    throw new Error('SECURITY_FATAL: MissingTenantContextException - Cannot query database without resolved tenantId');
  }

  return await prisma.$transaction(async (tx) => {
    // 1. Establish transaction-scoped GUC (Grand Unified Configuration) variable
    await tx.$executeRaw`SELECT set_config('app.current_tenant_id', ${tenantId}, true);`;

    // 2. Execute target domain queries safely inside protected transaction scope
    return await fn(tx);
  });
}
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
PostgreSQL RLS acts as a secondary defense layer. Application middleware MUST STILL validate JWT tenant claims and resource ownership before dispatching queries. RLS guarantees that even if a developer omits a `WHERE tenant_id = ?` clause in TypeScript, cross-tenant data access is physically impossible at the database engine layer.

#### E. Background Worker Tenant Context Resolution
Async background queue processors (e.g. task expiration sweepers, metric aggregators) MUST NOT run un-scoped global queries. Every worker task fetches the target `tenantId` from the queue payload and wraps execution inside `withTenantContext(tenantId, async (tx) => { ... })`.

#### F. Database User Roles & Migration Strategy
- **Migration Role (`netra_migration_runner`)**: Granted `SUPERUSER` or `BYPASSRLS` privileges. Used strictly during deployment pipelines (`npx prisma migrate deploy`) to alter DDL and execute schema migrations.
- **Application Runtime Role (`netra_app_user`)**: Restricted non-superuser role **WITHOUT** `BYPASSRLS` privileges. Used by the Node.js backend at runtime. RLS policies are strictly enforced on every query.

#### G. Automated Integration Test Strategy for RLS
The CI/CD test suite contains dedicated RLS enforcement tests asserting zero data leakage when querying without tenant context.

---

## 4. Finding vs. FindingEvidence Model Semantics

To prevent developer confusion between vulnerability definitions and scan execution attempts, NETRA strictly separates vulnerability identity from individual scan observations:

### 4.1 Concept Definitions
- **`Finding`**: Represents a normalized, ongoing security condition / vulnerability definition scoped to a tenant (`@@unique([tenantId, fingerprint])`). The `fingerprint` is a stable cryptographic SHA-256 hash derived from the vulnerability identity (e.g. `SHA-256(category + normalized_title + component)`).
- **`FindingEvidence`**: Represents an individual scan observation/occurrence of that condition on a specific target device during a specific execution attempt (`findingId`, `deviceId`, `taskId`, `executionId`, `details`, `observedAt`).

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
1. **`firstSeenAt`**: Timestamp recorded when the master `Finding` record is first created for a fingerprint within a tenant.
2. **`lastSeenAt`**: Updated automatically whenever a new `FindingEvidence` observation arrives matching this fingerprint.
3. **`severity`**: Current vulnerability severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). If new evidence indicates an escalated severity, `severity` is updated on the master `Finding` and an audit log event (`FINDING_SEVERITY_ESCALATED`) is created.
4. **`evidence` Insertion**: Every scan attempt observing a vulnerability creates a new `FindingEvidence` record linking `deviceId`, `taskId`, `executionId`, and raw JSON details without modifying the master `Finding` identity.
5. **`status` Transitions**:
   - `OPEN`: Set on initial finding discovery.
   - `RESOLVED`: Set when a subsequent scan execution on all affected devices confirms the vulnerability condition no longer exists.
   - `REOPENED`: Set automatically if a previously `RESOLVED` finding is observed again in a new scan execution.
   - `MUTED`: Set manually by a tenant administrator to suppress alert notifications.

---

## 5. Prisma Schema Blueprint (`prisma/schema.prisma`)

```prisma
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

enum Role {
  ADMIN
  OPERATOR
  AUDITOR
}

enum TaskStatus {
  CREATED
  QUEUED
  DELIVERED
  ACKNOWLEDGED
  RUNNING
  COMPLETED
  EXPIRED
  TIMEOUT
  FAILED
  CANCELLED
}

enum Severity {
  INFO
  LOW
  MEDIUM
  HIGH
  CRITICAL
}

enum FindingStatus {
  OPEN
  RESOLVED
  REOPENED
  MUTED
}

model Tenant {
  id               String             @id @default(cuid())
  name             String             @db.VarChar(100)
  slug             String             @unique @db.VarChar(100)
  createdAt        DateTime           @default(now())
  updatedAt        DateTime           @updatedAt

  memberships      TenantMembership[]
  devices          Device[]
  tasks            Task[]
  taskExecutions   TaskExecution[]
  findings         Finding[]
  findingEvidences FindingEvidence[]
  discordBindings  DiscordBinding[]
  discordSessions  DiscordSession[]
  auditEvents      AuditEvent[]
  enrollmentCodes  EnrollmentCode[]

  @@map("tenants")
}

model User {
  id              String             @id @default(cuid())
  email           String             @unique @db.VarChar(255)
  passwordHash    String             @db.VarChar(255)
  discordUserId   String?            @unique @db.VarChar(64)
  isActive        Boolean            @default(true)
  createdAt       DateTime           @default(now())
  updatedAt       DateTime           @updatedAt

  memberships     TenantMembership[]
  sessions        UserSession[]
  discordBindings DiscordBinding[]
  discordSessions DiscordSession[]
  createdCodes    EnrollmentCode[]

  @@map("users")
}

model TenantMembership {
  id        String   @id @default(cuid())
  tenantId  String
  userId    String
  role      Role     @default(OPERATOR)
  createdAt DateTime @default(now())

  tenant    Tenant   @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([tenantId, userId])
  @@index([tenantId])
  @@index([userId])
  @@map("tenant_memberships")
}

model UserSession {
  id           String    @id @default(cuid())
  userId       String
  refreshToken String    @unique @db.VarChar(512)
  ipAddress    String    @db.VarChar(45)
  userAgent    String    @db.VarChar(255)
  expiresAt    DateTime
  revokedAt    DateTime?
  createdAt    DateTime  @default(now())

  user         User      @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([userId])
  @@index([refreshToken])
  @@map("user_sessions")
}

model Device {
  id               String            @id @default(cuid())
  tenantId         String
  hostname         String            @db.VarChar(255)
  os               String            @db.VarChar(50)
  architecture     String            @db.VarChar(50)
  agentVersion     String            @db.VarChar(20)
  isPaired         Boolean           @default(true)
  lastHeartbeatAt  DateTime?
  createdAt        DateTime          @default(now())
  updatedAt        DateTime          @updatedAt

  tenant           Tenant            @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  credential       DeviceCredential?
  sessions         AgentSession[]
  tasks            Task[]
  evidences        FindingEvidence[]

  @@index([tenantId])
  @@index([tenantId, isPaired])
  @@map("devices")
}

model DeviceCredential {
  id               String    @id @default(cuid())
  deviceId         String    @unique
  publicKey        String    @db.VarChar(512)
  algorithm        String    @default("Ed25519") @db.VarChar(20)
  rotationCount    Int       @default(0)
  lastRotatedAt    DateTime  @default(now())

  device           Device    @relation(fields: [deviceId], references: [id], onDelete: Cascade)

  @@index([deviceId])
  @@map("device_credentials")
}

model AgentSession {
  id             String    @id @default(cuid())
  deviceId       String
  connectionId   String    @unique @db.VarChar(128)
  ipAddress      String    @db.VarChar(45)
  connectedAt    DateTime  @default(now())
  disconnectedAt DateTime?

  device         Device    @relation(fields: [deviceId], references: [id], onDelete: Cascade)

  @@index([deviceId])
  @@index([connectionId])
  @@map("agent_sessions")
}

model Task {
  id            String            @id @default(cuid())
  tenantId      String
  deviceId      String
  capability    String            @db.VarChar(100)
  parameters    Json              @default("{}")
  status        TaskStatus        @default(CREATED)
  createdAt     DateTime          @default(now())
  updatedAt     DateTime          @updatedAt

  tenant        Tenant            @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  device        Device            @relation(fields: [deviceId], references: [id], onDelete: Cascade)
  executions    TaskExecution[]
  evidences     FindingEvidence[]

  @@index([tenantId])
  @@index([tenantId, status])
  @@index([deviceId])
  @@index([deviceId, status])
  @@map("tasks")
}

model TaskExecution {
  id            String            @id @default(cuid())
  taskId        String
  tenantId      String
  executionId   String            @unique @db.VarChar(128)
  requestId     String            @db.VarChar(128)
  status        TaskStatus
  startedAt     DateTime          @default(now())
  completedAt   DateTime?
  errorMessage  String?           @db.Text

  task          Task              @relation(fields: [taskId], references: [id], onDelete: Cascade)
  tenant        Tenant            @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  evidences     FindingEvidence[]

  @@unique([taskId, executionId])
  @@index([taskId])
  @@index([tenantId])
  @@index([tenantId, executionId])
  @@index([requestId])
  @@map("task_executions")
}

model Finding {
  id          String            @id @default(cuid())
  tenantId    String
  title       String            @db.VarChar(255)
  category    String            @db.VarChar(100)
  severity    Severity
  status      FindingStatus     @default(OPEN)
  fingerprint String            @db.VarChar(64)
  firstSeenAt DateTime          @default(now())
  lastSeenAt  DateTime          @updatedAt

  tenant      Tenant            @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  evidences   FindingEvidence[]

  @@unique([tenantId, fingerprint])
  @@index([tenantId])
  @@index([tenantId, severity])
  @@index([tenantId, status])
  @@index([fingerprint])
  @@map("findings")
}

model FindingEvidence {
  id          String        @id @default(cuid())
  tenantId    String
  findingId   String
  deviceId    String
  taskId      String
  executionId String
  details     Json          @default("{}")
  observedAt  DateTime      @default(now())

  tenant      Tenant        @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  finding     Finding       @relation(fields: [findingId], references: [id], onDelete: Cascade)
  device      Device        @relation(fields: [deviceId], references: [id], onDelete: Cascade)
  task        Task          @relation(fields: [taskId], references: [id], onDelete: Cascade)
  execution   TaskExecution @relation(fields: [executionId], references: [executionId], onDelete: Cascade)

  @@index([tenantId])
  @@index([findingId])
  @@index([deviceId])
  @@index([taskId])
  @@index([executionId])
  @@index([observedAt])
  @@map("finding_evidences")
}

model DiscordBinding {
  id             String   @id @default(cuid())
  tenantId       String
  userId         String
  discordUserId  String   @unique @db.VarChar(64)
  discordGuildId String?  @db.VarChar(64)
  createdAt      DateTime @default(now())

  tenant         Tenant   @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  user           User     @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([tenantId, userId])
  @@index([tenantId])
  @@index([userId])
  @@index([discordUserId])
  @@map("discord_bindings")
}

model DiscordSession {
  id            String   @id @default(cuid())
  tenantId      String
  userId        String
  discordUserId String   @db.VarChar(64)
  sessionToken  String   @unique @db.VarChar(512)
  expiresAt     DateTime
  createdAt     DateTime @default(now())

  tenant        Tenant   @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  user          User     @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([tenantId])
  @@index([userId])
  @@index([sessionToken])
  @@map("discord_sessions")
}

model AuditEvent {
  id         String   @id @default(cuid())
  tenantId   String
  actorId    String   @db.VarChar(100)
  actorType  String   @db.VarChar(20)
  event      String   @db.VarChar(100)
  details    Json     @default("{}")
  ipAddress  String?  @db.VarChar(45)
  createdAt  DateTime @default(now())

  tenant     Tenant   @relation(fields: [tenantId], references: [id], onDelete: Cascade)

  @@index([tenantId])
  @@index([tenantId, createdAt])
  @@map("audit_events")
}

model EnrollmentCode {
  id             String    @id @default(cuid())
  tenantId       String
  createdById    String
  code           String    @unique @db.VarChar(32)
  expiresAt      DateTime
  usedAt         DateTime?
  usedByDeviceId String?   @db.VarChar(128)
  isRevoked      Boolean   @default(false)
  createdAt      DateTime  @default(now())

  tenant         Tenant    @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  createdBy      User      @relation(fields: [createdById], references: [id], onDelete: Cascade)

  @@index([tenantId])
  @@index([code])
  @@map("enrollment_codes")
}

model NonceCache {
  id         String   @id @default(cuid())
  deviceId   String   @db.VarChar(128)
  nonce      String   @db.VarChar(128)
  expiresAt  DateTime

  @@unique([deviceId, nonce])
  @@index([expiresAt])
  @@map("nonce_caches")
}
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

