# NETRA Database Design & PostgreSQL RLS Strategy

## 1. PostgreSQL Engine & Schema Governance

NETRA uses **PostgreSQL 16** as its core relational data store and **Prisma ORM** for type-safe query building and schema migration management.

- **Schema Single Source of Truth**: `prisma/schema.prisma` lives strictly in **Repository 1 (`netra-backend`)**.
- **No Direct DB Access in Repos 2 & 3**: Neither `netra-discord` nor `netra-agent` connect to PostgreSQL directly.

---

## 2. Multi-Tenant Hierarchy & PostgreSQL Row-Level Security (RLS)

### 2.1 Entity Hierarchy Diagram
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
The CI/CD test suite contains dedicated RLS enforcement tests:
```typescript
describe('PostgreSQL RLS Enforcement Verification', () => {
  it('should return 0 rows when app_user queries findings without tenant context', async () => {
    const rawResult = await rawAppUserClient.$queryRaw`SELECT * FROM findings;`;
    expect(rawResult).toHaveLength(0); // Asserts zero data leaked
  });
});
```

---

## 4. Prisma Schema Blueprint (`prisma/schema.prisma`)

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

model Tenant {
  id              String             @id @default(cuid())
  name            String             @db.VarChar(100)
  slug            String             @unique @db.VarChar(100)
  createdAt       DateTime           @default(now())
  updatedAt       DateTime           @updatedAt

  memberships     TenantMembership[]
  devices         Device[]
  tasks           Task[]
  taskExecutions  TaskExecution[]
  findings        Finding[]
  findingEvidences FindingEvidence[]
  discordBindings DiscordBinding[]
  discordSessions DiscordSession[]
  auditEvents     AuditEvent[]
  enrollmentCodes EnrollmentCode[]

  @@map("tenants")
}

model User {
  id              String             @id @default(cuid())
  email           String             @unique @db.VarChar(255)
  passwordHash    String             @db.VarChar(255)
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
  fingerprint String            @db.VarChar(64)
  firstSeenAt DateTime          @default(now())
  lastSeenAt  DateTime          @updatedAt

  tenant      Tenant            @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  evidences   FindingEvidence[]

  @@unique([tenantId, fingerprint])
  @@index([tenantId])
  @@index([tenantId, severity])
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
  @@index([tenantId, userId])
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
```

---

## 5. Formal DATABASE_INVARIANTS

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

### INVARIANT 6: User-Tenant & Discord Relationship Boundary
A `User` may belong to multiple tenants via `TenantMembership` (`@@unique([tenantId, userId])`). A `DiscordBinding` MUST explicitly map to a valid `Tenant` and a valid `User` via foreign keys (`tenantId`, `userId`), enforcing single Discord account mapping per tenant scope (`@@unique([tenantId, userId])`).

### INVARIANT 7: Immutable Audit Event Append-Only Storage
`AuditEvent` records MUST NEVER be updated (`UPDATE` operations disallowed) or manually deleted (`DELETE` operations disallowed except via tenant cascade deletion). All audit logs remain append-only for enterprise compliance.

---

## 6. Data Retention & Archival Policies

1. **`AuditEvent` Retention**: Retained for 365 days in PostgreSQL main partition. Automated pg_cron partition pruning archives records older than 1 year to long-term cold storage before deletion.
2. **`TaskExecution` Logs**: Successful execution metadata retained for 90 days. Failed/timed-out execution logs retained for 180 days for operational debugging.
3. **`FindingEvidence` Observations**: Detailed evidence JSON details pruned after 180 days while preserving aggregate count and `firstSeenAt`/`lastSeenAt` metadata on master `Finding` records.

