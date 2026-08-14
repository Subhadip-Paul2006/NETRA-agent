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
                             /      |      \
                            /       |       \
                           v        v        v
        +--------------------+  +--------+  +---------------+
        |  TenantMembership  |  | Device |  |  AuditEvent   |
        +--------------------+  +--------+  +---------------+
                   |                |
                   v                v
               +------+   +--------------------+
               | User |   |  DeviceCredential  |
               +------+   +--------------------+
                                    |
                                    v
                                +--------+
                                |  Task  |
                                +--------+
                                    |
                                    v
                            +---------------+
                            | TaskExecution |
                            +---------------+
                                    |
                                    v
                               +---------+
                               | Finding |
                               +---------+
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

### 3.2 Key RLS Technical Attributes

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

#### D. Database User Roles & Migration Strategy
- **Migration Role (`netra_migration_runner`)**: Granted `SUPERUSER` or `BYPASSRLS` privileges. Used strictly during deployment pipelines (`npx prisma migrate deploy`) to alter DDL and execute schema migrations.
- **Application Runtime Role (`netra_app_user`)**: Restricted non-superuser role **WITHOUT** `BYPASSRLS` privileges. Used by the Node.js backend at runtime. RLS policies are strictly enforced on every query.

#### E. Automated Integration Test Strategy for RLS
The CI/CD test suite contains dedicated RLS enforcement tests:
```typescript
describe('PostgreSQL RLS Enforcement Verification', () => {
  it('should return 0 rows when app_user queries findings without tenant context', async () => {
    // Connect as netra_app_user directly bypassing application middleware
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
  findings        Finding[]
  discordBindings DiscordBinding[]
  auditEvents     AuditEvent[]

  @@map("tenants")
}

model User {
  id            String             @id @default(cuid())
  email         String             @unique @db.VarChar(255)
  passwordHash  String             @db.VarChar(255)
  isActive      Boolean            @default(true)
  createdAt     DateTime           @default(now())
  updatedAt     DateTime           @updatedAt

  memberships   TenantMembership[]
  sessions      UserSession[]

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
  findings         Finding[]

  @@index([tenantId])
  @@index([tenantId, isPaired])
  @@map("devices")
}

model DeviceCredential {
  id               String    @id @default(cuid())
  deviceId         String    @unique
  hashedKey        String    @db.VarChar(255)
  rotationCount    Int       @default(0)
  lastRotatedAt    DateTime  @default(now())

  device           Device    @relation(fields: [deviceId], references: [id], onDelete: Cascade)

  @@map("device_credentials")
}

model AgentSession {
  id           String    @id @default(cuid())
  deviceId     String
  connectionId String    @unique @db.VarChar(128)
  ipAddress    String    @db.VarChar(45)
  connectedAt  DateTime  @default(now())
  disconnectedAt DateTime?

  device       Device    @relation(fields: [deviceId], references: [id], onDelete: Cascade)

  @@index([deviceId])
  @@map("agent_sessions")
}

model Task {
  id            String          @id @default(cuid())
  tenantId      String
  deviceId      String
  capability    String          @db.VarChar(100)
  parameters    Json            @default("{}")
  status        TaskStatus      @default(CREATED)
  createdAt     DateTime        @default(now())
  updatedAt     DateTime        @updatedAt

  tenant        Tenant          @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  device        Device          @relation(fields: [deviceId], references: [id], onDelete: Cascade)
  executions    TaskExecution[]
  findings      Finding[]

  @@index([tenantId])
  @@index([tenantId, status])
  @@index([deviceId, status])
  @@map("tasks")
}

model TaskExecution {
  id            String     @id @default(cuid())
  taskId        String
  tenantId      String
  executionId   String     @unique @db.VarChar(128)
  requestId     String     @db.VarChar(128)
  status        TaskStatus
  startedAt     DateTime   @default(now())
  completedAt   DateTime?
  errorMessage  String?    @db.Text

  task          Task       @relation(fields: [taskId], references: [id], onDelete: Cascade)

  @@index([taskId])
  @@index([tenantId, executionId])
  @@map("task_executions")
}

model Finding {
  id          String   @id @default(cuid())
  tenantId    String
  deviceId    String
  taskId      String
  title       String   @db.VarChar(255)
  category    String   @db.VarChar(100)
  severity    Severity
  details     Json     @default("{}")
  fingerprint String   @db.VarChar(64)
  createdAt   DateTime @default(now())

  tenant      Tenant   @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  device      Device   @relation(fields: [deviceId], references: [id], onDelete: Cascade)
  task        Task     @relation(fields: [taskId], references: [id], onDelete: Cascade)

  @@unique([tenantId, fingerprint])
  @@index([tenantId])
  @@index([tenantId, severity])
  @@index([deviceId])
  @@map("findings")
}

model DiscordBinding {
  id            String   @id @default(cuid())
  tenantId      String
  userId        String
  discordUserId String   @unique @db.VarChar(64)
  discordGuildId String? @db.VarChar(64)
  createdAt     DateTime @default(now())

  tenant        Tenant   @relation(fields: [tenantId], references: [id], onDelete: Cascade)

  @@index([tenantId])
  @@map("discord_bindings")
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
```
