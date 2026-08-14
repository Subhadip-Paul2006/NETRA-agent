# NETRA Database Design & Prisma Schema Architecture

## 1. Database Engine & Schema Governance

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

### 2.2 Real PostgreSQL RLS Technical Pattern with Prisma
Prisma does not natively append RLS settings to raw SQL queries automatically. NETRA enforces database-level RLS using Prisma's transactional `SET LOCAL` pattern:

**Backend Transaction Wrapper (`withTenantContext`):**
```typescript
export async function withTenantContext<T>(
  tenantId: string,
  fn: (tx: Prisma.TransactionClient) => Promise<T>
): Promise<T> {
  return await prisma.$transaction(async (tx) => {
    // 1. Establish session variable for current transaction scope
    await tx.$executeRawUnsafe(
      `SET LOCAL app.current_tenant_id = '${tenantId}';`
    );

    // 2. Execute target Prisma query within protected transaction scope
    return await fn(tx);
  });
}
```

**PostgreSQL Row-Level Security Policy Definition:**
```sql
-- Enable RLS on findings table
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

-- Create tenant isolation policy
CREATE POLICY tenant_isolation_policy ON findings
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true));
```

---

## 3. Expanded Prisma Schema Blueprint (`prisma/schema.prisma`)

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
