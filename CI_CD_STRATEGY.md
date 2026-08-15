# NETRA CI/CD Strategy & Automation Pipeline

## 1. Multi-Repository CI/CD Architecture

Because NETRA comprises 3 distinct repositories with different tech stacks, each repository contains its own tailored GitHub Actions workflow in `.github/workflows/ci.yml`:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Repository 1: netra-backend (Node.js 20 / TypeScript / Fastify / Prisma)│
│    - Lint & Typecheck: ESLint + Prettier + tsc --noEmit                    │
│    - Prisma Validation: Schema format + Prisma drift + migration deploy     │
│    - RLS Integration Tests: Ephemeral PostgreSQL 16 Service Container       │
│    - SAST & Container Scan: Gitleaks + Trivy Docker Image Scan              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. Repository 2: netra-discord (Node.js 20 / TypeScript / Discord.js)       │
│    - Lint & Typecheck: ESLint + Prettier + tsc --noEmit                    │
│    - Discord Command Validation: Zod schema & slash command builder audit   │
│    - Unit Tests: Jest mock tests for Backend API client & embed formatters  │
│    - Security Scan: Gitleaks + npm audit + Trivy Docker Image Scan          │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. Repository 3: netra-agent (Python 3.10+ / Hatch / Pytest / httpx)        │
│    - Lint & Format: Ruff + Black + mypy type checking                       │
│    - Unit & Integration Tests: Pytest with coverage + OS Keyring mocks      │
│    - Package Verification: Hatch build verification & artifact generation   │
│    - Security Audit: Bandit SAST + Safety dependency vulnerability audit    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. GitHub Actions CI Blueprints

### 2.1 Repository 1 CI Blueprint (`netra-backend/.github/workflows/ci.yml`)

```yaml
name: NETRA Backend CI Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  static-analysis:
    name: Backend Lint, Format & Typecheck
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
      - run: npm ci
      - run: npm run lint
      - run: npm run format:check
      - run: npm run typecheck

  prisma-migration-check:
    name: Validate Prisma Schema & Migrations
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npx prisma format --check
      - run: npx prisma validate

  unit-and-integration-tests:
    name: Run Backend Test Suite (PostgreSQL 16)
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: netra_test
          POSTGRES_PASSWORD: test_password
          POSTGRES_DB: netra_test_db
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - env:
          DATABASE_URL: postgresql://netra_test:test_password@localhost:5432/netra_test_db
        run: |
          npx prisma migrate deploy
          npm run test:unit
          npm run test:integration

  container-build-scan:
    name: Backend Container Build & Trivy Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t netra-backend:test .
      - uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'netra-backend:test'
          format: 'table'
          exit-code: '1'
          ignore-unfixed: true
          severity: 'CRITICAL,HIGH'
```

### 2.2 Repository 2 CI Blueprint (`netra-discord/.github/workflows/ci.yml`)

```yaml
name: NETRA Discord CI Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  static-analysis:
    name: Discord Bot Lint, Format & Typecheck
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
      - run: npm ci
      - run: npm run lint
      - run: npm run typecheck

  unit-tests:
    name: Discord Bot Command & Embed Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm run test:unit

  container-build-scan:
    name: Discord Bot Container Build & Trivy Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t netra-discord:test .
      - uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'netra-discord:test'
          format: 'table'
          exit-code: '1'
          ignore-unfixed: true
          severity: 'CRITICAL,HIGH'
```

### 2.3 Repository 3 CI Blueprint (`netra-agent/.github/workflows/ci.yml`)

```yaml
name: NETRA Agent CI Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  python-quality-checks:
    name: Agent Lint, Typecheck & Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install hatch ruff mypy pytest pytest-cov bandit
      - run: ruff check .
      - run: mypy netra
      - run: bandit -r netra

  agent-test-suite:
    name: Agent Pytest Suite & Coverage
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install hatch pytest pytest-cov httpx websockets cryptography keyring
      - run: pytest --cov=netra --cov-report=term-missing tests/

  package-build-check:
    name: Hatch Package Build Verification
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install hatch
      - run: hatch build
```

---

## 3. Multi-Repository Release & Version Compatibility Matrix

To prevent incompatible deployments across independent repository releases, NETRA enforces a Semantic Versioning (SemVer 2.0.0) compatibility matrix:

| Backend Release (`netra-backend`) | Compatible Discord Bot (`netra-discord`) | Compatible Agent Package (`netra-agent`) | Protocol & API Contract Horizon |
| :--- | :--- | :--- | :--- |
| `v1.0.x` | `v1.0.x` | `v1.0.x` | Base REST API `/api/v1`, Ed25519 WSS v1 protocol, 7 capabilities. |
| `v1.1.x` | `v1.0.x`, `v1.1.x` | `v1.0.x`, `v1.1.x` | Backwards-compatible `v1` field extensions; older agents fallback gracefully. |
| `v2.0.x` | `v2.0.x` | `v2.0.x` | Major API contract change (`/api/v2`); requires backend and bot deployment sync. |

### 3.1 Deployment Gate Rules
1. **API Schema Contract Audit**: Agent client payload structures and Discord bot API client schemas MUST match OpenAPI specs in `netra-backend`.
2. **Backwards Compatibility Shield**: Backend MUST maintain support for minor version agent packages (`v1.0.0` agent connected to `v1.1.0` backend) to prevent client host breakage during rolling upgrades.
3. **Automated Compatibility Verification**: CI pipeline executes cross-repository contract verification tests using OpenAPI schema validation tools (`spectral` / `openapi-generator`).


