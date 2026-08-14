# NETRA CI/CD Strategy & Automation Pipeline

## 1. Enterprise CI/CD Pipeline Stages

Every pull request and merge to `develop`/`main` across all repositories triggers an automated end-to-end security and build pipeline:

```
GitHub Actions Trigger (PR / Push)
   │
   ├── 1. Lint & Format (ESLint / Prettier / Black / Flake8)
   ├── 2. Type Check (tsc --noEmit / mypy)
   ├── 3. Unit Tests (Jest / Pytest with coverage)
   ├── 4. Integration Tests (Ephemeral PostgreSQL container)
   ├── 5. Migration Validation (Prisma schema drift detection)
   ├── 6. Secret Scanning (Gitleaks / TruffleHog)
   ├── 7. Dependency Audit (npm audit / safety / Snyk)
   ├── 8. SAST Security Scan (CodeQL / Semgrep)
   ├── 9. Container Security Scan (Trivy image scan)
   └── 10. Build Verification (TypeScript build / PyPI artifact package)
```

---

## 2. GitHub Actions CI Blueprint (`.github/workflows/ci.yml`)

```yaml
name: NETRA Enterprise CI Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  static-analysis:
    name: Lint, Format & Typecheck
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

  secret-scanning:
    name: Secret & Vulnerability Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
      - run: npm audit --audit-level=high

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
    name: Run Test Suite (with PostgreSQL)
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
    name: Container Build & Vulnerability Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Docker Image
        run: docker build -t netra-backend:test .
      - name: Scan Image with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'netra-backend:test'
          format: 'table'
          exit-code: '1'
          ignore-unfixed: true
          severity: 'CRITICAL,HIGH'
```
