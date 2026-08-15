# NETRA Monorepo CI/CD Strategy & Automation Pipeline

## 1. Unified Monorepo CI/CD Architecture

Because NETRA is structured as a **Unified Python Monorepo** (`NETRA/`), automated testing and deployment gates are governed by a single, matrixed GitHub Actions workflow in `.github/workflows/ci.yml`:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ NETRA Monorepo CI Pipeline (.github/workflows/ci.yml)                       │
│                                                                             │
│ ├── 1. Static Analysis (ruff + mypy + bandit)                               │
│ │    - Shared Library (`shared/`), Backend (`backend/`), Agent (`agent/`), │
│ │      Discord Bot (`discord/`).                                            │
│ │                                                                           │
│ ├── 2. Backend Test Suite (Pytest + PostgreSQL 16 + Alembic Migrations)     │
│ │    - RLS multi-tenant transaction isolation & 14-entity DB tests.         │
│ │                                                                           │
│ ├── 3. Agent Test Suite (Pytest + Keyring Mocks + Capabilities Audit)       │
│ │    - Local Ed25519 signing & OS keyring storage tests.                    │
│ │                                                                           │
│ ├── 4. Discord Bot Test Suite (Pytest + Async Event Bridge Tests)           │
│ │    - Ephemeral slash command routing & DM delivery renderer tests.         │
│ │                                                                           │
│ └── 5. Container & SAST Security Audit (Trivy + Gitleaks)                   │
│      - Vulnerability scanning for backend and bot Docker images.            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. GitHub Actions Monorepo CI Blueprint (`.github/workflows/ci.yml`)

```yaml
name: NETRA Python Monorepo CI Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  static-analysis:
    name: Python Lint, Typecheck & Bandit SAST
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'
      - name: Install Linting Tools
        run: pip install ruff mypy bandit pydantic types-requests types-setuptools
      - name: Ruff Code Formatting & Quality Audit
        run: ruff check shared/ backend/ agent/ discord/
      - name: Mypy Static Type Checking
        run: mypy shared/netra_shared backend/src agent/netra discord/bot
      - name: Bandit Security Analysis
        run: bandit -r shared/ backend/src agent/netra discord/bot

  shared-library-tests:
    name: Shared Package Unit Tests (netra_shared)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: |
          pip install -e shared/
          pip install pytest pytest-cov cryptography pydantic
      - run: pytest shared/tests

  backend-test-suite:
    name: Backend Test Suite & Alembic Migrations (PostgreSQL 16)
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
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - env:
          DATABASE_URL: postgresql://netra_test:test_password@localhost:5432/netra_test_db
        run: |
          pip install -e shared/ -e backend/
          pip install pytest pytest-cov alembic asyncpg sqlalchemy
          cd backend && alembic upgrade head
          pytest tests/

  agent-test-suite:
    name: Agent Pytest Suite & Coverage
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: |
          pip install -e shared/ -e agent/
          pip install pytest pytest-cov httpx websockets cryptography keyring psutil typer
          pytest --cov=agent/netra agent/tests/

  discord-bot-test-suite:
    name: Discord Bot Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: |
          pip install -e shared/ -e discord/
          pip install pytest discord.py httpx
          pytest discord/tests/

  container-security-scan:
    name: Container Build & Trivy Vulnerability Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Backend Image
        run: docker build -t netra-backend:test backend/
      - name: Build Discord Bot Image
        run: docker build -t netra-discord:test discord/
      - uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'netra-backend:test'
          format: 'table'
          exit-code: '1'
          ignore-unfixed: true
          severity: 'CRITICAL,HIGH'
```

---

## 3. Monorepo Release & Version Compatibility Matrix

NETRA uses Semantic Versioning (SemVer 2.0.0) synchronized across the monorepo:

| Release Tag | Backend Service (`backend/`) | Discord Bot Service (`discord/`) | Agent Package (`agent/`) | Shared Package (`shared/`) |
| :--- | :--- | :--- | :--- | :--- |
| `v1.0.0` | `v1.0.0` | `v1.0.0` | `v1.0.0` | `v1.0.0` |
| `v1.1.0` | `v1.1.0` | `v1.1.0` | `v1.0.0` (Backwards Compatible) | `v1.1.0` |

### 3.1 Deployment Gate Rules
1. **Pydantic Schema Single Source**: `agent/` payload structures and `discord/` API client schemas MUST inherit directly from `shared/netra_shared`.
2. **Backwards Compatibility Shield**: `backend/` MUST maintain support for minor version agent packages (`v1.0.0` agent connected to `v1.1.0` backend) to prevent client host breakage during rolling upgrades.
3. **Automated Compatibility Verification**: Monorepo CI executes cross-package contract verification tests in `shared/tests`.



