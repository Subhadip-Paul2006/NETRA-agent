# NETRA GitHub Workflow & Contribution Guidelines

## 1. Branch Strategy (Git Flow Variant)

NETRA uses a structured branching model across all three repositories (`netra-backend`, `netra-discord`, `netra-agent`).

```
  main --------------------------------------------*------------ (v1.0.0 Release Tag)
                                                  /
  release/1.0.0 ---------------------------------*
                                                /
  develop -------*-------------*---------------*---------------- (Integration)
                  \           / \             /
  feature/  -------*---------*   \-----------*------------------ (Short-lived topic branches)
  agent-wss
```

### 1.1 Branch Naming Standards
- **`main`**: Production baseline. Direct commits strictly prohibited.
- **`develop`**: Integration branch. Direct commits prohibited.
- **`feature/<short-description>`**: Feature topic branches.
- **`bugfix/<issue-id>-<description>`**: Patch fixes targeting `develop`.
- **`hotfix/<issue-id>-<description>`**: Production patches targeting `main` and merged back to `develop`.

---

## 2. Commit Conventions & PR Quality Gates

Commit messages must strictly follow **Conventional Commits v1.0.0** (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`, `refactor:`).

### Pull Request Gates
1. **TypeScript / Python Type Checking**: Zero type errors (`tsc --noEmit` / `mypy`).
2. **Linting & Formatting**: Clean ESLint / Black / Flake8 runs.
3. **Automated Tests**: 100% pass rate on unit and integration test suites.
4. **Prisma Migration Validation**: Zero schema drift (`prisma migrate diff`).
5. **Security Scanning**: Zero high/critical findings from SAST or dependency audit tools.
6. **Code Review**: At least **1 approving review** from a maintainer.

---

## 3. GitHub Environments & Secret Management

Secrets must NEVER be stored in repository code or plaintext variables. They are injected via **GitHub Environments** (`development`, `staging`, `production`):

- **Backend Secrets**: `DATABASE_URL`, `JWT_SECRET`, `AGENT_REGISTRATION_SECRET`
- **Discord Secrets**: `DISCORD_BOT_TOKEN`, `DISCORD_CLIENT_SECRET`, `DISCORD_SERVICE_SECRET`
- **Observability**: `SENTRY_DSN`, `DATADOG_API_KEY`
