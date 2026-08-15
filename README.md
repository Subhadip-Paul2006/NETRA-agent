# NETRA — Enterprise Threat Reconnaissance & Host Security Platform

## Python Monorepo Architecture Specifications

NETRA is an enterprise-grade, multi-tenant security operations and audit platform built as a **Unified Python Monorepo** (`NETRA/` using Python 3.11+). It features asymmetric Ed25519 device identity, controlled task capabilities, PostgreSQL 16 Row-Level Security (RLS), and isolated Discord control plane integration.

```
NETRA/
├── backend/       # Python Central Security Engine (FastAPI, AsyncPG, SQLAlchemy 2.0, Alembic, PostgreSQL 16)
├── agent/         # Python Host Agent Package (Typer CLI, httpx, websockets, cryptography, keyring)
├── discord/       # Python Discord Control Plane (discord.py, httpx)
├── shared/        # Common Python Package (netra_shared: Pydantic v2 schemas, Ed25519 crypto, errors)
├── docs/          # Architecture Specifications & Specifications
└── .github/       # Monorepo CI/CD Automation Workflows
```

### Core Architectural Specifications (`docs/`)
1. [ARCHITECTURE.md](file:///d:/NETRA-agent/ARCHITECTURE.md) — Python Monorepo Vision, Topology & ADRs
2. [SYSTEM_DESIGN.md](file:///d:/NETRA-agent/SYSTEM_DESIGN.md) — Sequence Diagrams, Task State Machine, 7 Capability Specs & Concurrency Matrix
3. [DATABASE_DESIGN.md](file:///d:/NETRA-agent/DATABASE_DESIGN.md) — 14-Entity SQLAlchemy 2.0 / SQLModel Schema, Deep PostgreSQL RLS & Invariants
4. [API_BOUNDARY.md](file:///d:/NETRA-agent/API_BOUNDARY.md) — REST `/api/v1` Contracts, Pydantic Schemas, WSS Protocol & Section 4 Async Event Bridge
5. [SECURITY_MODEL.md](file:///d:/NETRA-agent/SECURITY_MODEL.md) — Ed25519 Signature Protocol, OS Keyring Storage & Threat Matrix (T-01 to T-12)
6. [CI_CD_STRATEGY.md](file:///d:/NETRA-agent/CI_CD_STRATEGY.md) — Monorepo GitHub Actions Matrix Blueprints & Release Strategy
7. [DEVELOPMENT_ROADMAP.md](file:///d:/NETRA-agent/DEVELOPMENT_ROADMAP.md) — 10 Implementation Phases & Verification Gates

### Supporting Specifications
- [REPOSITORY_STRUCTURE.md](file:///d:/NETRA-agent/REPOSITORY_STRUCTURE.md) — Directory layout tree for `NETRA/` (`backend/`, `agent/`, `discord/`, `shared/`)
- [GITHUB_WORKFLOW.md](file:///d:/NETRA-agent/GITHUB_WORKFLOW.md) — Monorepo git branching strategy & contribution guidelines
- [THREAT_MODEL.md](file:///d:/NETRA-agent/THREAT_MODEL.md) — 12-Threat matrix & security mitigations
- [OBSERVABILITY.md](file:///d:/NETRA-agent/OBSERVABILITY.md) — JSON logging schemas, correlation IDs & Prometheus metrics
- [.env.example](file:///d:/NETRA-agent/.env.example) — Monorepo environment configuration template

> [!IMPORTANT]
> **Phase 0 Architecture Status**: **UNDER REVIEW**

