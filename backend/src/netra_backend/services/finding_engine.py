"""NETRA Security Finding Intelligence and Evidence Management Engine.

Implements deterministic SHA-256 finding fingerprinting, automated deduplication,
evidence ingestion, lifecycle state machine, and multi-tenant RLS query isolation.
"""

import hashlib
import json
from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netra_backend.logging import get_logger
from netra_backend.models import AuditEvent, Finding, FindingEvidence
from netra_backend.rls import with_tenant_context
from netra_shared.enums import FindingStatus, Role, Severity
from netra_shared.schemas.finding import (
    FindingDetailSchema,
    FindingEvidenceSchema,
    FindingPaginatedResponse,
    FindingSchema,
)
from netra_shared.schemas.task import FindingItem

logger = get_logger(__name__)

MAX_EVIDENCE_SIZE_BYTES = 1024 * 1024  # 1MB per evidence detail payload


def compute_finding_fingerprint(
    tenant_id: str,
    device_id: str,
    capability: str,
    category: str,
    title: str,
    resource_key: str = "",
) -> str:
    """Compute a deterministic SHA-256 finding fingerprint.

    Derived strictly from stable security identity attributes (tenant, device,
    capability, category, title, resource_key). Transient execution UUIDs or
    timestamps are excluded.
    """
    canonical_string = "|".join(
        [
            tenant_id.strip(),
            device_id.strip(),
            capability.strip().upper(),
            category.strip().upper(),
            title.strip(),
            resource_key.strip(),
        ]
    )
    return hashlib.sha256(canonical_string.encode("utf-8")).hexdigest()


def validate_finding_transition(
    current_status: FindingStatus, target_status: FindingStatus
) -> None:
    """Enforce valid vulnerability finding lifecycle state transitions."""
    if current_status == target_status:
        return  # Idempotent re-entry

    valid_transitions: dict[FindingStatus, set[FindingStatus]] = {
        FindingStatus.OPEN: {
            FindingStatus.ACKNOWLEDGED,
            FindingStatus.RESOLVED,
            FindingStatus.MUTED,
        },
        FindingStatus.ACKNOWLEDGED: {
            FindingStatus.RESOLVED,
            FindingStatus.OPEN,
            FindingStatus.MUTED,
        },
        FindingStatus.RESOLVED: {FindingStatus.REOPENED},
        FindingStatus.REOPENED: {
            FindingStatus.ACKNOWLEDGED,
            FindingStatus.RESOLVED,
            FindingStatus.MUTED,
        },
        FindingStatus.MUTED: {
            FindingStatus.OPEN,
            FindingStatus.ACKNOWLEDGED,
            FindingStatus.RESOLVED,
        },
    }

    allowed = valid_transitions.get(current_status, set())
    if target_status not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid finding status transition from '{current_status.value}' "
                f"to '{target_status.value}'."
            ),
        )


async def process_finding_ingestion(
    db: AsyncSession,
    tenant_id: str,
    device_id: str,
    task_id: str,
    execution_id: str,
    capability: str,
    raw_findings: list[FindingItem],
) -> list[Finding]:
    """Ingest, fingerprint, deduplicate, and store scan findings & evidence."""
    now = datetime.now(UTC)
    processed_findings: list[Finding] = []

    async with with_tenant_context(tenant_id, db):
        for item in raw_findings:
            # Evidence detail size validation
            details_json = json.dumps(item.details)
            if len(details_json.encode("utf-8")) > MAX_EVIDENCE_SIZE_BYTES:
                msg = f"Evidence payload size exceeds limit of {MAX_EVIDENCE_SIZE_BYTES} bytes."
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=msg,
                )

            # Extract resource key if present in details, or default to title
            resource_key = str(item.details.get("resource_key", item.details.get("path", "")))

            # Use item.fingerprint if valid 64-char hex, otherwise compute deterministic fingerprint
            if len(item.fingerprint) == 64 and all(
                c in "0123456789abcdefABCDEF" for c in item.fingerprint
            ):
                fingerprint = item.fingerprint.lower()
            else:
                fingerprint = compute_finding_fingerprint(
                    tenant_id=tenant_id,
                    device_id=device_id,
                    capability=capability,
                    category=item.category,
                    title=item.title,
                    resource_key=resource_key,
                )

            try:
                sev = Severity[item.severity.upper()]
            except KeyError:
                sev = Severity.MEDIUM

            # Lookup existing finding in tenant context
            stmt = select(Finding).where(
                Finding.tenant_id == tenant_id, Finding.fingerprint == fingerprint
            )
            res = await db.execute(stmt)
            finding = res.scalar_one_or_none()

            if finding:
                # Update existing finding timestamps and execution metadata
                finding.last_seen_at = now
                finding.updated_at = now
                finding.device_id = device_id
                finding.task_id = task_id
                finding.execution_id = execution_id
                finding.capability = capability

                # Reopen finding if previously resolved
                if finding.status == FindingStatus.RESOLVED:
                    finding.status = FindingStatus.REOPENED
                    logger.info(
                        "finding_reopened",
                        finding_id=finding.id,
                        tenant_id=tenant_id,
                        fingerprint=fingerprint,
                    )
            else:
                # Create master finding entry
                finding = Finding(
                    tenant_id=tenant_id,
                    device_id=device_id,
                    task_id=task_id,
                    execution_id=execution_id,
                    capability=capability,
                    title=item.title,
                    description=str(item.details.get("description", item.title)),
                    category=item.category,
                    severity=sev,
                    status=FindingStatus.OPEN,
                    fingerprint=fingerprint,
                    remediation=item.details.get("remediation"),
                    first_seen_at=now,
                    last_seen_at=now,
                    created_at=now,
                    updated_at=now,
                )
                db.add(finding)
                await db.flush()

            # Attach evidence history item
            evidence = FindingEvidence(
                tenant_id=tenant_id,
                finding_id=finding.id,
                device_id=device_id,
                task_id=task_id,
                execution_id=execution_id,
                details=item.details,
                observed_at=now,
            )
            db.add(evidence)
            processed_findings.append(finding)

    return processed_findings


async def mutate_finding_status(
    db: AsyncSession,
    tenant_id: str,
    user_id: str,
    user_role: Role,
    finding_id: str,
    target_status: FindingStatus,
) -> Finding:
    """Mutate finding lifecycle status with role checks and audit logging."""
    if user_role not in (Role.ADMIN, Role.OPERATOR):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role 'AUDITOR' lacks permission to mutate finding status.",
        )

    now = datetime.now(UTC)

    async with with_tenant_context(tenant_id, db):
        stmt = select(Finding).where(Finding.id == finding_id, Finding.tenant_id == tenant_id)
        res = await db.execute(stmt)
        finding = res.scalar_one_or_none()

        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found or unauthorized.",
            )

        validate_finding_transition(finding.status, target_status)
        previous_status = finding.status
        finding.status = target_status
        finding.updated_at = now

        audit = AuditEvent(
            tenant_id=tenant_id,
            actor_id=user_id,
            actor_type="USER",
            event="FINDING_STATUS_MUTATED",
            details={
                "finding_id": finding.id,
                "previous_status": previous_status.value,
                "new_status": target_status.value,
            },
        )
        db.add(audit)
        await db.commit()
        await db.refresh(finding)

        logger.info(
            "finding_status_mutated",
            tenant_id=tenant_id,
            user_id=user_id,
            finding_id=finding.id,
            previous_status=previous_status.value,
            new_status=target_status.value,
        )
        return finding


async def list_findings(
    db: AsyncSession,
    tenant_id: str,
    page: int = 1,
    page_size: int = 20,
    severity: Severity | None = None,
    status_filter: FindingStatus | None = None,
    category: str | None = None,
    capability: str | None = None,
    device_id: str | None = None,
) -> FindingPaginatedResponse:
    """Query paginated security findings isolated by tenant context."""
    if page < 1:
        page = 1
    if page_size < 1:
        page_size = 20
    if page_size > 100:
        page_size = 100

    offset = (page - 1) * page_size

    async with with_tenant_context(tenant_id, db):
        query = select(Finding).where(Finding.tenant_id == tenant_id)

        if severity:
            query = query.where(Finding.severity == severity)
        if status_filter:
            query = query.where(Finding.status == status_filter)
        if category:
            query = query.where(Finding.category == category)
        if capability:
            query = query.where(Finding.capability == capability)
        if device_id:
            query = query.where(Finding.device_id == device_id)

        # Count total matching findings
        count_query = select(func.count()).select_from(query.subquery())
        total_res = await db.execute(count_query)
        total = total_res.scalar() or 0

        # Execute paginated query ordered deterministically by last_seen_at desc, id desc
        query = (
            query.order_by(Finding.last_seen_at.desc(), Finding.id.desc())
            .offset(offset)
            .limit(page_size)
        )
        res = await db.execute(query)
        findings = res.scalars().all()

        items = [FindingSchema.model_validate(f) for f in findings]
        has_more = (offset + len(items)) < total

        return FindingPaginatedResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            has_more=has_more,
        )


async def get_finding_detail(
    db: AsyncSession,
    tenant_id: str,
    finding_id: str,
) -> FindingDetailSchema:
    """Retrieve detailed vulnerability finding with full evidence history."""
    async with with_tenant_context(tenant_id, db):
        stmt = (
            select(Finding)
            .options(selectinload(Finding.evidences))
            .where(Finding.id == finding_id, Finding.tenant_id == tenant_id)
        )
        res = await db.execute(stmt)
        finding = res.scalar_one_or_none()

        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found or unauthorized.",
            )

        evidences = [FindingEvidenceSchema.model_validate(ev) for ev in finding.evidences]
        detail = FindingDetailSchema.model_validate(finding)
        detail.evidences = evidences
        return detail
