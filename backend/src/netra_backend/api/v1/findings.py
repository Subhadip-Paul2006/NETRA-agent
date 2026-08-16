"""NETRA Backend Control-Plane Findings Endpoints.

Implements GET /api/v1/control/findings, GET /api/v1/control/findings/{finding_id},
and POST /api/v1/control/findings/{finding_id}/status with multi-tenant RLS and role checks.
"""

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from netra_backend.database import get_db_session
from netra_backend.logging import get_logger
from netra_backend.security import decode_token
from netra_backend.services import finding_engine
from netra_shared.enums import FindingStatus, Role, Severity
from netra_shared.schemas.finding import (
    FindingDetailSchema,
    FindingPaginatedResponse,
    FindingSchema,
    FindingStatusUpdateRequest,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/control/findings", tags=["Findings & Intelligence"])


def get_current_user_claims(authorization: str | None = Header(None)) -> dict[str, Any]:
    """Extract and validate bearer access token claims from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    token = authorization.split(" ", 1)[1].strip()
    try:
        return decode_token(token, expected_type="access")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc


@router.get("", response_model=FindingPaginatedResponse)
async def list_findings_endpoint(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: Severity | None = Query(default=None),
    status: FindingStatus | None = Query(default=None),
    category: str | None = Query(default=None),
    capability: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    claims: dict[str, Any] = Depends(get_current_user_claims),
    db: AsyncSession = Depends(get_db_session),
) -> FindingPaginatedResponse:
    """List paginated vulnerability findings for current tenant."""
    tenant_id = claims["tenant_id"]
    return await finding_engine.list_findings(
        db=db,
        tenant_id=tenant_id,
        page=page,
        page_size=page_size,
        severity=severity,
        status_filter=status,
        category=category,
        capability=capability,
        device_id=device_id,
    )


@router.get("/{finding_id}", response_model=FindingDetailSchema)
async def get_finding_detail_endpoint(
    finding_id: str,
    claims: dict[str, Any] = Depends(get_current_user_claims),
    db: AsyncSession = Depends(get_db_session),
) -> FindingDetailSchema:
    """Retrieve detailed vulnerability finding with attached evidence history."""
    tenant_id = claims["tenant_id"]
    return await finding_engine.get_finding_detail(
        db=db,
        tenant_id=tenant_id,
        finding_id=finding_id,
    )


@router.post("/{finding_id}/status", response_model=FindingSchema)
async def update_finding_status_endpoint(
    finding_id: str,
    body: FindingStatusUpdateRequest,
    claims: dict[str, Any] = Depends(get_current_user_claims),
    db: AsyncSession = Depends(get_db_session),
) -> FindingSchema:
    """Mutate finding lifecycle status (ACKNOWLEDGE, RESOLVE, REOPEN, MUTED)."""
    tenant_id = claims["tenant_id"]
    user_id = claims["sub"]
    role_str = claims.get("role", "OPERATOR")
    try:
        role = Role(role_str)
    except ValueError:
        role = Role.OPERATOR

    updated_finding = await finding_engine.mutate_finding_status(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        user_role=role,
        finding_id=finding_id,
        target_status=body.status,
    )
    return FindingSchema.model_validate(updated_finding)
