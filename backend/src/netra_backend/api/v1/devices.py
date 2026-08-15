"""NETRA Backend Device Enrollment and Management Endpoints.

Implements POST /api/v1/control/enrollment-codes and POST /api/v1/agent/enroll.
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from netra_backend.database import get_db_session
from netra_backend.logging import get_logger
from netra_backend.models import Device, DeviceCredential, EnrollmentCode, TenantMembership
from netra_backend.rls import with_tenant_context
from netra_backend.security import decode_token
from netra_shared.enums import DeviceCredentialStatus, Role

logger = get_logger(__name__)
router = APIRouter(tags=["Devices & Enrollment"])


class CreateEnrollmentCodeRequest(BaseModel):
    """Payload for generating a device enrollment code."""

    tenant_id: str


class EnrollmentCodeResponse(BaseModel):
    """Response containing plaintext enrollment code."""

    code: str
    tenant_id: str
    expires_at: datetime


class EnrollDeviceRequest(BaseModel):
    """Payload sent by local host agent during enrollment."""

    code: str = Field(min_length=6)
    hostname: str = Field(min_length=1, max_length=255)
    os: str = Field(min_length=1, max_length=50)
    architecture: str = Field(min_length=1, max_length=50)
    agent_version: str = Field(min_length=1, max_length=20)
    public_key: str = Field(min_length=32)


class EnrollDeviceResponse(BaseModel):
    """Response returned upon successful agent enrollment."""

    device_id: str
    tenant_id: str
    status: str = "ENROLLED"


def get_current_user_id(authorization: str | None = Header(None)) -> str:
    """Extract and validate bearer access token from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token, expected_type="access")
        return payload["sub"]
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc


@router.post("/control/enrollment-codes", response_model=EnrollmentCodeResponse)
async def create_enrollment_code(
    payload: CreateEnrollmentCodeRequest,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db_session),
) -> EnrollmentCodeResponse:
    """Generate a single-use 15-minute device enrollment authorization code."""
    async with with_tenant_context(payload.tenant_id, db):
        # Verify user has ADMIN or OPERATOR role in target tenant
        membership_stmt = select(TenantMembership).where(
            TenantMembership.tenant_id == payload.tenant_id,
            TenantMembership.user_id == user_id,
        )
        res = await db.execute(membership_stmt)
        membership = res.scalar_one_or_none()

        if not membership or membership.role not in (Role.ADMIN, Role.OPERATOR):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to generate enrollment code",
            )

        # Generate cryptographically secure enrollment code (e.g. NETRA-XXXX-YYYY-ZZZZ)
        raw_code = f"NETRA-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        code_hash = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()

        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=15)

        enrollment_entry = EnrollmentCode(
            tenant_id=payload.tenant_id,
            created_by_id=user_id,
            code_hash=code_hash,
            expires_at=expires_at,
        )
        db.add(enrollment_entry)
        await db.commit()

        logger.info("enrollment_code_generated", tenant_id=payload.tenant_id, created_by=user_id)

        return EnrollmentCodeResponse(
            code=raw_code,
            tenant_id=payload.tenant_id,
            expires_at=expires_at,
        )


@router.post("/agent/enroll", response_model=EnrollDeviceResponse)
async def enroll_device(
    payload: EnrollDeviceRequest,
    db: AsyncSession = Depends(get_db_session),
) -> EnrollDeviceResponse:
    """Enroll host agent using single-use code and register Ed25519 public key."""
    # Compute SHA256 hash of presented code
    code_hash = hashlib.sha256(payload.code.strip().encode("utf-8")).hexdigest()

    stmt = select(EnrollmentCode).where(EnrollmentCode.code_hash == code_hash)
    result = await db.execute(stmt)
    code_entry = result.scalar_one_or_none()

    now = datetime.now(UTC)

    # Fail closed validation checks
    if not code_entry:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid enrollment code"
        )

    if code_entry.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Enrollment code has been revoked"
        )

    if code_entry.used_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enrollment code has already been redeemed",
        )

    code_expires_at = code_entry.expires_at
    if code_expires_at.tzinfo is None:
        code_expires_at = code_expires_at.replace(tzinfo=UTC)

    if code_expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Enrollment code has expired"
        )

    tenant_id = code_entry.tenant_id

    async with with_tenant_context(tenant_id, db):
        # Create Device Record
        device = Device(
            tenant_id=tenant_id,
            hostname=payload.hostname,
            os=payload.os,
            architecture=payload.architecture,
            agent_version=payload.agent_version,
            is_paired=True,
            last_heartbeat_at=now,
        )
        db.add(device)
        await db.flush()

        # Create DeviceCredential (storing public key only)
        credential = DeviceCredential(
            device_id=device.id,
            public_key=payload.public_key,
            algorithm="Ed25519",
            status=DeviceCredentialStatus.ACTIVE,
        )
        db.add(credential)

        # Atomic conditional update to mark enrollment code as used
        update_stmt = (
            update(EnrollmentCode)
            .where(
                EnrollmentCode.id == code_entry.id,
                EnrollmentCode.used_at.is_(None),
                EnrollmentCode.is_revoked == False,  # noqa: E712
            )
            .values(used_at=now, used_by_device_id=device.id)
        )
        update_res = await db.execute(update_stmt)
        if getattr(update_res, "rowcount", 0) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Enrollment code has already been redeemed",
            )

        await db.commit()

        logger.info(
            "device_enrolled_successfully",
            device_id=device.id,
            tenant_id=tenant_id,
            hostname=payload.hostname,
        )

        return EnrollDeviceResponse(
            device_id=device.id,
            tenant_id=tenant_id,
            status="ENROLLED",
        )
