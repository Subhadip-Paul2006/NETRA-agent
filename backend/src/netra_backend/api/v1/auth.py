"""NETRA Backend Authentication API Endpoints.

Implements /api/v1/auth/login, /api/v1/auth/refresh, and /api/v1/auth/logout.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra_backend.config import get_settings
from netra_backend.database import get_db_session
from netra_backend.logging import get_logger
from netra_backend.models import TenantMembership, User, UserSession
from netra_backend.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_token,
    verify_password,
)

logger = get_logger(__name__)
router = APIRouter(tags=["Authentication"])


class LoginRequest(BaseModel):
    """User login request payload."""

    email: EmailStr
    password: str = Field(min_length=1)
    tenant_id: str | None = None


class TokenResponse(BaseModel):
    """Authentication token response payload."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in_seconds: int
    user_id: str
    tenant_id: str | None = None


class RefreshRequest(BaseModel):
    """Refresh token request payload."""

    refresh_token: str


class LogoutRequest(BaseModel):
    """Logout request payload."""

    refresh_token: str


@router.post("/login", summary="User Login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> TokenResponse:
    """Authenticate user credentials and issue access and refresh tokens."""
    settings = get_settings()

    # Query user by email
    stmt = select(User).where(User.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    # Generic security error response (prevents account enumeration)
    invalid_credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
    )

    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        client_ip = request.client.host if request.client else "unknown"
        logger.warning("failed_login_attempt", email=payload.email, ip=client_ip)
        raise invalid_credentials_exc

    # Determine tenant context if provided, or pick user's first tenant membership
    target_tenant_id = payload.tenant_id
    if not target_tenant_id:
        membership_stmt = (
            select(TenantMembership.tenant_id).where(TenantMembership.user_id == user.id).limit(1)
        )
        mem_res = await db.execute(membership_stmt)
        target_tenant_id = mem_res.scalar_one_or_none()

    # Issue access and refresh tokens
    access_token = create_access_token(user_id=user.id, tenant_id=target_tenant_id)
    refresh_token = create_refresh_token(user_id=user.id)
    rf_hash = hash_token(refresh_token)

    now = datetime.now(UTC)
    expires_at = now + timedelta(days=settings.jwt_refresh_expiration_days)

    # Record UserSession in database
    session = UserSession(
        user_id=user.id,
        refresh_token_hash=rf_hash,
        ip_address=request.client.host if request.client else "127.0.0.1",
        user_agent=request.headers.get("user-agent", "unknown"),
        expires_at=expires_at,
    )
    db.add(session)

    # Update user last_login_at
    user.last_login_at = now
    await db.commit()

    logger.info("user_login_success", user_id=user.id, tenant_id=target_tenant_id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in_seconds=settings.jwt_access_expiration_minutes * 60,
        user_id=user.id,
        tenant_id=target_tenant_id,
    )


@router.post("/refresh", summary="Rotate Refresh Token", response_model=TokenResponse)
async def refresh_tokens(
    payload: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> TokenResponse:
    """Validate refresh token, check revocation, rotate token, and issue new access token."""
    settings = get_settings()

    try:
        decoded = decode_token(payload.refresh_token, expected_type="refresh")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        ) from exc

    user_id = decoded["sub"]
    rf_hash = hash_token(payload.refresh_token)

    # Query UserSession
    stmt = select(UserSession).where(UserSession.refresh_token_hash == rf_hash)
    result = await db.execute(stmt)
    user_session = result.scalar_one_or_none()

    # Reuse detection / revocation handling
    if not user_session or user_session.revoked_at is not None:
        # SECURITY CRITICAL: If a revoked token is re-submitted, revoke ALL sessions for this user
        logger.error("refresh_token_reuse_detected", user_id=user_id)
        revoke_all_stmt = select(UserSession).where(UserSession.user_id == user_id)
        user_sessions = (await db.execute(revoke_all_stmt)).scalars().all()
        now = datetime.now(UTC)
        for s in user_sessions:
            s.revoked_at = now
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked refresh token",
        )

    # Check session expiration
    now = datetime.now(UTC)
    session_expires_at = user_session.expires_at
    if session_expires_at.tzinfo is None:
        session_expires_at = session_expires_at.replace(tzinfo=UTC)

    if session_expires_at < now:
        user_session.revoked_at = now
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expired refresh token session",
        )

    # Rotate refresh token
    new_access_token = create_access_token(user_id=user_id)
    new_refresh_token = create_refresh_token(user_id=user_id)
    new_rf_hash = hash_token(new_refresh_token)

    # Update session with rotated refresh token hash and new expiration
    user_session.refresh_token_hash = new_rf_hash
    user_session.expires_at = now + timedelta(days=settings.jwt_refresh_expiration_days)
    await db.commit()

    logger.info("refresh_token_rotated_success", user_id=user_id)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in_seconds=settings.jwt_access_expiration_minutes * 60,
        user_id=user_id,
    )


@router.post("/logout", summary="User Logout")
async def logout(
    payload: LogoutRequest,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Revoke user refresh session."""
    rf_hash = hash_token(payload.refresh_token)
    stmt = select(UserSession).where(UserSession.refresh_token_hash == rf_hash)
    result = await db.execute(stmt)
    user_session = result.scalar_one_or_none()

    if user_session and user_session.revoked_at is None:
        user_session.revoked_at = datetime.now(UTC)
        await db.commit()

    return {"success": True, "message": "Successfully logged out"}
