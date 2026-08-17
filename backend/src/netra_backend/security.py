"""NETRA Security, Password Hashing (Argon2id), and JWT Token Module."""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError

from netra_backend.config import get_settings

ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against an Argon2id hash."""
    try:
        return ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def hash_token(raw_token: str) -> str:
    """Derive SHA-256 hash string for raw refresh token session indexing."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_access_token(user_id: str, tenant_id: str | None = None, role: str | None = None) -> str:
    """Create a signed JWT access token.

    Claims: sub, tenant_id, role, type="access", iat, exp, jti, iss, aud.
    """
    settings = get_settings()
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=settings.jwt_access_expiration_minutes)

    payload: dict[str, Any] = {
        "sub": user_id,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": uuid.uuid4().hex,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    if tenant_id:
        payload["tenant_id"] = tenant_id
    if role:
        payload["role"] = role

    secret = settings.jwt_secret
    if not secret:
        raise ValueError("JWT secret is not configured.")

    return jwt.encode(payload, secret, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: str) -> str:
    """Create a signed JWT refresh token.

    Claims: sub, type="refresh", iat, exp, jti, iss, aud.
    """
    settings = get_settings()
    now = datetime.now(UTC)
    expires_at = now + timedelta(days=settings.jwt_refresh_expiration_days)

    payload: dict[str, Any] = {
        "sub": user_id,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": uuid.uuid4().hex,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }

    secret = settings.jwt_refresh_secret or settings.jwt_secret
    if not secret:
        raise ValueError("JWT refresh secret is not configured.")

    return jwt.encode(payload, secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    """Decode and validate a JWT token, asserting signature, expiration, issuer, audience, and type.

    Raises:
        ValueError: If token is expired, invalid, or type mismatch.
    """
    settings = get_settings()
    secrets_to_try: list[str] = []
    if expected_type == "refresh" and settings.jwt_refresh_secret:
        secrets_to_try.append(settings.jwt_refresh_secret)
    if settings.jwt_secret:
        secrets_to_try.append(settings.jwt_secret)

    payload = None
    last_exc: Exception | None = None
    for secret in secrets_to_try:
        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=[settings.jwt_algorithm],
                issuer=settings.jwt_issuer,
                audience=settings.jwt_audience,
            )
            break
        except jwt.PyJWTError as exc:
            last_exc = exc

    if payload is None:
        raise ValueError(f"Invalid authentication token: {last_exc}") from last_exc

    if payload.get("type") != expected_type:
        actual_type = payload.get("type")
        raise ValueError(f"Invalid token type: expected '{expected_type}', got '{actual_type}'")

    return payload
