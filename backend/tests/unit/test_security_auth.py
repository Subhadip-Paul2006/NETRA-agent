"""Unit tests for Argon2id Password Hashing, JWT Authentication, and Ed25519 Signatures."""

import pytest
from pydantic import ValidationError

from netra_backend.config import Settings
from netra_backend.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from netra_shared.crypto import generate_ed25519_keypair, sign_payload, verify_ed25519_signature


def test_argon2_password_hashing() -> None:
    """Verify Argon2id password hashing and verification."""
    password = "SuperSecurePassword123!"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_access_and_refresh_token_claims() -> None:
    """Verify JWT access and refresh token creation and claims structure."""
    user_id = "usr-12345"
    tenant_id = "tnt-67890"

    access_token = create_access_token(user_id=user_id, tenant_id=tenant_id)
    decoded_access = decode_token(access_token, expected_type="access")

    assert decoded_access["sub"] == user_id
    assert decoded_access["tenant_id"] == tenant_id
    assert decoded_access["type"] == "access"
    assert "jti" in decoded_access
    assert decoded_access["iss"] == "netra-backend"
    assert decoded_access["aud"] == "netra-client"

    refresh_token = create_refresh_token(user_id=user_id)
    decoded_refresh = decode_token(refresh_token, expected_type="refresh")

    assert decoded_refresh["sub"] == user_id
    assert decoded_refresh["type"] == "refresh"


def test_jwt_token_type_mismatch_rejected() -> None:
    """Verify presenting an access token where refresh token is expected fails validation."""
    access_token = create_access_token(user_id="usr-12345")

    with pytest.raises(ValueError) as exc_info:
        decode_token(access_token, expected_type="refresh")

    assert "Invalid token type" in str(exc_info.value)


def test_ed25519_crypto_utilities() -> None:
    """Verify Ed25519 keypair generation, signing, and signature verification."""
    private_key, public_key = generate_ed25519_keypair()
    payload = b"GET /api/v1/agent/connect HTTP/1.1\nNonce: 12345"

    signature = sign_payload(private_key, payload)

    # Valid signature
    assert verify_ed25519_signature(public_key, signature, payload) is True
    assert verify_ed25519_signature(public_key.hex(), signature.hex(), payload) is True

    # Invalid payload or signature
    assert verify_ed25519_signature(public_key, signature, b"TamperedPayload") is False


def test_production_secret_validation_rules() -> None:
    """Verify production mode rejects missing, placeholder, or weak JWT secrets."""
    # Missing secret
    with pytest.raises(ValidationError):
        Settings(env="production", database_url="postgresql+asyncpg://u:p@db/db")

    # Placeholder secret
    with pytest.raises(ValidationError):
        Settings(
            env="production",
            database_url="postgresql+asyncpg://u:p@db/db",
            jwt_secret="change_this_to_something_secret_32_chars!",
            jwt_refresh_secret="netra_prod_refresh_secret_key_32chars!",
        )

    # Weak secret (under 32 chars)
    with pytest.raises(ValidationError):
        Settings(
            env="production",
            database_url="postgresql+asyncpg://u:p@db/db",
            jwt_secret="short_secret",
            jwt_refresh_secret="netra_prod_refresh_secret_key_32chars!",
        )
