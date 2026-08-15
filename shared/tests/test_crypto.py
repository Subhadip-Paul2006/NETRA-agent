"""Unit tests for Ed25519 cryptographic utilities and canonical payload construction."""

import time
import uuid

from netra_shared.crypto import (
    construct_canonical_payload,
    generate_ed25519_keypair,
    sign_payload,
    verify_ed25519_signature,
)


def test_ed25519_keypair_generation_and_verification() -> None:
    """Verify Ed25519 keypair generation and signature verification."""
    priv_bytes, pub_bytes = generate_ed25519_keypair()
    assert len(priv_bytes) == 32
    assert len(pub_bytes) == 32

    payload = b"Hello NETRA Enterprise Security Engine"
    signature = sign_payload(priv_bytes, payload)
    assert len(signature) == 64

    # Verification with byte inputs
    assert verify_ed25519_signature(pub_bytes, signature, payload) is True

    # Verification with hex inputs
    pub_hex = pub_bytes.hex()
    sig_hex = signature.hex()
    assert verify_ed25519_signature(pub_hex, sig_hex, payload) is True


def test_tampered_payload_signature_rejection() -> None:
    """Verify tampered payload fails signature verification."""
    priv_bytes, pub_bytes = generate_ed25519_keypair()
    original_payload = b"Original NETRA Payload"
    signature = sign_payload(priv_bytes, original_payload)

    tampered_payload = b"Tampered NETRA Payload"
    assert verify_ed25519_signature(pub_bytes, signature, tampered_payload) is False


def test_canonical_payload_construction_and_signing() -> None:
    """Verify canonical payload string construction and Ed25519 signing."""
    priv_bytes, pub_bytes = generate_ed25519_keypair()

    method = "GET"
    path = "/api/v1/agent/connect"
    timestamp = str(time.time())
    nonce = str(uuid.uuid4())
    request_id = f"req_{uuid.uuid4().hex[:16]}"
    body = b'{"status": "ok"}'

    canonical_bytes = construct_canonical_payload(
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        request_id=request_id,
        body=body,
    )

    signature = sign_payload(priv_bytes, canonical_bytes)
    assert verify_ed25519_signature(pub_bytes, signature, canonical_bytes) is True
