"""Ed25519 Cryptographic Utilities using Python's cryptography library."""

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 keypair.

    Returns:
        tuple[bytes, bytes]: (private_key_bytes, public_key_bytes) in raw byte format.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def construct_canonical_payload(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    request_id: str,
    body: bytes | str = b"",
) -> bytes:
    """Construct the canonical payload string for Ed25519 signature verification according to SECURITY_MODEL.md.

    canonical_payload = HTTP_METHOD + "\n" +
                        REQUEST_PATH + "\n" +
                        TIMESTAMP + "\n" +
                        NONCE + "\n" +
                        REQUEST_ID + "\n" +
                        SHA256(REQUEST_BODY)
    """
    if isinstance(body, str):
        body_bytes = body.encode("utf-8")
    else:
        body_bytes = body

    body_hash = hashlib.sha256(body_bytes).hexdigest()
    canonical_str = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{request_id}\n{body_hash}"
    return canonical_str.encode("utf-8")


def sign_payload(private_key_bytes: bytes, payload: bytes) -> bytes:
    """Sign a byte payload with an Ed25519 private key."""
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.sign(payload)


def verify_ed25519_signature(
    public_key_input: str | bytes,
    signature_input: str | bytes,
    payload: bytes,
) -> bool:
    """Verify an Ed25519 signature against a payload using a public key.

    Supports raw bytes or hex-encoded strings.
    """
    try:
        if isinstance(public_key_input, str):
            public_bytes = bytes.fromhex(public_key_input)
        else:
            public_bytes = public_key_input

        if isinstance(signature_input, str):
            sig_bytes = bytes.fromhex(signature_input)
        else:
            sig_bytes = signature_input

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
