"""Unit tests for Agent Keyring and Ed25519 Local Device Key Storage."""

from cryptography.hazmat.primitives.asymmetric import ed25519

from netra_agent.auth.keyring import (
    get_or_create_device_keypair,
    has_device_keypair,
    load_device_private_key,
)


def test_get_or_create_device_keypair() -> None:
    """Verify device keypair generation and retrieval from local keyring abstraction."""
    priv_bytes, pub_hex = get_or_create_device_keypair()

    assert len(priv_bytes) == 32
    assert len(pub_hex) == 64
    assert has_device_keypair() is True

    # Calling again should retrieve the same keypair
    priv_bytes_2, pub_hex_2 = get_or_create_device_keypair()
    assert priv_bytes == priv_bytes_2
    assert pub_hex == pub_hex_2


def test_load_device_private_key() -> None:
    """Verify loading private key as cryptography Ed25519PrivateKey object."""
    get_or_create_device_keypair()
    key_obj = load_device_private_key()

    assert isinstance(key_obj, ed25519.Ed25519PrivateKey)
