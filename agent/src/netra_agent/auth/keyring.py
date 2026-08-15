"""NETRA Agent Local Ed25519 Keypair and OS Protected Keyring Module.

Generates host Ed25519 keypairs and stores private keys in OS credential manager.
Private keys NEVER leave the local host machine.
"""

import keyring
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

KEYRING_SERVICE_NAME = "netra_agent_ed25519"
KEYRING_USERNAME = "host_device_private_key"

# In-memory fallback dictionary for testing or head-less CI environments without OS Keyring daemon
_in_memory_key_store: dict[str, str] = {}


def _store_private_key_pem(pem_str: str) -> None:
    """Store private key PEM string in OS protected credential manager with fallback."""
    try:
        keyring.set_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME, pem_str)
    except Exception:
        _in_memory_key_store[KEYRING_USERNAME] = pem_str


def _retrieve_private_key_pem() -> str | None:
    """Retrieve private key PEM string from OS protected credential manager with fallback."""
    try:
        val = keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME)
        if val:
            return val
    except Exception:
        pass
    return _in_memory_key_store.get(KEYRING_USERNAME)


def get_or_create_device_keypair() -> tuple[bytes, str]:
    """Retrieve existing local Ed25519 device keypair or generate a new keypair.

    Returns:
        tuple[bytes, str]: (private_key_bytes, public_key_hex_string)
    """
    pem_str = _retrieve_private_key_pem()

    if pem_str:
        private_key = serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ValueError("Stored key is not a valid Ed25519PrivateKey")
    else:
        # Generate new Ed25519 private key
        private_key = ed25519.Ed25519PrivateKey.generate()
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pem_str = pem_bytes.decode("utf-8")
        _store_private_key_pem(pem_str)

    # Derive public key
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = pub_bytes.hex()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return priv_bytes, pub_hex


def load_device_private_key() -> ed25519.Ed25519PrivateKey:
    """Load local device Ed25519 private key object."""
    pem_str = _retrieve_private_key_pem()
    if not pem_str:
        raise ValueError("No local device keypair found. Run 'netra enroll' first.")

    key = serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("Invalid key format")
    return key


def has_device_keypair() -> bool:
    """Check if local host machine has an enrolled Ed25519 keypair."""
    return _retrieve_private_key_pem() is not None
