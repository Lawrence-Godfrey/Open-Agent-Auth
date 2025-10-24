"""Cryptographic operations using Ed25519."""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, bytes]:
    """Generate a new Ed25519 keypair.

    Returns:
        Tuple of (private_key, public_key_bytes)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return private_key, public_key_bytes


def sign(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign a message with Ed25519 private key.

    Args:
        private_key: Ed25519 private key
        message: Message to sign

    Returns:
        Signature bytes
    """
    return private_key.sign(message)


def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key_bytes: Ed25519 public key (32 bytes)
        message: Original message
        signature: Signature to verify

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def private_key_to_bytes(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Serialize private key to bytes.

    Args:
        private_key: Ed25519 private key

    Returns:
        Private key bytes (32 bytes)
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_key_from_bytes(key_bytes: bytes) -> ed25519.Ed25519PrivateKey:
    """Load private key from bytes.

    Args:
        key_bytes: Private key bytes (32 bytes)

    Returns:
        Ed25519 private key
    """
    return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)


def public_key_from_private(
    private_key: ed25519.Ed25519PrivateKey,
) -> bytes:
    """Extract public key bytes from private key.

    Args:
        private_key: Ed25519 private key

    Returns:
        Public key bytes (32 bytes)
    """
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
