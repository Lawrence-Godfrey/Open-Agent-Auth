"""Core functionality for open-agent-auth."""

from .crypto import (
    generate_keypair,
    sign,
    verify,
    private_key_to_bytes,
    private_key_from_bytes,
    public_key_from_private,
)
from .errors import (
    OpenAgentAuthError,
    CertificateError,
    CertificateExpiredError,
    CertificateNotYetValidError,
    CertificateRevokedError,
    InvalidCertificateSignatureError,
    UntrustedIssuerError,
    CertificateParseError,
    SignatureError,
    InvalidSignatureError,
    MissingSignatureError,
    ReplayAttackError,
    SignatureExpiredError,
    ConfigurationError,
    TrustStoreError,
    ValidationError,
    CapabilityError,
)
from .http_sig import Ed25519Signer, Ed25519Verifier
from .models import AgentCertificate, ValidationResult

__all__ = [
    # Crypto
    "generate_keypair",
    "sign",
    "verify",
    "private_key_to_bytes",
    "private_key_from_bytes",
    "public_key_from_private",
    # Errors
    "OpenAgentAuthError",
    "CertificateError",
    "CertificateExpiredError",
    "CertificateNotYetValidError",
    "CertificateRevokedError",
    "InvalidCertificateSignatureError",
    "UntrustedIssuerError",
    "CertificateParseError",
    "SignatureError",
    "InvalidSignatureError",
    "MissingSignatureError",
    "ReplayAttackError",
    "SignatureExpiredError",
    "ConfigurationError",
    "TrustStoreError",
    "ValidationError",
    "CapabilityError",
    # HTTP Signatures
    "Ed25519Signer",
    "Ed25519Verifier",
    # Models
    "AgentCertificate",
    "ValidationResult",
]
