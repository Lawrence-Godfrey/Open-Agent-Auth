"""Open Agent Auth - Decentralized agent authentication for agentic commerce."""

from .agent import AgentSigner
from .core import (
    AgentCertificate,
    ValidationResult,
    generate_keypair,
    private_key_from_bytes,
    private_key_to_bytes,
)
from .trust import TrustStore
from .validator import AgentVerifier, CertificateValidator

__version__ = "0.1.0"

__all__ = [
    # Agent
    "AgentSigner",
    # Core
    "AgentCertificate",
    "ValidationResult",
    "generate_keypair",
    "private_key_from_bytes",
    "private_key_to_bytes",
    # Trust
    "TrustStore",
    # Validator
    "AgentVerifier",
    "CertificateValidator",
]
