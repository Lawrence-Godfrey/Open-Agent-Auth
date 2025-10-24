"""Exception hierarchy for open-agent-auth."""


class OpenAgentAuthError(Exception):
    """Base exception for all open-agent-auth errors."""

    pass


# Certificate errors
class CertificateError(OpenAgentAuthError):
    """Base exception for certificate-related errors."""

    pass


class CertificateExpiredError(CertificateError):
    """Certificate has expired."""

    pass


class CertificateNotYetValidError(CertificateError):
    """Certificate is not yet valid."""

    pass


class CertificateRevokedError(CertificateError):
    """Certificate has been revoked."""

    pass


class InvalidCertificateSignatureError(CertificateError):
    """Certificate signature is invalid."""

    pass


class UntrustedIssuerError(CertificateError):
    """Certificate issuer is not trusted."""

    pass


class CertificateParseError(CertificateError):
    """Failed to parse certificate."""

    pass


# Signature errors
class SignatureError(OpenAgentAuthError):
    """Base exception for signature-related errors."""

    pass


class InvalidSignatureError(SignatureError):
    """Signature verification failed."""

    pass


class MissingSignatureError(SignatureError):
    """Required signature headers are missing."""

    pass


class ReplayAttackError(SignatureError):
    """Request appears to be a replay attack."""

    pass


class SignatureExpiredError(SignatureError):
    """Signature has expired."""

    pass


# Configuration errors
class ConfigurationError(OpenAgentAuthError):
    """Base exception for configuration errors."""

    pass


class TrustStoreError(ConfigurationError):
    """Trust store configuration or operation error."""

    pass


# Validation errors
class ValidationError(OpenAgentAuthError):
    """Base exception for validation errors."""

    pass


class CapabilityError(ValidationError):
    """Agent does not have required capability."""

    pass
