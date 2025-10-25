"""Certificate chain validation."""

from datetime import datetime
from typing import Optional

from ..core.crypto import verify
from ..core.errors import (
    CertificateExpiredError,
    CertificateNotYetValidError,
    CertificateRevokedError,
    InvalidCertificateSignatureError,
    UntrustedIssuerError,
)
from ..core.models import AgentCertificate
from ..trust.ocsp import OCSPClient
from ..trust.store import TrustStore


class CertificateValidator:
    """Validates agent certificates against a trust store."""

    def __init__(
        self,
        trust_store: TrustStore,
        check_ocsp: bool = False,
        ocsp_client: Optional[OCSPClient] = None,
    ):
        """Initialize validator.

        Args:
            trust_store: Trust store with trusted CAs
            check_ocsp: Whether to check OCSP for revocation
            ocsp_client: Optional OCSP client (creates default if not provided)
        """
        self.trust_store = trust_store
        self.check_ocsp = check_ocsp
        self.ocsp_client = ocsp_client or OCSPClient() if check_ocsp else None

    def validate_certificate(
        self, certificate: AgentCertificate, now: Optional[datetime] = None
    ) -> None:
        """Validate a certificate (synchronous, no OCSP check).

        Args:
            certificate: Certificate to validate
            now: Current time (default: datetime.now())

        Raises:
            UntrustedIssuerError: If certificate issuer is not trusted
            CertificateExpiredError: If certificate has expired
            CertificateNotYetValidError: If certificate is not yet valid
            InvalidCertificateSignatureError: If certificate signature is invalid
        """
        if now is None:
            now = datetime.now()

        # Check if issuer is trusted
        issuer_public_key = self.trust_store.get_public_key(
            certificate.issuer_identifier
        )
        if issuer_public_key is None:
            raise UntrustedIssuerError(
                f"Certificate issuer not trusted: {certificate.issuer_identifier}"
            )

        # Verify issuer public key matches certificate
        if issuer_public_key != certificate.issuer_public_key:
            raise InvalidCertificateSignatureError(
                "Issuer public key mismatch with trust store"
            )

        # Check validity period
        if now < certificate.not_before:
            raise CertificateNotYetValidError(
                f"Certificate not yet valid (not_before: {certificate.not_before})"
            )

        if now > certificate.not_after:
            raise CertificateExpiredError(
                f"Certificate expired (not_after: {certificate.not_after})"
            )

        # Verify certificate signature
        signing_payload = certificate.get_signing_payload()
        if not verify(
            certificate.issuer_public_key, signing_payload, certificate.signature
        ):
            raise InvalidCertificateSignatureError("Certificate signature verification failed")

    async def validate_certificate_with_ocsp(
        self, certificate: AgentCertificate, now: Optional[datetime] = None
    ) -> None:
        """Validate a certificate including OCSP revocation check.

        Args:
            certificate: Certificate to validate
            now: Current time (default: datetime.now())

        Raises:
            UntrustedIssuerError: If certificate issuer is not trusted
            CertificateExpiredError: If certificate has expired
            CertificateNotYetValidError: If certificate is not yet valid
            InvalidCertificateSignatureError: If certificate signature is invalid
            CertificateRevokedError: If certificate has been revoked
        """
        # First do standard validation
        self.validate_certificate(certificate, now)

        # Then check OCSP if enabled and URL provided
        if self.check_ocsp and self.ocsp_client and certificate.ocsp_url:
            try:
                is_revoked = await self.ocsp_client.is_revoked(
                    certificate.serial_number,
                    certificate.issuer_public_key,
                    certificate.ocsp_url,
                )
                if is_revoked:
                    raise CertificateRevokedError(
                        f"Certificate {certificate.serial_number} has been revoked"
                    )
            except CertificateRevokedError:
                raise
            except Exception:
                # OCSP check failed - fail open by default
                # In production, make this configurable
                pass

    def is_valid(self, certificate: AgentCertificate) -> bool:
        """Check if a certificate is valid.

        Args:
            certificate: Certificate to check

        Returns:
            True if certificate is valid, False otherwise
        """
        try:
            self.validate_certificate(certificate)
            return True
        except Exception:
            return False
