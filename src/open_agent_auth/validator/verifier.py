"""Request verifier for validating agent signatures."""

from datetime import datetime
from typing import Optional

import httpx

from ..core.errors import (
    CapabilityError,
    InvalidSignatureError,
    MissingSignatureError,
)
from ..core.http_sig import Ed25519Verifier
from ..core.models import AgentCertificate, ValidationResult
from ..trust.store import TrustStore
from .chain import CertificateValidator


class AgentVerifier:
    """Verifies agent requests and validates certificates."""

    def __init__(
        self,
        trust_store: TrustStore,
        max_signature_age: int = 300,
    ):
        """Initialize verifier.

        Args:
            trust_store: Trust store with trusted CAs
            max_signature_age: Maximum allowed signature age in seconds
        """
        self.trust_store = trust_store
        self.max_signature_age = max_signature_age
        self.cert_validator = CertificateValidator(trust_store)

    def verify_request(
        self,
        request: httpx.Request,
        required_capability: Optional[str] = None,
    ) -> ValidationResult:
        """Verify an HTTP request from an agent.

        Args:
            request: HTTP request to verify
            required_capability: Required capability (e.g., "can_purchase")

        Returns:
            ValidationResult with validation outcome
        """
        try:
            # Extract signature headers
            signature_input = request.headers.get("Signature-Input")
            signature = request.headers.get("Signature")
            cert_header = request.headers.get("X-Agent-Certificate")

            if not signature_input or not signature:
                return ValidationResult(
                    valid=False, error="Missing signature headers"
                )

            if not cert_header:
                return ValidationResult(
                    valid=False, error="Missing X-Agent-Certificate header"
                )

            # Parse certificate
            try:
                certificate = AgentCertificate.from_base64(cert_header)
            except Exception as e:
                return ValidationResult(
                    valid=False, error=f"Invalid certificate: {str(e)}"
                )

            # Validate certificate chain
            try:
                self.cert_validator.validate_certificate(certificate)
            except Exception as e:
                return ValidationResult(valid=False, error=str(e))

            # Verify request signature
            method = request.method
            url = str(request.url)
            headers_dict = {k.lower(): v for k, v in request.headers.items()}

            verifier = Ed25519Verifier(certificate.agent_public_key)
            is_valid, params = verifier.verify_request(
                method=method,
                url=url,
                headers=headers_dict,
                signature_input=signature_input,
                signature=signature,
                max_age=self.max_signature_age,
            )

            if not is_valid:
                return ValidationResult(valid=False, error="Invalid signature")

            # Check required capability
            if required_capability and not certificate.has_capability(
                required_capability
            ):
                return ValidationResult(
                    valid=False,
                    error=f"Agent does not have required capability: {required_capability}",
                )

            # Return successful validation
            return ValidationResult(
                valid=True,
                agent_id=certificate.agent_identifier,
                account_reference=certificate.account_reference,
                capabilities=certificate.capabilities,
                certificate=certificate,
                validated_at=datetime.now(),
                issuer=certificate.issuer_identifier,
            )

        except Exception as e:
            return ValidationResult(valid=False, error=f"Validation error: {str(e)}")

    def verify_dict(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        required_capability: Optional[str] = None,
    ) -> ValidationResult:
        """Verify request components.

        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            required_capability: Required capability

        Returns:
            ValidationResult with validation outcome
        """
        # Create a fake httpx.Request to reuse verify_request
        request = httpx.Request(method=method, url=url, headers=headers)
        return self.verify_request(request, required_capability)

    def require_capability(self, capability: str):
        """Decorator to require a specific capability.

        Args:
            capability: Required capability name

        Returns:
            Decorator function
        """

        def decorator(func):
            def wrapper(request, *args, **kwargs):
                result = self.verify_request(request, required_capability=capability)
                if not result.valid:
                    raise CapabilityError(result.error or "Capability check failed")
                return func(request, *args, **kwargs)

            return wrapper

        return decorator
