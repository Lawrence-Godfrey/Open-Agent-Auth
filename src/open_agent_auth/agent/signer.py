"""Agent request signer."""

from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
import httpx

from ..core.errors import CertificateExpiredError
from ..core.http_sig import Ed25519Signer
from ..core.models import AgentCertificate


class AgentSigner:
    """Signs HTTP requests for agents using Web Bot Auth protocol."""

    def __init__(
        self,
        certificate: AgentCertificate,
        private_key: ed25519.Ed25519PrivateKey,
        covered_headers: Optional[list[str]] = None,
    ):
        """Initialize agent signer.

        Args:
            certificate: Agent's certificate
            private_key: Agent's private key
            covered_headers: Headers to include in signature
                Default: ["@method", "@authority", "@path", "content-type", "content-digest"]
        """
        self.certificate = certificate
        self.private_key = private_key

        # Create HTTP signature signer
        self.http_signer = Ed25519Signer(
            private_key=private_key,
            key_id=certificate.agent_identifier,
            covered_component_ids=covered_headers,
        )

    def sign_request(
        self,
        request: httpx.Request,
        tag: str = "agent-browser-auth",
        expires_in: int = 300,
    ) -> httpx.Request:
        """Sign an HTTP request.

        Args:
            request: HTTP request to sign
            tag: Signature tag (agent-browser-auth or agent-payer-auth)
            expires_in: Signature validity in seconds (default 300 = 5 minutes)

        Returns:
            New request with signature headers added

        Raises:
            CertificateExpiredError: If certificate has expired
        """
        # Check if certificate is still valid
        if not self.certificate.is_valid():
            raise CertificateExpiredError("Agent certificate has expired")

        # Get request details
        method = request.method
        url = str(request.url)

        # Convert headers to dict (lowercase keys)
        headers_dict = {k.lower(): v for k, v in request.headers.items()}

        # Sign request
        signature_headers = self.http_signer.sign_request(
            method=method, url=url, headers=headers_dict, tag=tag, expires_in=expires_in
        )

        # Add certificate to headers (base64 encoded)
        signature_headers["X-Agent-Certificate"] = self.certificate.to_base64()

        # Create new request with added headers
        new_headers = dict(request.headers)
        new_headers.update(signature_headers)

        return httpx.Request(
            method=request.method,
            url=request.url,
            headers=new_headers,
            content=request.content,
        )

    def sign_dict(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        tag: str = "agent-browser-auth",
        expires_in: int = 300,
    ) -> dict[str, str]:
        """Sign request components and return signature headers.

        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            tag: Signature tag
            expires_in: Signature validity in seconds

        Returns:
            Dictionary with Signature-Input, Signature, and X-Agent-Certificate headers
        """
        # Check if certificate is still valid
        if not self.certificate.is_valid():
            raise CertificateExpiredError("Agent certificate has expired")

        # Sign request
        signature_headers = self.http_signer.sign_request(
            method=method, url=url, headers=headers, tag=tag, expires_in=expires_in
        )

        # Add certificate
        signature_headers["X-Agent-Certificate"] = self.certificate.to_base64()

        return signature_headers
