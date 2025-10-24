"""HTTP Message Signatures (RFC 9421) implementation wrapper."""

import secrets
import time
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    algorithms,
)

from .crypto import private_key_to_bytes, public_key_from_private


class Ed25519Signer:
    """Wrapper for signing HTTP requests with Ed25519."""

    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey,
        key_id: str,
        covered_component_ids: Optional[list[str]] = None,
    ):
        """Initialize signer.

        Args:
            private_key: Ed25519 private key
            key_id: Key identifier (usually agent identifier)
            covered_component_ids: List of components to include in signature
                Default: ["@method", "@authority", "@path", "content-type", "content-digest"]
        """
        self.private_key = private_key
        self.key_id = key_id
        self.covered_component_ids = covered_component_ids or [
            "@method",
            "@authority",
            "@path",
            "content-type",
            "content-digest",
        ]

    def sign_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        tag: str = "agent-browser-auth",
        expires_in: int = 300,
    ) -> dict[str, str]:
        """Sign an HTTP request.

        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            tag: Signature tag (agent-browser-auth or agent-payer-auth)
            expires_in: Signature validity in seconds (default 300 = 5 minutes)

        Returns:
            Dictionary with Signature-Input and Signature headers
        """
        # Generate nonce and timestamps
        nonce = secrets.token_urlsafe(16)
        created = int(time.time())
        expires = created + expires_in

        # Create signature parameters
        signature_params = {
            "created": created,
            "expires": expires,
            "keyid": self.key_id,
            "nonce": nonce,
            "tag": tag,
        }

        # Prepare request for signing
        # http-message-signatures library expects a specific format
        # We'll build the signature input and signature manually for more control

        # Build signature base string according to RFC 9421
        signature_base = self._build_signature_base(
            method=method,
            url=url,
            headers=headers,
            params=signature_params,
        )

        # Sign with Ed25519
        signature_bytes = self.private_key.sign(signature_base.encode("utf-8"))

        # Build Signature-Input header
        covered = " ".join(f'"{c}"' for c in self.covered_component_ids)

        # Build params string
        param_parts = []
        for k, v in signature_params.items():
            if isinstance(v, int):
                param_parts.append(f"{k}={v}")
            else:
                param_parts.append(f'{k}="{v}"')
        params_str = ";".join(param_parts)

        signature_input = f"sig1=({covered});{params_str}"

        # Build Signature header (base64)
        import base64

        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")
        signature_header = f"sig1=:{signature_b64}:"

        return {
            "Signature-Input": signature_input,
            "Signature": signature_header,
        }

    def _build_signature_base(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        params: dict[str, any],
    ) -> str:
        """Build signature base string according to RFC 9421.

        This is a simplified implementation for our specific use case.
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        authority = parsed.netloc
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = []

        # Add covered components
        for component in self.covered_component_ids:
            if component == "@method":
                lines.append(f'"@method": {method.upper()}')
            elif component == "@authority":
                lines.append(f'"@authority": {authority}')
            elif component == "@path":
                lines.append(f'"@path": {path}')
            elif component in headers:
                # Regular header
                header_value = headers[component].strip()
                lines.append(f'"{component}": {header_value}')

        # Add signature parameters
        params_parts = []
        for key in ["created", "expires", "keyid", "nonce", "tag"]:
            if key in params:
                value = params[key]
                if isinstance(value, int):
                    params_parts.append(f"{key}={value}")
                else:
                    params_parts.append(f'{key}="{value}"')

        covered_quoted = " ".join(f'"{c}"' for c in self.covered_component_ids)
        params_line = f'"@signature-params": ({covered_quoted});{";".join(params_parts)}'
        lines.append(params_line)

        return "\n".join(lines)


class Ed25519Verifier:
    """Wrapper for verifying HTTP request signatures with Ed25519."""

    def __init__(self, public_key_bytes: bytes):
        """Initialize verifier.

        Args:
            public_key_bytes: Ed25519 public key (32 bytes)
        """
        self.public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

    def verify_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        signature_input: str,
        signature: str,
        max_age: int = 300,
    ) -> tuple[bool, Optional[dict[str, any]]]:
        """Verify an HTTP request signature.

        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            signature_input: Signature-Input header value
            signature: Signature header value
            max_age: Maximum allowed signature age in seconds

        Returns:
            Tuple of (is_valid, params_dict)
        """
        try:
            # Parse signature input
            params = self._parse_signature_input(signature_input)

            # Check timestamp validity
            current_time = int(time.time())
            created = params.get("created")
            expires = params.get("expires")

            if created is None or expires is None:
                return False, None

            # Check if signature has expired
            if current_time > expires:
                return False, None

            # Check if signature is too old (created)
            if current_time - created > max_age:
                return False, None

            # Extract covered components and rebuild signature base
            covered_components = params.get("covered_components", [])
            signature_base = self._build_signature_base(
                method=method,
                url=url,
                headers=headers,
                covered_components=covered_components,
                params=params,
            )

            # Parse signature (remove sig1=: prefix and : suffix)
            import base64

            sig_value = signature.split(":", 2)[1] if ":" in signature else signature
            signature_bytes = base64.b64decode(sig_value)

            # Verify signature
            self.public_key.verify(signature_bytes, signature_base.encode("utf-8"))

            return True, params

        except Exception:
            return False, None

    def _parse_signature_input(self, signature_input: str) -> dict[str, any]:
        """Parse Signature-Input header.

        Example: sig1=("@method" "@authority" "@path");created=1718206800;expires=1718207100;keyid="agent-123";nonce="abc";tag="agent-payer-auth"
        """
        params = {}

        # Extract sig1=(...) part
        if not signature_input.startswith("sig1=("):
            raise ValueError("Invalid signature input format")

        # Find the closing parenthesis
        paren_end = signature_input.find(")")
        covered_str = signature_input[6:paren_end]  # Extract between sig1=( and )

        # Parse covered components
        covered_components = [
            c.strip().strip('"') for c in covered_str.split() if c.strip()
        ]
        params["covered_components"] = covered_components

        # Parse parameters after the parenthesis
        params_str = signature_input[paren_end + 1 :]
        if params_str.startswith(";"):
            params_str = params_str[1:]

        # Split by ; and parse key=value pairs
        for param in params_str.split(";"):
            if "=" in param:
                key, value = param.split("=", 1)
                key = key.strip()
                value = value.strip()

                # Remove quotes if present
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                # Try to convert to int
                elif value.isdigit():
                    value = int(value)

                params[key] = value

        return params

    def _build_signature_base(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        covered_components: list[str],
        params: dict[str, any],
    ) -> str:
        """Build signature base string for verification."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        authority = parsed.netloc
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = []

        # Add covered components
        for component in covered_components:
            if component == "@method":
                lines.append(f'"@method": {method.upper()}')
            elif component == "@authority":
                lines.append(f'"@authority": {authority}')
            elif component == "@path":
                lines.append(f'"@path": {path}')
            elif component in headers:
                header_value = headers[component].strip()
                lines.append(f'"{component}": {header_value}')

        # Add signature parameters line
        params_parts = []
        for key in ["created", "expires", "keyid", "nonce", "tag"]:
            if key in params and key != "covered_components":
                value = params[key]
                if isinstance(value, int):
                    params_parts.append(f"{key}={value}")
                else:
                    params_parts.append(f'{key}="{value}"')

        covered_quoted = " ".join(f'"{c}"' for c in covered_components)
        params_line = (
            f'"@signature-params": ({covered_quoted});{";".join(params_parts)}'
        )
        lines.append(params_line)

        return "\n".join(lines)
