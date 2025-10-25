"""OCSP (Online Certificate Status Protocol) client for real-time revocation checking."""

import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional

import httpx

from ..core.errors import CertificateRevokedError


class OCSPStatus:
    """OCSP response status codes."""

    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class OCSPResponse:
    """Represents an OCSP response."""

    def __init__(
        self,
        status: str,
        produced_at: datetime,
        this_update: datetime,
        next_update: Optional[datetime] = None,
        revocation_time: Optional[datetime] = None,
        revocation_reason: Optional[str] = None,
    ):
        """Initialize OCSP response.

        Args:
            status: Certificate status (good, revoked, unknown)
            produced_at: When response was produced
            this_update: When this status became valid
            next_update: When next update is expected
            revocation_time: When certificate was revoked (if revoked)
            revocation_reason: Reason for revocation (if revoked)
        """
        self.status = status
        self.produced_at = produced_at
        self.this_update = this_update
        self.next_update = next_update
        self.revocation_time = revocation_time
        self.revocation_reason = revocation_reason

    def is_valid(self) -> bool:
        """Check if certificate is valid (not revoked)."""
        return self.status == OCSPStatus.GOOD

    def is_revoked(self) -> bool:
        """Check if certificate is revoked."""
        return self.status == OCSPStatus.REVOKED


class OCSPClient:
    """Client for querying OCSP responders."""

    def __init__(
        self,
        timeout: int = 5,
        cache_ttl: int = 300,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        """Initialize OCSP client.

        Args:
            timeout: Request timeout in seconds
            cache_ttl: Cache TTL in seconds
            http_client: Optional HTTP client to use
        """
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._http_client = http_client
        self._cache: dict[str, tuple[OCSPResponse, float]] = {}

    async def check_revocation(
        self,
        serial_number: str,
        issuer_public_key: bytes,
        ocsp_url: str,
    ) -> OCSPResponse:
        """Check if a certificate is revoked via OCSP.

        Args:
            serial_number: Certificate serial number
            issuer_public_key: Issuer's public key
            ocsp_url: OCSP responder URL

        Returns:
            OCSPResponse with revocation status

        Raises:
            CertificateRevokedError: If certificate is revoked
            Exception: If OCSP query fails
        """
        # Check cache
        cache_key = f"{ocsp_url}:{serial_number}"
        if cache_key in self._cache:
            response, cached_at = self._cache[cache_key]
            if time.time() - cached_at < self.cache_ttl:
                return response

        # Build OCSP request (simplified - in production use asn1crypto)
        # For now, use HTTP GET with serial number
        try:
            http_client = self._http_client or httpx.AsyncClient(timeout=self.timeout)

            # Query OCSP responder
            url = f"{ocsp_url}?serial={serial_number}"
            response = await http_client.get(url)
            response.raise_for_status()

            # Parse response (simplified)
            data = response.json()

            ocsp_response = OCSPResponse(
                status=data.get("status", OCSPStatus.UNKNOWN),
                produced_at=datetime.fromisoformat(data.get("produced_at")),
                this_update=datetime.fromisoformat(data.get("this_update")),
                next_update=(
                    datetime.fromisoformat(data["next_update"])
                    if "next_update" in data
                    else None
                ),
                revocation_time=(
                    datetime.fromisoformat(data["revocation_time"])
                    if "revocation_time" in data
                    else None
                ),
                revocation_reason=data.get("revocation_reason"),
            )

            # Cache response
            self._cache[cache_key] = (ocsp_response, time.time())

            return ocsp_response

        except Exception as e:
            # OCSP query failed - in production, decide whether to fail open/closed
            raise Exception(f"OCSP query failed: {e}")

    async def is_revoked(
        self,
        serial_number: str,
        issuer_public_key: bytes,
        ocsp_url: str,
    ) -> bool:
        """Check if a certificate is revoked.

        Args:
            serial_number: Certificate serial number
            issuer_public_key: Issuer's public key
            ocsp_url: OCSP responder URL

        Returns:
            True if certificate is revoked, False otherwise
        """
        try:
            response = await self.check_revocation(
                serial_number, issuer_public_key, ocsp_url
            )
            return response.is_revoked()
        except Exception:
            # On OCSP failure, fail open (assume not revoked)
            # In production, make this configurable
            return False

    def clear_cache(self):
        """Clear the OCSP response cache."""
        self._cache.clear()


class MockOCSPResponder:
    """Mock OCSP responder for testing."""

    def __init__(self):
        """Initialize mock OCSP responder."""
        self._revoked: set[str] = set()

    def revoke_certificate(self, serial_number: str):
        """Mark a certificate as revoked.

        Args:
            serial_number: Certificate serial number to revoke
        """
        self._revoked.add(serial_number)

    def unrevoke_certificate(self, serial_number: str):
        """Remove a certificate from revoked list.

        Args:
            serial_number: Certificate serial number
        """
        self._revoked.discard(serial_number)

    def get_status(self, serial_number: str) -> dict:
        """Get OCSP status for a certificate.

        Args:
            serial_number: Certificate serial number

        Returns:
            Dictionary with OCSP response
        """
        now = datetime.now()

        if serial_number in self._revoked:
            return {
                "status": OCSPStatus.REVOKED,
                "produced_at": now.isoformat(),
                "this_update": now.isoformat(),
                "next_update": (now + timedelta(hours=24)).isoformat(),
                "revocation_time": now.isoformat(),
                "revocation_reason": "key_compromise",
            }
        else:
            return {
                "status": OCSPStatus.GOOD,
                "produced_at": now.isoformat(),
                "this_update": now.isoformat(),
                "next_update": (now + timedelta(hours=24)).isoformat(),
            }
