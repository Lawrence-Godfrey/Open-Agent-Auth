"""OCSP responder implementation for Certificate Authorities."""

from datetime import datetime, timedelta
from typing import Optional

from ..trust.ocsp import OCSPStatus


class OCSPResponder:
    """OCSP responder for CAs to answer revocation queries."""

    def __init__(self, validity_period: int = 86400):
        """Initialize OCSP responder.

        Args:
            validity_period: How long OCSP responses are valid (seconds)
        """
        self.validity_period = validity_period
        self._revoked: dict[str, dict] = {}

    def revoke_certificate(
        self,
        serial_number: str,
        revocation_time: Optional[datetime] = None,
        reason: str = "unspecified",
    ):
        """Revoke a certificate.

        Args:
            serial_number: Certificate serial number
            revocation_time: When certificate was revoked (default: now)
            reason: Reason for revocation
        """
        self._revoked[serial_number] = {
            "revocation_time": revocation_time or datetime.now(),
            "reason": reason,
        }

    def unrevoke_certificate(self, serial_number: str):
        """Remove certificate from revoked list (for testing).

        Args:
            serial_number: Certificate serial number
        """
        if serial_number in self._revoked:
            del self._revoked[serial_number]

    def respond(self, serial_number: str) -> dict:
        """Generate OCSP response for a certificate.

        Args:
            serial_number: Certificate serial number to check

        Returns:
            Dictionary with OCSP response data
        """
        now = datetime.now()
        next_update = now + timedelta(seconds=self.validity_period)

        if serial_number in self._revoked:
            revocation_info = self._revoked[serial_number]
            return {
                "status": OCSPStatus.REVOKED,
                "produced_at": now.isoformat(),
                "this_update": now.isoformat(),
                "next_update": next_update.isoformat(),
                "revocation_time": revocation_info["revocation_time"].isoformat(),
                "revocation_reason": revocation_info["reason"],
            }
        else:
            return {
                "status": OCSPStatus.GOOD,
                "produced_at": now.isoformat(),
                "this_update": now.isoformat(),
                "next_update": next_update.isoformat(),
            }

    def is_revoked(self, serial_number: str) -> bool:
        """Check if a certificate is revoked.

        Args:
            serial_number: Certificate serial number

        Returns:
            True if revoked, False otherwise
        """
        return serial_number in self._revoked

    def get_revoked_count(self) -> int:
        """Get number of revoked certificates.

        Returns:
            Count of revoked certificates
        """
        return len(self._revoked)
