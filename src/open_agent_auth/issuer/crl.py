"""CRL generator for Certificate Authorities."""

from datetime import datetime, timedelta
from typing import Optional


class CRLGenerator:
    """Generates Certificate Revocation Lists for CAs."""

    def __init__(self, validity_period: int = 86400):
        """Initialize CRL generator.

        Args:
            validity_period: CRL validity in seconds (default: 24 hours)
        """
        self.validity_period = validity_period
        self._revoked: dict[str, dict] = {}

    def revoke_certificate(
        self,
        serial_number: str,
        revocation_time: Optional[datetime] = None,
        reason: str = "unspecified",
    ):
        """Add certificate to revocation list.

        Args:
            serial_number: Certificate serial number
            revocation_time: When revoked (default: now)
            reason: Revocation reason
        """
        self._revoked[serial_number] = {
            "revocation_time": revocation_time or datetime.now(),
            "reason": reason,
        }

    def unrevoke_certificate(self, serial_number: str):
        """Remove certificate from CRL (for testing)."""
        if serial_number in self._revoked:
            del self._revoked[serial_number]

    def generate_crl(self) -> dict:
        """Generate CRL.

        Returns:
            Dictionary with CRL data
        """
        now = datetime.now()
        return {
            "version": "1.0",
            "issuer": "CA",
            "this_update": now.isoformat(),
            "next_update": (now + timedelta(seconds=self.validity_period)).isoformat(),
            "revoked": list(self._revoked.keys()),
            "revocation_details": {
                serial: {
                    "revocation_time": info["revocation_time"].isoformat(),
                    "reason": info["reason"],
                }
                for serial, info in self._revoked.items()
            },
        }

    def is_revoked(self, serial_number: str) -> bool:
        """Check if certificate is revoked."""
        return serial_number in self._revoked

    def get_revoked_count(self) -> int:
        """Get count of revoked certificates."""
        return len(self._revoked)
