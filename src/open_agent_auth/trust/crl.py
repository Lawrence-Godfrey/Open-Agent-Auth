"""CRL (Certificate Revocation List) support for batch revocation checking."""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx


class CRLClient:
    """Client for downloading and checking CRLs."""

    def __init__(self, cache_dir: Optional[Path] = None, cache_ttl: int = 3600):
        """Initialize CRL client.

        Args:
            cache_dir: Directory to cache CRLs (default: temp)
            cache_ttl: Cache TTL in seconds (default: 1 hour)
        """
        self.cache_dir = cache_dir or Path("/tmp/open-agent-auth/crl")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = cache_ttl
        self._memory_cache: dict[str, tuple[set[str], float]] = {}

    async def download_crl(self, crl_url: str) -> set[str]:
        """Download CRL from URL.

        Args:
            crl_url: CRL distribution point URL

        Returns:
            Set of revoked certificate serial numbers
        """
        # Check memory cache first
        if crl_url in self._memory_cache:
            revoked_set, cached_at = self._memory_cache[crl_url]
            if time.time() - cached_at < self.cache_ttl:
                return revoked_set

        # Download CRL
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(crl_url)
            response.raise_for_status()
            data = response.json()

        revoked_set = set(data.get("revoked", []))

        # Cache in memory
        self._memory_cache[crl_url] = (revoked_set, time.time())

        return revoked_set

    async def is_revoked(self, serial_number: str, crl_url: str) -> bool:
        """Check if certificate is in CRL.

        Args:
            serial_number: Certificate serial number
            crl_url: CRL URL

        Returns:
            True if revoked, False otherwise
        """
        try:
            revoked_set = await self.download_crl(crl_url)
            return serial_number in revoked_set
        except Exception:
            # CRL download failed - fail open
            return False

    def clear_cache(self):
        """Clear CRL cache."""
        self._memory_cache.clear()
