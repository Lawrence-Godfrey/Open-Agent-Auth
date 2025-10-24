"""Trust store for managing trusted certificate authorities."""

import base64
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from ..core.errors import TrustStoreError


class TrustedCA(BaseModel):
    """Represents a trusted certificate authority."""

    identifier: str = Field(description="CA identifier (e.g., domain)")
    name: str = Field(description="Human-readable CA name")
    public_key: bytes = Field(description="CA's Ed25519 public key")
    enabled: bool = Field(default=True, description="Whether CA is enabled")

    model_config = {
        "json_encoders": {
            bytes: lambda v: f"ed25519:{base64.b64encode(v).decode('utf-8')}"
        }
    }


class TrustStoreConfig(BaseModel):
    """Trust store configuration."""

    version: str = Field(default="1.0")
    trusted_cas: list[TrustedCA] = Field(default_factory=list)


class TrustStore:
    """Manages trusted certificate authorities."""

    def __init__(self):
        """Initialize an empty trust store."""
        self._cas: dict[str, TrustedCA] = {}

    def add_trusted_ca(
        self, identifier: str, public_key: bytes, name: str, enabled: bool = True
    ) -> None:
        """Add a trusted CA to the store.

        Args:
            identifier: CA identifier (e.g., "bank.example.com")
            public_key: CA's Ed25519 public key (32 bytes)
            name: Human-readable name
            enabled: Whether the CA is enabled (default True)
        """
        ca = TrustedCA(
            identifier=identifier, name=name, public_key=public_key, enabled=enabled
        )
        self._cas[identifier] = ca

    def remove_trusted_ca(self, identifier: str) -> None:
        """Remove a CA from the trust store.

        Args:
            identifier: CA identifier to remove
        """
        if identifier in self._cas:
            del self._cas[identifier]

    def get_ca(self, identifier: str) -> Optional[TrustedCA]:
        """Get a CA by identifier.

        Args:
            identifier: CA identifier

        Returns:
            TrustedCA if found and enabled, None otherwise
        """
        ca = self._cas.get(identifier)
        if ca and ca.enabled:
            return ca
        return None

    def is_trusted(self, identifier: str) -> bool:
        """Check if a CA is trusted.

        Args:
            identifier: CA identifier

        Returns:
            True if CA is trusted and enabled
        """
        return self.get_ca(identifier) is not None

    def get_public_key(self, identifier: str) -> Optional[bytes]:
        """Get the public key for a CA.

        Args:
            identifier: CA identifier

        Returns:
            Public key bytes if CA is trusted, None otherwise
        """
        ca = self.get_ca(identifier)
        return ca.public_key if ca else None

    def list_cas(self) -> list[TrustedCA]:
        """List all CAs in the trust store.

        Returns:
            List of all CAs (including disabled ones)
        """
        return list(self._cas.values())

    @classmethod
    def from_config(cls, config_path: str | Path) -> "TrustStore":
        """Load trust store from a YAML configuration file.

        Args:
            config_path: Path to YAML config file

        Returns:
            TrustStore instance

        Raises:
            TrustStoreError: If config file cannot be loaded or parsed
        """
        try:
            config_path = Path(config_path)
            if not config_path.exists():
                raise TrustStoreError(f"Config file not found: {config_path}")

            with open(config_path, "r") as f:
                data = yaml.safe_load(f)

            store = cls()

            # Parse trusted CAs
            for ca_data in data.get("trusted_cas", []):
                # Parse public key (format: "ed25519:BASE64")
                public_key_str = ca_data["public_key"]
                if public_key_str.startswith("ed25519:"):
                    public_key_b64 = public_key_str[8:]  # Remove "ed25519:" prefix
                else:
                    public_key_b64 = public_key_str

                public_key = base64.b64decode(public_key_b64)

                store.add_trusted_ca(
                    identifier=ca_data["identifier"],
                    name=ca_data["name"],
                    public_key=public_key,
                    enabled=ca_data.get("enabled", True),
                )

            return store

        except Exception as e:
            raise TrustStoreError(f"Failed to load trust store: {e}")

    def save(self, config_path: str | Path) -> None:
        """Save trust store to a YAML configuration file.

        Args:
            config_path: Path to save YAML config
        """
        config_path = Path(config_path)

        # Build config data
        data = {
            "version": "1.0",
            "trusted_cas": [
                {
                    "identifier": ca.identifier,
                    "name": ca.name,
                    "public_key": f"ed25519:{base64.b64encode(ca.public_key).decode('utf-8')}",
                    "enabled": ca.enabled,
                }
                for ca in self._cas.values()
            ],
        }

        with open(config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
