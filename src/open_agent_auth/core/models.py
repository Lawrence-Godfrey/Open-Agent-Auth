"""Core data models for open-agent-auth."""

import base64
import json
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class AgentCertificate(BaseModel):
    """Represents an agent authentication certificate."""

    # Version and identification
    version: str = Field(default="1.0", description="Certificate version")
    serial_number: str = Field(description="Unique certificate identifier")

    # Issuer (Certificate Authority / Bank)
    issuer_name: str = Field(description="Human-readable issuer name")
    issuer_identifier: str = Field(description="Issuer domain/identifier")
    issuer_public_key: bytes = Field(description="Issuer's Ed25519 public key")

    # Subject (Agent)
    agent_identifier: str = Field(description="Unique agent identifier")
    agent_public_key: bytes = Field(description="Agent's Ed25519 public key")
    account_reference: str = Field(
        description="Hashed account ID (privacy-preserving)"
    )

    # Validity period
    not_before: datetime = Field(description="Certificate valid from")
    not_after: datetime = Field(description="Certificate valid until")

    # Capabilities
    capabilities: dict[str, Any] = Field(
        default_factory=dict, description="Agent capabilities"
    )

    # Extensions (optional metadata)
    extensions: dict[str, Any] = Field(
        default_factory=dict, description="Optional extensions"
    )

    # Revocation endpoints
    ocsp_url: Optional[str] = Field(default=None, description="OCSP responder URL")
    crl_url: Optional[str] = Field(default=None, description="CRL distribution point")

    # Signature
    signature: bytes = Field(default=b"", description="Issuer's signature over certificate")

    model_config = {
        "json_encoders": {
            bytes: lambda v: base64.b64encode(v).decode("utf-8"),
            datetime: lambda v: v.isoformat(),
        }
    }

    @field_validator("issuer_public_key", "agent_public_key", "signature", mode="before")
    @classmethod
    def decode_base64_bytes(cls, v: Any) -> bytes:
        """Decode base64 strings to bytes if needed."""
        if isinstance(v, str):
            return base64.b64decode(v)
        return v

    @field_validator("not_before", "not_after", mode="before")
    @classmethod
    def parse_datetime(cls, v: Any) -> datetime:
        """Parse datetime strings if needed."""
        if isinstance(v, str):
            return datetime.fromisoformat(v)
        return v

    def is_valid(self, now: Optional[datetime] = None) -> bool:
        """Check if certificate is currently valid (time-wise)."""
        if now is None:
            now = datetime.now()
        return self.not_before <= now <= self.not_after

    def has_capability(self, capability: str) -> bool:
        """Check if certificate grants a specific capability."""
        return self.capabilities.get(capability, False) is True

    def to_base64(self) -> str:
        """Serialize certificate to base64 for HTTP headers."""
        json_str = self.model_dump_json()
        return base64.b64encode(json_str.encode("utf-8")).decode("utf-8")

    @classmethod
    def from_base64(cls, b64: str) -> "AgentCertificate":
        """Deserialize certificate from base64."""
        json_str = base64.b64decode(b64).decode("utf-8")
        return cls.model_validate_json(json_str)

    def get_signing_payload(self) -> bytes:
        """Get the payload that should be signed by the issuer.

        This includes all fields except the signature itself.
        """
        data = self.model_dump(exclude={"signature"})
        # Use canonical JSON (sorted keys, no whitespace)
        json_str = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
        return json_str.encode("utf-8")


class ValidationResult(BaseModel):
    """Result of validating an agent request."""

    valid: bool = Field(description="Whether validation succeeded")
    error: Optional[str] = Field(default=None, description="Error message if invalid")

    # If valid, extracted information
    agent_id: Optional[str] = Field(default=None, description="Agent identifier")
    account_reference: Optional[str] = Field(
        default=None, description="Account reference"
    )
    capabilities: Optional[dict[str, Any]] = Field(
        default=None, description="Agent capabilities"
    )
    certificate: Optional[AgentCertificate] = Field(
        default=None, description="Validated certificate"
    )

    # Validation metadata
    validated_at: datetime = Field(
        default_factory=datetime.now, description="Validation timestamp"
    )
    issuer: Optional[str] = Field(default=None, description="Certificate issuer")

    def __bool__(self) -> bool:
        """Allow using ValidationResult in boolean context."""
        return self.valid
