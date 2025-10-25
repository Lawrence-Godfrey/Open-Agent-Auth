"""Tests for CRL support."""

import pytest

from open_agent_auth.issuer import CRLGenerator


def test_crl_generator_basic():
    """Test basic CRL generation."""
    generator = CRLGenerator()

    # Revoke some certificates
    generator.revoke_certificate("CERT-001", reason="key_compromise")
    generator.revoke_certificate("CERT-002", reason="cessation_of_operation")

    # Generate CRL
    crl = generator.generate_crl()

    assert "CERT-001" in crl["revoked"]
    assert "CERT-002" in crl["revoked"]
    assert len(crl["revoked"]) == 2
    assert crl["revocation_details"]["CERT-001"]["reason"] == "key_compromise"


def test_crl_generator_unrevoke():
    """Test unrevoking certificates."""
    generator = CRLGenerator()

    generator.revoke_certificate("CERT-001")
    assert generator.is_revoked("CERT-001")

    generator.unrevoke_certificate("CERT-001")
    assert not generator.is_revoked("CERT-001")


def test_crl_generator_count():
    """Test revoked certificate count."""
    generator = CRLGenerator()

    assert generator.get_revoked_count() == 0

    generator.revoke_certificate("CERT-001")
    generator.revoke_certificate("CERT-002")
    assert generator.get_revoked_count() == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
