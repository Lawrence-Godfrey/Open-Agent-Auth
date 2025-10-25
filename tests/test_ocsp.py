"""Tests for OCSP support."""

from datetime import datetime, timedelta

import pytest

from open_agent_auth import AgentCertificate, TrustStore, generate_keypair
from open_agent_auth.core.crypto import sign
from open_agent_auth.issuer import OCSPResponder
from open_agent_auth.trust.ocsp import MockOCSPResponder, OCSPStatus
from open_agent_auth.validator import CertificateValidator


def test_mock_ocsp_responder_good_certificate():
    """Test mock OCSP responder with good certificate."""
    responder = MockOCSPResponder()

    status = responder.get_status("CERT-123")
    assert status["status"] == OCSPStatus.GOOD
    assert "revocation_time" not in status


def test_mock_ocsp_responder_revoked_certificate():
    """Test mock OCSP responder with revoked certificate."""
    responder = MockOCSPResponder()
    responder.revoke_certificate("REVOKED-456")

    status = responder.get_status("REVOKED-456")
    assert status["status"] == OCSPStatus.REVOKED
    assert status["revocation_reason"] == "key_compromise"
    assert "revocation_time" in status


def test_mock_ocsp_responder_revoke_and_unrevoke():
    """Test revoking and unrevoking certificates."""
    responder = MockOCSPResponder()

    # Initially good
    status = responder.get_status("CERT-789")
    assert status["status"] == OCSPStatus.GOOD

    # Revoke
    responder.revoke_certificate("CERT-789")
    status = responder.get_status("CERT-789")
    assert status["status"] == OCSPStatus.REVOKED

    # Unrevoke
    responder.unrevoke_certificate("CERT-789")
    status = responder.get_status("CERT-789")
    assert status["status"] == OCSPStatus.GOOD


def test_ocsp_responder_basic():
    """Test OCSP responder basic functionality."""
    responder = OCSPResponder()

    # Certificate not revoked
    response = responder.respond("GOOD-001")
    assert response["status"] == OCSPStatus.GOOD
    assert "revocation_time" not in response

    # Revoke certificate
    responder.revoke_certificate("GOOD-001", reason="key_compromise")

    # Now should be revoked
    response = responder.respond("GOOD-001")
    assert response["status"] == OCSPStatus.REVOKED
    assert response["revocation_reason"] == "key_compromise"
    assert "revocation_time" in response


def test_ocsp_responder_multiple_certificates():
    """Test OCSP responder with multiple certificates."""
    responder = OCSPResponder()

    # Revoke some certificates
    responder.revoke_certificate("REVOKED-1")
    responder.revoke_certificate("REVOKED-2")
    responder.revoke_certificate("REVOKED-3")

    # Check counts
    assert responder.get_revoked_count() == 3

    # Check individual status
    assert responder.is_revoked("REVOKED-1") is True
    assert responder.is_revoked("REVOKED-2") is True
    assert responder.is_revoked("NOT-REVOKED") is False

    # Unrevoke one
    responder.unrevoke_certificate("REVOKED-2")
    assert responder.get_revoked_count() == 2
    assert responder.is_revoked("REVOKED-2") is False


def test_ocsp_responder_revocation_time():
    """Test OCSP responder with custom revocation time."""
    responder = OCSPResponder()

    revocation_time = datetime(2024, 1, 1, 12, 0, 0)
    responder.revoke_certificate("TIME-TEST", revocation_time=revocation_time, reason="cessation_of_operation")

    response = responder.respond("TIME-TEST")
    assert response["status"] == OCSPStatus.REVOKED
    assert response["revocation_reason"] == "cessation_of_operation"
    assert datetime.fromisoformat(response["revocation_time"]) == revocation_time


def test_certificate_validator_without_ocsp():
    """Test certificate validator works without OCSP (backwards compatibility)."""
    # Set up CA and trust store
    ca_private_key, ca_public_key = generate_keypair()
    trust_store = TrustStore()
    trust_store.add_trusted_ca(
        identifier="bank.example.com", public_key=ca_public_key, name="Test Bank"
    )

    # Create certificate WITHOUT OCSP URL
    agent_private_key, agent_public_key = generate_keypair()
    certificate = AgentCertificate(
        serial_number="NO-OCSP-001",
        issuer_name="Test Bank",
        issuer_identifier="bank.example.com",
        issuer_public_key=ca_public_key,
        agent_identifier="test-agent",
        agent_public_key=agent_public_key,
        account_reference="test_account",
        not_before=datetime.now() - timedelta(hours=1),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={"can_browse": True},
    )
    certificate.signature = sign(ca_private_key, certificate.get_signing_payload())

    # Validator without OCSP should work
    validator = CertificateValidator(trust_store=trust_store, check_ocsp=False)
    validator.validate_certificate(certificate)  # Should not raise


def test_certificate_validator_ocsp_disabled_by_default():
    """Test that OCSP checking is disabled by default."""
    ca_private_key, ca_public_key = generate_keypair()
    trust_store = TrustStore()
    trust_store.add_trusted_ca(
        identifier="bank.example.com", public_key=ca_public_key, name="Test Bank"
    )

    validator = CertificateValidator(trust_store=trust_store)

    # OCSP should be disabled
    assert validator.check_ocsp is False
    assert validator.ocsp_client is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
