"""End-to-end test for open-agent-auth."""

from datetime import datetime, timedelta

import httpx
import pytest

from open_agent_auth import (
    AgentCertificate,
    AgentSigner,
    AgentVerifier,
    TrustStore,
    generate_keypair,
    private_key_from_bytes,
)
from open_agent_auth.core.crypto import sign


def test_end_to_end_flow():
    """Test the complete flow: issue certificate, sign request, verify request."""

    # 1. Set up CA (Bank)
    ca_private_key, ca_public_key = generate_keypair()
    ca_identifier = "bank.example.com"
    ca_name = "Example Bank"

    # 2. Set up trust store
    trust_store = TrustStore()
    trust_store.add_trusted_ca(
        identifier=ca_identifier, public_key=ca_public_key, name=ca_name
    )

    # 3. Agent generates keypair
    agent_private_key, agent_public_key = generate_keypair()
    agent_id = "shopping-agent-v1"

    # 4. CA issues certificate to agent
    certificate = AgentCertificate(
        serial_number="abc123",
        issuer_name=ca_name,
        issuer_identifier=ca_identifier,
        issuer_public_key=ca_public_key,
        agent_identifier=agent_id,
        agent_public_key=agent_public_key,
        account_reference="hashed_account_id_xyz",
        not_before=datetime.now() - timedelta(days=1),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={
            "can_browse": True,
            "can_purchase": True,
            "max_transaction_amount": 5000.0,
        },
    )

    # CA signs the certificate
    signing_payload = certificate.get_signing_payload()
    certificate.signature = sign(ca_private_key, signing_payload)

    # 5. Agent creates signer
    signer = AgentSigner(certificate=certificate, private_key=agent_private_key)

    # 6. Agent signs a request
    request = httpx.Request(
        method="POST",
        url="https://merchant.example.com/api/purchase",
        headers={
            "Content-Type": "application/json",
        },
        json={"product_id": "12345", "quantity": 1},
    )

    signed_request = signer.sign_request(request, tag="agent-payer-auth")

    # Verify signature headers were added
    assert "Signature-Input" in signed_request.headers
    assert "Signature" in signed_request.headers
    assert "X-Agent-Certificate" in signed_request.headers

    # 7. Merchant verifies the request
    verifier = AgentVerifier(trust_store=trust_store)
    result = verifier.verify_request(signed_request, required_capability="can_purchase")

    # Verify validation succeeded
    assert result.valid is True
    assert result.agent_id == agent_id
    assert result.account_reference == "hashed_account_id_xyz"
    assert result.capabilities["can_purchase"] is True


def test_verification_fails_with_wrong_capability():
    """Test that verification fails when agent lacks required capability."""

    # Set up CA
    ca_private_key, ca_public_key = generate_keypair()
    ca_identifier = "bank.example.com"

    trust_store = TrustStore()
    trust_store.add_trusted_ca(
        identifier=ca_identifier, public_key=ca_public_key, name="Example Bank"
    )

    # Agent with limited capabilities
    agent_private_key, agent_public_key = generate_keypair()

    certificate = AgentCertificate(
        serial_number="def456",
        issuer_name="Example Bank",
        issuer_identifier=ca_identifier,
        issuer_public_key=ca_public_key,
        agent_identifier="limited-agent",
        agent_public_key=agent_public_key,
        account_reference="account_123",
        not_before=datetime.now() - timedelta(days=1),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={
            "can_browse": True,
            "can_purchase": False,  # No purchase capability
        },
    )

    signing_payload = certificate.get_signing_payload()
    certificate.signature = sign(ca_private_key, signing_payload)

    # Agent tries to make a purchase
    signer = AgentSigner(certificate=certificate, private_key=agent_private_key)

    request = httpx.Request(
        method="POST",
        url="https://merchant.example.com/api/purchase",
        headers={"Content-Type": "application/json"},
        json={"product_id": "12345"},
    )

    signed_request = signer.sign_request(request, tag="agent-payer-auth")

    # Merchant verifies with required capability
    verifier = AgentVerifier(trust_store=trust_store)
    result = verifier.verify_request(signed_request, required_capability="can_purchase")

    # Verification should fail
    assert result.valid is False
    assert "capability" in result.error.lower()


def test_verification_fails_with_untrusted_issuer():
    """Test that verification fails when certificate issuer is not trusted."""

    # Set up trust store (empty)
    trust_store = TrustStore()

    # Rogue CA issues certificate
    rogue_ca_private_key, rogue_ca_public_key = generate_keypair()
    agent_private_key, agent_public_key = generate_keypair()

    certificate = AgentCertificate(
        serial_number="rogue123",
        issuer_name="Rogue Bank",
        issuer_identifier="rogue.example.com",
        issuer_public_key=rogue_ca_public_key,
        agent_identifier="rogue-agent",
        agent_public_key=agent_public_key,
        account_reference="account_xyz",
        not_before=datetime.now() - timedelta(days=1),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={"can_browse": True, "can_purchase": True},
    )

    signing_payload = certificate.get_signing_payload()
    certificate.signature = sign(rogue_ca_private_key, signing_payload)

    # Agent signs request
    signer = AgentSigner(certificate=certificate, private_key=agent_private_key)

    request = httpx.Request(
        method="GET",
        url="https://merchant.example.com/products",
        headers={"Content-Type": "application/json"},
    )

    signed_request = signer.sign_request(request)

    # Merchant verifies
    verifier = AgentVerifier(trust_store=trust_store)
    result = verifier.verify_request(signed_request)

    # Verification should fail
    assert result.valid is False
    assert "not trusted" in result.error.lower() or "unknown" in result.error.lower()


def test_certificate_serialization():
    """Test certificate serialization to/from base64."""

    ca_private_key, ca_public_key = generate_keypair()
    agent_private_key, agent_public_key = generate_keypair()

    certificate = AgentCertificate(
        serial_number="serial123",
        issuer_name="Test Bank",
        issuer_identifier="bank.test.com",
        issuer_public_key=ca_public_key,
        agent_identifier="test-agent",
        agent_public_key=agent_public_key,
        account_reference="account_ref",
        not_before=datetime.now(),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={"can_browse": True},
    )

    signing_payload = certificate.get_signing_payload()
    certificate.signature = sign(ca_private_key, signing_payload)

    # Serialize to base64
    cert_b64 = certificate.to_base64()
    assert isinstance(cert_b64, str)
    assert len(cert_b64) > 0

    # Deserialize back
    restored_cert = AgentCertificate.from_base64(cert_b64)

    # Verify all fields match
    assert restored_cert.serial_number == certificate.serial_number
    assert restored_cert.agent_identifier == certificate.agent_identifier
    assert restored_cert.agent_public_key == certificate.agent_public_key
    assert restored_cert.signature == certificate.signature


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
