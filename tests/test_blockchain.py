"""Tests for blockchain-based trust store."""

from datetime import datetime, timedelta

import httpx
import pytest

from open_agent_auth import AgentCertificate, AgentSigner, generate_keypair
from open_agent_auth.core.crypto import sign
from open_agent_auth.trust.blockchain import BlockchainTrustStore
from open_agent_auth.trust.mock_contract import MockCARegistryContract, MockWeb3
from open_agent_auth.validator import AgentVerifier


def test_blockchain_trust_store_basic():
    """Test basic BlockchainTrustStore operations."""

    # Set up mock blockchain
    mock_registry = MockCARegistryContract()
    mock_web3 = MockWeb3(mock_registry)

    # Create blockchain trust store
    trust_store = BlockchainTrustStore(
        web3_provider=mock_web3,
        registry_address="0x1234567890123456789012345678901234567890",
        min_stake=1000,
    )

    # Register a CA on-chain
    ca_private_key, ca_public_key = generate_keypair()
    mock_registry.register_ca(
        identifier="bank.example.com",
        name="Example Bank",
        public_key=ca_public_key,
        stake=5000,  # Above minimum
    )

    # Check CA is trusted
    assert trust_store.is_trusted("bank.example.com")

    # Get CA public key
    public_key = trust_store.get_public_key("bank.example.com")
    assert public_key == ca_public_key

    # Get CA details
    ca = trust_store.get_ca("bank.example.com")
    assert ca is not None
    assert ca.identifier == "bank.example.com"
    assert ca.name == "Example Bank"
    assert ca.enabled is True


def test_blockchain_trust_store_min_stake():
    """Test that CAs below minimum stake are not trusted."""

    mock_registry = MockCARegistryContract()
    mock_web3 = MockWeb3(mock_registry)

    trust_store = BlockchainTrustStore(
        web3_provider=mock_web3,
        registry_address="0x1234567890123456789012345678901234567890",
        min_stake=10000,  # High minimum stake
    )

    # Register CA with low stake
    ca_private_key, ca_public_key = generate_keypair()
    mock_registry.register_ca(
        identifier="lowstake.example.com",
        name="Low Stake Bank",
        public_key=ca_public_key,
        stake=5000,  # Below minimum
    )

    # CA should not be trusted
    assert not trust_store.is_trusted("lowstake.example.com")
    assert trust_store.get_public_key("lowstake.example.com") is None


def test_blockchain_trust_store_deactivated_ca():
    """Test that deactivated CAs are not trusted."""

    mock_registry = MockCARegistryContract()
    mock_web3 = MockWeb3(mock_registry)

    trust_store = BlockchainTrustStore(
        web3_provider=mock_web3,
        registry_address="0x1234567890123456789012345678901234567890",
        min_stake=1000,
    )

    # Register and then deactivate CA
    ca_private_key, ca_public_key = generate_keypair()
    mock_registry.register_ca(
        identifier="deactivated.example.com",
        name="Deactivated Bank",
        public_key=ca_public_key,
        stake=5000,
    )

    # Initially trusted
    assert trust_store.is_trusted("deactivated.example.com")

    # Deactivate
    mock_registry.deactivate_ca("deactivated.example.com")

    # No longer trusted
    assert not trust_store.is_trusted("deactivated.example.com")


def test_blockchain_trust_store_list_cas():
    """Test listing all trusted CAs."""

    mock_registry = MockCARegistryContract()
    mock_web3 = MockWeb3(mock_registry)

    trust_store = BlockchainTrustStore(
        web3_provider=mock_web3,
        registry_address="0x1234567890123456789012345678901234567890",
        min_stake=1000,
    )

    # Register multiple CAs
    for i in range(3):
        _, pub_key = generate_keypair()
        mock_registry.register_ca(
            identifier=f"bank{i}.example.com",
            name=f"Bank {i}",
            public_key=pub_key,
            stake=5000,
        )

    # List CAs
    cas = trust_store.list_cas()
    assert len(cas) == 3
    identifiers = {ca.identifier for ca in cas}
    assert identifiers == {
        "bank0.example.com",
        "bank1.example.com",
        "bank2.example.com",
    }


def test_blockchain_trust_store_unknown_ca():
    """Test querying unknown CA returns None."""

    mock_registry = MockCARegistryContract()
    mock_web3 = MockWeb3(mock_registry)

    trust_store = BlockchainTrustStore(
        web3_provider=mock_web3,
        registry_address="0x1234567890123456789012345678901234567890",
    )

    assert not trust_store.is_trusted("unknown.example.com")
    assert trust_store.get_public_key("unknown.example.com") is None
    assert trust_store.get_ca("unknown.example.com") is None


def test_end_to_end_with_blockchain_trust_store():
    """Test complete flow with blockchain trust store."""

    # Set up mock blockchain
    mock_registry = MockCARegistryContract()
    mock_web3 = MockWeb3(mock_registry)

    # Create blockchain trust store
    trust_store = BlockchainTrustStore(
        web3_provider=mock_web3,
        registry_address="0x1234567890123456789012345678901234567890",
        min_stake=1000,
    )

    # CA registers on blockchain
    ca_private_key, ca_public_key = generate_keypair()
    mock_registry.register_ca(
        identifier="blockchain.bank.com",
        name="Blockchain Bank",
        public_key=ca_public_key,
        stake=10000,
    )

    # Agent gets certificate from CA
    agent_private_key, agent_public_key = generate_keypair()

    certificate = AgentCertificate(
        serial_number="BLOCKCHAIN-123",
        issuer_name="Blockchain Bank",
        issuer_identifier="blockchain.bank.com",
        issuer_public_key=ca_public_key,
        agent_identifier="blockchain-agent",
        agent_public_key=agent_public_key,
        account_reference="blockchain_account",
        not_before=datetime.now() - timedelta(hours=1),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={
            "can_browse": True,
            "can_purchase": True,
        },
    )

    # CA signs certificate
    certificate.signature = sign(ca_private_key, certificate.get_signing_payload())

    # Agent signs request
    signer = AgentSigner(certificate=certificate, private_key=agent_private_key)

    request = httpx.Request(
        method="POST",
        url="https://merchant.example.com/api/purchase",
        headers={"Content-Type": "application/json"},
        json={"product_id": "12345"},
    )

    signed_request = signer.sign_request(request, tag="agent-payer-auth")

    # Merchant verifies using blockchain trust store
    verifier = AgentVerifier(trust_store=trust_store)
    result = verifier.verify_request(signed_request, required_capability="can_purchase")

    # Should succeed
    assert result.valid is True
    assert result.agent_id == "blockchain-agent"
    assert result.issuer == "blockchain.bank.com"


def test_verification_fails_with_deactivated_blockchain_ca():
    """Test that verification fails when blockchain CA is deactivated."""

    # Set up mock blockchain
    mock_registry = MockCARegistryContract()
    mock_web3 = MockWeb3(mock_registry)

    trust_store = BlockchainTrustStore(
        web3_provider=mock_web3,
        registry_address="0x1234567890123456789012345678901234567890",
        min_stake=1000,
    )

    # CA registers on blockchain
    ca_private_key, ca_public_key = generate_keypair()
    mock_registry.register_ca(
        identifier="temp.bank.com",
        name="Temporary Bank",
        public_key=ca_public_key,
        stake=10000,
    )

    # Agent gets certificate
    agent_private_key, agent_public_key = generate_keypair()

    certificate = AgentCertificate(
        serial_number="TEMP-456",
        issuer_name="Temporary Bank",
        issuer_identifier="temp.bank.com",
        issuer_public_key=ca_public_key,
        agent_identifier="temp-agent",
        agent_public_key=agent_public_key,
        account_reference="temp_account",
        not_before=datetime.now() - timedelta(hours=1),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={"can_browse": True, "can_purchase": True},
    )

    certificate.signature = sign(ca_private_key, certificate.get_signing_payload())

    # Agent signs request
    signer = AgentSigner(certificate=certificate, private_key=agent_private_key)
    request = httpx.Request(
        method="GET",
        url="https://merchant.example.com/products",
        headers={"Content-Type": "application/json"},
    )
    signed_request = signer.sign_request(request)

    # Initially verification succeeds
    verifier = AgentVerifier(trust_store=trust_store)
    result = verifier.verify_request(signed_request)
    assert result.valid is True

    # CA gets deactivated on blockchain
    mock_registry.deactivate_ca("temp.bank.com")

    # Now verification should fail
    result = verifier.verify_request(signed_request)
    assert result.valid is False
    assert "not trusted" in result.error.lower() or "unknown" in result.error.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
