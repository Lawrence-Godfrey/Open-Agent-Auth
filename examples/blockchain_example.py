#!/usr/bin/env python3
"""
Blockchain-based trust store example.

This example demonstrates using a blockchain smart contract as a
decentralized CA registry instead of local YAML trust stores.

Key advantages:
- No central authority controls the trust store
- Economic incentives via staking prevent malicious CAs
- Transparent, auditable CA registration
- Merchants don't need to manually update trust stores
- Community governance can deactivate bad actors
"""

from datetime import datetime, timedelta

import httpx

from open_agent_auth import AgentCertificate, AgentSigner, AgentVerifier, generate_keypair
from open_agent_auth.core.crypto import sign
from open_agent_auth.trust.blockchain import BlockchainTrustStore
from open_agent_auth.trust.mock_contract import MockCARegistryContract, MockWeb3


def main():
    print("=== Blockchain Trust Store Example ===\n")

    # ========================================================================
    # SETUP: Mock blockchain (in production, use real Web3 provider)
    # ========================================================================
    print("1. Setting up mock blockchain...")
    mock_registry = MockCARegistryContract()
    web3 = MockWeb3(mock_registry)
    registry_address = "0x1234567890123456789012345678901234567890"
    print(f"   ✓ Mock blockchain initialized")
    print(f"   ✓ CA Registry deployed at: {registry_address}\n")

    # ========================================================================
    # STEP 1: Banks register as CAs on the blockchain with stake
    # ========================================================================
    print("2. Banks registering as CAs on blockchain (with stake)...")

    # Bank 1 registers
    bank1_private_key, bank1_public_key = generate_keypair()
    mock_registry.register_ca(
        identifier="globalbank.com",
        name="Global Bank",
        public_key=bank1_public_key,
        stake=100_000,  # 100k wei stake (shows commitment)
    )
    print("   ✓ Global Bank registered")
    print("     - Identifier: globalbank.com")
    print("     - Stake: 100,000 wei")

    # Bank 2 registers
    bank2_private_key, bank2_public_key = generate_keypair()
    mock_registry.register_ca(
        identifier="cryptobank.io",
        name="Crypto Bank",
        public_key=bank2_public_key,
        stake=250_000,  # Higher stake = more trust
    )
    print("   ✓ Crypto Bank registered")
    print("     - Identifier: cryptobank.io")
    print("     - Stake: 250,000 wei")

    # Low-stake bank (below minimum)
    bank3_private_key, bank3_public_key = generate_keypair()
    mock_registry.register_ca(
        identifier="shady.bank",
        name="Shady Bank",
        public_key=bank3_public_key,
        stake=500,  # Very low stake
    )
    print("   ✓ Shady Bank registered")
    print("     - Identifier: shady.bank")
    print("     - Stake: 500 wei (below minimum threshold!)\n")

    # ========================================================================
    # STEP 2: Merchants set up blockchain trust store
    # ========================================================================
    print("3. Merchants setting up blockchain trust store...")

    # Merchants connect to the same blockchain registry
    # They set a minimum stake requirement (e.g., 10,000 wei)
    trust_store = BlockchainTrustStore(
        web3_provider=web3,
        registry_address=registry_address,
        min_stake=10_000,  # Minimum 10k wei to be trusted
    )

    print("   ✓ Trust store connected to blockchain")
    print("   ✓ Minimum stake requirement: 10,000 wei")

    # List all trusted CAs
    trusted_cas = trust_store.list_cas()
    print(f"   ✓ Trusted CAs: {len(trusted_cas)}")
    for ca in trusted_cas:
        print(f"     - {ca.name} ({ca.identifier})")
    print()

    # ========================================================================
    # STEP 3: Agent gets certificate from Global Bank
    # ========================================================================
    print("4. Agent obtaining certificate from Global Bank...")

    agent_private_key, agent_public_key = generate_keypair()
    agent_id = "shopping-bot-v2"

    certificate = AgentCertificate(
        serial_number="BLOCKCHAIN-001",
        issuer_name="Global Bank",
        issuer_identifier="globalbank.com",
        issuer_public_key=bank1_public_key,
        agent_identifier=agent_id,
        agent_public_key=agent_public_key,
        account_reference="user_account_hash_abc",
        not_before=datetime.now() - timedelta(hours=1),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={
            "can_browse": True,
            "can_purchase": True,
            "max_transaction_amount": 10000.0,
        },
    )

    # Bank signs certificate
    certificate.signature = sign(bank1_private_key, certificate.get_signing_payload())
    print("   ✓ Certificate issued by Global Bank")
    print(f"   ✓ Agent ID: {agent_id}\n")

    # ========================================================================
    # STEP 4: Agent signs request
    # ========================================================================
    print("5. Agent signing purchase request...")

    signer = AgentSigner(certificate=certificate, private_key=agent_private_key)

    request = httpx.Request(
        method="POST",
        url="https://merchant.example.com/api/purchase",
        headers={"Content-Type": "application/json"},
        json={"product_id": "WIDGET-789", "amount": 99.99},
    )

    signed_request = signer.sign_request(request, tag="agent-payer-auth")
    print("   ✓ Request signed\n")

    # ========================================================================
    # STEP 5: Merchant verifies request (queries blockchain)
    # ========================================================================
    print("6. Merchant verifying request (checking blockchain)...")

    verifier = AgentVerifier(trust_store=trust_store)
    result = verifier.verify_request(signed_request, required_capability="can_purchase")

    if result.valid:
        print("   ✓ Verification SUCCESS")
        print(f"   - Agent: {result.agent_id}")
        print(f"   - Issuer: {result.issuer}")
        print(f"   - CA verified on blockchain")
        print(f"   - CA stake meets minimum requirement\n")
    else:
        print(f"   ✗ Verification FAILED: {result.error}\n")

    # ========================================================================
    # STEP 6: Test with low-stake bank (should fail)
    # ========================================================================
    print("7. Testing with low-stake bank...")

    # Agent tries to get certificate from Shady Bank
    shady_agent_key, shady_agent_pub = generate_keypair()

    shady_cert = AgentCertificate(
        serial_number="SHADY-001",
        issuer_name="Shady Bank",
        issuer_identifier="shady.bank",
        issuer_public_key=bank3_public_key,
        agent_identifier="shady-agent",
        agent_public_key=shady_agent_pub,
        account_reference="shady_account",
        not_before=datetime.now() - timedelta(hours=1),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={"can_browse": True, "can_purchase": True},
    )

    shady_cert.signature = sign(bank3_private_key, shady_cert.get_signing_payload())

    shady_signer = AgentSigner(certificate=shady_cert, private_key=shady_agent_key)
    shady_request = shady_signer.sign_request(request, tag="agent-payer-auth")

    # Verify
    shady_result = verifier.verify_request(shady_request)

    if not shady_result.valid:
        print("   ✓ Verification correctly FAILED")
        print(f"   - Error: {shady_result.error}")
        print("   - Reason: CA stake (500 wei) below minimum (10,000 wei)\n")
    else:
        print("   ✗ Unexpected success!\n")

    # ========================================================================
    # STEP 7: Governance deactivates a malicious CA
    # ========================================================================
    print("8. Simulating governance action (deactivating malicious CA)...")

    # Suppose Global Bank is found to be malicious
    # Community governance votes to deactivate it
    mock_registry.deactivate_ca("globalbank.com")
    print("   ✓ Global Bank deactivated by governance vote")

    # Previous valid request now fails
    deactivated_result = verifier.verify_request(signed_request)

    if not deactivated_result.valid:
        print("   ✓ Previously valid request now FAILS")
        print(f"   - Error: {deactivated_result.error}")
        print("   - Merchants protected from malicious CA instantly!\n")
    else:
        print("   ✗ Unexpected success!\n")

    # ========================================================================
    # STEP 8: Show decentralization benefits
    # ========================================================================
    print("=== Decentralization Benefits ===\n")

    print("✅ No Central Authority:")
    print("   - No Visa/Mastercard controlling access")
    print("   - Any bank can register as a CA by staking\n")

    print("✅ Economic Security:")
    print("   - CAs must stake tokens to be trusted")
    print("   - Malicious CAs lose their stake (slashing)\n")

    print("✅ Transparent & Auditable:")
    print("   - All CA registrations on public blockchain")
    print("   - Anyone can verify CA stake and status\n")

    print("✅ Instant Updates:")
    print("   - Merchants query blockchain in real-time")
    print("   - No manual trust store updates needed\n")

    print("✅ Community Governance:")
    print("   - Token holders can vote to deactivate bad CAs")
    print("   - Democratic control instead of corporate control\n")

    print("=== Example Complete ===\n")

    print("In production, you would:")
    print("1. Deploy CA Registry smart contract to Ethereum/Polygon/etc")
    print("2. Use real Web3 provider (Infura, Alchemy, etc)")
    print("3. Banks stake real tokens (ETH, stablecoin, etc)")
    print("4. Implement governance contract for CA management")
    print("5. Add slashing mechanism for malicious behavior")


if __name__ == "__main__":
    main()
