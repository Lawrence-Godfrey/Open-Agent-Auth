#!/usr/bin/env python3
"""
Basic example demonstrating the complete open-agent-auth workflow:
1. CA issues a certificate to an agent
2. Agent signs a request
3. Merchant verifies the request
"""

from datetime import datetime, timedelta

import httpx

from open_agent_auth import (
    AgentCertificate,
    AgentSigner,
    AgentVerifier,
    TrustStore,
    generate_keypair,
)
from open_agent_auth.core.crypto import sign


def main():
    print("=== Open Agent Auth - Basic Example ===\n")

    # ============================================================================
    # STEP 1: Set up Certificate Authority (Bank)
    # ============================================================================
    print("1. Setting up Certificate Authority (Bank)...")
    ca_private_key, ca_public_key = generate_keypair()
    ca_identifier = "bank.example.com"
    ca_name = "Example Bank"
    print(f"   ✓ CA: {ca_name} ({ca_identifier})\n")

    # ============================================================================
    # STEP 2: Agent generates keypair and requests certificate
    # ============================================================================
    print("2. Agent generating keypair...")
    agent_private_key, agent_public_key = generate_keypair()
    agent_id = "shopping-agent-v1"
    print(f"   ✓ Agent ID: {agent_id}\n")

    # ============================================================================
    # STEP 3: CA issues certificate to agent
    # ============================================================================
    print("3. CA issuing certificate to agent...")
    certificate = AgentCertificate(
        serial_number="ABC123456789",
        issuer_name=ca_name,
        issuer_identifier=ca_identifier,
        issuer_public_key=ca_public_key,
        agent_identifier=agent_id,
        agent_public_key=agent_public_key,
        account_reference="hashed_user_account_xyz",
        not_before=datetime.now() - timedelta(hours=1),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={
            "can_browse": True,
            "can_purchase": True,
            "max_transaction_amount": 5000.0,
            "currency": "USD",
        },
    )

    # CA signs the certificate
    signing_payload = certificate.get_signing_payload()
    certificate.signature = sign(ca_private_key, signing_payload)
    print(f"   ✓ Certificate issued")
    print(f"   - Serial: {certificate.serial_number}")
    print(f"   - Valid until: {certificate.not_after.strftime('%Y-%m-%d')}")
    print(f"   - Capabilities: {list(certificate.capabilities.keys())}\n")

    # ============================================================================
    # STEP 4: Merchant sets up trust store
    # ============================================================================
    print("4. Merchant setting up trust store...")
    trust_store = TrustStore()
    trust_store.add_trusted_ca(
        identifier=ca_identifier, public_key=ca_public_key, name=ca_name
    )
    print(f"   ✓ Trust store configured")
    print(f"   - Trusted CAs: {len(trust_store.list_cas())}\n")

    # ============================================================================
    # STEP 5: Agent creates signer
    # ============================================================================
    print("5. Agent creating request signer...")
    signer = AgentSigner(certificate=certificate, private_key=agent_private_key)
    print(f"   ✓ Signer ready\n")

    # ============================================================================
    # STEP 6: Agent signs a browsing request
    # ============================================================================
    print("6. Agent signing browsing request...")
    browse_request = httpx.Request(
        method="GET",
        url="https://merchant.example.com/api/products",
        headers={"Content-Type": "application/json"},
    )

    signed_browse = signer.sign_request(browse_request, tag="agent-browser-auth")
    print(f"   ✓ Browsing request signed")
    print(f"   - Method: {signed_browse.method}")
    print(f"   - URL: {signed_browse.url}")
    print(f"   - Tag: agent-browser-auth\n")

    # ============================================================================
    # STEP 7: Merchant verifies browsing request
    # ============================================================================
    print("7. Merchant verifying browsing request...")
    verifier = AgentVerifier(trust_store=trust_store)
    browse_result = verifier.verify_request(signed_browse)

    if browse_result.valid:
        print(f"   ✓ Verification SUCCESS")
        print(f"   - Agent: {browse_result.agent_id}")
        print(f"   - Account: {browse_result.account_reference}")
        print(f"   - Issuer: {browse_result.issuer}\n")
    else:
        print(f"   ✗ Verification FAILED")
        print(f"   - Error: {browse_result.error}\n")
        return

    # ============================================================================
    # STEP 8: Agent signs a purchase request
    # ============================================================================
    print("8. Agent signing purchase request...")
    purchase_request = httpx.Request(
        method="POST",
        url="https://merchant.example.com/api/purchase",
        headers={"Content-Type": "application/json"},
        json={
            "product_id": "WIDGET-123",
            "quantity": 2,
            "price": 49.99,
        },
    )

    signed_purchase = signer.sign_request(purchase_request, tag="agent-payer-auth")
    print(f"   ✓ Purchase request signed")
    print(f"   - Method: {signed_purchase.method}")
    print(f"   - URL: {signed_purchase.url}")
    print(f"   - Tag: agent-payer-auth\n")

    # ============================================================================
    # STEP 9: Merchant verifies purchase request with capability check
    # ============================================================================
    print("9. Merchant verifying purchase request...")
    purchase_result = verifier.verify_request(
        signed_purchase, required_capability="can_purchase"
    )

    if purchase_result.valid:
        print(f"   ✓ Verification SUCCESS")
        print(f"   - Agent: {purchase_result.agent_id}")
        print(f"   - Has purchase capability: {purchase_result.capabilities['can_purchase']}")
        print(f"   - Max transaction: ${purchase_result.capabilities['max_transaction_amount']}\n")
    else:
        print(f"   ✗ Verification FAILED")
        print(f"   - Error: {purchase_result.error}\n")
        return

    # ============================================================================
    # STEP 10: Test with invalid request (wrong capability)
    # ============================================================================
    print("10. Testing verification failure (wrong capability)...")

    # Create agent with limited capabilities
    limited_agent_key, limited_agent_pub = generate_keypair()
    limited_cert = AgentCertificate(
        serial_number="LIMITED-123",
        issuer_name=ca_name,
        issuer_identifier=ca_identifier,
        issuer_public_key=ca_public_key,
        agent_identifier="limited-agent",
        agent_public_key=limited_agent_pub,
        account_reference="limited_account",
        not_before=datetime.now(),
        not_after=datetime.now() + timedelta(days=30),
        capabilities={
            "can_browse": True,
            "can_purchase": False,  # No purchase capability!
        },
    )
    limited_cert.signature = sign(ca_private_key, limited_cert.get_signing_payload())

    limited_signer = AgentSigner(certificate=limited_cert, private_key=limited_agent_key)
    limited_purchase = limited_signer.sign_request(purchase_request, tag="agent-payer-auth")

    limited_result = verifier.verify_request(
        limited_purchase, required_capability="can_purchase"
    )

    if not limited_result.valid:
        print(f"   ✓ Verification correctly FAILED")
        print(f"   - Error: {limited_result.error}\n")
    else:
        print(f"   ✗ Unexpected success\n")

    # ============================================================================
    print("=== Example Complete ===")
    print("\nKey takeaways:")
    print("1. Certificates are issued by trusted CAs (banks)")
    print("2. Agents sign requests with their private key")
    print("3. Merchants verify signatures and check capabilities")
    print("4. Decentralized model - no central registry needed!")


if __name__ == "__main__":
    main()
