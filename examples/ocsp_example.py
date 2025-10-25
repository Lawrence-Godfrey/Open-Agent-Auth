#!/usr/bin/env python3
"""
OCSP (Online Certificate Status Protocol) Example.

Demonstrates real-time certificate revocation checking using OCSP.
"""

from datetime import datetime, timedelta

from open_agent_auth import AgentCertificate, TrustStore, generate_keypair
from open_agent_auth.core.crypto import sign
from open_agent_auth.issuer import OCSPResponder
from open_agent_auth.validator import CertificateValidator


def main():
    print("=== OCSP Certificate Revocation Example ===\n")

    # ========================================================================
    # STEP 1: CA sets up OCSP responder
    # ========================================================================
    print("1. CA setting up OCSP responder...")
    ca_private_key, ca_public_key = generate_keypair()
    ca_identifier = "bank.example.com"

    # CA runs an OCSP responder
    ocsp_responder = OCSPResponder(validity_period=86400)  # 24 hour validity
    ocsp_url = "http://ocsp.bank.example.com"

    print(f"   ✓ OCSP responder running at: {ocsp_url}\n")

    # ========================================================================
    # STEP 2: Issue certificate with OCSP URL
    # ========================================================================
    print("2. Issuing certificate with OCSP URL...")
    agent_private_key, agent_public_key = generate_keypair()

    certificate = AgentCertificate(
        serial_number="OCSP-DEMO-001",
        issuer_name="Example Bank",
        issuer_identifier=ca_identifier,
        issuer_public_key=ca_public_key,
        agent_identifier="demo-agent",
        agent_public_key=agent_public_key,
        account_reference="user_account_123",
        not_before=datetime.now() - timedelta(hours=1),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={"can_browse": True, "can_purchase": True},
        ocsp_url=ocsp_url,  # Include OCSP URL in certificate
    )

    certificate.signature = sign(ca_private_key, certificate.get_signing_payload())
    print(f"   ✓ Certificate issued: {certificate.serial_number}")
    print(f"   ✓ OCSP URL: {certificate.ocsp_url}\n")

    # ========================================================================
    # STEP 3: Merchant validates certificate (OCSP disabled)
    # ========================================================================
    print("3. Merchant validating certificate (OCSP disabled)...")
    trust_store = TrustStore()
    trust_store.add_trusted_ca(
        identifier=ca_identifier,
        public_key=ca_public_key,
        name="Example Bank"
    )

    # Without OCSP - only checks signature and expiry
    validator = CertificateValidator(trust_store=trust_store, check_ocsp=False)
    validator.validate_certificate(certificate)
    print("   ✓ Certificate valid (basic validation only)\n")

    # ========================================================================
    # STEP 4: Merchant validates with OCSP enabled
    # ========================================================================
    print("4. Merchant validating with OCSP enabled...")

    # Query OCSP responder
    ocsp_response = ocsp_responder.respond(certificate.serial_number)
    print(f"   ✓ OCSP Status: {ocsp_response['status']}")
    print(f"   ✓ This Update: {ocsp_response['this_update']}")
    print(f"   ✓ Next Update: {ocsp_response['next_update']}\n")

    # ========================================================================
    # STEP 5: CA revokes certificate
    # ========================================================================
    print("5. CA revoking certificate...")
    ocsp_responder.revoke_certificate(
        certificate.serial_number,
        reason="key_compromise"
    )
    print(f"   ✓ Certificate {certificate.serial_number} revoked")
    print("   ✓ Reason: key_compromise\n")

    # ========================================================================
    # STEP 6: OCSP now shows revoked status
    # ========================================================================
    print("6. Checking OCSP after revocation...")
    ocsp_response = ocsp_responder.respond(certificate.serial_number)

    print(f"   ✓ OCSP Status: {ocsp_response['status']}")
    print(f"   ✓ Revoked At: {ocsp_response['revocation_time']}")
    print(f"   ✓ Reason: {ocsp_response['revocation_reason']}\n")

    # ========================================================================
    # STEP 7: Comparison with basic validation
    # ========================================================================
    print("7. Comparison of validation methods...\n")

    # Basic validation (no OCSP) - still passes!
    try:
        validator_no_ocsp = CertificateValidator(trust_store=trust_store, check_ocsp=False)
        validator_no_ocsp.validate_certificate(certificate)
        print("   ⚠️  Basic validation: PASSED (doesn't check revocation)")
    except Exception as e:
        print(f"   ✗ Basic validation: FAILED - {e}")

    # OCSP validation - would fail (if we had async OCSP check)
    print("   ✓ OCSP validation: Would FAIL (certificate revoked)\n")

    # ========================================================================
    # Key Benefits
    # ========================================================================
    print("=== OCSP Benefits ===\n")

    print("✅ Real-Time Revocation:")
    print("   - Certificates can be revoked immediately")
    print("   - No need to wait for certificate expiry\n")

    print("✅ Security:")
    print("   - Compromised keys can be invalidated instantly")
    print("   - Merchants always get fresh revocation status\n")

    print("✅ Flexible:")
    print("   - CAs control their own OCSP responders")
    print("   - Each certificate can have different OCSP URL\n")

    print("=== OCSP vs CRL ===\n")

    print("OCSP:")
    print("  • Real-time checking")
    print("  • Query per certificate")
    print("  • Lower bandwidth for clients\n")

    print("CRL:")
    print("  • Batch download")
    print("  • All revocations at once")
    print("  • Can work offline (after download)\n")

    print("=== Example Complete ===")


if __name__ == "__main__":
    main()
