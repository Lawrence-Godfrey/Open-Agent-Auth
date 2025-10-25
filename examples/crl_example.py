#!/usr/bin/env python3
"""CRL (Certificate Revocation List) Example - Batch revocation checking."""

from open_agent_auth.issuer import CRLGenerator


def main():
    print("=== CRL (Certificate Revocation List) Example ===\n")

    # CA creates CRL generator
    crl_gen = CRLGenerator(validity_period=86400)

    # Revoke certificates
    print("1. Revoking certificates...")
    crl_gen.revoke_certificate("CERT-001", reason="key_compromise")
    crl_gen.revoke_certificate("CERT-002", reason="cessation_of_operation")
    crl_gen.revoke_certificate("CERT-003", reason="superseded")
    print(f"   ✓ Revoked {crl_gen.get_revoked_count()} certificates\n")

    # Generate CRL
    print("2. Generating CRL...")
    crl = crl_gen.generate_crl()
    print(f"   ✓ CRL Version: {crl['version']}")
    print(f"   ✓ This Update: {crl['this_update']}")
    print(f"   ✓ Next Update: {crl['next_update']}")
    print(f"   ✓ Revoked Count: {len(crl['revoked'])}\n")

    # Check revocation
    print("3. Checking certificate status...")
    for serial in ["CERT-001", "CERT-999"]:
        status = "REVOKED" if crl_gen.is_revoked(serial) else "GOOD"
        print(f"   • {serial}: {status}")

    print("\n=== CRL vs OCSP ===")
    print("CRL: Batch download, works offline, larger bandwidth")
    print("OCSP: Real-time queries, smaller bandwidth, requires online access")


if __name__ == "__main__":
    main()
