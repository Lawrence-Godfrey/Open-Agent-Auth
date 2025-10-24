# Open Agent Auth

**Decentralized agent authentication for agentic commerce using Web Bot Auth protocol**

Open Agent Auth is a Python library that implements decentralized agent authentication for autonomous commerce. It provides a certificate-based trust model that eliminates the need for central registries (like Visa/Mastercard), while remaining compatible with the Web Bot Auth protocol and HTTP Message Signatures (RFC 9421).

## Features

-  **Decentralized Trust Model** - No dependency on central registries
-  **Web Bot Auth Compatible** - Implements HTTP Message Signatures (RFC 9421)
-  **Ed25519 Cryptography** - Fast, secure public-key signatures
-  **Certificate-Based Authentication** - Similar to SSL/TLS certificate chains
-  **Type-Safe** - Built with Pydantic for data validation
-  **Async-Ready** - Designed for async/await patterns
-  **Production-Ready** - Comprehensive error handling and validation

## Installation

```bash
# Using uv (recommended)
uv add open-agent-auth

# Using pip
pip install open-agent-auth
```

## Quick Start

### For Agents: Signing Requests

```python
from datetime import datetime, timedelta
import httpx
from open_agent_auth import AgentSigner, AgentCertificate, generate_keypair
from open_agent_auth.core.crypto import sign

# 1. Generate agent keypair
agent_private_key, agent_public_key = generate_keypair()

# 2. Obtain certificate from your bank/payment provider
# (In production, this would be issued by a CA after verification)
certificate = AgentCertificate(
    serial_number="abc123",
    issuer_name="Example Bank",
    issuer_identifier="bank.example.com",
    issuer_public_key=ca_public_key,  # Bank's public key
    agent_identifier="my-shopping-agent",
    agent_public_key=agent_public_key,
    account_reference="hashed_account_id",
    not_before=datetime.now(),
    not_after=datetime.now() + timedelta(days=365),
    capabilities={
        "can_browse": True,
        "can_purchase": True,
    },
)

# Certificate is signed by the bank
certificate.signature = sign(ca_private_key, certificate.get_signing_payload())

# 3. Create signer
signer = AgentSigner(certificate=certificate, private_key=agent_private_key)

# 4. Sign requests
request = httpx.Request(
    method="POST",
    url="https://merchant.example.com/api/purchase",
    headers={"Content-Type": "application/json"},
    json={"product_id": "12345", "quantity": 1}
)

signed_request = signer.sign_request(request, tag="agent-payer-auth")

# 5. Send signed request
async with httpx.AsyncClient() as client:
    response = await client.send(signed_request)
```

### For Merchants: Verifying Requests

```python
from open_agent_auth import AgentVerifier, TrustStore

# 1. Set up trust store with trusted CAs (banks)
trust_store = TrustStore()
trust_store.add_trusted_ca(
    identifier="bank.example.com",
    public_key=bank_public_key,
    name="Example Bank"
)

# Or load from YAML config
# trust_store = TrustStore.from_config("trust_store.yaml")

# 2. Create verifier
verifier = AgentVerifier(trust_store=trust_store)

# 3. Verify incoming requests
result = verifier.verify_request(request, required_capability="can_purchase")

if result.valid:
    # Request is authenticated!
    print(f"Agent: {result.agent_id}")
    print(f"Account: {result.account_reference}")
    print(f"Capabilities: {result.capabilities}")
    # Process the request...
else:
    # Authentication failed
    print(f"Error: {result.error}")
    return {"error": "Unauthorized"}, 403
```

### Trust Store Configuration

Create a `trust_store.yaml` file:

```yaml
version: "1.0"

trusted_cas:
  - identifier: "bank.example.com"
    name: "Example Bank"
    public_key: "ed25519:BASE64_ENCODED_PUBLIC_KEY_HERE"
    enabled: true

  - identifier: "payments.bigbank.com"
    name: "Big Bank Payments"
    public_key: "ed25519:BASE64_ENCODED_PUBLIC_KEY_HERE"
    enabled: true
```

Load it in your code:

```python
from open_agent_auth import TrustStore

trust_store = TrustStore.from_config("trust_store.yaml")
```

## Architecture

### How It Works

1. **Certificate Issuance**: Banks/payment providers issue certificates to agents after verifying user authorization
2. **Request Signing**: Agents sign HTTP requests using Ed25519 and include their certificate
3. **Chain Validation**: Merchants verify the certificate chain against their trust store
4. **Signature Verification**: Merchants verify the request signature using the agent's public key from the certificate

### Comparison to Centralized Model

| Aspect | Centralized (Visa/MC) | Decentralized (Open Agent Auth) |
|--------|----------------------|--------------------------------|
| Trust Model | Single registry | Multiple trusted CAs |
| Validation | Query registry | Verify certificate chain |
| Privacy | Central party sees all activity | No central visibility |
| Single Point of Failure | Yes | No |
| Certificate Transport | Registry lookup | Included in request |

## API Reference

### Core Functions

#### `generate_keypair()`
Generate a new Ed25519 keypair for an agent.

```python
from open_agent_auth import generate_keypair

private_key, public_key = generate_keypair()
```

### Classes

#### `AgentCertificate`
Represents an agent authentication certificate.

**Key Fields:**
- `agent_identifier`: Unique agent ID
- `agent_public_key`: Agent's Ed25519 public key
- `issuer_identifier`: CA/bank identifier
- `capabilities`: Dict of agent capabilities
- `not_before`/`not_after`: Validity period

**Methods:**
- `is_valid()`: Check if certificate is currently valid
- `has_capability(capability)`: Check if agent has a specific capability
- `to_base64()`: Serialize for HTTP headers
- `from_base64(b64)`: Deserialize from HTTP headers

#### `AgentSigner`
Signs HTTP requests for agents.

```python
signer = AgentSigner(certificate=cert, private_key=key)
signed_request = signer.sign_request(request, tag="agent-payer-auth")
```

#### `AgentVerifier`
Verifies agent requests and validates certificates.

```python
verifier = AgentVerifier(trust_store=trust_store)
result = verifier.verify_request(request, required_capability="can_purchase")
```

#### `TrustStore`
Manages trusted certificate authorities.

```python
trust_store = TrustStore()
trust_store.add_trusted_ca(identifier="bank.com", public_key=key, name="Bank")
trust_store.save("trust_store.yaml")
```

## Web Bot Auth Protocol

Open Agent Auth implements the Web Bot Auth protocol with HTTP Message Signatures (RFC 9421):

### Request Headers

Signed requests include:

```
Signature-Input: sig1=("@method" "@authority" "@path" "content-type");created=1718206800;expires=1718207100;keyid="agent-123";nonce="abc";tag="agent-payer-auth"
Signature: sig1=:BASE64_SIGNATURE:
X-Agent-Certificate: BASE64_CERTIFICATE
```

### Tags

- `agent-browser-auth`: Browsing/product discovery
- `agent-payer-auth`: Payment/purchase actions

## Testing

Run the test suite:

```bash
# Using uv
uv run pytest

# Using pytest directly
pytest tests/
```

## Development

```bash
# Clone the repository
git clone https://github.com/yourusername/open-agent-auth.git
cd open-agent-auth

# Install with dev dependencies
uv sync --dev

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=open_agent_auth
```

## Roadmap

- [x] Core certificate and crypto operations
- [x] HTTP Message Signatures (RFC 9421)
- [x] Trust store management
- [x] Certificate chain validation
- [x] Agent signer
- [x] Request verifier
- [x] Basic tests
- [ ] OCSP support for certificate revocation
- [ ] CRL support
- [ ] FastAPI integration middleware
- [ ] Flask integration
- [ ] Django integration
- [ ] Certificate renewal automation
- [ ] CLI tools for certificate management
- [ ] Comprehensive documentation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details.

## Related Documentation

- Design Document: See `../open-agent-auth-design.md` for detailed architecture
- Decentralized Model Analysis: See `../decentralized-agent-auth.md` for comparison with centralized models

## Security Considerations

- Always validate certificates against a trusted CA list
- Use short signature validity periods (default: 5 minutes)
- Implement nonce checking to prevent replay attacks
- Rotate agent keys periodically
- Secure storage of private keys (HSM recommended for production)
- Monitor certificate expiration and renew proactively

## Support

For issues, questions, or contributions:
- GitHub Issues: [github.com/yourusername/open-agent-auth/issues]
- Documentation: [See design docs in parent directory]

---

**Status**: Alpha - Core functionality implemented and tested. Additional features in development.
