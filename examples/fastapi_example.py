#!/usr/bin/env python3
"""FastAPI Integration Example - Agent authentication middleware."""

from datetime import datetime, timedelta

import httpx
from fastapi import Depends, FastAPI

from open_agent_auth import AgentCertificate, AgentSigner, TrustStore, generate_keypair
from open_agent_auth.core.crypto import sign
from open_agent_auth.integrations.fastapi import (
    AgentAuthMiddleware,
    get_agent_info,
    require_agent_auth,
)


# Create FastAPI app
app = FastAPI(title="Agent Commerce API")

# Set up trust store
trust_store = TrustStore()
ca_private_key, ca_public_key = generate_keypair()
trust_store.add_trusted_ca(
    identifier="bank.example.com", public_key=ca_public_key, name="Example Bank"
)

# Add agent auth middleware
app.add_middleware(AgentAuthMiddleware, trust_store=trust_store, optional=True)


# Public endpoint - no auth required
@app.get("/products")
async def list_products(agent_info: dict = Depends(get_agent_info(required=False))):
    """List products - optionally personalized for agents."""
    if agent_info:
        return {
            "products": ["Widget A", "Widget B"],
            "personalized": True,
            "for_agent": agent_info["agent_id"],
        }
    return {"products": ["Widget A", "Widget B"], "personalized": False}


# Protected endpoint - requires agent auth
@app.post("/cart")
async def add_to_cart(
    product_id: str, agent_info: dict = Depends(require_agent_auth())
):
    """Add to cart - requires agent authentication."""
    return {
        "status": "added",
        "product_id": product_id,
        "agent": agent_info["agent_id"],
    }


# Protected endpoint - requires specific capability
@app.post("/purchase")
async def purchase(
    product_id: str,
    amount: float,
    agent_info: dict = Depends(require_agent_auth(capability="can_purchase")),
):
    """Make purchase - requires can_purchase capability."""
    return {
        "status": "purchased",
        "product_id": product_id,
        "amount": amount,
        "agent": agent_info["agent_id"],
        "account": agent_info["account_reference"],
    }


def main():
    print("=== FastAPI Integration Example ===\n")

    # Create agent certificate
    agent_private_key, agent_public_key = generate_keypair()
    certificate = AgentCertificate(
        serial_number="FASTAPI-001",
        issuer_name="Example Bank",
        issuer_identifier="bank.example.com",
        issuer_public_key=ca_public_key,
        agent_identifier="fastapi-agent",
        agent_public_key=agent_public_key,
        account_reference="user_123",
        not_before=datetime.now() - timedelta(hours=1),
        not_after=datetime.now() + timedelta(days=365),
        capabilities={"can_browse": True, "can_purchase": True},
    )
    certificate.signature = sign(ca_private_key, certificate.get_signing_payload())

    # Create signer
    signer = AgentSigner(certificate=certificate, private_key=agent_private_key)

    print("FastAPI app configured with agent authentication!\n")
    print("Endpoints:")
    print("  GET  /products        - Public (optional auth)")
    print("  POST /cart            - Requires agent auth")
    print("  POST /purchase        - Requires can_purchase capability\n")
    print("To run:")
    print("  uvicorn fastapi_example:app --reload\n")
    print("Example authenticated request:")
    print("  Agent signs request → Middleware validates → Endpoint processes")


if __name__ == "__main__":
    # For demo purposes - in production use uvicorn
    main()
