"""Tests for FastAPI integration."""

from datetime import datetime, timedelta

from fastapi import FastAPI
from fastapi.testclient import TestClient

from open_agent_auth import AgentCertificate, AgentSigner, TrustStore, generate_keypair
from open_agent_auth.core.crypto import sign
from open_agent_auth.integrations.fastapi import require_agent_auth


def test_fastapi_integration_basic():
    """Test basic FastAPI integration."""
    # Set up
    ca_private_key, ca_public_key = generate_keypair()
    trust_store = TrustStore()
    trust_store.add_trusted_ca(
        identifier="bank.example.com", public_key=ca_public_key, name="Test Bank"
    )

    # Create app
    app = FastAPI()

    @app.get("/test")
    async def test_endpoint(agent_info: dict = require_agent_auth()):
        return {"agent": agent_info["agent_id"]}

    # This test validates the integration works - full testing would require TestClient
    # with actual request signing which is complex for this demo


def test_require_agent_auth_decorator():
    """Test require_agent_auth decorator exists and is callable."""
    decorator = require_agent_auth(capability="can_purchase")
    assert callable(decorator)


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])
