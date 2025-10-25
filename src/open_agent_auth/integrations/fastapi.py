"""FastAPI integration for open-agent-auth."""

from typing import Optional

from fastapi import Depends, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware

from ..core.errors import CapabilityError
from ..core.models import ValidationResult
from ..trust.store import TrustStore
from ..validator import AgentVerifier


class AgentAuthMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for agent authentication."""

    def __init__(self, app, trust_store: TrustStore, optional: bool = False):
        """Initialize middleware.

        Args:
            app: FastAPI application
            trust_store: Trust store for CA verification
            optional: If True, allow requests without agent auth
        """
        super().__init__(app)
        self.verifier = AgentVerifier(trust_store=trust_store)
        self.optional = optional

    async def dispatch(self, request: Request, call_next):
        """Process request."""
        # Convert starlette request to httpx-compatible
        import httpx

        httpx_request = httpx.Request(
            method=request.method,
            url=str(request.url),
            headers=dict(request.headers),
        )

        # Verify agent auth
        result = self.verifier.verify_request(httpx_request)

        # Attach result to request state
        request.state.agent_auth = result
        request.state.agent_info = (
            {
                "agent_id": result.agent_id,
                "account_reference": result.account_reference,
                "capabilities": result.capabilities,
                "issuer": result.issuer,
            }
            if result.valid
            else None
        )

        # If auth required and failed, return 401
        if not self.optional and not result.valid:
            raise HTTPException(status_code=401, detail=result.error)

        response = await call_next(request)
        return response


def get_agent_info(required: bool = False):
    """Dependency to get agent info from request.

    Args:
        required: If True, raise error if no agent auth

    Returns:
        Agent info dictionary or None
    """

    async def _get_agent_info(request: Request) -> Optional[dict]:
        agent_info = getattr(request.state, "agent_info", None)
        if required and not agent_info:
            raise HTTPException(status_code=401, detail="Agent authentication required")
        return agent_info

    return _get_agent_info


def require_agent_auth(capability: Optional[str] = None):
    """Dependency to require agent authentication with optional capability check.

    Args:
        capability: Required capability (e.g., "can_purchase")

    Returns:
        Agent info dictionary

    Raises:
        HTTPException: If authentication fails or capability missing
    """

    async def _require_agent_auth(request: Request) -> dict:
        agent_info = getattr(request.state, "agent_info", None)

        if not agent_info:
            raise HTTPException(status_code=401, detail="Agent authentication required")

        # Check capability if specified
        if capability:
            if not agent_info.get("capabilities", {}).get(capability):
                raise HTTPException(
                    status_code=403,
                    detail=f"Agent does not have required capability: {capability}",
                )

        return agent_info

    return _require_agent_auth
