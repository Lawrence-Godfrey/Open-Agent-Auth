"""Mock smart contract for testing BlockchainTrustStore."""

from typing import Any


class MockCARegistryContract:
    """Mock implementation of CA Registry smart contract for testing."""

    def __init__(self):
        """Initialize mock contract with empty registry."""
        self._cas: dict[str, dict[str, Any]] = {}

    def register_ca(
        self, identifier: str, name: str, public_key: bytes, stake: int
    ) -> None:
        """Register a CA in the mock registry."""
        self._cas[identifier] = {
            "identifier": identifier,
            "name": name,
            "publicKey": public_key,
            "stake": stake,
            "isActive": True,
        }

    def deactivate_ca(self, identifier: str) -> None:
        """Deactivate a CA."""
        if identifier in self._cas:
            self._cas[identifier]["isActive"] = False

    def get_ca(self, identifier: str) -> tuple[str, str, bytes, int, bool]:
        """Get CA information.

        Returns tuple: (identifier, name, publicKey, stake, isActive)
        """
        if identifier not in self._cas:
            # Return empty CA (contract would revert, but we'll return defaults)
            return ("", "", b"", 0, False)

        ca = self._cas[identifier]
        return (
            ca["identifier"],
            ca["name"],
            ca["publicKey"],
            ca["stake"],
            ca["isActive"],
        )

    def get_trusted_cas(self) -> list[str]:
        """Get list of all CA identifiers."""
        return [
            identifier
            for identifier, ca in self._cas.items()
            if ca.get("isActive", False)
        ]


class MockWeb3:
    """Mock Web3 instance for testing."""

    def __init__(self, mock_contract: MockCARegistryContract):
        """Initialize mock Web3 with a mock contract."""
        self._mock_contract = mock_contract
        self.eth = MockEth(mock_contract)

    def to_checksum_address(self, address: str) -> str:
        """Mock checksum address conversion."""
        return address


class MockEth:
    """Mock eth module."""

    def __init__(self, mock_contract: MockCARegistryContract):
        """Initialize mock eth."""
        self._mock_contract = mock_contract
        self.gas_price = 1000000000  # 1 gwei

    def contract(self, address: str, abi: list) -> "MockContract":
        """Return mock contract."""
        return MockContract(self._mock_contract)

    def get_transaction_count(self, address: str) -> int:
        """Mock transaction count."""
        return 0


class MockContract:
    """Mock contract instance."""

    def __init__(self, mock_registry: MockCARegistryContract):
        """Initialize mock contract."""
        self._registry = mock_registry
        self.functions = MockContractFunctions(mock_registry)


class MockContractFunctions:
    """Mock contract functions."""

    def __init__(self, mock_registry: MockCARegistryContract):
        """Initialize mock functions."""
        self._registry = mock_registry

    def getCA(self, identifier: str) -> "MockCall":
        """Mock getCA function."""
        return MockCall(lambda: self._registry.get_ca(identifier))

    def getTrustedCAs(self) -> "MockCall":
        """Mock getTrustedCAs function."""
        return MockCall(lambda: self._registry.get_trusted_cas())

    def registerCA(
        self, identifier: str, name: str, public_key: bytes
    ) -> "MockTransaction":
        """Mock registerCA function."""
        return MockTransaction(
            lambda stake: self._registry.register_ca(
                identifier, name, public_key, stake
            )
        )

    def deactivateCA(self, identifier: str) -> "MockTransaction":
        """Mock deactivateCA function."""
        return MockTransaction(lambda: self._registry.deactivate_ca(identifier))


class MockCall:
    """Mock contract call."""

    def __init__(self, func):
        """Initialize mock call."""
        self._func = func

    def call(self):
        """Execute the call."""
        return self._func()


class MockTransaction:
    """Mock transaction builder."""

    def __init__(self, func):
        """Initialize mock transaction."""
        self._func = func

    def build_transaction(self, params: dict):
        """Build transaction (mock)."""
        # Execute immediately for testing
        value = params.get("value", 0)
        self._func(value) if value else self._func()
        return {"hash": b"0x1234"}
