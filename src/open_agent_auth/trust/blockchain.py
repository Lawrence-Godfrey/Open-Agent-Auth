"""Blockchain-based trust store for decentralized CA registry."""

from typing import Optional

from web3 import Web3
from web3.contract import Contract

from ..core.errors import TrustStoreError
from .store import TrustedCA


# CA Registry ABI - minimal interface for our needs
CA_REGISTRY_ABI = [
    {
        "inputs": [{"name": "identifier", "type": "string"}],
        "name": "getCA",
        "outputs": [
            {"name": "identifier", "type": "string"},
            {"name": "name", "type": "string"},
            {"name": "publicKey", "type": "bytes"},
            {"name": "stake", "type": "uint256"},
            {"name": "isActive", "type": "bool"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getTrustedCAs",
        "outputs": [{"name": "", "type": "string[]"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "identifier", "type": "string"},
            {"name": "name", "type": "string"},
            {"name": "publicKey", "type": "bytes"},
        ],
        "name": "registerCA",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function",
    },
    {
        "inputs": [{"name": "identifier", "type": "string"}],
        "name": "deactivateCA",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]


class BlockchainTrustStore:
    """Trust store backed by a blockchain smart contract.

    This implementation queries a smart contract registry instead of
    maintaining a local YAML file. CAs register themselves on-chain
    with stake, providing economic security.
    """

    def __init__(
        self,
        web3_provider: Web3,
        registry_address: str,
        min_stake: int = 0,
        abi: Optional[list] = None,
    ):
        """Initialize blockchain trust store.

        Args:
            web3_provider: Web3 instance connected to a blockchain
            registry_address: Address of the CA registry contract
            min_stake: Minimum stake required for a CA to be trusted (in wei)
            abi: Contract ABI (uses default CA_REGISTRY_ABI if not provided)
        """
        self.web3 = web3_provider
        self.registry_address = Web3.to_checksum_address(registry_address)
        self.min_stake = min_stake
        self.contract: Contract = self.web3.eth.contract(
            address=self.registry_address, abi=abi or CA_REGISTRY_ABI
        )

    def get_ca(self, identifier: str) -> Optional[TrustedCA]:
        """Get a CA by identifier from the blockchain.

        Args:
            identifier: CA identifier

        Returns:
            TrustedCA if found and meets requirements, None otherwise
        """
        try:
            result = self.contract.functions.getCA(identifier).call()

            # Unpack result (identifier, name, publicKey, stake, isActive)
            ca_identifier, ca_name, public_key_bytes, stake, is_active = result

            # Check if CA meets requirements
            if not is_active:
                return None

            if stake < self.min_stake:
                return None

            return TrustedCA(
                identifier=ca_identifier,
                name=ca_name,
                public_key=public_key_bytes,
                enabled=True,
            )

        except Exception:
            # CA not found or contract call failed
            return None

    def is_trusted(self, identifier: str) -> bool:
        """Check if a CA is trusted.

        Args:
            identifier: CA identifier

        Returns:
            True if CA is trusted and meets stake requirements
        """
        return self.get_ca(identifier) is not None

    def get_public_key(self, identifier: str) -> Optional[bytes]:
        """Get the public key for a CA.

        Args:
            identifier: CA identifier

        Returns:
            Public key bytes if CA is trusted, None otherwise
        """
        ca = self.get_ca(identifier)
        return ca.public_key if ca else None

    def list_cas(self) -> list[TrustedCA]:
        """List all trusted CAs from the blockchain.

        Returns:
            List of all active CAs that meet stake requirements
        """
        try:
            identifiers = self.contract.functions.getTrustedCAs().call()
            cas = []

            for identifier in identifiers:
                ca = self.get_ca(identifier)
                if ca:
                    cas.append(ca)

            return cas

        except Exception as e:
            raise TrustStoreError(f"Failed to list CAs from blockchain: {e}")

    def register_ca(
        self,
        identifier: str,
        name: str,
        public_key: bytes,
        stake_amount: int,
        sender_address: str,
        private_key: Optional[str] = None,
    ) -> str:
        """Register a new CA on the blockchain.

        Args:
            identifier: CA identifier
            name: CA name
            public_key: CA public key
            stake_amount: Amount to stake (in wei)
            sender_address: Address sending the transaction
            private_key: Private key for signing (if not using provider's accounts)

        Returns:
            Transaction hash

        Raises:
            TrustStoreError: If registration fails
        """
        try:
            # Build transaction
            tx = self.contract.functions.registerCA(
                identifier, name, public_key
            ).build_transaction(
                {
                    "from": Web3.to_checksum_address(sender_address),
                    "value": stake_amount,
                    "gas": 300000,
                    "gasPrice": self.web3.eth.gas_price,
                    "nonce": self.web3.eth.get_transaction_count(
                        Web3.to_checksum_address(sender_address)
                    ),
                }
            )

            # Sign and send
            if private_key:
                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
            else:
                tx_hash = self.web3.eth.send_transaction(tx)

            return tx_hash.hex()

        except Exception as e:
            raise TrustStoreError(f"Failed to register CA: {e}")

    def deactivate_ca(
        self, identifier: str, sender_address: str, private_key: Optional[str] = None
    ) -> str:
        """Deactivate a CA on the blockchain.

        Args:
            identifier: CA identifier to deactivate
            sender_address: Address sending the transaction
            private_key: Private key for signing

        Returns:
            Transaction hash

        Raises:
            TrustStoreError: If deactivation fails
        """
        try:
            tx = self.contract.functions.deactivateCA(identifier).build_transaction(
                {
                    "from": Web3.to_checksum_address(sender_address),
                    "gas": 100000,
                    "gasPrice": self.web3.eth.gas_price,
                    "nonce": self.web3.eth.get_transaction_count(
                        Web3.to_checksum_address(sender_address)
                    ),
                }
            )

            if private_key:
                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
            else:
                tx_hash = self.web3.eth.send_transaction(tx)

            return tx_hash.hex()

        except Exception as e:
            raise TrustStoreError(f"Failed to deactivate CA: {e}")
