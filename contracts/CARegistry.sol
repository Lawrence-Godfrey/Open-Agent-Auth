// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CARegistry
 * @dev Decentralized Certificate Authority Registry
 *
 * This smart contract allows banks and payment providers to register
 * as trusted Certificate Authorities by staking tokens. Merchants can
 * query this registry to verify which CAs are trustworthy.
 *
 * Key Features:
 * - Economic security via staking
 * - Community governance for CA management
 * - Transparent, auditable CA registry
 * - No central authority
 */
contract CARegistry {
    struct CA {
        string identifier;      // Domain/identifier (e.g., "bank.example.com")
        string name;           // Human-readable name
        bytes publicKey;       // Ed25519 public key (32 bytes)
        uint256 stake;         // Amount staked (in wei)
        bool isActive;         // Whether CA is currently active
        address owner;         // Address that registered the CA
        uint256 registeredAt;  // Timestamp of registration
    }

    // Mapping from identifier to CA info
    mapping(string => CA) public cas;

    // Array of all CA identifiers (for enumeration)
    string[] public caIdentifiers;

    // Minimum stake required to register as CA
    uint256 public minStake;

    // Governance address (can deactivate malicious CAs)
    address public governance;

    // Events
    event CARegistered(string indexed identifier, string name, uint256 stake, address owner);
    event CADeactivated(string indexed identifier, string reason);
    event CAReactivated(string indexed identifier);
    event StakeIncreased(string indexed identifier, uint256 newStake);
    event StakeWithdrawn(string indexed identifier, uint256 amount);

    constructor(uint256 _minStake) {
        minStake = _minStake;
        governance = msg.sender;
    }

    /**
     * @dev Register as a Certificate Authority
     * @param identifier Domain/identifier for the CA
     * @param name Human-readable name
     * @param publicKey Ed25519 public key (32 bytes)
     */
    function registerCA(
        string memory identifier,
        string memory name,
        bytes memory publicKey
    ) external payable {
        require(bytes(identifier).length > 0, "Identifier cannot be empty");
        require(bytes(name).length > 0, "Name cannot be empty");
        require(publicKey.length == 32, "Public key must be 32 bytes");
        require(msg.value >= minStake, "Insufficient stake");
        require(bytes(cas[identifier].identifier).length == 0, "CA already registered");

        cas[identifier] = CA({
            identifier: identifier,
            name: name,
            publicKey: publicKey,
            stake: msg.value,
            isActive: true,
            owner: msg.sender,
            registeredAt: block.timestamp
        });

        caIdentifiers.push(identifier);

        emit CARegistered(identifier, name, msg.value, msg.sender);
    }

    /**
     * @dev Get CA information
     * @param identifier CA identifier
     * @return CA struct (identifier, name, publicKey, stake, isActive)
     */
    function getCA(string memory identifier)
        external
        view
        returns (
            string memory,
            string memory,
            bytes memory,
            uint256,
            bool
        )
    {
        CA memory ca = cas[identifier];
        return (ca.identifier, ca.name, ca.publicKey, ca.stake, ca.isActive);
    }

    /**
     * @dev Get list of all active CA identifiers
     * @return Array of CA identifiers
     */
    function getTrustedCAs() external view returns (string[] memory) {
        // Count active CAs
        uint256 activeCount = 0;
        for (uint256 i = 0; i < caIdentifiers.length; i++) {
            if (cas[caIdentifiers[i]].isActive) {
                activeCount++;
            }
        }

        // Build array of active identifiers
        string[] memory activeCAs = new string[](activeCount);
        uint256 index = 0;
        for (uint256 i = 0; i < caIdentifiers.length; i++) {
            if (cas[caIdentifiers[i]].isActive) {
                activeCAs[index] = caIdentifiers[i];
                index++;
            }
        }

        return activeCAs;
    }

    /**
     * @dev Increase stake for a CA
     * @param identifier CA identifier
     */
    function increaseStake(string memory identifier) external payable {
        require(bytes(cas[identifier].identifier).length > 0, "CA not registered");
        require(msg.sender == cas[identifier].owner, "Not CA owner");
        require(msg.value > 0, "Must send stake");

        cas[identifier].stake += msg.value;

        emit StakeIncreased(identifier, cas[identifier].stake);
    }

    /**
     * @dev Deactivate a CA (only governance)
     * @param identifier CA identifier
     * @param reason Reason for deactivation
     */
    function deactivateCA(string memory identifier, string memory reason) external {
        require(msg.sender == governance, "Only governance can deactivate");
        require(bytes(cas[identifier].identifier).length > 0, "CA not registered");
        require(cas[identifier].isActive, "CA already deactivated");

        cas[identifier].isActive = false;

        emit CADeactivated(identifier, reason);
    }

    /**
     * @dev Reactivate a CA (only governance)
     * @param identifier CA identifier
     */
    function reactivateCA(string memory identifier) external {
        require(msg.sender == governance, "Only governance can reactivate");
        require(bytes(cas[identifier].identifier).length > 0, "CA not registered");
        require(!cas[identifier].isActive, "CA already active");

        cas[identifier].isActive = true;

        emit CAReactivated(identifier);
    }

    /**
     * @dev Withdraw stake (only after deactivation)
     * @param identifier CA identifier
     */
    function withdrawStake(string memory identifier) external {
        require(msg.sender == cas[identifier].owner, "Not CA owner");
        require(!cas[identifier].isActive, "CA must be deactivated first");
        require(cas[identifier].stake > 0, "No stake to withdraw");

        uint256 amount = cas[identifier].stake;
        cas[identifier].stake = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit StakeWithdrawn(identifier, amount);
    }

    /**
     * @dev Update minimum stake requirement (only governance)
     * @param newMinStake New minimum stake
     */
    function updateMinStake(uint256 newMinStake) external {
        require(msg.sender == governance, "Only governance");
        minStake = newMinStake;
    }

    /**
     * @dev Transfer governance to new address
     * @param newGovernance New governance address
     */
    function transferGovernance(address newGovernance) external {
        require(msg.sender == governance, "Only governance");
        require(newGovernance != address(0), "Invalid address");
        governance = newGovernance;
    }

    /**
     * @dev Check if a CA meets minimum stake requirement
     * @param identifier CA identifier
     * @return bool True if CA is active and meets stake requirement
     */
    function isTrusted(string memory identifier) external view returns (bool) {
        CA memory ca = cas[identifier];
        return ca.isActive && ca.stake >= minStake;
    }
}
