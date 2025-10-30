// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable-v4/access/Ownable2StepUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable-v4/security/PausableUpgradeable.sol";

import {ReentrancyGuard} from "../common/ReentrancyGuard.sol";
import {UnsafeBytes} from "../common/libraries/UnsafeBytes.sol";
import {IBridgehub} from "../bridgehub/IBridgehub.sol";
import {L2Message} from "../common/Messaging.sol";
import {L2_ASSET_ROUTER_ADDR} from "../common/l2-helpers/L2ContractAddresses.sol";

// Reuse your error types for consistency with the rest of the codebase.
import {InvalidProof, WrongL2Sender, WrongMsgLength, AddressAlreadySet} from "../common/L1ContractErrors.sol";

/**
 * @title L1IntentRegistry
 * @notice Minimal, non-custodial registry for L2-proven post-withdrawal intents.
 *         - Verifies an L2->L1 message via Bridgehub
 *         - Parses only requestId from a tiny packed payload
 *         - Records isIntentAdmitted[requestId] = true
 * @dev Upgradeable (Ownable2StepUpgradeable), Pausable, ReentrancyGuard.
 *      Keep this contract lean; policy/route checks live off-chain or in executor logic.
 */
contract L1IntentRegistry is ReentrancyGuard, Ownable2StepUpgradeable, PausableUpgradeable {
    /// @dev Bridgehub used to prove L2 message inclusion.
    IBridgehub public BRIDGE_HUB;

    /// @dev Allowlist of L2 senders permitted to emit intents for this registry.
    mapping(address => bool) public isAllowedL2Sender;

    /// @dev True if a given requestId (emitted on L2) has been proven/admitted on L1.
    mapping(bytes32 => bool) public isIntentAdmitted;

    /// @dev Emitted when an intent is admitted (proved) on L1.
    event IntentAdmitted(bytes32 indexed requestId);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize with Bridgehub and an initial allowed L2 sender (defaults to L2_ASSET_ROUTER_ADDR).
     * @param _bridgehub   Bridgehub address.
     * @param _owner       Owner (governor).
     * @param _initialL2Sender Optional initial L2 sender; if zero, uses L2_ASSET_ROUTER_ADDR.
     */
    function initialize(IBridgehub _bridgehub, address _owner, address _initialL2Sender)
        external
        initializer
        reentrancyGuardInitializer
    {
        if (address(_bridgehub) == address(0)) revert InvalidProof(); // reuse error for bad config
        if (_owner == address(0)) revert WrongL2Sender(address(0));   // consistent error style

        BRIDGE_HUB = _bridgehub;
        _transferOwnership(_owner);
        __Pausable_init();

        address sender = _initialL2Sender == address(0) ? L2_ASSET_ROUTER_ADDR : _initialL2Sender;
        isAllowedL2Sender[sender] = true;
    }

    /*//////////////////////////////////////////////////////////////
                         GOVERNANCE / ADMIN
    //////////////////////////////////////////////////////////////*/

    function setAllowedL2Sender(address _sender, bool _allowed) external onlyOwner {
        if (_sender == address(0)) revert WrongL2Sender(address(0));
        isAllowedL2Sender[_sender] = _allowed;
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                 ADMIT L2-PROVEN POST-WITHDRAWAL INTENT (MIN)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verifies & admits a post-withdrawal intent that L2 emitted.
     * @dev L2 sends a packed message to THIS contract with:
     *      abi.encodePacked(this.admitPostWithdrawalIntent.selector, requestId)
     *      total length = 36 bytes.
     *
     * @param _chainId           ZK chain ID the intent originated from.
     * @param _l2BatchNumber     Batch where the intent message was included.
     * @param _l2MessageIndex    Index in the L2->L1 logs tree.
     * @param _l2Sender          Expected L2 sender (must be allowlisted).
     * @param _l2TxNumberInBatch TX number in the batch that emitted the message.
     * @param _message           Packed message bytes (36 bytes).
     * @param _merkleProof       Inclusion proof for the message.
     */
    function admitPostWithdrawalIntent(
        uint256 _chainId,
        uint256 _l2BatchNumber,
        uint256 _l2MessageIndex,
        address _l2Sender,
        uint16  _l2TxNumberInBatch,
        bytes   calldata _message,
        bytes32[] calldata _merkleProof
    ) external nonReentrant whenNotPaused {
        // 1) Validate L2 sender address against allowlist.
        if (!isAllowedL2Sender[_l2Sender]) {
            revert WrongL2Sender(_l2Sender);
        }

        // 2) Prove inclusion of the L2->L1 message via Bridgehub.
        L2Message memory l2ToL1Message = L2Message({
            txNumberInBatch: _l2TxNumberInBatch,
            sender: _l2Sender,
            data: _message
        });

        bool ok = BRIDGE_HUB.proveL2MessageInclusion({
            _chainId: _chainId,
            _batchNumber: _l2BatchNumber,
            _index: _l2MessageIndex,
            _message: l2ToL1Message,
            _proof: _merkleProof
        });
        if (!ok) {
            revert InvalidProof();
        }

        // 3) Parse requestId (selector + requestId = 36 bytes).
        bytes32 requestId = _parseL2IntentId(_message);

        // 4) Admit once (prevent replay).
        if (isIntentAdmitted[requestId]) {
            // You can introduce a dedicated error; using WrongMsgLength here would be misleading.
            // For minimal changes and consistency, just revert with a generic custom error if you have one,
            // or use a common revert message:
            revert AddressAlreadySet(address(0)); // reusing to avoid adding a new error; swap for a custom one if desired
        }

        isIntentAdmitted[requestId] = true;
        emit IntentAdmitted(requestId);
    }

    /*//////////////////////////////////////////////////////////////
                     INTENT MESSAGE DECODING (MIN)
    //////////////////////////////////////////////////////////////*/

    /// @dev Decode the packed L2->L1 intent message:
    ///      0..3   : bytes4 selector == this.admitPostWithdrawalIntent.selector
    ///      4..35  : bytes32 requestId
    function _parseL2IntentId(bytes memory _l2ToL1message) internal pure returns (bytes32 requestId) {
        if (_l2ToL1message.length != 36) {
            revert WrongMsgLength(36, _l2ToL1message.length);
        }
        (uint32 functionSignature, uint256 offset) = UnsafeBytes.readUint32(_l2ToL1message, 0);
        require(bytes4(functionSignature) == this.admitPostWithdrawalIntent.selector, "intent/bad-selector");
        (requestId, /*offset*/ ) = UnsafeBytes.readBytes32(_l2ToL1message, offset);
    }
}
