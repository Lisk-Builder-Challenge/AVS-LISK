// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import {ECDSAServiceManagerBase} from
    "@eigenlayer-middleware/src/unaudited/ECDSAServiceManagerBase.sol";
import {ECDSAStakeRegistry} from "@eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";
import {IServiceManager} from "@eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {ECDSAUpgradeable} from
    "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";
import {IERC1271Upgradeable} from
    "@openzeppelin-upgrades/contracts/interfaces/IERC1271Upgradeable.sol";
import {IHelloWorldServiceManager} from "./IHelloWorldServiceManager.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {IAllocationManager} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import {TransparentUpgradeableProxy} from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title Primary entrypoint for procuring services from HelloWorld.
 * @author Eigen Labs, Inc.
 */
contract HelloWorldServiceManager is ECDSAServiceManagerBase, IHelloWorldServiceManager {
    using ECDSAUpgradeable for bytes32;

    uint32 public latestTaskNum;

    // mapping of task indices to all tasks hashes
    // when a task is created, task hash is stored here,
    // and responses need to pass the actual task,
    // which is hashed onchain and checked against this mapping
    mapping(uint32 => bytes32) public allTaskHashes;

    // mapping of task indices to hash of abi.encode(taskResponse, taskResponseMetadata)
    mapping(address => mapping(uint32 => bytes)) public allTaskResponses;

    // mapping of task indices to task status (true if task has been responded to, false otherwise)
    // TODO: use bitmap?
    mapping(uint32 => bool) public taskWasResponded;

    // max interval in blocks for responding to a task
    // operators can be penalized if they don't respond in time
    uint32 public immutable MAX_RESPONSE_INTERVAL_BLOCKS;

    modifier onlyOperator() {
        require(
            ECDSAStakeRegistry(stakeRegistry).operatorRegistered(msg.sender),
            "Operator must be the caller"
        );
        _;
    }

    constructor(
        address _avsDirectory,
        address _stakeRegistry,
        address _rewardsCoordinator,
        address _delegationManager,
        address _allocationManager,
        uint32 _maxResponseIntervalBlocks
    )
        ECDSAServiceManagerBase(
            _avsDirectory,
            _stakeRegistry,
            _rewardsCoordinator,
            _delegationManager,
            _allocationManager
        )
    {
        MAX_RESPONSE_INTERVAL_BLOCKS = _maxResponseIntervalBlocks;
    }

    function initialize(address initialOwner, address _rewardsInitiator) external initializer {
        __ServiceManagerBase_init(initialOwner, _rewardsInitiator);
    }

    // These are just to comply with IServiceManager interface
    function addPendingAdmin(
        address admin
    ) external onlyOwner {}

    function removePendingAdmin(
        address pendingAdmin
    ) external onlyOwner {}

    function removeAdmin(
        address admin
    ) external onlyOwner {}

    function setAppointee(address appointee, address target, bytes4 selector) external onlyOwner {}

    function removeAppointee(
        address appointee,
        address target,
        bytes4 selector
    ) external onlyOwner {}

    function deregisterOperatorFromOperatorSets(
        address operator,
        uint32[] memory operatorSetIds
    ) external {
        // unused
    }

    /* FUNCTIONS */
    // function to create new borrow request and approve order directly
    function RegisterOperator(
        string memory name,
        uint256 amount,
        uint256 rate,
        uint32 maturity
    ) external {   
        // check if operator is already registered
        require(
            !ECDSAStakeRegistry(stakeRegistry).operatorRegistered(msg.sender),
            "Operator is already registered"
        );
        // register operator
        IDelegationManager(delegationManager).registerAsOperator(
            address(0), 0, ""
        );
    }
    function borrowfund(
        uint256 shares 
    ) 
        external{
        // Vault(_vault).borrowByAVS(amount);
        // address token = address(Vault(_vault).token());
        // IERC20(token).transfer(msg.sender, amount);
        // }
    function respondToTask (
        Task calldata task,
        uint32 referenceTaskIndex,
        bytes memory signature
    ) external {
        // check that the task is valid, hasn't been responded yet, and is being responded in time

        require(
            keccak256(abi.encode(task)) == allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );
        require(
            block.number <= task.taskCreatedBlock + MAX_RESPONSE_INTERVAL_BLOCKS,
            "Task response time has already expired"
        );

        // The message that was signed
        bytes32 messageHash = keccak256(abi.encodePacked("Hello, ", task.name));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        bytes4 magicValue = IERC1271Upgradeable.isValidSignature.selector;

        // Decode the signature data to get operators and their signatures
        (address[] memory operators, bytes[] memory signatures, uint32 referenceBlock) =
            abi.decode(signature, (address[], bytes[], uint32));

        // Check that referenceBlock matches task creation block
        require(
            referenceBlock == task.taskCreatedBlock,
            "Reference block must match task creation block"
        );

        // Store each operator's signature
        for (uint256 i = 0; i < operators.length; i++) {
            // Check that this operator hasn't already responded
            require(
                allTaskResponses[operators[i]][referenceTaskIndex].length == 0,
                "Operator has already responded to the task"
            );

            // Store the operator's signature
            allTaskResponses[operators[i]][referenceTaskIndex] = signatures[i];

            // Emit event for this operator 
            emit TaskResponded(referenceTaskIndex, task, operators[i]);
        }

        taskWasResponded[referenceTaskIndex] = true;

        // Verify all signatures at once
        bytes4 isValidSignatureResult =
            ECDSAStakeRegistry(stakeRegistry).isValidSignature(ethSignedMessageHash, signature);

        require(magicValue == isValidSignatureResult, "Invalid signature");

    // logika yang harus divalidasi operator lain (balance, bunga, jangka waktu berapa)
    }

    function slashOperator(
        Task calldata task,
        uint32 referenceTaskIndex,
        address operator
    ) external {
        // check that the task is valid, hasn't been responsed yet
        require(
            keccak256(abi.encode(task)) == allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );
        require(!taskWasResponded[referenceTaskIndex], "Task has already been responded to");
        require(
            allTaskResponses[operator][referenceTaskIndex].length == 0,
            "Operator has already responded to the task"
        );
        require(
            block.number > task.taskCreatedBlock + MAX_RESPONSE_INTERVAL_BLOCKS,
            "Task response time has not expired yet"
        );
        // check operator was registered when task was created
        uint256 operatorWeight = ECDSAStakeRegistry(stakeRegistry).getOperatorWeightAtBlock(
            operator, task.taskCreatedBlock
        );
        require(operatorWeight > 0, "Operator was not registered when task was created");

        // we update the storage with a sentinel value
        allTaskResponses[operator][referenceTaskIndex] = "slashed";

// TODO: slash operator <- diisi logika akibat yang diterima operator jika melanggar atau terbukti curang (opsional)
    }
}
