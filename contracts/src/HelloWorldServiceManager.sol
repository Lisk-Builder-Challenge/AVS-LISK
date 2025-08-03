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
import {IHelloWorldServiceManager} from "./Interfaces/IHelloWorldServiceManager.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {IAllocationManager} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import {TransparentUpgradeableProxy} from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IVault} from "./Interfaces/IVault.sol";
import {IYieldzAVS} from "./Interfaces/IYieldzAVS.sol";

contract HelloWorldServiceManager is 
    ECDSAServiceManagerBase, 
    IHelloWorldServiceManager 
{
    using ECDSAUpgradeable for bytes32;

    uint32 public latestTaskNum;

    //mapping menyimpan hash dari setiap task berdasarkan Task struct dengan indeks uint32 <- untuk validasi task di respondTask
    mapping(uint32 => bytes32) public allTaskHashes;

    //mapping bertingkat untuk mentimpan respons (signature) dari operator untuk setiap task
    mapping(address => mapping(uint32 => bytes)) public allTaskResponses;

    // mapping of task indices to task status (true if task has been responded to, false otherwise)
    // TODO: use bitmap?
    mapping(uint32 => bool) public taskWasResponded;

    mapping(uint256 => TaskStatus) public taskStatus;
    mapping(uint256 => Task) public tasks;

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

    address public immutable yieldzAVS;
    address public immutable vault;

constructor(
        address _avsDirectory,
        address _stakeRegistry,
        address _rewardsCoordinator,
        address _delegationManager,
        address _allocationManager,
        address _yieldzAVS,
        address _vault,
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
        yieldzAVS = _yieldzAVS;
        vault = _vault;
        MAX_RESPONSE_INTERVAL_BLOCKS = _maxResponseIntervalBlocks;
    }

    //Inisialisasi untuk kontrak upgradeable
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
        // register operator; Memanggil fungsi registerAsOperator pada kontrak DelegationManager (komponen EigenLayer) untuk mendaftarkan msg.sender sebagai operator. Parameter address(0), 0, dan "" adalah nilai placeholder (sesuai dengan template HelloWorldAVS), yang menunjukkan bahwa registrasi dilakukan tanpa delegasi atau metadata tambahan.
        IDelegationManager(delegationManager).registerAsOperator(
            address(0), 0, ""
        );
        // Buat task peminjaman
        createBorrowTask(msg.sender, name, amount, rate, maturity);
    }

    //fungsi untuk membuat task peminjaman
    function createBorrowTask(
        address operator,
        string memory name,
        uint256 amount,
        uint256 rate,
        uint256 maturity
    ) public onlyOwner returns (Task memory){
        require(maturity > block.timestamp, "Maturity must be in the future");
        require(amount > 0, "Amount must be greater than zero");
        require(amount <= IVault(vault).totalAssets()-IVault(vault).totalBorrowed(), "Insufficient liquidity");

        Task memory newTask = Task({
            operator: operator,
            name: name,
            amount: amount,
            rate: rate,
            maturity: uint32(maturity),
            taskCreatedBlock: uint32(block.number)
        });

        //menghitung hash dari stuktur Task lalu menyimpannya di allTaskHashes dengan indeks LastestTaskNum <- validasi task di fungsi respondToTask
        allTaskHashes[latestTaskNum] = keccak256(abi.encode(newTask));
        // emit TaskCreated(latestTaskNum, newTask);
        latestTaskNum++;
        return newTask;
    }

    //Fungsi untuk merespons task peminjaman 
    function respondToTask (
        Task calldata task,
        uint32 referenceTaskIndex,
        bytes memory signature
    ) external {
        //Validasi task 
        require(
            keccak256(abi.encode(task)) == allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );
        require(
            block.number <= task.taskCreatedBlock + MAX_RESPONSE_INTERVAL_BLOCKS,
            "Task response time has already expired"
        );
        require(
            ECDSAStakeRegistry(stakeRegistry).operatorRegistered(task.operator),
            "Operator Not Registered"
        );
        // require(
        //     operators.length == 1 && operators[0] == task.operator, "Only task operator can respond"
        // );

        // The message that was signed
        bytes32 messageHash = keccak256(abi.encode(task));
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

            require(
                ECDSAStakeRegistry(stakeRegistry).operatorRegistered(operators[i]),
                "Responder not registered"
            );

            // Store the operator's signature
            allTaskResponses[operators[i]][referenceTaskIndex] = signatures[i];

            // Emit event for this operator 
            emit TaskResponded(referenceTaskIndex, task, operators[i]);
            emit BorrowFilled(referenceTaskIndex, task);
        }

        taskWasResponded[referenceTaskIndex] = true;

        // Verify all signatures at once
        bytes4 isValidSignatureResult =
            ECDSAStakeRegistry(stakeRegistry).isValidSignature(ethSignedMessageHash, signature);

        require(magicValue == isValidSignatureResult, "Invalid signature");

        //proses peminjaman melalui IYieldzAVS
        IYieldzAVS(yieldzAVS).borrowFund(vault, task.operator, task.amount, task.rate, task.maturity);

    }
    
    function cancelBorrowTask(uint32 taskIndex) external onlyOwner {
        require(!taskWasResponded[taskIndex], "Task already responded");
        require(allTaskHashes[taskIndex] != bytes32(0), "Task does not exist");
        taskStatus[taskIndex] = TaskStatus.CANCELED;
        emit BorrowCanceled(taskIndex, tasks[taskIndex], msg.sender);
    }

    //fungsi untuk menangani pelanggaran operator
    function slashOperator(
        Task calldata task,
        uint32 referenceTaskIndex,
        address operator
    ) external onlyOwner{
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

        uint256 operatorWeight = ECDSAStakeRegistry(stakeRegistry).getOperatorWeightAtBlock(
            operator, task.taskCreatedBlock
        );
        require(operatorWeight > 0, "Operator was not registered when task was created");

        // we update the storage with a sentinel value
        allTaskResponses[operator][referenceTaskIndex] = "slashed";

        //Batalkan pinjaman di YieldAVS jika ada
        //mengambil detail pinjaman operator dari YieldAVS
        (uint256 loanAmount,, uint256 borrowedAt, uint256 maturity) = IYieldzAVS(yieldzAVS).getLoanDetails(operator);

        //Apakah operator memliki pinjaman aktif dan apakah telah jatuh tempo
        //jika terpenuhi pinjaman akan dibatalkan
        if(loanAmount > 0 && block.timestamp > maturity){
            IVault(vault).reduceBorrowed(loanAmount);
            emit OperatorSlashed(operator, referenceTaskIndex, loanAmount);
        } else {
            emit OperatorSlashed(operator, referenceTaskIndex, 0);
        }

    }
}
