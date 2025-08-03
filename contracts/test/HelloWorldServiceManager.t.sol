// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {HelloWorldServiceManager} from "../src/HelloWorldServiceManager.sol";
import {MockAVSDeployer} from "@eigenlayer-middleware/test/utils/MockAVSDeployer.sol";
import {ECDSAStakeRegistry} from "@eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";
import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/Test.sol";
import {HelloWorldDeploymentLib} from "../script/utils/HelloWorldDeploymentLib.sol";
import {
    CoreDeployLib,
    CoreDeploymentParsingLib
} from "../script/utils/CoreDeploymentParsingLib.sol";
import {UpgradeableProxyLib} from "../script/utils/UpgradeableProxyLib.sol";
import {ERC20Mock} from "./ERC20Mock.sol";
import {IERC20, StrategyFactory} from "@eigenlayer/contracts/strategies/StrategyFactory.sol";

import {
    IECDSAStakeRegistryTypes,
    IStrategy
} from "@eigenlayer-middleware/src/interfaces/IECDSAStakeRegistry.sol";
import {IStrategyManager} from "@eigenlayer/contracts/interfaces/IStrategyManager.sol";
import {
    IDelegationManager,
    IDelegationManagerTypes
} from "@eigenlayer/contracts/interfaces/IDelegationManager.sol";
import {DelegationManager} from "@eigenlayer/contracts/core/DelegationManager.sol";
import {StrategyManager} from "@eigenlayer/contracts/core/StrategyManager.sol";
import {ISignatureUtilsMixinTypes} from "@eigenlayer/contracts/interfaces/ISignatureUtilsMixin.sol";
import {AVSDirectory} from "@eigenlayer/contracts/core/AVSDirectory.sol";
import {IAVSDirectoryTypes} from "@eigenlayer/contracts/interfaces/IAVSDirectory.sol";
import {Test, console2 as console} from "forge-std/Test.sol";
import {IHelloWorldServiceManager} from "../src/Interfaces/IHelloWorldServiceManager.sol";
import {ECDSAUpgradeable} from
    "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";
import {IVault} from "../src/Interfaces/IVault.sol";
import {IYieldzAVS} from "../src/Interfaces/IYieldzAVS.sol";
import {MockVault} from "./MockVault.sol";
import {MockYieldzAVS} from "./MockYieldzAVS.sol";

contract HelloWorldTaskManagerSetup is Test {
    // used for `toEthSignedMessageHash`
    using ECDSAUpgradeable for bytes32;

    IECDSAStakeRegistryTypes.Quorum internal quorum;

    struct Operator {
        Vm.Wallet key;
        Vm.Wallet signingKey;
    }

    struct TrafficGenerator {
        Vm.Wallet key;
    }

    struct AVSOwner {
        Vm.Wallet key;
    }

    Operator[] internal operators;
    TrafficGenerator internal generator;
    AVSOwner internal owner;

    HelloWorldDeploymentLib.DeploymentData internal helloWorldDeployment;
    CoreDeployLib.DeploymentData internal coreDeployment;
    CoreDeployLib.DeploymentConfigData internal coreConfigData;

    address proxyAdmin;

    ERC20Mock public mockToken;
    MockVault public mockVault;
    MockYieldzAVS public mockYieldzAVS;

    mapping(address => IStrategy) public tokenToStrategy;

    function setUp() public virtual {
        generator = TrafficGenerator({key: vm.createWallet("generator_wallet")});
        owner = AVSOwner({key: vm.createWallet("owner_wallet")});

        proxyAdmin = UpgradeableProxyLib.deployProxyAdmin();

        coreConfigData = CoreDeploymentParsingLib.readDeploymentConfigValues("test/mockData/config/core/", 1337);
        coreDeployment = CoreDeployLib.deployContracts(proxyAdmin, coreConfigData);

        vm.prank(coreConfigData.strategyManager.initialOwner);
        StrategyManager(coreDeployment.strategyManager).setStrategyWhitelister(coreDeployment.strategyFactory);

        mockToken = new ERC20Mock();
        mockVault = new MockVault();
        mockYieldzAVS = new MockYieldzAVS();

        IStrategy strategy = addStrategy(address(mockToken));
        quorum.strategies.push(
            IECDSAStakeRegistryTypes.StrategyParams({strategy: strategy, multiplier: 10_000})
        );

        helloWorldDeployment = HelloWorldDeploymentLib.deployContracts(
            proxyAdmin, coreDeployment, quorum, owner.key.addr, owner.key.addr
        );
        helloWorldDeployment.strategy = address(strategy);
        helloWorldDeployment.token = address(mockToken);
        helloWorldDeployment.vault = address(mockVault); // Tambahkan vault mock
        helloWorldDeployment.yieldzAVS = address(mockYieldzAVS); // Tambahkan yieldzAVS mock
        labelContracts(coreDeployment, helloWorldDeployment);
    }

    function addStrategy(
        address token
    ) public returns (IStrategy) {
        if (tokenToStrategy[token] != IStrategy(address(0))) {
            return tokenToStrategy[token];
        }

        StrategyFactory strategyFactory = StrategyFactory(coreDeployment.strategyFactory);
        IStrategy newStrategy = strategyFactory.deployNewStrategy(IERC20(token));
        tokenToStrategy[token] = newStrategy;
        return newStrategy;
    }

    function labelContracts(
        CoreDeployLib.DeploymentData memory _coreDeployment,
        HelloWorldDeploymentLib.DeploymentData memory _helloWorldDeployment
    ) internal {
        vm.label(_coreDeployment.delegationManager, "DelegationManager");
        vm.label(_coreDeployment.avsDirectory, "AVSDirectory");
        vm.label(_coreDeployment.strategyManager, "StrategyManager");
        vm.label(_coreDeployment.eigenPodManager, "EigenPodManager");
        vm.label(_coreDeployment.rewardsCoordinator, "RewardsCoordinator");
        vm.label(_coreDeployment.eigenPodBeacon, "EigenPodBeacon");
        vm.label(_coreDeployment.pauserRegistry, "PauserRegistry");
        vm.label(_coreDeployment.strategyFactory, "StrategyFactory");
        vm.label(_coreDeployment.strategyBeacon, "StrategyBeacon");
        vm.label(_helloWorldDeployment.helloWorldServiceManager, "HelloWorldServiceManager");
        vm.label(_helloWorldDeployment.stakeRegistry, "StakeRegistry");
    }

    function signWithOperatorKey(
        Operator memory operator,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operator.key.privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function signWithSigningKey(
        Operator memory operator,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operator.signingKey.privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function mintMockTokens(Operator memory operator, uint256 amount) internal {
        mockToken.mint(operator.key.addr, amount);
    }

    function depositTokenIntoStrategy(
        Operator memory operator,
        address token,
        uint256 amount
    ) internal returns (uint256) {
        IStrategy strategy = IStrategy(tokenToStrategy[token]);
        require(address(strategy) != address(0), "Strategy was not found");
        IStrategyManager strategyManager = IStrategyManager(coreDeployment.strategyManager);

        vm.startPrank(operator.key.addr);
        mockToken.approve(address(strategyManager), amount);
        uint256 shares = strategyManager.depositIntoStrategy(strategy, IERC20(token), amount);
        vm.stopPrank();

        return shares;
    }

    function registerAsOperator(
        Operator memory operator
    ) internal {
        IDelegationManager delegationManager = IDelegationManager(coreDeployment.delegationManager);

        vm.prank(operator.key.addr);
        delegationManager.registerAsOperator(address(0), 0, "");
    }

    function registerOperatorToAVS(
        Operator memory operator
    ) internal {
        ECDSAStakeRegistry stakeRegistry = ECDSAStakeRegistry(helloWorldDeployment.stakeRegistry);
        AVSDirectory avsDirectory = AVSDirectory(coreDeployment.avsDirectory);

        bytes32 salt = keccak256(abi.encodePacked(block.timestamp, operator.key.addr));
        uint256 expiry = block.timestamp + 1 hours;

        bytes32 operatorRegistrationDigestHash = avsDirectory
            .calculateOperatorAVSRegistrationDigestHash(
            operator.key.addr, address(helloWorldDeployment.helloWorldServiceManager), salt, expiry
        );

        bytes memory signature = signWithOperatorKey(operator, operatorRegistrationDigestHash);

        ISignatureUtilsMixinTypes.SignatureWithSaltAndExpiry memory operatorSignature =
        ISignatureUtilsMixinTypes.SignatureWithSaltAndExpiry({
            signature: signature,
            salt: salt,
            expiry: expiry
        });

        vm.prank(address(operator.key.addr));
        stakeRegistry.registerOperatorWithSignature(operatorSignature, operator.signingKey.addr);
    }

    function deregisterOperatorFromAVS(
        Operator memory operator
    ) internal {
        ECDSAStakeRegistry stakeRegistry = ECDSAStakeRegistry(helloWorldDeployment.stakeRegistry);

        vm.prank(operator.key.addr);
        stakeRegistry.deregisterOperator();
    }

    function createAndAddOperator() internal returns (Operator memory) {
        Vm.Wallet memory operatorKey =
            vm.createWallet(string.concat("operator", vm.toString(operators.length)));
        Vm.Wallet memory signingKey =
            vm.createWallet(string.concat("signing", vm.toString(operators.length)));

        Operator memory newOperator = Operator({key: operatorKey, signingKey: signingKey});

        operators.push(newOperator);
        return newOperator;
    }

    function updateOperatorWeights(
        Operator[] memory _operators
    ) internal {
        ECDSAStakeRegistry stakeRegistry = ECDSAStakeRegistry(helloWorldDeployment.stakeRegistry);

        address[] memory operatorAddresses = new address[](_operators.length);
        for (uint256 i = 0; i < _operators.length; i++) {
            operatorAddresses[i] = _operators[i].key.addr;
        }

        stakeRegistry.updateOperators(operatorAddresses);
    }

    function getOperators(
        uint256 numOperators
    ) internal view returns (Operator[] memory) {
        require(numOperators <= operators.length, "Not enough operators");

        Operator[] memory operatorsMem = new Operator[](numOperators);
        for (uint256 i = 0; i < numOperators; i++) {
            operatorsMem[i] = operators[i];
        }
        // Sort the operators by address
        for (uint256 i = 0; i < numOperators - 1; i++) {
            uint256 minIndex = i;
            // Find the minimum operator by address
            for (uint256 j = i + 1; j < numOperators; j++) {
                if (operatorsMem[minIndex].key.addr > operatorsMem[j].key.addr) {
                    minIndex = j;
                }
            }
            // Swap the minimum operator with the ith operator
            Operator memory temp = operatorsMem[i];
            operatorsMem[i] = operatorsMem[minIndex];
            operatorsMem[minIndex] = temp;
        }
        return operatorsMem;
    }

    function createTask(
        string memory taskName,
        address operator,
        uint256 amount,
        uint256 rate,
        uint32 maturity
    ) internal returns (IHelloWorldServiceManager.Task memory task, uint32 taskIndex) {
        IHelloWorldServiceManager helloWorldServiceManager =
            IHelloWorldServiceManager(helloWorldDeployment.helloWorldServiceManager);

        vm.prank(owner.key.addr); // Hanya owner yang bisa memanggil createBorrowTask
        taskIndex = helloWorldServiceManager.latestTaskNum();
        task = helloWorldServiceManager.createBorrowTask(operator, taskName, amount, rate, maturity);
        return (task, taskIndex);
    }

    function respondToTask(
        Operator[] memory operatorsMem,
        IHelloWorldServiceManager.Task memory task,
        uint32 referenceTaskIndex
    ) internal {
        bytes memory signedResponse = makeTaskResponse(operatorsMem, task);

        IHelloWorldServiceManager(helloWorldDeployment.helloWorldServiceManager).respondToTask(
            task, referenceTaskIndex, signedResponse
        );
    }

    function makeTaskResponse(
        Operator[] memory operatorsMem,
        IHelloWorldServiceManager.Task memory task
    ) internal pure returns (bytes memory) {
        bytes32 messageHash = keccak256(abi.encodePacked("Hello, ", task.name));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();

        address[] memory operatorAddrs = new address[](operatorsMem.length);
        for (uint256 i = 0; i < operatorsMem.length; i++) {
            operatorAddrs[i] = operatorsMem[i].key.addr;
        }
        bytes[] memory signatures = new bytes[](operatorsMem.length);
        for (uint256 i = 0; i < operatorsMem.length; i++) {
            signatures[i] = signWithSigningKey(operatorsMem[i], ethSignedMessageHash);
        }

        bytes memory signedTask = abi.encode(operatorAddrs, signatures, task.taskCreatedBlock);

        return signedTask;
    }

    function slashOperator(
        IHelloWorldServiceManager.Task memory task,
        uint32 referenceTaskIndex,
        address operator
    ) internal {
        IHelloWorldServiceManager(helloWorldDeployment.helloWorldServiceManager).slashOperator(
            task, referenceTaskIndex, operator
        );
    }
}

contract CreateTask is HelloWorldTaskManagerSetup {
    IHelloWorldServiceManager internal sm;

    function setUp() public override {
        super.setUp();
        sm = IHelloWorldServiceManager(helloWorldDeployment.helloWorldServiceManager);
    }

    function testCreateBorrowTask() public {
        string memory taskName = "Test Borrow Task";
        address operator = address(0x123); // Operator dummy
        uint256 amount = 100 ether;
        uint256 rate = 100; // Contoh rate
        uint32 maturity = uint32(block.timestamp + 1 days); // Maturity di masa depan

        // Tambahkan aset ke mockVault untuk memenuhi validasi likuiditas
        vm.prank(address(sm));
        mockVault.addAssets(1000 ether);

        vm.prank(owner.key.addr); // Hanya owner yang bisa
        IHelloWorldServiceManager.Task memory newTask = sm.createBorrowTask(
            operator, taskName, amount, rate, maturity
        );

        require(
            keccak256(abi.encodePacked(newTask.name)) == keccak256(abi.encodePacked(taskName)),
            "Task name not set correctly"
        );
        require(newTask.taskCreatedBlock == uint32(block.number), "Task created block not set correctly");
        require(newTask.operator == operator, "Operator not set correctly");
        require(newTask.amount == amount, "Amount not set correctly");
        require(newTask.rate == rate, "Rate not set correctly");
        require(newTask.maturity > block.timestamp, "Maturity not in future");
    }
}

contract RespondToTask is HelloWorldTaskManagerSetup {
    uint256 internal constant INITIAL_BALANCE = 100 ether;
    uint256 internal constant DEPOSIT_AMOUNT = 1 ether;
    uint256 internal constant OPERATOR_COUNT = 4;

    IDelegationManager internal delegationManager;
    AVSDirectory internal avsDirectory;
    IHelloWorldServiceManager internal sm;
    ECDSAStakeRegistry internal stakeRegistry;

    function setUp() public override {
        super.setUp();

        delegationManager = IDelegationManager(coreDeployment.delegationManager);
        avsDirectory = AVSDirectory(coreDeployment.avsDirectory);
        sm = IHelloWorldServiceManager(helloWorldDeployment.helloWorldServiceManager);
        stakeRegistry = ECDSAStakeRegistry(helloWorldDeployment.stakeRegistry);

        addStrategy(address(mockToken));

        while (operators.length < OPERATOR_COUNT) {
            createAndAddOperator();
        }

        for (uint256 i = 0; i < OPERATOR_COUNT; i++) {
            mintMockTokens(operators[i], INITIAL_BALANCE);
            depositTokenIntoStrategy(operators[i], address(mockToken), DEPOSIT_AMOUNT);
            registerAsOperator(operators[i]);
            registerOperatorToAVS(operators[i]);
        }
    }

    function testRespondToTask() public {
        (IHelloWorldServiceManager.Task memory newTask, uint32 taskIndex) = createTask(
            "TestTask", 
            address(operators[0].key.addr), 
            100 ether, 
            100, 
            uint32(block.timestamp + 1 days)
        );

        Operator[] memory operatorsMem = getOperators(1);
        bytes memory signedResponse = makeTaskResponse(operatorsMem, newTask);

        vm.roll(block.number + 1);
        sm.respondToTask(newTask, taskIndex, signedResponse);
    }
    function testRespondToTaskWith2OperatorsAggregatedSignature() public {
        (IHelloWorldServiceManager.Task memory newTask, uint32 taskIndex) = createTask(
            "TestTask2Aggregated",
            address(operators[0].key.addr),
            100 ether, 
            500, 
            uint32(block.timestamp + 1 days)
        );
        
        require(uint32(block.timestamp + 1 days) > block.timestamp, "Maturity must be in future");

        // Generate aggregated response with two operators
        Operator[] memory operatorsMem = getOperators(2);
        bytes memory signedResponse = makeTaskResponse(operatorsMem, newTask);

        vm.roll(block.number + 1);
        sm.respondToTask(newTask, taskIndex, signedResponse);
    }

    function testRespondToTaskWith3OperatorsAggregatedSignature() public {
        (IHelloWorldServiceManager.Task memory newTask, uint32 taskIndex) = createTask(
            "TestTask3Aggregated",
            operators[0].key.addr, // Pilih operator pertama
            100 ether,
            500,
            uint32(block.timestamp + 1 days) // Konversi eksplisit
        );
        require(uint32(block.timestamp + 1 days) > block.timestamp, "Maturity must be in future");

        // Generate aggregated response with three operators
        Operator[] memory operatorsMem = getOperators(3);
        bytes memory signedResponse = makeTaskResponse(operatorsMem, newTask);

        vm.roll(block.number + 1);
        sm.respondToTask(newTask, taskIndex, signedResponse);
    }
}

contract SlashOperator is HelloWorldTaskManagerSetup {
    uint256 internal constant INITIAL_BALANCE = 100 ether;
    uint256 internal constant DEPOSIT_AMOUNT = 1 ether;
    uint256 internal constant OPERATOR_COUNT = 4;

    IDelegationManager internal delegationManager;
    AVSDirectory internal avsDirectory;
    IHelloWorldServiceManager internal sm;
    ECDSAStakeRegistry internal stakeRegistry;

    function setUp() public override {
        super.setUp();

        delegationManager = IDelegationManager(coreDeployment.delegationManager);
        avsDirectory = AVSDirectory(coreDeployment.avsDirectory);
        sm = IHelloWorldServiceManager(helloWorldDeployment.helloWorldServiceManager);
        stakeRegistry = ECDSAStakeRegistry(helloWorldDeployment.stakeRegistry);

        addStrategy(address(mockToken));

        while (operators.length < OPERATOR_COUNT) {
            createAndAddOperator();
        }

        for (uint256 i = 0; i < OPERATOR_COUNT; i++) {
            mintMockTokens(operators[i], INITIAL_BALANCE);

            depositTokenIntoStrategy(operators[i], address(mockToken), DEPOSIT_AMOUNT);

            registerAsOperator(operators[i]);

            registerOperatorToAVS(operators[i]);
        }
    }

    function testValidResponseIsNotSlashable() public {
        (IHelloWorldServiceManager.Task memory newTask, uint32 taskIndex) = createTask(
            "TestValidResponseIsNotSlashable",
            operators[0].key.addr, // Pilih operator pertama
            100 ether,
            500,
            uint32(block.timestamp + 1 days) // Konversi eksplisit
        );
        require(uint32(block.timestamp + 1 days) > block.timestamp, "Maturity must be in future");

        Operator[] memory operatorsMem = getOperators(1);

        vm.roll(block.number + 1);
        respondToTask(operatorsMem, newTask, taskIndex);

        vm.expectRevert("Task has already been responded to");
        slashOperator(newTask, taskIndex, operatorsMem[0].key.addr);

        // TODO: check the operator's balance was not reduced
    }

    function testNoResponseIsSlashable() public {
        (IHelloWorldServiceManager.Task memory newTask, uint32 taskIndex) = createTask(
            "TestNoResponseIsSlashable",
            operators[0].key.addr, // Pilih operator pertama
            100 ether,
            500,
            uint32(block.timestamp + 1 days) // Konversi eksplisit
        );
        require(uint32(block.timestamp + 1 days) > block.timestamp, "Maturity must be in future");

        Operator[] memory operatorsMem = getOperators(1);

        uint32 maxResponseIntervalBlocks =
            HelloWorldServiceManager(address(sm)).MAX_RESPONSE_INTERVAL_BLOCKS();
        vm.roll(block.number + maxResponseIntervalBlocks + 1);

        slashOperator(newTask, taskIndex, operatorsMem[0].key.addr);

        // TODO: check the operator's balance was reduced
    }

    function testMultipleSlashings() public {
        (IHelloWorldServiceManager.Task memory newTask, uint32 taskIndex) = createTask(
            "TestMultipleSlashings",
            operators[0].key.addr, // Pilih operator pertama
            100 ether,
            500,
            uint32(block.timestamp + 1 days) // Konversi eksplisit
        );
        require(uint32(block.timestamp + 1 days) > block.timestamp, "Maturity must be in future");

        Operator[] memory operatorsMem = getOperators(3);

        uint32 maxResponseIntervalBlocks =
            HelloWorldServiceManager(address(sm)).MAX_RESPONSE_INTERVAL_BLOCKS();
        vm.roll(block.number + maxResponseIntervalBlocks + 1);

        slashOperator(newTask, taskIndex, operatorsMem[0].key.addr);
        slashOperator(newTask, taskIndex, operatorsMem[1].key.addr);
        slashOperator(newTask, taskIndex, operatorsMem[2].key.addr);

        // TODO: check the operator's balance was reduced
    }
}
