// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script} from "forge-std/Script.sol";
import {CoreDeployLib, CoreDeploymentParsingLib} from "./utils/CoreDeploymentParsingLib.sol";
import {UpgradeableProxyLib} from "./utils/UpgradeableProxyLib.sol";
import {IRewardsCoordinator} from "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {StrategyManager} from "@eigenlayer/contracts/core/StrategyManager.sol";
import "forge-std/Test.sol";

contract DeployEigenLayerCore is Script, Test {
    using CoreDeployLib for *;
    using UpgradeableProxyLib for address;

    address internal deployer;
    address internal proxyAdmin;
    CoreDeployLib.DeploymentData internal deploymentData;
    CoreDeployLib.DeploymentConfigData internal configData;

    function setUp() public virtual {
        deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        vm.label(deployer, "Deployer");
    }

    function run() external {
        vm.startBroadcast(deployer);
        initializeConfig();
        deployStep1(); // Deploy proxies
        deployPermissionController();
        deployStrategyManager();
        deployAllocationManager();
        deployDelegationManager();
        deployAVSDirectory();
        deployEigenPodBeacon();
        deployEigenPodManager();
        deployStrategyBeacon();
        deployStrategyFactory();
        deployRewardsCoordinator();
        configureContracts();
        writeDeploymentData();
        vm.stopBroadcast();
    }

    function initializeConfig() internal {
        configData = CoreDeploymentParsingLib.readDeploymentConfigValues("config/core/", block.chainid);
        configData.rewardsCoordinator.rewardsUpdater = deployer;
    }

    function deployStep1() internal {
        proxyAdmin = UpgradeableProxyLib.deployProxyAdmin();
        deploymentData = CoreDeployLib.deployEmptyProxies(proxyAdmin);
    }

    function deployPermissionController() internal {
        CoreDeployLib.deployPermissionController(deploymentData);
    }

    function deployStrategyManager() internal {
        CoreDeployLib.deployStrategyManager(deploymentData, configData);
    }

    function deployAllocationManager() internal {
        CoreDeployLib.deployAllocationManager(deploymentData, configData);
    }

    function deployDelegationManager() internal {
        CoreDeployLib.deployDelegationManager(deploymentData, configData);
    }

    function deployAVSDirectory() internal {
        CoreDeployLib.deployAVSDirectory(deploymentData, configData);
    }

    function deployEigenPodBeacon() internal {
        CoreDeployLib.deployEigenPodBeacon(deploymentData, configData);
    }

    function deployEigenPodManager() internal {
        CoreDeployLib.deployEigenPodManager(deploymentData, configData);
    }

    function deployStrategyBeacon() internal {
        CoreDeployLib.deployStrategyBeacon(deploymentData, configData);
    }

    function deployStrategyFactory() internal {
        CoreDeployLib.deployStrategyFactory(deploymentData, configData);
    }

    function deployRewardsCoordinator() internal {
        CoreDeployLib.deployRewardsCoordinator(deploymentData, configData);
    }

    function configureContracts() internal {
        StrategyManager(deploymentData.strategyManager).setStrategyWhitelister(deploymentData.strategyFactory);
    }

    function writeDeploymentData() internal {
        string memory deploymentPath = "deployments/core/";
        CoreDeploymentParsingLib.writeDeploymentJson(deploymentPath, block.chainid, deploymentData);
    }
}