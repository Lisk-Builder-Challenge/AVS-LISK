// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface IHelloWorldServiceManager {
    event NewTaskCreated(uint32 indexed taskIndex, Task task);

    event TaskResponded(uint32 indexed taskIndex, Task task, address operator);

    struct Task {
        string name;
        address operator;
        uint256 amount;
        uint256 rate;
        uint32 maturity;
        uint32 taskCreatedBlock;

    }

    function latestTaskNum() external view returns (uint32);

    function allTaskHashes(
        uint32 taskIndex
    ) external view returns (bytes32);

    function allTaskResponses(
        address operator,
        uint32 taskIndex
    ) external view returns (bytes memory);

    function deposit(
        uint256 amount
    )external;

    function withdraw(
        uint256 shares
    )external;

    function distributeYield(
        uint256 amount
    )external;

    function borrowFund(
        uint256 amount
    ) external;

    function respondToTask(
        Task calldata task,
        uint32 referenceTaskIndex,
        bytes calldata signature
    ) external;
// <- batas diganti
    function slashOperator(
        Task calldata task,
        uint32 referenceTaskIndex,
        address operator
    ) external;
}
