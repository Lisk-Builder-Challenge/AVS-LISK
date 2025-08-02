// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface IHelloWorldServiceManager {
    enum TaskStatus{
        PENDING,
        RESPONDED,
        FILLED,
        CANCELED
    }
    event NewTaskCreated(uint32 indexed taskIndex, Task task);

    event TaskResponded(uint32 indexed taskIndex, Task task, address operator);

    event BorrowFilled(uint32 indexed taskNum, Task task);

    event BorrowCanceled(uint32 indexed taskNum, Task task, address operator);

    event OperatorSlashed(address indexed operator, uint32 indexed taskNum, uint256 amount );

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

    function respondToTask(
        Task calldata task,
        uint32 referenceTaskIndex,
        bytes calldata signature
    ) external;

    function cancelBorrowTask(
        uint32 taskIndex
    ) external;
// <- batas diganti
    function slashOperator(
        Task calldata task,
        uint32 referenceTaskIndex,
        address operator
    ) external;
}
