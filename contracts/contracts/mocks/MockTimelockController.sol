// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title MockTimelockController
 * @notice Mock that enforces real time-delayed execution for integration tests.
 * @dev Mirrors the OpenZeppelin TimelockController's schedule → wait → execute
 *      flow so tests can prove governed config changes are actually delayed.
 */
contract MockTimelockController {
    uint256 private _minDelay;
    address public owner;

    struct QueuedOp {
        address target;
        bytes data;
        uint256 readyAt;
        bool executed;
    }
    mapping(bytes32 => QueuedOp) public queuedOps;
    uint256 private _nonce;

    error NotOwner();
    error OperationNotReady();
    error OperationAlreadyExecuted();
    error OperationNotQueued();
    error DirectExecutionDisabled();

    event OperationQueued(bytes32 indexed opId, address target, uint256 readyAt);
    event OperationExecuted(bytes32 indexed opId, address target);

    constructor(uint256 minDelay_, address owner_) {
        _minDelay = minDelay_;
        owner = owner_;
    }

    function getMinDelay() external view returns (uint256) {
        return _minDelay;
    }

    function setMinDelay(uint256 newDelay) external {
        if (msg.sender != owner) revert NotOwner();
        _minDelay = newDelay;
    }

    /**
     * @notice Queue a governance action for time-delayed execution.
     * @param target The contract to call.
     * @param data The calldata to forward.
     * @return opId The unique operation identifier.
     */
    function queueCall(address target, bytes calldata data) external returns (bytes32 opId) {
        if (msg.sender != owner) revert NotOwner();
        opId = keccak256(abi.encode(target, data, _nonce++));
        queuedOps[opId] = QueuedOp({
            target: target,
            data: data,
            readyAt: block.timestamp + _minDelay,
            executed: false
        });
        emit OperationQueued(opId, target, block.timestamp + _minDelay);
    }

    /**
     * @notice Execute a previously queued action after delay has elapsed.
     * @param opId The operation identifier returned by queueCall.
     * @return result The return data from the call.
     */
    function executeQueuedCall(bytes32 opId) external returns (bytes memory result) {
        if (msg.sender != owner) revert NotOwner();
        QueuedOp storage op = queuedOps[opId];
        if (op.target == address(0)) revert OperationNotQueued();
        if (op.executed) revert OperationAlreadyExecuted();
        if (block.timestamp < op.readyAt) revert OperationNotReady();

        op.executed = true;
        bool success;
        (success, result) = op.target.call(op.data);
        require(success, "MockTimelockController: call failed");
        emit OperationExecuted(opId, op.target);
    }
}
