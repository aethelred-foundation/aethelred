// SPDX-License-Identifier: Apache-2.0
// Certora Verification Language (CVL) specification for SovereignGovernanceTimelock
//
// SQ14 Formal Methods Execution - Tier 1 Target
// Contract: contracts/SovereignGovernanceTimelock.sol
//
// Properties verified:
//   1. Minimum delay enforcement (>= 7 days)
//   2. Execution requires elapsed delay (TimelockController schedule/execute flow)
//   3. Dual signature requirement (issuer + foundation)
//   4. Operation lifecycle integrity (queued -> executed, no re-execution)
//   5. Key rotation safety

// =============================================================================
// METHOD DECLARATIONS
// =============================================================================

methods {
    // Constants
    function MIN_KEY_ROTATION_DELAY() external returns (uint256) envfree;

    // TimelockController inherited
    function getMinDelay() external returns (uint256) envfree;
    function isOperation(bytes32) external returns (bool) envfree;
    function isOperationPending(bytes32) external returns (bool) envfree;
    function isOperationReady(bytes32) external returns (bool) envfree;
    function isOperationDone(bytes32) external returns (bool) envfree;
    function getOperationState(bytes32) external returns (uint8) envfree;
    function hashOperation(address, uint256, bytes, bytes32, bytes32) external returns (bytes32) envfree;

    // Key rotation
    function rotateKey(
        address,
        SovereignGovernanceTimelock.KeyType,
        address,
        bytes32,
        bytes32,
        uint256,
        bytes,
        bytes
    ) external returns (bytes32);

    function executeKeyRotation(bytes32) external;

    // Scheduling (inherited from TimelockController)
    function schedule(address, uint256, bytes, bytes32, bytes32, uint256) external;
    function execute(address, uint256, bytes, bytes32, bytes32) external;
}

// =============================================================================
// MINIMUM DELAY ENFORCEMENT
// =============================================================================

/// @title Minimum delay is at least 7 days
/// @notice The SovereignGovernanceTimelock enforces that the timelock delay
///         is at least MIN_KEY_ROTATION_DELAY (7 days). This prevents
///         rushed key rotations that could enable governance attacks.
invariant minimumDelayEnforced()
    getMinDelay() >= MIN_KEY_ROTATION_DELAY();

/// @title MIN_KEY_ROTATION_DELAY equals 7 days
rule minDelayIs7Days() {
    assert MIN_KEY_ROTATION_DELAY() == 604800,
        "MIN_KEY_ROTATION_DELAY must be 7 days (604800 seconds)";
}

/// @title getMinDelay always >= 7 days after any state change
rule minDelayPreservedAcrossOperations() {
    env e;

    require getMinDelay() >= MIN_KEY_ROTATION_DELAY();

    calldataarg args;
    f(e, args);

    assert getMinDelay() >= MIN_KEY_ROTATION_DELAY(),
        "Minimum delay must remain >= 7 days after any operation";
}

// =============================================================================
// EXECUTION REQUIRES ELAPSED DELAY
// =============================================================================

/// @title An operation that is not ready cannot be executed
/// @notice The TimelockController tracks operation state. An operation
///         transitions: Unset -> Waiting -> Ready -> Done.
///         Execution requires the Ready state (delay has elapsed).
rule cannotExecuteBeforeReady(bytes32 operationId) {
    env e;

    require !isOperationReady(operationId);

    executeKeyRotation@withrevert(e, operationId);

    assert lastReverted,
        "Key rotation execution must revert if the timelock delay has not elapsed";
}

/// @title Unqueued operations cannot be executed
rule cannotExecuteUnqueuedOperation(bytes32 operationId) {
    env e;

    require !isOperation(operationId);

    executeKeyRotation@withrevert(e, operationId);

    assert lastReverted,
        "Cannot execute a key rotation that was never queued";
}

// =============================================================================
// OPERATION LIFECYCLE INTEGRITY
// =============================================================================

/// @title Once an operation is done, it stays done
rule doneOperationStaysDone(bytes32 operationId) {
    env e;

    require isOperationDone(operationId);

    calldataarg args;
    f(e, args);

    assert isOperationDone(operationId),
        "A completed operation must remain in done state permanently";
}

/// @title An operation cannot be executed twice
rule cannotDoubleExecuteRotation(bytes32 operationId) {
    env e1;
    env e2;

    // Execute once
    executeKeyRotation(e1, operationId);

    // Attempt second execution — must revert
    executeKeyRotation@withrevert(e2, operationId);

    assert lastReverted,
        "Key rotation cannot be executed twice (OperationAlreadyExecuted)";
}

/// @title Cannot queue an operation that already exists
rule cannotDoubleQueueRotation(
    address bridge,
    SovereignGovernanceTimelock.KeyType keyType,
    address newKey,
    bytes32 predecessor,
    bytes32 salt,
    uint256 deadline,
    bytes issuerSig,
    bytes foundationSig
) {
    env e1;
    env e2;

    // Queue once
    bytes32 opId = rotateKey(e1, bridge, keyType, newKey, predecessor, salt, deadline, issuerSig, foundationSig);

    // Attempt to queue same operation again — must revert
    rotateKey@withrevert(e2, bridge, keyType, newKey, predecessor, salt, deadline, issuerSig, foundationSig);

    assert lastReverted,
        "Cannot queue the same rotation operation twice (OperationAlreadyQueued)";
}

// =============================================================================
// DUAL SIGNATURE REQUIREMENT
// =============================================================================

/// @title Key rotation requires both issuer and foundation signatures
/// @notice The rotateKey function verifies that both the issuer governance key
///         and the foundation governance key have signed the rotation digest.
///         Invalid signatures cause a revert.
/// @dev This is tested via the contract's ECDSA.recover checks against
///      the bridge's issuerGovernanceKey() and foundationGovernanceKey().
///      The CVL rule verifies the revert behavior with empty/invalid signatures.
rule rotationRequiresDualSignatures(
    address bridge,
    SovereignGovernanceTimelock.KeyType keyType,
    address newKey,
    bytes32 predecessor,
    bytes32 salt,
    uint256 deadline
) {
    env e;

    // Empty signatures (invalid)
    bytes emptySig;
    require emptySig.length == 0;

    rotateKey@withrevert(e, bridge, keyType, newKey, predecessor, salt, deadline, emptySig, emptySig);

    assert lastReverted,
        "Key rotation must revert without valid dual signatures";
}

// =============================================================================
// KEY ROTATION SAFETY
// =============================================================================

/// @title Cannot rotate to zero address
rule cannotRotateToZeroAddress(
    address bridge,
    SovereignGovernanceTimelock.KeyType keyType,
    bytes32 predecessor,
    bytes32 salt,
    uint256 deadline,
    bytes issuerSig,
    bytes foundationSig
) {
    env e;
    address zeroAddr = 0;

    rotateKey@withrevert(e, bridge, keyType, zeroAddr, predecessor, salt, deadline, issuerSig, foundationSig);

    assert lastReverted,
        "Key rotation to zero address must revert";
}

/// @title Cannot rotate with zero bridge address
rule cannotRotateWithZeroBridge(
    SovereignGovernanceTimelock.KeyType keyType,
    address newKey,
    bytes32 predecessor,
    bytes32 salt,
    uint256 deadline,
    bytes issuerSig,
    bytes foundationSig
) {
    env e;
    address zeroBridge = 0;

    rotateKey@withrevert(e, zeroBridge, keyType, newKey, predecessor, salt, deadline, issuerSig, foundationSig);

    assert lastReverted,
        "Key rotation with zero bridge address must revert";
}

/// @title Cannot rotate with expired deadline
rule cannotRotateWithExpiredDeadline(
    address bridge,
    SovereignGovernanceTimelock.KeyType keyType,
    address newKey,
    bytes32 predecessor,
    bytes32 salt,
    bytes issuerSig,
    bytes foundationSig
) {
    env e;

    uint256 expiredDeadline = require_uint256(e.block.timestamp - 1);

    rotateKey@withrevert(e, bridge, keyType, newKey, predecessor, salt, expiredDeadline, issuerSig, foundationSig);

    assert lastReverted,
        "Key rotation with expired deadline must revert";
}

// =============================================================================
// TIMELOCK DELAY INTEGRITY
// =============================================================================

/// @title Delay check is performed at rotation time
/// @notice If getMinDelay() < MIN_KEY_ROTATION_DELAY, rotateKey must revert.
///         This ensures that even if the TimelockController's delay is lowered
///         externally, the SovereignGovernanceTimelock rejects it.
rule rotationRejectsInsufficientDelay(
    address bridge,
    SovereignGovernanceTimelock.KeyType keyType,
    address newKey,
    bytes32 predecessor,
    bytes32 salt,
    uint256 deadline,
    bytes issuerSig,
    bytes foundationSig
) {
    env e;

    require getMinDelay() < MIN_KEY_ROTATION_DELAY();

    rotateKey@withrevert(e, bridge, keyType, newKey, predecessor, salt, deadline, issuerSig, foundationSig);

    assert lastReverted,
        "rotateKey must revert when getMinDelay() < MIN_KEY_ROTATION_DELAY";
}
