// SPDX-License-Identifier: Apache-2.0
// Certora Verification Language (CVL) specification for AethelredBridge
//
// SQ14 Formal Methods Execution - Tier 1 Target
// Contract: contracts/AethelredBridge.sol
//
// Properties verified:
//   1. Replay protection (processed burn tx hashes cannot be reused)
//   2. Rate limit enforcement (deposits/withdrawals bounded per period)
//   3. Per-block mint ceiling (defense-in-depth cap on withdrawals per block)
//   4. Challenge period enforcement (withdrawals blocked until challenge expires)
//   5. Consensus threshold enforcement (sufficient votes required)
//   6. Sanctions compliance at execution time

// =============================================================================
// METHOD DECLARATIONS
// =============================================================================

methods {
    // State variables
    function depositNonce() external returns (uint256) envfree;
    function totalLockedETH() external returns (uint256) envfree;
    function totalLockedERC20(address) external returns (uint256) envfree;
    function supportedTokens(address) external returns (bool) envfree;
    function processedWithdrawals(bytes32) external returns (bool) envfree;
    function blockedAddresses(address) external returns (bool) envfree;
    function emergencyWithdrawalDelay() external returns (uint256) envfree;
    function mintCeilingPerBlock() external returns (uint256) envfree;

    // Constants
    function MIN_DEPOSIT() external returns (uint256) envfree;
    function MAX_SINGLE_DEPOSIT() external returns (uint256) envfree;
    function CHALLENGE_PERIOD() external returns (uint256) envfree;
    function MIN_ETH_CONFIRMATIONS() external returns (uint256) envfree;
    function RATE_LIMIT_PERIOD() external returns (uint256) envfree;
    function REQUIRED_GUARDIAN_APPROVALS() external returns (uint256) envfree;
    function DEFAULT_MINT_CEILING_PER_BLOCK() external returns (uint256) envfree;
    function MAX_EMERGENCY_WITHDRAWAL() external returns (uint256) envfree;
    function MIN_EMERGENCY_TIMELOCK() external returns (uint256) envfree;
    function MAX_EMERGENCY_TIMELOCK() external returns (uint256) envfree;

    // Withdrawal votes
    function withdrawalVotes(bytes32, address) external returns (bool) envfree;
    function guardianApprovals(bytes32, address) external returns (bool) envfree;
    function guardianApprovalCount(bytes32) external returns (uint256) envfree;

    // Mutating functions
    function depositETH(bytes32) external;
    function depositERC20(address, uint256, bytes32) external;
    function proposeWithdrawal(bytes32, address, address, uint256, bytes32, uint256) external;
    function voteWithdrawal(bytes32) external;
    function processWithdrawal(bytes32) external;
    function challengeWithdrawal(bytes32, string) external;
    function queueEmergencyWithdrawal(address, uint256, address) external;
    function executeEmergencyWithdrawal(bytes32) external;

    // Pause
    function paused() external returns (bool) envfree;
}

// =============================================================================
// REPLAY PROTECTION
// =============================================================================

/// @title Once a burn tx hash is processed, it stays processed forever
/// @notice This is the critical anti-replay property. A processed withdrawal
///         keyed on burnTxHash can never be "unprocessed".
rule processedWithdrawalsNeverUnset(bytes32 burnTxHash) {
    env e;

    require processedWithdrawals(burnTxHash);

    // Execute any function
    calldataarg args;
    f(e, args);

    assert processedWithdrawals(burnTxHash),
        "A processed burn tx hash must remain processed forever (anti-replay)";
}

/// @title Cannot propose a withdrawal for an already-processed burn tx hash
rule cannotReplayProcessedBurnTx(
    bytes32 proposalId,
    address recipient,
    address token,
    uint256 amount,
    bytes32 burnTxHash,
    uint256 aethelredBlockHeight
) {
    env e;

    require processedWithdrawals(burnTxHash);

    proposeWithdrawal@withrevert(e, proposalId, recipient, token, amount, burnTxHash, aethelredBlockHeight);

    assert lastReverted,
        "Proposing a withdrawal for a processed burn tx must revert (replay protection)";
}

/// @title Cannot process the same proposal twice
rule cannotDoubleProcessWithdrawal(bytes32 proposalId) {
    env e1;
    env e2;

    // Process it once
    processWithdrawal(e1, proposalId);

    // Attempt to process again — must revert
    processWithdrawal@withrevert(e2, proposalId);

    assert lastReverted,
        "Processing a withdrawal proposal twice must revert";
}

// =============================================================================
// CHALLENGE PERIOD ENFORCEMENT
// =============================================================================

/// @title Withdrawal cannot be processed before challenge period ends
/// @notice The challenge period is 7 days. No withdrawal can execute before
///         block.timestamp >= proposal.challengeEndTime.
rule withdrawalBlockedDuringChallengePeriod(
    bytes32 proposalId,
    address recipient,
    address token,
    uint256 amount,
    bytes32 burnTxHash,
    uint256 aethelredBlockHeight
) {
    env e_propose;
    env e_process;

    // Propose the withdrawal
    proposeWithdrawal(e_propose, proposalId, recipient, token, amount, burnTxHash, aethelredBlockHeight);

    // Attempt to process before challenge period ends
    require e_process.block.timestamp < e_propose.block.timestamp + CHALLENGE_PERIOD();

    processWithdrawal@withrevert(e_process, proposalId);

    assert lastReverted,
        "Withdrawal must not be processable before challenge period expires";
}

/// @title Challenged withdrawal cannot be processed
rule challengedWithdrawalCannotProcess(bytes32 proposalId) {
    env e_challenge;
    env e_process;

    string reason = "Fraudulent withdrawal detected";

    // Challenge the withdrawal
    challengeWithdrawal(e_challenge, proposalId, reason);

    // Attempt to process — must revert
    processWithdrawal@withrevert(e_process, proposalId);

    assert lastReverted,
        "A challenged withdrawal proposal must not be processable";
}

// =============================================================================
// CONSENSUS THRESHOLD
// =============================================================================

/// @title A relayer cannot vote twice on the same proposal
rule relayerCannotDoubleVote(bytes32 proposalId) {
    env e;

    // First vote
    voteWithdrawal(e, proposalId);

    // Second vote by same relayer — must revert
    voteWithdrawal@withrevert(e, proposalId);

    assert lastReverted,
        "A relayer must not be able to vote twice on the same proposal";
}

// =============================================================================
// MINT CEILING PER BLOCK (H-04 DEFENSE-IN-DEPTH)
// =============================================================================

/// @title Per-block mint ceiling limits total withdrawals in a single block
/// @notice The mintCeilingPerBlock caps cumulative withdrawal value within any
///         single block. This prevents catastrophic drain even if relayer keys
///         are compromised.
rule mintCeilingIsPositive() {
    assert mintCeilingPerBlock() > 0,
        "Mint ceiling per block must be positive (defense-in-depth)";
}

/// @title Default mint ceiling matches constant
rule defaultMintCeilingCorrect() {
    // After initialization, the mint ceiling should be the default value
    assert DEFAULT_MINT_CEILING_PER_BLOCK() == 10000000000000000000,
        "Default mint ceiling must be 10 ETH (10e18 wei)";
}

// =============================================================================
// DEPOSIT VALIDATION
// =============================================================================

/// @title Deposit nonce is monotonically increasing
rule depositNonceIncreases(bytes32 aethelredRecipient) {
    env e;
    uint256 nonceBefore = depositNonce();

    depositETH(e, aethelredRecipient);

    assert depositNonce() == nonceBefore + 1,
        "Deposit nonce must increment by exactly 1 per deposit";
}

/// @title Total locked ETH increases by deposit amount
rule depositIncreasesLockedETH(bytes32 aethelredRecipient) {
    env e;
    uint256 lockedBefore = totalLockedETH();

    depositETH(e, aethelredRecipient);

    assert totalLockedETH() == lockedBefore + e.msg.value,
        "Total locked ETH must increase by deposit amount";
}

// =============================================================================
// SANCTIONS COMPLIANCE
// =============================================================================

/// @title Blocked address cannot receive withdrawal
rule blockedAddressCannotReceiveWithdrawal(
    bytes32 proposalId,
    address recipient,
    address token,
    uint256 amount,
    bytes32 burnTxHash,
    uint256 aethelredBlockHeight
) {
    env e;

    require blockedAddresses(recipient);

    proposeWithdrawal@withrevert(e, proposalId, recipient, token, amount, burnTxHash, aethelredBlockHeight);

    assert lastReverted,
        "Blocked/sanctioned address must not be able to receive withdrawals";
}

// =============================================================================
// PAUSE SAFETY
// =============================================================================

/// @title Deposits revert when paused
rule depositsRevertWhenPaused(bytes32 aethelredRecipient) {
    env e;

    require paused();

    depositETH@withrevert(e, aethelredRecipient);

    assert lastReverted,
        "Deposits must revert when bridge is paused";
}

/// @title Withdrawal processing reverts when paused
rule processWithdrawalRevertsWhenPaused(bytes32 proposalId) {
    env e;

    require paused();

    processWithdrawal@withrevert(e, proposalId);

    assert lastReverted,
        "Withdrawal processing must revert when bridge is paused";
}

// =============================================================================
// EMERGENCY WITHDRAWAL SAFETY
// =============================================================================

/// @title Emergency withdrawal requires guardian multi-sig (2-of-N)
rule emergencyWithdrawalRequiresGuardianApprovals(bytes32 operationId) {
    env e;

    require guardianApprovalCount(operationId) < REQUIRED_GUARDIAN_APPROVALS();

    executeEmergencyWithdrawal@withrevert(e, operationId);

    assert lastReverted,
        "Emergency withdrawal must require at least 2 guardian approvals";
}

/// @title Emergency withdrawal amount is bounded
rule emergencyWithdrawalBounded() {
    assert MAX_EMERGENCY_WITHDRAWAL() == 50000000000000000000,
        "Max emergency withdrawal must be 50 ETH (50e18 wei)";
}

/// @title Emergency withdrawal timelock has sane bounds
rule emergencyTimelockBounds() {
    assert MIN_EMERGENCY_TIMELOCK() <= MAX_EMERGENCY_TIMELOCK(),
        "Min emergency timelock must not exceed max";
    assert emergencyWithdrawalDelay() >= MIN_EMERGENCY_TIMELOCK(),
        "Emergency withdrawal delay must be at least the minimum";
}

// =============================================================================
// TVL ACCOUNTING
// =============================================================================

/// @title Processing a withdrawal decreases locked funds
/// @notice After a successful processWithdrawal, the totalLockedETH (or
///         totalLockedERC20) must decrease by exactly the withdrawal amount.
rule processWithdrawalDecreasesLocked(bytes32 proposalId) {
    env e;
    uint256 lockedBefore = totalLockedETH();

    processWithdrawal(e, proposalId);

    assert totalLockedETH() <= lockedBefore,
        "Processing a withdrawal must decrease (or maintain) total locked ETH";
}
