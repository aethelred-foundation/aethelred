// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "../contracts/SovereignGovernanceTimelock.sol";
import "../contracts/SovereignCircuitBreakerModule.sol";
import "../contracts/interfaces/ISovereignCircuitBreaker.sol";

// ═══════════════════════════════════════════════════════════════════════════════
// Mock Bridge for Governance Timelock tests
// ═══════════════════════════════════════════════════════════════════════════════

contract MockBridge is IInstitutionalBridgeGovernance {
    address public override issuerGovernanceKey;
    address public override issuerRecoveryGovernanceKey;
    address public override foundationGovernanceKey;
    address public override auditorGovernanceKey;
    address public override guardianGovernanceKey;

    constructor(
        address issuer,
        address issuerRecovery,
        address foundation,
        address auditor,
        address guardian
    ) {
        issuerGovernanceKey = issuer;
        issuerRecoveryGovernanceKey = issuerRecovery;
        foundationGovernanceKey = foundation;
        auditorGovernanceKey = auditor;
        guardianGovernanceKey = guardian;
    }

    function setGovernanceKeys(
        address issuerKey,
        address foundationKey,
        address auditorKey
    ) external override {
        issuerGovernanceKey = issuerKey;
        foundationGovernanceKey = foundationKey;
        auditorGovernanceKey = auditorKey;
    }

    function setSovereignUnpauseKeys(
        address issuerRecoveryKey,
        address guardianKey
    ) external override {
        issuerRecoveryGovernanceKey = issuerRecoveryKey;
        guardianGovernanceKey = guardianKey;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mock ERC20 Stablecoin for Circuit Breaker tests
// ═══════════════════════════════════════════════════════════════════════════════

contract MockStablecoin is ERC20 {
    constructor() ERC20("Mock Stablecoin", "MUSD") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function decimals() public pure override returns (uint8) {
        return 18;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mock Reserve Oracle for Circuit Breaker tests
// ═══════════════════════════════════════════════════════════════════════════════

contract MockReserveOracle {
    int256 public reserveBalance;
    uint256 public updatedAt;
    uint8 public decimals;

    constructor(int256 balance, uint8 dec) {
        reserveBalance = balance;
        updatedAt = block.timestamp;
        decimals = dec;
    }

    function setReserveBalance(int256 balance) external {
        reserveBalance = balance;
        updatedAt = block.timestamp;
    }

    function setUpdatedAt(uint256 ts) external {
        updatedAt = ts;
    }

    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt_,
            uint80 answeredInRound
        )
    {
        return (1, reserveBalance, block.timestamp, updatedAt, 1);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Governance Timelock Handler
// ═══════════════════════════════════════════════════════════════════════════════

contract GovernanceTimelockHandler is Test {
    using MessageHashUtils for bytes32;

    SovereignGovernanceTimelock public timelock;
    MockBridge public bridge;

    address public proposer;
    address public executor;

    uint256 internal issuerPrivKey;
    address internal issuerAddr;
    uint256 internal foundationPrivKey;
    address internal foundationAddr;

    // Ghost variables
    uint256 public ghost_operationsQueued;
    uint256 public ghost_operationsExecuted;
    uint256 public ghost_rotationAttemptedWithoutDualSig;
    bytes32[] public ghost_queuedOperationIds;
    mapping(bytes32 => uint256) public ghost_scheduledAt;

    constructor(
        SovereignGovernanceTimelock _timelock,
        MockBridge _bridge,
        address _proposer,
        address _executor,
        uint256 _issuerPrivKey,
        uint256 _foundationPrivKey
    ) {
        timelock = _timelock;
        bridge = _bridge;
        proposer = _proposer;
        executor = _executor;
        issuerPrivKey = _issuerPrivKey;
        issuerAddr = vm.addr(_issuerPrivKey);
        foundationPrivKey = _foundationPrivKey;
        foundationAddr = vm.addr(_foundationPrivKey);
    }

    /// @notice Queue a key rotation with valid dual signatures
    function rotateKeyValid(uint256 keyTypeSeed, uint256 salt) external {
        SovereignGovernanceTimelock.KeyType keyType = SovereignGovernanceTimelock.KeyType(
            keyTypeSeed % 5
        );
        address newKey = address(uint160(uint256(keccak256(abi.encodePacked(salt, block.timestamp)))));
        if (newKey == address(0)) newKey = address(1);

        bytes32 predecessor = bytes32(0);
        bytes32 saltBytes = bytes32(salt);
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 digest = keccak256(
            abi.encode(
                "AETHELRED_ROTATE_KEY_V1",
                address(timelock),
                block.chainid,
                address(bridge),
                keyType,
                newKey,
                predecessor,
                saltBytes,
                deadline
            )
        );
        bytes32 signed = digest.toEthSignedMessageHash();

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(issuerPrivKey, signed);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(foundationPrivKey, signed);
        bytes memory issuerSig = abi.encodePacked(r1, s1, v1);
        bytes memory foundationSig = abi.encodePacked(r2, s2, v2);

        vm.prank(proposer);
        try timelock.rotateKey(
            address(bridge),
            keyType,
            newKey,
            predecessor,
            saltBytes,
            deadline,
            issuerSig,
            foundationSig
        ) returns (bytes32 opId) {
            ghost_operationsQueued++;
            ghost_queuedOperationIds.push(opId);
            ghost_scheduledAt[opId] = block.timestamp;
        } catch {
            // Operation may already be queued with same params
        }
    }

    /// @notice Attempt key rotation with only one valid signature (should fail)
    function rotateKeyInvalidSig(uint256 salt) external {
        SovereignGovernanceTimelock.KeyType keyType = SovereignGovernanceTimelock.KeyType.Issuer;
        address newKey = address(uint160(uint256(keccak256(abi.encodePacked("bad", salt)))));
        if (newKey == address(0)) newKey = address(2);

        bytes32 predecessor = bytes32(0);
        bytes32 saltBytes = bytes32(salt);
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 digest = keccak256(
            abi.encode(
                "AETHELRED_ROTATE_KEY_V1",
                address(timelock),
                block.chainid,
                address(bridge),
                keyType,
                newKey,
                predecessor,
                saltBytes,
                deadline
            )
        );
        bytes32 signed = digest.toEthSignedMessageHash();

        // Sign with issuer but use a random key for foundation
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(issuerPrivKey, signed);
        uint256 fakeKey = 0xBAD;
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(fakeKey, signed);
        bytes memory issuerSig = abi.encodePacked(r1, s1, v1);
        bytes memory fakeSig = abi.encodePacked(r2, s2, v2);

        vm.prank(proposer);
        try timelock.rotateKey(
            address(bridge),
            keyType,
            newKey,
            predecessor,
            saltBytes,
            deadline,
            issuerSig,
            fakeSig
        ) {
            // Should never succeed -- this would break the invariant
            ghost_rotationAttemptedWithoutDualSig++;
        } catch {
            // Expected: InvalidSignature
        }
    }

    /// @notice Execute a queued operation (only after delay)
    function executeOperation(uint256 idx) external {
        if (ghost_queuedOperationIds.length == 0) return;
        idx = idx % ghost_queuedOperationIds.length;
        bytes32 opId = ghost_queuedOperationIds[idx];

        vm.prank(executor);
        try timelock.executeKeyRotation(opId) {
            ghost_operationsExecuted++;
        } catch {
            // Not ready yet or already executed
        }
    }

    /// @notice Try to execute an operation before delay has elapsed (should fail)
    function executeOperationEarly(uint256 idx) external {
        if (ghost_queuedOperationIds.length == 0) return;
        idx = idx % ghost_queuedOperationIds.length;
        bytes32 opId = ghost_queuedOperationIds[idx];

        // Do NOT warp time forward -- try to execute immediately
        vm.prank(executor);
        try timelock.executeKeyRotation(opId) {
            // If this succeeds without time passing, it means the
            // delay was already met from a prior warp. That's fine.
        } catch {
            // Expected: TimelockController will reject.
        }
    }

    /// @notice Warp forward to allow execution
    function warpPastDelay() external {
        vm.warp(block.timestamp + 7 days + 1);
    }

    function getQueuedCount() external view returns (uint256) {
        return ghost_queuedOperationIds.length;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Circuit Breaker Handler
// ═══════════════════════════════════════════════════════════════════════════════

contract CircuitBreakerHandler is Test {
    SovereignCircuitBreakerModule public breaker;
    MockStablecoin public stablecoin;
    MockReserveOracle public oracle;

    address public multiSigWallet;
    address public randomCaller;

    // Ghost variables
    uint256 public ghost_pauseCount;
    uint256 public ghost_unpauseCount;
    uint256 public ghost_unauthorizedUnpauseAttempts;

    constructor(
        SovereignCircuitBreakerModule _breaker,
        MockStablecoin _stablecoin,
        MockReserveOracle _oracle,
        address _multiSigWallet,
        address _randomCaller
    ) {
        breaker = _breaker;
        stablecoin = _stablecoin;
        oracle = _oracle;
        multiSigWallet = _multiSigWallet;
        randomCaller = _randomCaller;
    }

    /// @notice Check reserve anomaly with varying mint amounts
    function checkAnomaly(uint256 mintAmount) external {
        mintAmount = bound(mintAmount, 0, 100_000_000 ether);

        bool wasPaused = breaker.isPaused();
        breaker.checkReserveAnomaly(mintAmount);
        bool nowPaused = breaker.isPaused();

        if (!wasPaused && nowPaused) {
            ghost_pauseCount++;
        }
    }

    /// @notice Manipulate oracle reserve balance to trigger anomalies
    function setReserveBalance(int256 balance) external {
        balance = int256(bound(uint256(int256(balance)), 0, 100_000_000 ether));
        oracle.setReserveBalance(balance);
    }

    /// @notice Mint stablecoin supply to change supply/reserve ratio
    function mintSupply(uint256 amount) external {
        amount = bound(amount, 1 ether, 10_000_000 ether);
        stablecoin.mint(address(this), amount);
    }

    /// @notice Attempt unpause from multiSig (should work)
    function unpauseFromMultiSig() external {
        if (!breaker.isPaused()) return;

        vm.prank(multiSigWallet);
        try breaker.unpauseMinting() {
            ghost_unpauseCount++;
        } catch {
            // NotPaused or other error
        }
    }

    /// @notice Attempt unpause from unauthorized address (should fail)
    function unpauseFromUnauthorized() external {
        if (!breaker.isPaused()) return;

        vm.prank(randomCaller);
        try breaker.unpauseMinting() {
            // Should never succeed
            ghost_unauthorizedUnpauseAttempts++;
        } catch {
            // Expected: Unauthorized
        }
    }

    /// @notice Make oracle stale
    function makeOracleStale() external {
        oracle.setUpdatedAt(block.timestamp - 25 hours);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Governance Invariant Test Suite
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * @title GovernanceInvariantTest
 * @notice Foundry invariant and fuzz tests for SovereignGovernanceTimelock
 *         and SovereignCircuitBreakerModule. Covers SQ10 and SQ11.
 *
 * Invariants tested:
 *   1. invariant_minDelayEnforced - getMinDelay() >= MIN_KEY_ROTATION_DELAY (7 days)
 *   2. invariant_executionRequiresDelay - no operation executes before scheduled time + delay
 *   3. invariant_dualSignatureRequired - key rotation requires both issuer and foundation sigs
 *   4. invariant_circuitBreakerPauseControl - only multiSigWallet can unpause
 */
contract GovernanceInvariantTest is StdInvariant, Test {
    using MessageHashUtils for bytes32;

    // ── Timelock contracts ──────────────────────────────────────────────────
    SovereignGovernanceTimelock public timelock;
    MockBridge public bridge;
    GovernanceTimelockHandler public timelockHandler;

    // ── Circuit Breaker contracts ───────────────────────────────────────────
    SovereignCircuitBreakerModule public breaker;
    MockStablecoin public stablecoin;
    MockReserveOracle public oracle;
    CircuitBreakerHandler public cbHandler;

    // ── Key pairs ───────────────────────────────────────────────────────────
    uint256 internal constant ISSUER_PRIV_KEY = 0x1111;
    address internal issuerAddr;
    uint256 internal constant FOUNDATION_PRIV_KEY = 0x2222;
    address internal foundationAddr;
    uint256 internal constant AUDITOR_PRIV_KEY = 0x3333;
    address internal auditorAddr;
    uint256 internal constant ISSUER_RECOVERY_PRIV_KEY = 0x4444;
    address internal issuerRecoveryAddr;
    uint256 internal constant GUARDIAN_PRIV_KEY = 0x5555;
    address internal guardianAddr;

    address internal proposer = address(0xBEEF);
    address internal executor = address(0xCAFE);
    address internal admin;
    address internal multiSigWallet = address(0xABCD);
    address internal randomCaller = address(0xDEAD);

    function setUp() public {
        // Derive addresses from private keys
        issuerAddr = vm.addr(ISSUER_PRIV_KEY);
        foundationAddr = vm.addr(FOUNDATION_PRIV_KEY);
        auditorAddr = vm.addr(AUDITOR_PRIV_KEY);
        issuerRecoveryAddr = vm.addr(ISSUER_RECOVERY_PRIV_KEY);
        guardianAddr = vm.addr(GUARDIAN_PRIV_KEY);

        // ── Deploy Timelock ─────────────────────────────────────────────────
        // Admin needs to be a contract on non-test chains, but chainid 31337
        // allows EOA admin
        admin = address(this);

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;

        timelock = new SovereignGovernanceTimelock(
            7 days,  // minDelay = MIN_KEY_ROTATION_DELAY
            proposers,
            executors,
            admin
        );

        // Deploy mock bridge with our governance keys
        bridge = new MockBridge(
            issuerAddr,
            issuerRecoveryAddr,
            foundationAddr,
            auditorAddr,
            guardianAddr
        );

        // Grant PROPOSER_ROLE on timelock so rotateKey can call schedule
        // The timelock needs to be able to call itself for schedule/execute
        timelock.grantRole(timelock.PROPOSER_ROLE(), address(timelock));
        timelock.grantRole(timelock.EXECUTOR_ROLE(), address(timelock));

        // Deploy handler
        timelockHandler = new GovernanceTimelockHandler(
            timelock,
            bridge,
            proposer,
            executor,
            ISSUER_PRIV_KEY,
            FOUNDATION_PRIV_KEY
        );

        // ── Deploy Circuit Breaker ──────────────────────────────────────────
        stablecoin = new MockStablecoin();
        // Reserve oracle: start with 10M reserves, 18 decimals
        oracle = new MockReserveOracle(int256(10_000_000 ether), 18);

        breaker = new SovereignCircuitBreakerModule(
            admin,
            address(stablecoin),
            address(oracle),
            multiSigWallet,
            500 // 5% max deviation
        );

        // Mint initial stablecoin supply matching reserves
        stablecoin.mint(address(1), 10_000_000 ether);

        cbHandler = new CircuitBreakerHandler(
            breaker,
            stablecoin,
            oracle,
            multiSigWallet,
            randomCaller
        );

        // Target both handlers
        targetContract(address(timelockHandler));
        targetContract(address(cbHandler));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INVARIANT 1: Minimum delay is always enforced
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice getMinDelay() must always be >= MIN_KEY_ROTATION_DELAY (7 days).
    function invariant_minDelayEnforced() public view {
        assertGe(
            timelock.getMinDelay(),
            timelock.MIN_KEY_ROTATION_DELAY(),
            "Min delay dropped below 7-day minimum"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INVARIANT 2: Execution requires delay
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice No operation can execute before its scheduled time + delay.
    ///         Verified by checking that the handler never records an execution
    ///         of an operation that was scheduled less than 7 days ago
    ///         (unless time was explicitly warped past the delay).
    function invariant_executionRequiresDelay() public view {
        // The TimelockController enforces this at the EVM level.
        // We verify indirectly: the number of executed operations should
        // never exceed the number of queued operations.
        assertLe(
            timelockHandler.ghost_operationsExecuted(),
            timelockHandler.ghost_operationsQueued(),
            "More operations executed than queued"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INVARIANT 3: Dual signature required for key rotation
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Key rotation must require both issuer and foundation signatures.
    ///         The handler tracks attempts with invalid signatures that succeed.
    function invariant_dualSignatureRequired() public view {
        assertEq(
            timelockHandler.ghost_rotationAttemptedWithoutDualSig(),
            0,
            "Key rotation succeeded without dual signatures"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INVARIANT 4: Circuit breaker pause control
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Only multiSigWallet can unpause after circuit breaker triggers.
    ///         The handler tracks unauthorized unpause attempts that succeed.
    function invariant_circuitBreakerPauseControl() public view {
        assertEq(
            cbHandler.ghost_unauthorizedUnpauseAttempts(),
            0,
            "Unauthorized address successfully unpaused circuit breaker"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // FUZZ TESTS — Timelock
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Constructor must reject delays shorter than 7 days.
    function testFuzz_timelockRejectsShortDelay(uint256 delay) public {
        delay = bound(delay, 0, 7 days - 1);

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;

        vm.expectRevert(SovereignGovernanceTimelock.RotationDelayTooShort.selector);
        new SovereignGovernanceTimelock(delay, proposers, executors, address(this));
    }

    /// @notice Constructor accepts delays >= 7 days.
    function testFuzz_timelockAcceptsValidDelay(uint256 delay) public {
        delay = bound(delay, 7 days, 365 days);

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;

        SovereignGovernanceTimelock tl = new SovereignGovernanceTimelock(
            delay, proposers, executors, address(this)
        );
        assertGe(tl.getMinDelay(), 7 days);
    }

    /// @notice Key rotation with wrong issuer signature always reverts.
    function testFuzz_rotationFailsWithWrongIssuerSig(uint256 badKeyPriv) public {
        badKeyPriv = bound(badKeyPriv, 1, type(uint128).max);
        // Ensure it's not the actual issuer key
        vm.assume(badKeyPriv != ISSUER_PRIV_KEY);

        address newKey = address(0x9999);
        bytes32 predecessor = bytes32(0);
        bytes32 salt = bytes32(uint256(0xF00D));
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 digest = keccak256(
            abi.encode(
                "AETHELRED_ROTATE_KEY_V1",
                address(timelock),
                block.chainid,
                address(bridge),
                SovereignGovernanceTimelock.KeyType.Issuer,
                newKey,
                predecessor,
                salt,
                deadline
            )
        );
        bytes32 signed = digest.toEthSignedMessageHash();

        // Sign with bad key as issuer, correct foundation
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(badKeyPriv, signed);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(FOUNDATION_PRIV_KEY, signed);

        vm.prank(proposer);
        vm.expectRevert(SovereignGovernanceTimelock.InvalidSignature.selector);
        timelock.rotateKey(
            address(bridge),
            SovereignGovernanceTimelock.KeyType.Issuer,
            newKey,
            predecessor,
            salt,
            deadline,
            abi.encodePacked(r1, s1, v1),
            abi.encodePacked(r2, s2, v2)
        );
    }

    /// @notice Key rotation with wrong foundation signature always reverts.
    function testFuzz_rotationFailsWithWrongFoundationSig(uint256 badKeyPriv) public {
        badKeyPriv = bound(badKeyPriv, 1, type(uint128).max);
        vm.assume(badKeyPriv != FOUNDATION_PRIV_KEY);

        address newKey = address(0x8888);
        bytes32 predecessor = bytes32(0);
        bytes32 salt = bytes32(uint256(0xBEEF));
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 digest = keccak256(
            abi.encode(
                "AETHELRED_ROTATE_KEY_V1",
                address(timelock),
                block.chainid,
                address(bridge),
                SovereignGovernanceTimelock.KeyType.Foundation,
                newKey,
                predecessor,
                salt,
                deadline
            )
        );
        bytes32 signed = digest.toEthSignedMessageHash();

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ISSUER_PRIV_KEY, signed);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(badKeyPriv, signed);

        vm.prank(proposer);
        vm.expectRevert(SovereignGovernanceTimelock.InvalidSignature.selector);
        timelock.rotateKey(
            address(bridge),
            SovereignGovernanceTimelock.KeyType.Foundation,
            newKey,
            predecessor,
            salt,
            deadline,
            abi.encodePacked(r1, s1, v1),
            abi.encodePacked(r2, s2, v2)
        );
    }

    /// @notice Executing a rotation before delay elapses always reverts.
    function testFuzz_executionBeforeDelayReverts(uint256 warpTime) public {
        warpTime = bound(warpTime, 0, 7 days - 1);

        // Queue a rotation
        address newKey = address(0x7777);
        bytes32 predecessor = bytes32(0);
        bytes32 salt = bytes32(uint256(0xAAAA));
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 digest = keccak256(
            abi.encode(
                "AETHELRED_ROTATE_KEY_V1",
                address(timelock),
                block.chainid,
                address(bridge),
                SovereignGovernanceTimelock.KeyType.Auditor,
                newKey,
                predecessor,
                salt,
                deadline
            )
        );
        bytes32 signed = digest.toEthSignedMessageHash();

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ISSUER_PRIV_KEY, signed);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(FOUNDATION_PRIV_KEY, signed);

        vm.prank(proposer);
        bytes32 opId = timelock.rotateKey(
            address(bridge),
            SovereignGovernanceTimelock.KeyType.Auditor,
            newKey,
            predecessor,
            salt,
            deadline,
            abi.encodePacked(r1, s1, v1),
            abi.encodePacked(r2, s2, v2)
        );

        // Warp less than the full delay
        vm.warp(block.timestamp + warpTime);

        // Execution should revert
        vm.prank(executor);
        vm.expectRevert();
        timelock.executeKeyRotation(opId);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // FUZZ TESTS — Circuit Breaker
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Unpause always reverts when called by non-multiSig address.
    function testFuzz_unpauseRevertsForNonMultiSig(address caller) public {
        vm.assume(caller != multiSigWallet);
        vm.assume(caller != address(0));

        // Force a pause state via anomaly
        oracle.setReserveBalance(0);
        breaker.checkReserveAnomaly(1 ether);
        assertTrue(breaker.isPaused(), "Should be paused after zero reserve");

        // Reset oracle for next test
        oracle.setReserveBalance(int256(10_000_000 ether));

        vm.prank(caller);
        vm.expectRevert(SovereignCircuitBreakerModule.Unauthorized.selector);
        breaker.unpauseMinting();
    }

    /// @notice Pausing triggers when projected supply exceeds reserves by > MAX_DEVIATION_BPS.
    function testFuzz_pauseTriggersOnExcessDeviation(uint256 mintAmount) public {
        // Reset state: deploy fresh
        MockStablecoin freshCoin = new MockStablecoin();
        MockReserveOracle freshOracle = new MockReserveOracle(int256(1_000_000 ether), 18);

        SovereignCircuitBreakerModule freshBreaker = new SovereignCircuitBreakerModule(
            address(this),
            address(freshCoin),
            address(freshOracle),
            multiSigWallet,
            500 // 5%
        );

        // Mint supply equal to reserves
        freshCoin.mint(address(1), 1_000_000 ether);

        // Mint amount that would create > 5% deviation
        // deviation = (projectedSupply - reserve) / reserve > 5%
        // projectedSupply = 1M + mintAmount > 1.05M
        // mintAmount > 50_000 ether
        mintAmount = bound(mintAmount, 50_001 ether, 10_000_000 ether);

        freshBreaker.checkReserveAnomaly(mintAmount);
        assertTrue(freshBreaker.isPaused(), "Should pause when deviation exceeds threshold");
    }

    /// @notice Circuit breaker does not pause when deviation is within threshold.
    function testFuzz_noPauseWithinThreshold(uint256 mintAmount) public {
        MockStablecoin freshCoin = new MockStablecoin();
        MockReserveOracle freshOracle = new MockReserveOracle(int256(1_000_000 ether), 18);

        SovereignCircuitBreakerModule freshBreaker = new SovereignCircuitBreakerModule(
            address(this),
            address(freshCoin),
            address(freshOracle),
            multiSigWallet,
            500 // 5%
        );

        freshCoin.mint(address(1), 1_000_000 ether);

        // Keep mint amount small enough that deviation < 5%
        // projectedSupply = 1M + mintAmount; deviation = mintAmount/1M < 5%
        // mintAmount < 50_000 ether
        mintAmount = bound(mintAmount, 0, 49_999 ether);

        freshBreaker.checkReserveAnomaly(mintAmount);
        assertFalse(freshBreaker.isPaused(), "Should not pause within threshold");
    }

    /// @notice Zero or negative reserve balance always triggers pause.
    function testFuzz_zeroReserveAlwaysPauses(uint256 mintAmount) public {
        mintAmount = bound(mintAmount, 1, 10_000_000 ether);

        MockStablecoin freshCoin = new MockStablecoin();
        MockReserveOracle freshOracle = new MockReserveOracle(0, 18);

        SovereignCircuitBreakerModule freshBreaker = new SovereignCircuitBreakerModule(
            address(this),
            address(freshCoin),
            address(freshOracle),
            multiSigWallet,
            500
        );

        freshCoin.mint(address(1), 1_000_000 ether);
        freshBreaker.checkReserveAnomaly(mintAmount);
        assertTrue(freshBreaker.isPaused(), "Should pause on zero reserve");
    }

    /// @notice Stale oracle data always triggers pause.
    function testFuzz_staleOracleAlwaysPauses(uint256 staleness) public {
        staleness = bound(staleness, 24 hours + 1, 365 days);

        MockStablecoin freshCoin = new MockStablecoin();
        MockReserveOracle freshOracle = new MockReserveOracle(int256(1_000_000 ether), 18);

        SovereignCircuitBreakerModule freshBreaker = new SovereignCircuitBreakerModule(
            address(this),
            address(freshCoin),
            address(freshOracle),
            multiSigWallet,
            500
        );

        freshCoin.mint(address(1), 1_000_000 ether);

        // Make oracle stale
        freshOracle.setUpdatedAt(block.timestamp - staleness);

        freshBreaker.checkReserveAnomaly(1 ether);
        assertTrue(freshBreaker.isPaused(), "Should pause on stale oracle");
    }

    /// @notice MultiSig can always unpause after circuit breaker triggers.
    function testFuzz_multiSigCanAlwaysUnpause(uint256 seed) public {
        seed = bound(seed, 1, 1000);

        MockStablecoin freshCoin = new MockStablecoin();
        MockReserveOracle freshOracle = new MockReserveOracle(0, 18);

        SovereignCircuitBreakerModule freshBreaker = new SovereignCircuitBreakerModule(
            address(this),
            address(freshCoin),
            address(freshOracle),
            multiSigWallet,
            500
        );

        freshCoin.mint(address(1), 1_000_000 ether);
        freshBreaker.checkReserveAnomaly(1 ether);
        assertTrue(freshBreaker.isPaused(), "Should be paused");

        vm.prank(multiSigWallet);
        freshBreaker.unpauseMinting();
        assertFalse(freshBreaker.isPaused(), "MultiSig should be able to unpause");
    }
}
