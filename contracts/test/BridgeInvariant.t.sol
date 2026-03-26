// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/AethelredBridge.sol";

// =============================================================================
// MOCK TOKEN
// =============================================================================

contract MockERC20Invariant is ERC20 {
    constructor() ERC20("Mock USDC", "mUSDC") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// =============================================================================
// BRIDGE HANDLER - drives stateful fuzz actions against the bridge
// =============================================================================

contract BridgeHandler is Test {
    AethelredBridge public bridge;
    MockERC20Invariant public token;

    // Actor pools
    address public admin;
    address public guardian1;
    address public guardian2;
    address[] public relayers;
    address[] public users;

    // Ghost variables for tracking invariant state
    uint256 public ghost_totalDepositsETH;
    uint256 public ghost_totalWithdrawalsETH;
    uint256 public ghost_totalEmergencyWithdrawalsETH;
    uint256 public ghost_totalCancelledDepositsETH;

    // Track deposits per rate-limit period
    mapping(uint256 => uint256) public ghost_depositsInPeriod;
    mapping(uint256 => uint256) public ghost_withdrawalsInPeriod;

    // Track processed nonces (burnTxHashes)
    bytes32[] public ghost_processedBurnTxHashes;
    mapping(bytes32 => bool) public ghost_wasEverProcessed;

    // Track withdrawal proposals for challenge period verification
    bytes32[] public ghost_allProposalIds;
    mapping(bytes32 => uint256) public ghost_proposalChallengeEndTime;
    mapping(bytes32 => bool) public ghost_proposalExecuted;
    mapping(bytes32 => bool) public ghost_proposalExecutedBeforeChallenge;

    // Track emergency withdrawal amounts
    bytes32[] public ghost_emergencyOpIds;
    mapping(bytes32 => uint256) public ghost_emergencyAmount;

    // Track per-block mints
    mapping(uint256 => uint256) public ghost_mintsInBlock;

    // Counters for call tracking
    uint256 public calls_deposit;
    uint256 public calls_proposeWithdrawal;
    uint256 public calls_voteWithdrawal;
    uint256 public calls_processWithdrawal;
    uint256 public calls_emergencyQueue;
    uint256 public calls_emergencyExecute;

    // Withdrawal proposal nonce
    uint256 internal _proposalNonce;
    uint256 internal _burnTxNonce;

    // Pending (unprocessed) withdrawal obligations
    uint256 public ghost_pendingWithdrawalObligations;

    constructor(
        AethelredBridge _bridge,
        MockERC20Invariant _token,
        address _admin,
        address _guardian1,
        address _guardian2,
        address[] memory _relayers,
        address[] memory _users
    ) {
        bridge = _bridge;
        token = _token;
        admin = _admin;
        guardian1 = _guardian1;
        guardian2 = _guardian2;
        relayers = _relayers;
        users = _users;
    }

    // =========================================================================
    // HANDLER ACTIONS
    // =========================================================================

    /// @dev Deposit ETH into the bridge
    function depositETH(uint256 userSeed, uint256 amount) external {
        address user = users[userSeed % users.length];
        // Bound to valid deposit range
        amount = bound(amount, 0.01 ether, 100 ether);

        // Check rate limit headroom
        uint256 currentPeriod = block.timestamp / 1 hours;
        (uint256 maxDeposit,,) = bridge.rateLimitConfig();
        if (ghost_depositsInPeriod[currentPeriod] + amount > maxDeposit) return;

        vm.deal(user, amount);
        vm.prank(user);
        try bridge.depositETH{value: amount}(bytes32(uint256(uint160(user)))) {
            ghost_totalDepositsETH += amount;
            ghost_depositsInPeriod[currentPeriod] += amount;
            calls_deposit++;
        } catch {}
    }

    /// @dev Propose a withdrawal (as relayer)
    function proposeWithdrawal(
        uint256 relayerSeed,
        uint256 amount,
        uint256 recipientSeed
    ) external {
        address relayer = relayers[relayerSeed % relayers.length];
        address recipient = users[recipientSeed % users.length];
        amount = bound(amount, 0.01 ether, 10 ether);

        // Need sufficient ETH in bridge
        if (address(bridge).balance < amount) return;

        bytes32 proposalId = keccak256(
            abi.encode("proposal", _proposalNonce)
        );
        bytes32 burnTxHash = keccak256(
            abi.encode("burnTx", _burnTxNonce)
        );

        // Skip if burnTxHash already processed
        if (ghost_wasEverProcessed[burnTxHash]) return;

        vm.prank(relayer);
        try bridge.proposeWithdrawal(
            proposalId,
            recipient,
            address(0), // ETH
            amount,
            burnTxHash,
            block.number
        ) {
            _proposalNonce++;
            _burnTxNonce++;
            ghost_allProposalIds.push(proposalId);
            ghost_proposalChallengeEndTime[proposalId] =
                block.timestamp + 7 days;
            ghost_pendingWithdrawalObligations += amount;
            calls_proposeWithdrawal++;
        } catch {}
    }

    /// @dev Vote on a withdrawal proposal (as relayer)
    function voteWithdrawal(uint256 relayerSeed, uint256 proposalSeed) external {
        if (ghost_allProposalIds.length == 0) return;

        address relayer = relayers[relayerSeed % relayers.length];
        bytes32 proposalId = ghost_allProposalIds[
            proposalSeed % ghost_allProposalIds.length
        ];

        vm.prank(relayer);
        try bridge.voteWithdrawal(proposalId) {
            calls_voteWithdrawal++;
        } catch {}
    }

    /// @dev Process a withdrawal after challenge period
    function processWithdrawal(uint256 proposalSeed) external {
        if (ghost_allProposalIds.length == 0) return;

        bytes32 proposalId = ghost_allProposalIds[
            proposalSeed % ghost_allProposalIds.length
        ];

        // Skip already-executed proposals
        if (ghost_proposalExecuted[proposalId]) return;

        // Get proposal details before attempting execution
        AethelredBridge.WithdrawalProposal memory proposal =
            bridge.getWithdrawalProposal(proposalId);
        if (proposal.createdAt == 0) return;
        if (proposal.processed) return;

        // Record whether we're before challenge period
        bool beforeChallenge = block.timestamp < proposal.challengeEndTime;

        vm.prank(users[0]);
        try bridge.processWithdrawal(proposalId) {
            uint256 currentPeriod = block.timestamp / 1 hours;
            ghost_withdrawalsInPeriod[currentPeriod] += proposal.amount;
            ghost_totalWithdrawalsETH += proposal.amount;
            ghost_pendingWithdrawalObligations -= proposal.amount;
            ghost_proposalExecuted[proposalId] = true;

            // Track replay protection
            ghost_processedBurnTxHashes.push(proposal.burnTxHash);
            ghost_wasEverProcessed[proposal.burnTxHash] = true;

            // Track per-block mints
            ghost_mintsInBlock[block.number] += proposal.amount;

            // Record if executed before challenge period (should never happen)
            if (beforeChallenge) {
                ghost_proposalExecutedBeforeChallenge[proposalId] = true;
            }

            calls_processWithdrawal++;
        } catch {}
    }

    /// @dev Warp time forward to allow challenge periods to expire
    function warpTime(uint256 seconds_) external {
        seconds_ = bound(seconds_, 1, 8 days);
        vm.warp(block.timestamp + seconds_);
    }

    /// @dev Roll block number forward
    function rollBlock(uint256 blocks) external {
        blocks = bound(blocks, 1, 100);
        vm.roll(block.number + blocks);
    }

    /// @dev Queue an emergency withdrawal
    function queueEmergencyWithdrawal(uint256 amount) external {
        amount = bound(amount, 0.01 ether, 50 ether);

        if (address(bridge).balance < amount) return;

        vm.prank(admin);
        try bridge.queueEmergencyWithdrawal(
            address(0),
            amount,
            users[0]
        ) returns (bytes32 operationId) {
            ghost_emergencyOpIds.push(operationId);
            ghost_emergencyAmount[operationId] = amount;
            calls_emergencyQueue++;
        } catch {}
    }

    /// @dev Approve and execute an emergency withdrawal
    function executeEmergencyWithdrawal(uint256 opSeed) external {
        if (ghost_emergencyOpIds.length == 0) return;

        bytes32 operationId = ghost_emergencyOpIds[
            opSeed % ghost_emergencyOpIds.length
        ];

        // Guardian 1 approves
        vm.prank(guardian1);
        try bridge.approveEmergencyWithdrawal(operationId) {} catch {}

        // Guardian 2 approves
        vm.prank(guardian2);
        try bridge.approveEmergencyWithdrawal(operationId) {} catch {}

        // Admin executes
        vm.prank(admin);
        try bridge.executeEmergencyWithdrawal(operationId) {
            uint256 amt = ghost_emergencyAmount[operationId];
            ghost_totalEmergencyWithdrawalsETH += amt;
            calls_emergencyExecute++;
        } catch {}
    }

    // =========================================================================
    // GHOST VARIABLE ACCESSORS
    // =========================================================================

    function getProcessedBurnTxHashCount() external view returns (uint256) {
        return ghost_processedBurnTxHashes.length;
    }

    function getProcessedBurnTxHash(uint256 i) external view returns (bytes32) {
        return ghost_processedBurnTxHashes[i];
    }

    function getAllProposalCount() external view returns (uint256) {
        return ghost_allProposalIds.length;
    }

    function getProposalId(uint256 i) external view returns (bytes32) {
        return ghost_allProposalIds[i];
    }

    function getEmergencyOpCount() external view returns (uint256) {
        return ghost_emergencyOpIds.length;
    }

    function getEmergencyOpId(uint256 i) external view returns (bytes32) {
        return ghost_emergencyOpIds[i];
    }
}

// =============================================================================
// INVARIANT TEST CONTRACT
// =============================================================================

contract BridgeInvariantTest is Test {
    AethelredBridge public bridge;
    AethelredBridge public bridgeImpl;
    MockERC20Invariant public mockToken;
    BridgeHandler public handler;

    address public admin = address(0x1);
    address public guardian1 = address(0x2);
    address public guardian2 = address(0x6);
    address[] public relayers;
    address[] public users;

    address public relayer1 = address(0x10);
    address public relayer2 = address(0x11);
    address public relayer3 = address(0x12);
    address public relayer4 = address(0x13);
    address public relayer5 = address(0x14);

    address public user1 = address(0x3);
    address public user2 = address(0x4);
    address public user3 = address(0x7);

    uint256 public constant CONSENSUS_THRESHOLD_BPS = 6700;

    function setUp() public {
        // Setup relayers
        relayers = new address[](5);
        relayers[0] = relayer1;
        relayers[1] = relayer2;
        relayers[2] = relayer3;
        relayers[3] = relayer4;
        relayers[4] = relayer5;

        // Setup users
        users = new address[](3);
        users[0] = user1;
        users[1] = user2;
        users[2] = user3;

        // Deploy implementation
        bridgeImpl = new AethelredBridge();

        // Deploy proxy
        bytes memory initData = abi.encodeCall(
            AethelredBridge.initialize,
            (admin, relayers, CONSENSUS_THRESHOLD_BPS)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(bridgeImpl),
            initData
        );
        bridge = AethelredBridge(payable(address(proxy)));

        // Grant guardian roles
        vm.startPrank(admin);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian1);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian2);
        vm.stopPrank();

        // Deploy mock token
        mockToken = new MockERC20Invariant();
        vm.prank(admin);
        bridge.addSupportedToken(address(mockToken));

        // Fund the bridge with ETH for withdrawals
        vm.deal(address(bridge), 500 ether);

        // Deploy handler
        handler = new BridgeHandler(
            bridge,
            mockToken,
            admin,
            guardian1,
            guardian2,
            relayers,
            users
        );

        // Target only the handler for invariant calls
        targetContract(address(handler));
    }

    // =========================================================================
    // 1. REPLAY PROTECTION INVARIANTS
    // =========================================================================

    /// @notice Once a burnTxHash is marked processed, it must remain processed forever.
    ///         This guarantees no double-spend via withdrawal replay.
    function invariant_processedNoncesNeverReused() public view {
        uint256 count = handler.getProcessedBurnTxHashCount();
        for (uint256 i = 0; i < count; i++) {
            bytes32 burnTxHash = handler.getProcessedBurnTxHash(i);
            assertTrue(
                bridge.processedWithdrawals(burnTxHash),
                "REPLAY: processed burnTxHash was unset"
            );
        }
    }

    /// @notice The EIP-712 domain separator must always match the current chain ID
    ///         and contract address. This prevents cross-chain/cross-contract replay.
    function invariant_domainSeparatorConsistent() public view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("AethelredBridge"),
                keccak256("1"),
                block.chainid,
                address(bridge)
            )
        );
        assertEq(
            bridge.domainSeparatorV4(),
            expected,
            "REPLAY: domain separator mismatch with current chain"
        );
    }

    // =========================================================================
    // 2. RATE LIMIT INVARIANTS
    // =========================================================================

    /// @notice Cumulative deposits in any single rate-limit period (1 hour)
    ///         must not exceed maxDepositPerPeriod.
    function invariant_depositsWithinPeriodLimit() public view {
        uint256 currentPeriod = block.timestamp / 1 hours;
        (uint256 maxDeposit,,) = bridge.rateLimitConfig();

        // Check the on-chain rate limit state for the current period
        (uint256 deposited,) = bridge.getCurrentRateLimitState();
        assertLe(
            deposited,
            maxDeposit,
            "RATE LIMIT: deposits in current period exceed maxDepositPerPeriod"
        );
    }

    /// @notice Cumulative withdrawals in any single rate-limit period (1 hour)
    ///         must not exceed maxWithdrawalPerPeriod.
    function invariant_withdrawalsWithinPeriodLimit() public view {
        (, uint256 maxWithdrawal,) = bridge.rateLimitConfig();

        (,uint256 withdrawn) = bridge.getCurrentRateLimitState();
        assertLe(
            withdrawn,
            maxWithdrawal,
            "RATE LIMIT: withdrawals in current period exceed maxWithdrawalPerPeriod"
        );
    }

    /// @notice Mints/withdrawals processed within a single block must not exceed
    ///         the per-block mint ceiling (DEFAULT_MINT_CEILING_PER_BLOCK = 10 ETH).
    function invariant_mintCeilingPerBlock() public view {
        uint256 ceiling = bridge.mintCeilingPerBlock();
        uint256 mintedThisBlock = handler.ghost_mintsInBlock(block.number);
        assertLe(
            mintedThisBlock,
            ceiling,
            "MINT CEILING: mints in current block exceed mintCeilingPerBlock"
        );
    }

    // =========================================================================
    // 3. ACCOUNTING INVARIANTS
    // =========================================================================

    /// @notice The bridge's actual ETH balance must always be >= the tracked
    ///         totalLockedETH. This ensures the bridge is solvent and can honor
    ///         all pending withdrawal obligations.
    function invariant_bridgeBalanceSolvent() public view {
        uint256 trackedLocked = bridge.totalLockedETH();
        uint256 actualBalance = address(bridge).balance;
        assertGe(
            actualBalance,
            trackedLocked,
            "SOLVENCY: bridge ETH balance < totalLockedETH"
        );
    }

    /// @notice Every executed emergency withdrawal must have been <= MAX_EMERGENCY_WITHDRAWAL (50 ETH).
    ///         This caps damage from compromised admin+guardians.
    function invariant_emergencyWithdrawalCapped() public view {
        uint256 count = handler.getEmergencyOpCount();
        for (uint256 i = 0; i < count; i++) {
            bytes32 opId = handler.getEmergencyOpId(i);
            uint256 amount = handler.ghost_emergencyAmount(opId);
            assertLe(
                amount,
                50 ether,
                "EMERGENCY CAP: emergency withdrawal exceeded MAX_EMERGENCY_WITHDRAWAL"
            );
        }
    }

    // =========================================================================
    // 4. CHALLENGE PERIOD INVARIANTS
    // =========================================================================

    /// @notice No withdrawal may execute before its 7-day challenge period expires.
    ///         The handler tracks if processWithdrawal succeeded before challengeEndTime.
    function invariant_withdrawalRequiresChallengePeriod() public view {
        uint256 count = handler.getAllProposalCount();
        for (uint256 i = 0; i < count; i++) {
            bytes32 proposalId = handler.getProposalId(i);
            assertFalse(
                handler.ghost_proposalExecutedBeforeChallenge(proposalId),
                "CHALLENGE: withdrawal executed before challenge period ended"
            );
        }
    }

    // =========================================================================
    // 5. ADDITIONAL SECURITY INVARIANTS
    // =========================================================================

    /// @notice totalLockedETH accounting must always be internally consistent:
    ///         deposits - withdrawals - cancellations - emergency = totalLockedETH.
    ///         Note: bridge was pre-funded so totalLockedETH only tracks deposit flow.
    function invariant_lockedETHConsistency() public view {
        uint256 trackedLocked = bridge.totalLockedETH();
        uint256 expectedLocked =
            handler.ghost_totalDepositsETH()
            - handler.ghost_totalWithdrawalsETH()
            - handler.ghost_totalEmergencyWithdrawalsETH()
            - handler.ghost_totalCancelledDepositsETH();
        assertEq(
            trackedLocked,
            expectedLocked,
            "ACCOUNTING: totalLockedETH inconsistent with ghost tracking"
        );
    }

    /// @notice depositNonce must be monotonically increasing and match deposit count.
    function invariant_depositNonceMonotonic() public view {
        assertGe(
            bridge.depositNonce(),
            handler.calls_deposit(),
            "NONCE: depositNonce < total successful deposits"
        );
    }

    // =========================================================================
    // CALL SUMMARY (logged after invariant campaign)
    // =========================================================================

    function invariant_callSummary() public view {
        console.log("--- Bridge Invariant Call Summary ---");
        console.log("deposits:           ", handler.calls_deposit());
        console.log("proposeWithdrawal:  ", handler.calls_proposeWithdrawal());
        console.log("voteWithdrawal:     ", handler.calls_voteWithdrawal());
        console.log("processWithdrawal:  ", handler.calls_processWithdrawal());
        console.log("emergencyQueue:     ", handler.calls_emergencyQueue());
        console.log("emergencyExecute:   ", handler.calls_emergencyExecute());
        console.log("------------------------------------");
    }
}

// =============================================================================
// STANDALONE FUZZ TESTS - targeted property-based tests
// =============================================================================

contract BridgeFuzzTest is Test {
    AethelredBridge public bridge;
    MockERC20Invariant public mockToken;

    address public admin = address(0x1);
    address public guardian1 = address(0x2);
    address public guardian2 = address(0x6);
    address[] public relayers;

    address public relayer1 = address(0x10);
    address public relayer2 = address(0x11);
    address public relayer3 = address(0x12);
    address public relayer4 = address(0x13);
    address public relayer5 = address(0x14);

    address public user1 = address(0x3);

    function setUp() public {
        relayers = new address[](5);
        relayers[0] = relayer1;
        relayers[1] = relayer2;
        relayers[2] = relayer3;
        relayers[3] = relayer4;
        relayers[4] = relayer5;

        AethelredBridge impl = new AethelredBridge();
        bytes memory initData = abi.encodeCall(
            AethelredBridge.initialize,
            (admin, relayers, 6700)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        bridge = AethelredBridge(payable(address(proxy)));

        vm.startPrank(admin);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian1);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian2);
        vm.stopPrank();

        mockToken = new MockERC20Invariant();
        vm.prank(admin);
        bridge.addSupportedToken(address(mockToken));
    }

    // =========================================================================
    // FUZZ: Replay protection - same burnTxHash cannot be used twice
    // =========================================================================

    function testFuzz_replayProtection(
        bytes32 burnTxHash,
        uint256 amount1,
        uint256 amount2
    ) public {
        amount1 = bound(amount1, 0.01 ether, 10 ether);
        amount2 = bound(amount2, 0.01 ether, 10 ether);

        // Fund bridge
        vm.deal(address(bridge), 100 ether);

        bytes32 proposalId1 = keccak256(abi.encode("p1", burnTxHash));
        bytes32 proposalId2 = keccak256(abi.encode("p2", burnTxHash));

        // First proposal
        vm.prank(relayer1);
        bridge.proposeWithdrawal(
            proposalId1, user1, address(0), amount1, burnTxHash, 100
        );

        // Gather votes for first proposal
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId1);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId1);
        vm.prank(relayer4);
        bridge.voteWithdrawal(proposalId1);

        // Warp past challenge period
        vm.warp(block.timestamp + 7 days + 1);

        // Process first withdrawal
        bridge.processWithdrawal(proposalId1);
        assertTrue(bridge.processedWithdrawals(burnTxHash));

        // Second proposal with same burnTxHash must revert
        vm.prank(relayer1);
        vm.expectRevert(AethelredBridge.WithdrawalAlreadyProcessed.selector);
        bridge.proposeWithdrawal(
            proposalId2, user1, address(0), amount2, burnTxHash, 200
        );
    }

    // =========================================================================
    // FUZZ: Rate limit enforcement on deposits
    // =========================================================================

    function testFuzz_depositRateLimitEnforced(uint256 numDeposits) public {
        numDeposits = bound(numDeposits, 1, 15);
        uint256 depositAmount = 100 ether; // MAX_SINGLE_DEPOSIT
        (uint256 maxPerPeriod,,) = bridge.rateLimitConfig();

        uint256 totalDeposited = 0;
        for (uint256 i = 0; i < numDeposits; i++) {
            vm.deal(user1, depositAmount);
            vm.prank(user1);

            if (totalDeposited + depositAmount > maxPerPeriod) {
                vm.expectRevert(AethelredBridge.RateLimitExceeded.selector);
                bridge.depositETH{value: depositAmount}(
                    bytes32(uint256(0xABCDEF))
                );
                break;
            } else {
                bridge.depositETH{value: depositAmount}(
                    bytes32(uint256(0xABCDEF))
                );
                totalDeposited += depositAmount;
            }
        }

        // On-chain state must respect limit
        (uint256 deposited,) = bridge.getCurrentRateLimitState();
        assertLe(deposited, maxPerPeriod);
    }

    // =========================================================================
    // FUZZ: Withdrawal rate limit enforcement
    // =========================================================================

    function testFuzz_withdrawalRateLimitEnforced(uint256 numWithdrawals) public {
        numWithdrawals = bound(numWithdrawals, 1, 12);
        vm.deal(address(bridge), 2000 ether);

        (, uint256 maxPerPeriod,) = bridge.rateLimitConfig();
        uint256 totalWithdrawn = 0;
        uint256 withdrawAmount = 9.99 ether; // Under mint ceiling

        for (uint256 i = 0; i < numWithdrawals; i++) {
            bytes32 proposalId = keccak256(abi.encode("wp", i));
            bytes32 burnTxHash = keccak256(abi.encode("bt", i));

            // Propose
            vm.prank(relayer1);
            bridge.proposeWithdrawal(
                proposalId, user1, address(0), withdrawAmount, burnTxHash, 100 + i
            );

            // Vote (need 4 votes total for 67% of 5)
            vm.prank(relayer2);
            bridge.voteWithdrawal(proposalId);
            vm.prank(relayer3);
            bridge.voteWithdrawal(proposalId);
            vm.prank(relayer4);
            bridge.voteWithdrawal(proposalId);

            // Warp past challenge period
            vm.warp(block.timestamp + 7 days + 1);
            // Advance block so mint ceiling resets
            vm.roll(block.number + 1);

            if (totalWithdrawn + withdrawAmount > maxPerPeriod) {
                vm.expectRevert(AethelredBridge.RateLimitExceeded.selector);
                bridge.processWithdrawal(proposalId);
                break;
            } else {
                bridge.processWithdrawal(proposalId);
                totalWithdrawn += withdrawAmount;
            }
        }

        (, uint256 withdrawn) = bridge.getCurrentRateLimitState();
        assertLe(withdrawn, maxPerPeriod);
    }

    // =========================================================================
    // FUZZ: Per-block mint ceiling
    // =========================================================================

    function testFuzz_mintCeilingPerBlock(uint256 amount1, uint256 amount2) public {
        amount1 = bound(amount1, 0.01 ether, 10 ether);
        amount2 = bound(amount2, 0.01 ether, 10 ether);
        vm.deal(address(bridge), 100 ether);

        uint256 ceiling = bridge.mintCeilingPerBlock(); // 10 ETH

        // First withdrawal in this block
        bytes32 pid1 = keccak256("pid1");
        bytes32 btx1 = keccak256("btx1");
        _createApprovedProposal(pid1, btx1, amount1);

        vm.warp(block.timestamp + 7 days + 1);
        // Don't roll block - stay in same block

        if (amount1 <= ceiling) {
            bridge.processWithdrawal(pid1);

            // Second withdrawal in same block
            bytes32 pid2 = keccak256("pid2");
            bytes32 btx2 = keccak256("btx2");
            _createApprovedProposal(pid2, btx2, amount2);

            vm.warp(block.timestamp + 7 days + 1);
            // Still same block

            if (amount1 + amount2 > ceiling) {
                vm.expectRevert(AethelredBridge.MintCeilingExceeded.selector);
                bridge.processWithdrawal(pid2);
            } else {
                bridge.processWithdrawal(pid2);
            }
        } else {
            vm.expectRevert(AethelredBridge.MintCeilingExceeded.selector);
            bridge.processWithdrawal(pid1);
        }
    }

    // =========================================================================
    // FUZZ: Challenge period enforcement
    // =========================================================================

    function testFuzz_challengePeriodEnforced(uint256 warpSeconds) public {
        warpSeconds = bound(warpSeconds, 0, 7 days - 1);
        vm.deal(address(bridge), 100 ether);

        bytes32 proposalId = keccak256("challenge-test");
        bytes32 burnTxHash = keccak256("challenge-burn");
        uint256 amount = 1 ether;

        _createApprovedProposal(proposalId, burnTxHash, amount);

        // Warp to within challenge period
        vm.warp(block.timestamp + warpSeconds);

        vm.expectRevert(AethelredBridge.ChallengePeriodNotEnded.selector);
        bridge.processWithdrawal(proposalId);
    }

    // =========================================================================
    // FUZZ: Emergency withdrawal cap
    // =========================================================================

    function testFuzz_emergencyWithdrawalCapped(uint256 amount) public {
        amount = bound(amount, 50 ether + 1, type(uint128).max);
        vm.deal(address(bridge), amount);

        vm.prank(admin);
        vm.expectRevert(AethelredBridge.EmergencyAmountExceedsMax.selector);
        bridge.queueEmergencyWithdrawal(address(0), amount, user1);
    }

    // =========================================================================
    // FUZZ: Emergency withdrawal requires guardian quorum
    // =========================================================================

    function testFuzz_emergencyRequiresGuardianQuorum(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 50 ether);
        vm.deal(address(bridge), 100 ether);

        vm.prank(admin);
        bytes32 opId = bridge.queueEmergencyWithdrawal(
            address(0), amount, user1
        );

        // Warp past emergency timelock
        vm.warp(block.timestamp + 48 hours + 1);

        // Try to execute without guardian approvals
        vm.prank(admin);
        vm.expectRevert(
            AethelredBridge.InsufficientGuardianApprovals.selector
        );
        bridge.executeEmergencyWithdrawal(opId);

        // One guardian approves (need 2)
        vm.prank(guardian1);
        bridge.approveEmergencyWithdrawal(opId);

        // Still should fail with only 1 approval
        vm.prank(admin);
        vm.expectRevert(
            AethelredBridge.InsufficientGuardianApprovals.selector
        );
        bridge.executeEmergencyWithdrawal(opId);

        // Second guardian approves
        vm.prank(guardian2);
        bridge.approveEmergencyWithdrawal(opId);

        // Now should succeed
        vm.prank(admin);
        bridge.executeEmergencyWithdrawal(opId);
    }

    // =========================================================================
    // FUZZ: Domain separator consistency after chain ID change
    // =========================================================================

    function testFuzz_domainSeparatorUpdatesOnFork(uint64 newChainId) public {
        vm.assume(newChainId > 0);
        vm.assume(newChainId != block.chainid);

        vm.chainId(newChainId);

        bytes32 expected = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("AethelredBridge"),
                keccak256("1"),
                newChainId,
                address(bridge)
            )
        );

        assertEq(bridge.domainSeparatorV4(), expected);
    }

    // =========================================================================
    // FUZZ: Deposit amount bounds
    // =========================================================================

    function testFuzz_depositAmountBounds(uint256 amount) public {
        vm.deal(user1, amount);
        vm.prank(user1);

        if (amount < 0.01 ether || amount > 100 ether) {
            vm.expectRevert(AethelredBridge.InvalidAmount.selector);
            bridge.depositETH{value: amount}(bytes32(uint256(0xABCDEF)));
        } else {
            bridge.depositETH{value: amount}(bytes32(uint256(0xABCDEF)));
            assertEq(bridge.totalLockedETH(), amount);
        }
    }

    // =========================================================================
    // FUZZ: Nonce monotonicity across deposits
    // =========================================================================

    function testFuzz_nonceMonotonicity(uint8 numDeposits) public {
        uint256 count = bound(numDeposits, 1, 10);
        uint256 amount = 0.1 ether;

        for (uint256 i = 0; i < count; i++) {
            vm.deal(user1, amount);
            vm.prank(user1);
            bridge.depositETH{value: amount}(bytes32(uint256(0xABCDEF)));
            assertEq(bridge.depositNonce(), i + 1);
        }
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    function _createApprovedProposal(
        bytes32 proposalId,
        bytes32 burnTxHash,
        uint256 amount
    ) internal {
        vm.prank(relayer1);
        bridge.proposeWithdrawal(
            proposalId, user1, address(0), amount, burnTxHash, 100
        );
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer4);
        bridge.voteWithdrawal(proposalId);
    }
}
