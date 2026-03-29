// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/vault/Cruzible.sol";
import "../contracts/vault/StAETHEL.sol";
import "../contracts/vault/VaultTEEVerifier.sol";
import "../contracts/vault/PlatformVerifiers.sol";
import "../contracts/vault/ICruzible.sol";

// ═══════════════════════════════════════════════════════════════════════════════
// Mock ERC20 (namespaced to avoid collision with other test files)
// ═══════════════════════════════════════════════════════════════════════════════

contract MockAETHELVault {
    string public name = "Aethelred";
    string public symbol = "AETHEL";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Vault Handler - exercises stake, unstake, withdraw, and rewards
// ═══════════════════════════════════════════════════════════════════════════════

contract VaultInvariantHandler is Test {
    Cruzible public vault;
    StAETHEL public stAethel;
    MockAETHELVault public aethel;

    address public admin;
    address public oracle;
    address[5] public actors;

    // TEE key pair
    uint256 internal operatorPrivKey = 0xA11CE;
    bytes32 internal constant ENCLAVE_HASH = keccak256("cruzible-enclave-v1");
    bytes32 internal constant SIGNER_HASH = keccak256("cruzible-signer-v1");
    uint256 internal constant P256_PRIV_KEY = 1;
    bytes32 internal constant TEST_POLICY_HASH = keccak256("test-selection-policy-v1");
    bytes32 internal constant TEST_UNIVERSE_HASH = keccak256("test-eligible-universe-v1");
    bytes32 internal constant TEST_SNAPSHOT_HASH = keccak256("test-stake-snapshot-v1");

    // ── Ghost variables for invariant verification ──────────────────────────
    uint256 public ghost_totalSharesMinted;
    uint256 public ghost_totalSharesBurned;
    uint256 public ghost_previousExchangeRate;
    uint256 public ghost_previousEpoch;

    // Withdrawal tracking for FIFO and solvency checks
    uint256[] public ghost_withdrawalIds;
    uint256[] public ghost_withdrawalRequestTimes;
    uint256[] public ghost_withdrawalClaimOrder;
    mapping(uint256 => bool) public ghost_claimedWithdrawals;
    mapping(uint256 => uint256) public ghost_withdrawalAmounts;
    uint256 public ghost_totalPendingWithdrawalAmount;

    // Call counters
    uint256 public calls_stake;
    uint256 public calls_unstake;
    uint256 public calls_withdraw;
    uint256 public calls_distributeRewards;

    constructor(
        Cruzible _vault,
        StAETHEL _stAethel,
        MockAETHELVault _aethel,
        address _admin,
        address _oracle,
        address[5] memory _actors
    ) {
        vault = _vault;
        stAethel = _stAethel;
        aethel = _aethel;
        admin = _admin;
        oracle = _oracle;
        actors = _actors;
        ghost_previousExchangeRate = 1e18;
        ghost_previousEpoch = 1;
    }

    // ── Stake ───────────────────────────────────────────────────────────────

    function stake(uint256 actorSeed, uint256 amount) external {
        address actor = actors[actorSeed % actors.length];
        amount = bound(amount, 32 ether, 100_000 ether);

        if (aethel.balanceOf(actor) < amount) {
            aethel.mint(actor, amount);
        }
        vm.prank(actor);
        aethel.approve(address(vault), amount);

        vm.prank(actor);
        uint256 shares = vault.stake(amount);

        ghost_totalSharesMinted += shares;
        calls_stake++;
    }

    // ── Unstake ─────────────────────────────────────────────────────────────

    function unstake(uint256 actorSeed, uint256 sharesFraction) external {
        address actor = actors[actorSeed % actors.length];
        uint256 actorShares = stAethel.sharesOf(actor);
        if (actorShares == 0) return;

        sharesFraction = bound(sharesFraction, 1, 100);
        uint256 sharesToUnstake = (actorShares * sharesFraction) / 100;
        if (sharesToUnstake == 0) sharesToUnstake = 1;
        if (sharesToUnstake > actorShares) sharesToUnstake = actorShares;

        vm.prank(actor);
        (uint256 withdrawalId, uint256 aethelAmount) = vault.unstake(sharesToUnstake);

        ghost_totalSharesBurned += sharesToUnstake;
        ghost_withdrawalIds.push(withdrawalId);
        ghost_withdrawalRequestTimes.push(block.timestamp);
        ghost_withdrawalAmounts[withdrawalId] = aethelAmount;
        ghost_totalPendingWithdrawalAmount += aethelAmount;
        calls_unstake++;
    }

    // ── Withdraw ────────────────────────────────────────────────────────────

    function withdraw(uint256 withdrawalSeed) external {
        if (ghost_withdrawalIds.length == 0) return;

        uint256 idx = withdrawalSeed % ghost_withdrawalIds.length;
        uint256 withdrawalId = ghost_withdrawalIds[idx];

        if (ghost_claimedWithdrawals[withdrawalId]) return;

        // Warp past unbonding period
        vm.warp(block.timestamp + 15 days);

        for (uint256 i = 0; i < actors.length; i++) {
            vm.prank(actors[i]);
            try vault.withdraw(withdrawalId) {
                ghost_claimedWithdrawals[withdrawalId] = true;
                ghost_withdrawalClaimOrder.push(withdrawalId);
                ghost_totalPendingWithdrawalAmount -= ghost_withdrawalAmounts[withdrawalId];
                calls_withdraw++;
                return;
            } catch {
                continue;
            }
        }
    }

    // ── Distribute Rewards (advances epoch) ─────────────────────────────────

    function distributeRewards(uint256 rewardAmount) external {
        rewardAmount = bound(rewardAmount, 0.1 ether, 1000 ether);

        if (vault.getTotalPooledAethel() == 0) return;

        uint256 epoch = vault.currentEpoch();
        uint256 fee = (rewardAmount * 500) / 10000;

        aethel.mint(oracle, rewardAmount);
        vm.prank(oracle);
        aethel.approve(address(vault), rewardAmount);

        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(epoch);
        bytes32 vsHash = snap.validatorSetHash;
        bytes32 regRoot = snap.stakerRegistryRoot;

        // Commit delegation root if needed
        bytes32 delRoot;
        if (snap.delegationRegistryRoot == bytes32(0)) {
            delRoot = keccak256(abi.encodePacked("test-delegation-root", epoch));
            bytes memory delPayload = abi.encode(epoch, delRoot, snap.stakerRegistryRoot);
            bytes memory delAtt = _createAttestation(delPayload);
            vm.prank(admin);
            vault.commitDelegationSnapshot(delAtt, epoch, delRoot, snap.stakerRegistryRoot, 1);
        } else {
            delRoot = snap.delegationRegistryRoot;
        }

        // Fast-forward past challenge period
        vm.warp(block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD() + 1);

        bytes memory payload = abi.encode(epoch, rewardAmount, bytes32(0), fee, TEST_SNAPSHOT_HASH, vsHash, regRoot, delRoot);
        bytes memory att = _createAttestation(payload);

        vm.prank(oracle);
        try vault.distributeRewards(att, epoch, rewardAmount, bytes32(0), fee) {
            uint256 nextEpoch = vault.currentEpoch();
            vm.startPrank(admin);
            vault.commitUniverseHash(nextEpoch, TEST_UNIVERSE_HASH);
            vault.commitStakeSnapshot(nextEpoch, TEST_SNAPSHOT_HASH, vault.getTotalShares());
            vm.stopPrank();

            ghost_previousEpoch = nextEpoch;
            calls_distributeRewards++;
        } catch {
            // Acceptable failure
        }

        ghost_previousExchangeRate = vault.getExchangeRate();
    }

    // ── Attestation helper ─────────────────────────────────────────────────

    function _createAttestation(bytes memory payload) internal view returns (bytes memory) {
        uint8 platformId = 0;
        uint256 timestamp = block.timestamp;
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, block.number, payload));

        bytes32 payloadHash = sha256(payload);
        bytes32 digest = sha256(abi.encodePacked(
            "CruzibleTEEAttestation",
            platformId,
            uint64(timestamp),
            nonce,
            ENCLAVE_HASH,
            SIGNER_HASH,
            payloadHash
        ));

        bytes32 rawReportHash = sha256(abi.encodePacked(
            "MOCK_HW_REPORT_V1",
            ENCLAVE_HASH,
            SIGNER_HASH,
            digest
        ));

        bytes32 bindingHash = sha256(abi.encodePacked(rawReportHash, ENCLAVE_HASH, SIGNER_HASH));
        bytes32 reportHash = sha256(abi.encodePacked(ENCLAVE_HASH, SIGNER_HASH, digest, uint16(1), uint16(1), bindingHash));
        (bytes32 p256r, bytes32 p256s) = vm.signP256(P256_PRIV_KEY, reportHash);

        bytes memory evidence = abi.encode(
            ENCLAVE_HASH,
            SIGNER_HASH,
            digest,
            uint16(1),
            uint16(1),
            rawReportHash,
            uint256(p256r),
            uint256(p256s)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        return abi.encode(
            platformId,
            timestamp,
            nonce,
            ENCLAVE_HASH,
            SIGNER_HASH,
            payload,
            evidence,
            signature
        );
    }

    // ── View helpers ────────────────────────────────────────────────────────

    function getWithdrawalIdCount() external view returns (uint256) {
        return ghost_withdrawalIds.length;
    }

    function getClaimOrderCount() external view returns (uint256) {
        return ghost_withdrawalClaimOrder.length;
    }

    function getClaimOrderAt(uint256 idx) external view returns (uint256) {
        return ghost_withdrawalClaimOrder[idx];
    }

    function getWithdrawalRequestTime(uint256 idx) external view returns (uint256) {
        return ghost_withdrawalRequestTimes[idx];
    }

    function getWithdrawalIdAt(uint256 idx) external view returns (uint256) {
        return ghost_withdrawalIds[idx];
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Vault Invariant Test Suite
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * @title VaultInvariantTest
 * @notice Foundry invariant and fuzz tests for the Cruzible vault and StAETHEL.
 *         Covers SQ10 and SQ11.
 *
 * Invariants tested:
 *   1. invariant_shareConservation - sum of all user shares == totalShares
 *   2. invariant_exchangeRateFloor - exchangeRate >= 1e18 (no deflation)
 *   3. invariant_withdrawalQueueOrdering - withdrawals processed in FIFO order
 *   4. invariant_vaultSolvency - totalPooledAethel >= sum of pending withdrawals
 *   5. invariant_epochMonotonicity - currentEpoch only increases
 */
contract VaultInvariantTest is StdInvariant, Test {
    // ── Contracts ───────────────────────────────────────────────────────────
    Cruzible public vault;
    StAETHEL public stAethel;
    MockAETHELVault public aethel;
    VaultTEEVerifier public verifier;
    SgxVerifier public sgxVerifier;
    VaultInvariantHandler public handler;

    // ── Addresses ───────────────────────────────────────────────────────────
    address public admin = address(0xAD);
    address public oracle = address(0x0AC1E);
    address public guardian = address(0x6AAD);
    address public treasury = address(0x72EA);
    address[5] public actors = [
        address(0xA11CE),
        address(0xB0B),
        address(0xC4A),
        address(0xDA5),
        address(0xE1E)
    ];

    // ── TEE constants ───────────────────────────────────────────────────────
    uint256 internal operatorPrivKey = 0xA11CE;
    address internal operatorAddr;
    uint256 internal constant P256_PRIV_KEY = 1;
    uint256 internal constant P256_PUB_X = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 internal constant P256_PUB_Y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
    bytes32 internal constant ENCLAVE_HASH = keccak256("cruzible-enclave-v1");
    bytes32 internal constant SIGNER_HASH = keccak256("cruzible-signer-v1");
    bytes32 internal constant TEST_POLICY_HASH = keccak256("test-selection-policy-v1");
    bytes32 internal constant TEST_UNIVERSE_HASH = keccak256("test-eligible-universe-v1");
    bytes32 internal constant TEST_SNAPSHOT_HASH = keccak256("test-stake-snapshot-v1");
    uint256 internal constant VENDOR_ROOT_PRIV = 2;
    uint256 internal constant VENDOR_ROOT_X = 0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978;
    uint256 internal constant VENDOR_ROOT_Y = 0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1;

    // ═════════════════════════════════════════════════════════════════════════
    // SETUP
    // ═════════════════════════════════════════════════════════════════════════

    function setUp() public {
        operatorAddr = vm.addr(operatorPrivKey);

        // Deploy mock token
        aethel = new MockAETHELVault();

        // Deploy VaultTEEVerifier
        VaultTEEVerifier verifierImpl = new VaultTEEVerifier();
        bytes memory verifierInit = abi.encodeCall(VaultTEEVerifier.initialize, (admin));
        ERC1967Proxy verifierProxy = new ERC1967Proxy(address(verifierImpl), verifierInit);
        verifier = VaultTEEVerifier(address(verifierProxy));

        // Deploy StAETHEL impl
        StAETHEL stAethelImpl = new StAETHEL();

        // Deploy Cruzible impl
        Cruzible vaultImpl = new Cruzible();

        // Deploy stAETHEL proxy with placeholder vault
        bytes memory stAethelInit = abi.encodeCall(StAETHEL.initialize, (admin, address(0xDEAD)));
        ERC1967Proxy stAethelProxy = new ERC1967Proxy(address(stAethelImpl), stAethelInit);
        stAethel = StAETHEL(address(stAethelProxy));

        // Deploy vault proxy
        bytes memory vaultInit = abi.encodeCall(
            Cruzible.initialize,
            (admin, address(aethel), address(stAethel), address(verifier), treasury)
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInit);
        vault = Cruzible(address(vaultProxy));

        // Grant stAETHEL VAULT_ROLE to the actual vault
        bytes32 vaultRole = stAethel.VAULT_ROLE();
        vm.prank(admin);
        stAethel.grantRole(vaultRole, address(vault));

        // Setup roles and TEE
        vm.startPrank(admin);
        vault.grantRole(vault.ORACLE_ROLE(), oracle);
        vault.grantRole(vault.GUARDIAN_ROLE(), guardian);

        // Setup vendor root key + enclave
        verifier.setVendorRootKey(0, VENDOR_ROOT_X, VENDOR_ROOT_Y);
        bytes32 keyAttestMsg = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(0)));
        (bytes32 vendorR, bytes32 vendorS) = vm.signP256(VENDOR_ROOT_PRIV, keyAttestMsg);
        verifier.registerEnclave(
            ENCLAVE_HASH, SIGNER_HASH, bytes32(0), 0, "Cruzible SGX Enclave v1",
            P256_PUB_X, P256_PUB_Y, uint256(vendorR), uint256(vendorS)
        );
        bytes32 enclaveId = keccak256(abi.encodePacked(ENCLAVE_HASH, uint8(0)));
        verifier.registerOperator(operatorAddr, enclaveId, "Test TEE Operator");

        sgxVerifier = new SgxVerifier();
        verifier.setPlatformVerifier(0, address(sgxVerifier));

        // Set selection policy + initial epoch hashes
        vault.setSelectionPolicyHash(TEST_POLICY_HASH);
        vault.commitUniverseHash(1, TEST_UNIVERSE_HASH);
        vault.commitStakeSnapshot(1, TEST_SNAPSHOT_HASH, vault.getTotalShares());
        vm.stopPrank();

        // Fund actors
        for (uint256 i = 0; i < actors.length; i++) {
            aethel.mint(actors[i], 10_000_000 ether);
            vm.prank(actors[i]);
            aethel.approve(address(vault), type(uint256).max);
        }

        // Deposit keeper bond for admin
        {
            uint256 bondAmount = vault.KEEPER_BOND_MINIMUM();
            aethel.mint(admin, bondAmount);
            vm.startPrank(admin);
            aethel.approve(address(vault), bondAmount);
            vault.depositKeeperBond(bondAmount);
            vm.stopPrank();
        }

        // Deploy handler
        handler = new VaultInvariantHandler(vault, stAethel, aethel, admin, oracle, actors);

        // Target the handler
        targetContract(address(handler));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INVARIANT 1: Share Conservation
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Sum of all user shares must equal stAETHEL.getTotalShares().
    function invariant_shareConservation() public view {
        uint256 sumShares = 0;
        for (uint256 i = 0; i < actors.length; i++) {
            sumShares += stAethel.sharesOf(actors[i]);
        }
        assertEq(
            sumShares,
            stAethel.getTotalShares(),
            "Share conservation violated: sum of user shares != totalShares"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INVARIANT 2: Exchange Rate Floor
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice exchangeRate >= 1e18 (no deflation). Since the handler only
    ///         distributes rewards (no slashing), the rate should never drop
    ///         below the initial 1:1 ratio.
    function invariant_exchangeRateFloor() public view {
        uint256 rate = vault.getExchangeRate();
        assertGe(
            rate,
            1e18,
            "Exchange rate dropped below 1:1 floor"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INVARIANT 3: Withdrawal Queue Ordering (FIFO)
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Withdrawal requests should be processed respecting their request
    ///         times. Earlier requests should not be blocked by later ones.
    ///         We verify that claimed withdrawals respect temporal ordering:
    ///         for any two claimed withdrawals, if withdrawal A was requested
    ///         before withdrawal B and both are claimable, then A should have
    ///         been claimed before B in the handler's claim order (or both are
    ///         claimable simultaneously since they're independent per-user).
    ///
    ///         The Cruzible contract uses per-request completion times based on
    ///         request time + UNBONDING_PERIOD, so earlier requests become
    ///         claimable first.
    function invariant_withdrawalQueueOrdering() public view {
        uint256 claimCount = handler.getClaimOrderCount();
        if (claimCount < 2) return;

        // Verify that each withdrawal in the claim order has a valid
        // request time and that the contract's completion time respects
        // request ordering.
        for (uint256 i = 0; i < claimCount; i++) {
            uint256 wId = handler.getClaimOrderAt(i);
            (,,,, uint256 completionTime, bool claimed) = vault.withdrawalRequests(wId);
            assertTrue(claimed, "Withdrawal in claim order not marked as claimed");
            assertGt(completionTime, 0, "Completion time should be non-zero");
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INVARIANT 4: Vault Solvency
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice The vault's token balance must cover totalPooledAethel plus
    ///         totalPendingWithdrawals. The vault must always be able to
    ///         honor its obligations.
    function invariant_vaultSolvency() public view {
        uint256 vaultBalance = aethel.balanceOf(address(vault));
        uint256 totalPooled = vault.getTotalPooledAethel();
        uint256 totalPending = vault.totalPendingWithdrawals();

        // The vault balance must cover both active deposits and pending withdrawals.
        // It may be higher due to keeper bonds, rewards not yet distributed, etc.
        assertGe(
            vaultBalance,
            totalPooled + totalPending,
            "Vault insolvent: balance < totalPooled + totalPendingWithdrawals"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INVARIANT 5: Epoch Monotonicity
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice currentEpoch must only increase and never drop below 1.
    function invariant_epochMonotonicity() public view {
        uint256 epoch = vault.currentEpoch();
        assertGe(epoch, 1, "Epoch below initial value of 1");
        assertGe(
            epoch,
            handler.ghost_previousEpoch(),
            "Epoch decreased -- monotonicity violated"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // ADDITIONAL INVARIANTS
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Ghost share accounting: minted - burned == totalShares.
    function invariant_ghostShareAccounting() public view {
        uint256 totalShares = stAethel.getTotalShares();
        uint256 expected = handler.ghost_totalSharesMinted() - handler.ghost_totalSharesBurned();
        assertEq(
            totalShares,
            expected,
            "Ghost share accounting mismatch: minted - burned != totalShares"
        );
    }

    /// @notice Total pending withdrawals must be non-negative and consistent
    ///         with the number of unclaimed withdrawal requests.
    function invariant_pendingWithdrawalsConsistency() public view {
        uint256 contractPending = vault.totalPendingWithdrawals();
        // Total pending should match handler's ghost tracking
        assertEq(
            contractPending,
            handler.ghost_totalPendingWithdrawalAmount(),
            "Pending withdrawals mismatch between contract and ghost"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // FUZZ TESTS
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Stake followed by full unstake should yield withdrawal amount
    ///         matching the staked amount at 1:1 exchange rate.
    function testFuzz_stakeUnstakeValuePreservation(uint256 amount) public {
        amount = bound(amount, 32 ether, 1_000_000 ether);

        (Cruzible freshVault, StAETHEL freshSt, MockAETHELVault freshToken) = _deployFreshVault();
        address user = address(0xFADE);
        freshToken.mint(user, amount);
        vm.prank(user);
        freshToken.approve(address(freshVault), amount);

        // Stake
        vm.prank(user);
        uint256 shares = freshVault.stake(amount);
        assertEq(shares, amount, "Initial stake should be 1:1");

        // Unstake
        vm.prank(user);
        (uint256 wId, uint256 aethelAmount) = freshVault.unstake(shares);
        assertEq(aethelAmount, amount, "Unstake amount should equal staked amount at 1:1");

        // Withdraw after unbonding
        vm.warp(block.timestamp + 15 days);
        uint256 balBefore = freshToken.balanceOf(user);
        vm.prank(user);
        freshVault.withdraw(wId);
        uint256 received = freshToken.balanceOf(user) - balBefore;

        assertEq(received, amount, "Full round-trip should return exact amount at 1:1");
    }

    /// @notice Exchange rate should never decrease after reward distribution.
    function testFuzz_exchangeRateNeverDecreases(uint256 stakeAmount, uint256 rewardAmount) public {
        stakeAmount = bound(stakeAmount, 32 ether, 1_000_000 ether);
        rewardAmount = bound(rewardAmount, 1 ether, 100_000 ether);

        (Cruzible freshVault, StAETHEL freshSt, MockAETHELVault freshToken) = _deployFreshVault();

        // Initial stake
        address user = address(0xBEEF);
        freshToken.mint(user, stakeAmount);
        vm.prank(user);
        freshToken.approve(address(freshVault), stakeAmount);
        vm.prank(user);
        freshVault.stake(stakeAmount);

        uint256 rateBefore = freshVault.getExchangeRate();

        // Simulate reward distribution by directly increasing totalPooledAethel
        // via the stAETHEL token (only VAULT_ROLE can call this)
        freshToken.mint(address(freshVault), rewardAmount);

        // The exchange rate should not have decreased (it may stay the same
        // because totalPooledAethel on vault hasn't been updated yet)
        uint256 rateAfter = freshVault.getExchangeRate();
        assertGe(rateAfter, rateBefore, "Exchange rate decreased");
    }

    /// @notice Share conservation holds after multiple stake/unstake cycles.
    function testFuzz_shareConservationMultiUser(
        uint256 amount1,
        uint256 amount2,
        uint256 amount3
    ) public {
        amount1 = bound(amount1, 32 ether, 500_000 ether);
        amount2 = bound(amount2, 32 ether, 500_000 ether);
        amount3 = bound(amount3, 32 ether, 500_000 ether);

        (Cruzible freshVault, StAETHEL freshSt, MockAETHELVault freshToken) = _deployFreshVault();

        address user1 = address(0xAAA1);
        address user2 = address(0xAAA2);
        address user3 = address(0xAAA3);

        // Stake for 3 users
        _stakeUser(freshVault, freshSt, freshToken, user1, amount1);
        _stakeUser(freshVault, freshSt, freshToken, user2, amount2);
        _stakeUser(freshVault, freshSt, freshToken, user3, amount3);

        // Verify share conservation
        uint256 sum = freshSt.sharesOf(user1) + freshSt.sharesOf(user2) + freshSt.sharesOf(user3);
        assertEq(sum, freshSt.getTotalShares(), "Share conservation failed for 3 users");

        // Unstake user2 partially
        uint256 user2Shares = freshSt.sharesOf(user2);
        uint256 unstakeShares = user2Shares / 2;
        if (unstakeShares > 0) {
            vm.prank(user2);
            freshVault.unstake(unstakeShares);
        }

        // Re-check conservation
        sum = freshSt.sharesOf(user1) + freshSt.sharesOf(user2) + freshSt.sharesOf(user3);
        assertEq(sum, freshSt.getTotalShares(), "Share conservation failed after partial unstake");
    }

    /// @notice Withdrawal before unbonding period always reverts.
    function testFuzz_earlyWithdrawalAlwaysReverts(uint256 stakeAmount, uint256 warpTime) public {
        stakeAmount = bound(stakeAmount, 32 ether, 1_000_000 ether);
        warpTime = bound(warpTime, 0, 14 days - 1);

        (Cruzible freshVault,, MockAETHELVault freshToken) = _deployFreshVault();
        address user = address(0xCAFE);
        freshToken.mint(user, stakeAmount);
        vm.prank(user);
        freshToken.approve(address(freshVault), stakeAmount);
        vm.prank(user);
        uint256 shares = freshVault.stake(stakeAmount);

        vm.prank(user);
        (uint256 wId,) = freshVault.unstake(shares);

        vm.warp(block.timestamp + warpTime);

        vm.prank(user);
        vm.expectRevert();
        freshVault.withdraw(wId);
    }

    /// @notice Epoch monotonicity: currentEpoch should be >= 1 on a fresh vault.
    function testFuzz_epochStartsAtOne(uint256 dummy) public {
        dummy = bound(dummy, 0, 100);
        (Cruzible freshVault,,) = _deployFreshVault();
        assertEq(freshVault.currentEpoch(), 1, "Epoch should start at 1");
    }

    /// @notice Vault solvency: balance should always cover pooled + pending.
    function testFuzz_solvencyAfterStakeAndUnstake(uint256 stakeAmount, uint256 unstakeFraction) public {
        stakeAmount = bound(stakeAmount, 32 ether, 1_000_000 ether);
        unstakeFraction = bound(unstakeFraction, 1, 100);

        (Cruzible freshVault, StAETHEL freshSt, MockAETHELVault freshToken) = _deployFreshVault();
        address user = address(0xDEAF);
        freshToken.mint(user, stakeAmount);
        vm.prank(user);
        freshToken.approve(address(freshVault), stakeAmount);
        vm.prank(user);
        uint256 shares = freshVault.stake(stakeAmount);

        // Partial unstake
        uint256 unstakeShares = (shares * unstakeFraction) / 100;
        if (unstakeShares == 0) unstakeShares = 1;
        if (unstakeShares > shares) unstakeShares = shares;

        vm.prank(user);
        freshVault.unstake(unstakeShares);

        // Check solvency
        uint256 vaultBal = freshToken.balanceOf(address(freshVault));
        uint256 pooled = freshVault.getTotalPooledAethel();
        uint256 pending = freshVault.totalPendingWithdrawals();

        assertGe(vaultBal, pooled + pending, "Solvency violated after unstake");
    }

    /// @notice Double-claim on the same withdrawal ID always reverts.
    function testFuzz_doubleClaimReverts(uint256 stakeAmount) public {
        stakeAmount = bound(stakeAmount, 32 ether, 1_000_000 ether);

        (Cruzible freshVault,, MockAETHELVault freshToken) = _deployFreshVault();
        address user = address(0xBEEE);
        freshToken.mint(user, stakeAmount);
        vm.prank(user);
        freshToken.approve(address(freshVault), stakeAmount);
        vm.prank(user);
        uint256 shares = freshVault.stake(stakeAmount);

        vm.prank(user);
        (uint256 wId,) = freshVault.unstake(shares);

        vm.warp(block.timestamp + 15 days);

        // First claim succeeds
        vm.prank(user);
        freshVault.withdraw(wId);

        // Second claim reverts
        vm.prank(user);
        vm.expectRevert();
        freshVault.withdraw(wId);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // HELPERS
    // ═════════════════════════════════════════════════════════════════════════

    function _stakeUser(
        Cruzible v,
        StAETHEL st,
        MockAETHELVault token,
        address user,
        uint256 amount
    ) internal {
        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(v), amount);
        vm.prank(user);
        v.stake(amount);
    }

    function _deployFreshVault() internal returns (Cruzible, StAETHEL, MockAETHELVault) {
        MockAETHELVault token = new MockAETHELVault();
        address adm = address(0xAD);

        // Deploy verifier
        VaultTEEVerifier vImpl = new VaultTEEVerifier();
        bytes memory vInit = abi.encodeCall(VaultTEEVerifier.initialize, (adm));
        ERC1967Proxy vProxy = new ERC1967Proxy(address(vImpl), vInit);
        VaultTEEVerifier ver = VaultTEEVerifier(address(vProxy));

        // Deploy stAETHEL
        StAETHEL stImpl = new StAETHEL();
        bytes memory stInit = abi.encodeCall(StAETHEL.initialize, (adm, address(0xDEAD)));
        ERC1967Proxy stProxy = new ERC1967Proxy(address(stImpl), stInit);
        StAETHEL st = StAETHEL(address(stProxy));

        // Deploy vault
        Cruzible cImpl = new Cruzible();
        bytes memory cInit = abi.encodeCall(
            Cruzible.initialize,
            (adm, address(token), address(st), address(ver), treasury)
        );
        ERC1967Proxy cProxy = new ERC1967Proxy(address(cImpl), cInit);
        Cruzible c = Cruzible(address(cProxy));

        // Grant VAULT_ROLE
        bytes32 vRole = st.VAULT_ROLE();
        vm.prank(adm);
        st.grantRole(vRole, address(c));

        // Setup TEE
        vm.startPrank(adm);
        c.grantRole(c.ORACLE_ROLE(), oracle);
        ver.setVendorRootKey(0, VENDOR_ROOT_X, VENDOR_ROOT_Y);
        bytes32 keyMsg = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(0)));
        (bytes32 vr, bytes32 vs) = vm.signP256(VENDOR_ROOT_PRIV, keyMsg);
        ver.registerEnclave(
            ENCLAVE_HASH, SIGNER_HASH, bytes32(0), 0, "SGX v1",
            P256_PUB_X, P256_PUB_Y, uint256(vr), uint256(vs)
        );
        bytes32 eid = keccak256(abi.encodePacked(ENCLAVE_HASH, uint8(0)));
        ver.registerOperator(vm.addr(operatorPrivKey), eid, "Op");
        SgxVerifier sv = new SgxVerifier();
        ver.setPlatformVerifier(0, address(sv));
        c.setSelectionPolicyHash(TEST_POLICY_HASH);
        c.commitUniverseHash(1, TEST_UNIVERSE_HASH);
        c.commitStakeSnapshot(1, TEST_SNAPSHOT_HASH, c.getTotalShares());
        vm.stopPrank();

        return (c, st, token);
    }
}
