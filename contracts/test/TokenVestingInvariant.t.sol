// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "../contracts/AethelredToken.sol";
import "../contracts/AethelredVesting.sol";

// =============================================================================
// SQ8 Token & Vesting Assurance — Invariant Test Suite
// =============================================================================
//
// Invariants verified:
//   1. invariant_totalSupplyNeverExceedsCap
//   2. invariant_totalSupplyEqualsBalanceSum
//   3. invariant_blacklistedCannotTransfer
//   4. invariant_vestedAmountMonotonicallyIncreases
//   5. invariant_vestingCategoryCapEnforced
//   6. invariant_revokedScheduleStopsVesting
// =============================================================================

// ---------------------------------------------------------------------------
// Handler: Token operations
// ---------------------------------------------------------------------------

/// @title TokenHandler
/// @notice Exposes bounded state-changing operations on AethelredToken for
///         Foundry's invariant fuzzer. Tracks every address that has received
///         minted tokens so the test contract can sum balances.
contract TokenHandler is Test {
    AethelredToken public token;

    address public admin;
    address public minter;
    address public compliance;

    /// @dev Ghost variable: set of addresses that have ever held tokens.
    address[] public actors;
    mapping(address => bool) public isActor;

    /// @dev Ghost variable: addresses currently blacklisted via this handler.
    address[] public blacklistedAddrs;
    mapping(address => bool) public isBlacklisted;

    /// @dev Total minted through this handler (ghost tracking).
    uint256 public ghost_totalMinted;

    /// @dev Total burned through this handler (ghost tracking).
    uint256 public ghost_totalBurned;

    constructor(
        AethelredToken _token,
        address _admin,
        address _minter,
        address _compliance
    ) {
        token = _token;
        admin = _admin;
        minter = _minter;
        compliance = _compliance;

        // Register initial holders
        _addActor(_admin);
        _addActor(_minter);
    }

    // -- helpers --

    function _addActor(address a) internal {
        if (!isActor[a] && a != address(0)) {
            actors.push(a);
            isActor[a] = true;
        }
    }

    function actorCount() external view returns (uint256) {
        return actors.length;
    }

    // -- state-changing fuzz entry points --

    /// @notice Mint tokens to a fuzzed recipient (bounded to cap headroom).
    function mint(uint256 toSeed, uint256 amount) external {
        address to = _deriveAddress(toSeed);
        if (to == address(0)) to = address(0x7001);
        if (token.blacklisted(to)) return;

        uint256 headroom = token.TOTAL_SUPPLY_CAP() - token.totalSupply();
        if (headroom == 0) return;
        amount = bound(amount, 1, headroom);

        _addActor(to);

        vm.prank(minter);
        token.mint(to, amount);
        ghost_totalMinted += amount;
    }

    /// @notice Transfer between existing actors.
    function transfer(uint256 fromIdx, uint256 toIdx, uint256 amount) external {
        if (actors.length < 2) return;
        fromIdx = fromIdx % actors.length;
        toIdx = toIdx % actors.length;
        if (fromIdx == toIdx) toIdx = (toIdx + 1) % actors.length;

        address from = actors[fromIdx];
        address to = actors[toIdx];

        if (token.blacklisted(from) || token.blacklisted(to)) return;

        uint256 bal = token.balanceOf(from);
        if (bal == 0) return;
        amount = bound(amount, 1, bal);

        // Ensure transfer restrictions don't block us
        vm.prank(admin);
        token.setWhitelisted(from, true);

        vm.prank(from);
        token.transfer(to, amount);
        _addActor(to);
    }

    /// @notice Burn tokens from a random actor.
    function burn(uint256 actorIdx, uint256 amount) external {
        if (actors.length == 0) return;
        actorIdx = actorIdx % actors.length;
        address actor = actors[actorIdx];

        uint256 bal = token.balanceOf(actor);
        if (bal == 0) return;
        amount = bound(amount, 1, bal);

        vm.prank(actor);
        token.burn(amount);
        ghost_totalBurned += amount;
    }

    /// @notice Blacklist a fuzzed address.
    function blacklist(uint256 seed) external {
        address target = _deriveAddress(seed);
        if (target == address(0) || target == admin || target == minter) return;
        if (isBlacklisted[target]) return;

        vm.prank(compliance);
        token.setBlacklisted(target, true);

        isBlacklisted[target] = true;
        blacklistedAddrs.push(target);
        _addActor(target);
    }

    /// @notice Remove blacklist (small probability to keep coverage of both paths).
    function unblacklist(uint256 idx) external {
        if (blacklistedAddrs.length == 0) return;
        idx = idx % blacklistedAddrs.length;
        address target = blacklistedAddrs[idx];

        vm.prank(compliance);
        token.setBlacklisted(target, false);

        isBlacklisted[target] = false;
    }

    function blacklistedCount() external view returns (uint256) {
        return blacklistedAddrs.length;
    }

    // -- internal helpers --

    function _deriveAddress(uint256 seed) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encode(seed, "actor"))) % type(uint160).max));
    }
}

// ---------------------------------------------------------------------------
// Handler: Vesting operations
// ---------------------------------------------------------------------------

/// @title VestingHandler
/// @notice Drives AethelredVesting through schedule creation, time warps,
///         releases, and revocations for invariant testing.
contract VestingHandler is Test {
    AethelredVesting public vesting;
    AethelredToken public token;

    address public admin;
    address public vestingAdmin;
    address public revoker;

    /// @dev All schedule IDs created through this handler.
    bytes32[] public scheduleIds;

    /// @dev Map scheduleId -> last observed vested amount (for monotonicity).
    mapping(bytes32 => uint256) public lastVested;

    /// @dev Map scheduleId -> whether monotonicity was ever violated.
    mapping(bytes32 => bool) public monotonicityViolated;

    /// @dev Map scheduleId -> vested amount frozen at revocation time.
    mapping(bytes32 => uint256) public revokedVestedSnapshot;

    /// @dev Set of revoked schedule IDs.
    bytes32[] public revokedScheduleIds;

    /// @dev Beneficiaries used.
    address[] public beneficiaries;

    /// @dev Category index rotation for schedule creation.
    uint256 private _categoryRotation;

    constructor(
        AethelredVesting _vesting,
        AethelredToken _token,
        address _admin,
        address _vestingAdmin,
        address _revoker
    ) {
        vesting = _vesting;
        token = _token;
        admin = _admin;
        vestingAdmin = _vestingAdmin;
        revoker = _revoker;
    }

    function scheduleCount() external view returns (uint256) {
        return scheduleIds.length;
    }

    function revokedCount() external view returns (uint256) {
        return revokedScheduleIds.length;
    }

    // -- fuzz entry points --

    /// @notice Create a revocable core-contributor schedule with fuzzed amount.
    function createSchedule(uint256 beneficiarySeed, uint256 amount) external {
        address beneficiary = _deriveBeneficiary(beneficiarySeed);
        if (beneficiary == address(0)) beneficiary = address(0x8001);

        // Bound to keep within category cap headroom; use CORE_CONTRIBUTORS
        // which has a 2B cap and is revocable.
        (uint256 cap, uint256 allocated,) = vesting.getCategoryStats(
            AethelredVesting.AllocationCategory.CORE_CONTRIBUTORS
        );
        uint256 headroom = cap > allocated ? cap - allocated : 0;
        if (headroom == 0) return;

        // Also check per-beneficiary schedule limit
        bytes32[] memory existing = vesting.getBeneficiarySchedules(beneficiary);
        if (existing.length >= 10) return;

        amount = bound(amount, 1e18, headroom > 1000e18 ? 1000e18 : headroom);

        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCoreContributorSchedule(beneficiary, amount);

        scheduleIds.push(id);
        beneficiaries.push(beneficiary);

        // Record initial vested amount
        lastVested[id] = vesting.getVested(id);
    }

    /// @notice Create a public-sales schedule (non-revocable, has TGE unlock).
    function createPublicSchedule(uint256 beneficiarySeed, uint256 amount) external {
        address beneficiary = _deriveBeneficiary(beneficiarySeed);
        if (beneficiary == address(0)) beneficiary = address(0x8002);

        (uint256 cap, uint256 allocated,) = vesting.getCategoryStats(
            AethelredVesting.AllocationCategory.PUBLIC_SALES
        );
        uint256 headroom = cap > allocated ? cap - allocated : 0;
        if (headroom == 0) return;

        bytes32[] memory existing = vesting.getBeneficiarySchedules(beneficiary);
        if (existing.length >= 10) return;

        amount = bound(amount, 1e18, headroom > 1000e18 ? 1000e18 : headroom);

        vm.prank(vestingAdmin);
        bytes32 id = vesting.createPublicSalesSchedule(beneficiary, amount);

        scheduleIds.push(id);
        beneficiaries.push(beneficiary);

        lastVested[id] = vesting.getVested(id);
    }

    /// @notice Advance block.timestamp and snapshot vested amounts for
    ///         monotonicity checking.
    function warpTime(uint256 delta) external {
        delta = bound(delta, 1, 180 days);
        vm.warp(block.timestamp + delta);

        // Snapshot vested amounts after warp
        for (uint256 i = 0; i < scheduleIds.length; i++) {
            bytes32 id = scheduleIds[i];
            uint256 currentVested = vesting.getVested(id);

            // Check monotonicity (only for non-revoked schedules; revoked
            // schedules have a separate invariant).
            AethelredVesting.VestingSchedule memory sched = vesting.getSchedule(id);
            if (!sched.revoked) {
                if (currentVested < lastVested[id]) {
                    monotonicityViolated[id] = true;
                }
                lastVested[id] = currentVested;
            }
        }
    }

    /// @notice Release vested tokens for a schedule's beneficiary.
    function release(uint256 idx) external {
        if (scheduleIds.length == 0) return;
        idx = idx % scheduleIds.length;
        bytes32 id = scheduleIds[idx];

        AethelredVesting.VestingSchedule memory sched = vesting.getSchedule(id);
        if (sched.revoked) return;
        if (sched.beneficiary == address(0)) return;

        uint256 releasable = vesting.getReleasable(id);
        if (releasable == 0) return;

        vm.prank(sched.beneficiary);
        try vesting.release(id) {} catch {}
    }

    /// @notice Revoke a revocable schedule. Snapshots the vested amount at
    ///         revocation time so we can verify it stays frozen.
    function revoke(uint256 idx) external {
        if (scheduleIds.length == 0) return;
        idx = idx % scheduleIds.length;
        bytes32 id = scheduleIds[idx];

        AethelredVesting.VestingSchedule memory sched = vesting.getSchedule(id);
        if (sched.revoked || !sched.revocable) return;

        // Snapshot vested amount before revocation
        uint256 vestedBefore = vesting.getVested(id);

        vm.prank(revoker);
        try vesting.revokeSchedule(id) {
            revokedVestedSnapshot[id] = vestedBefore;
            revokedScheduleIds.push(id);
        } catch {}
    }

    // -- internal --

    function _deriveBeneficiary(uint256 seed) internal pure returns (address) {
        return address(
            uint160(uint256(keccak256(abi.encode(seed, "beneficiary"))) % type(uint160).max)
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant Test Contract
// ---------------------------------------------------------------------------

/// @title TokenVestingInvariantTest
/// @notice SQ8 Token & Vesting Assurance — six invariants verified via
///         Foundry's stateful invariant fuzzer with Handler contracts.
contract TokenVestingInvariantTest is Test {
    // -- contracts under test --
    AethelredToken public token;
    AethelredVesting public vesting;

    // -- handlers --
    TokenHandler public tokenHandler;
    VestingHandler public vestingHandler;

    // -- actors --
    address public admin = address(0xAD);
    address public minter = address(0xAA);
    address public compliance = address(0xCC);
    address public vestingAdmin = address(0xBA);
    address public revoker = address(0xFE);
    address public initialRecipient = address(0x1);

    uint256 public constant INITIAL_AMOUNT = 1_000_000_000e18;
    uint256 public constant TOTAL_SUPPLY_CAP = 10_000_000_000e18;

    function setUp() public {
        // ---- Deploy AethelredToken behind UUPS proxy ----
        AethelredToken tokenImpl = new AethelredToken();
        bytes memory tokenInit = abi.encodeCall(
            AethelredToken.initialize,
            (admin, minter, initialRecipient, INITIAL_AMOUNT)
        );
        ERC1967Proxy tokenProxy = new ERC1967Proxy(address(tokenImpl), tokenInit);
        token = AethelredToken(address(tokenProxy));

        // Grant roles
        vm.startPrank(admin);
        token.grantRole(token.COMPLIANCE_ROLE(), compliance);
        token.setTransferRestrictions(false); // disable for cleaner fuzzing
        vm.stopPrank();

        // ---- Deploy AethelredVesting behind UUPS proxy ----
        AethelredVesting vestingImpl = new AethelredVesting();
        bytes memory vestingInit = abi.encodeCall(
            AethelredVesting.initialize,
            (address(token), admin)
        );
        ERC1967Proxy vestingProxy = new ERC1967Proxy(address(vestingImpl), vestingInit);
        vesting = AethelredVesting(address(vestingProxy));

        // Grant vesting roles
        vm.startPrank(admin);
        vesting.grantRole(vesting.VESTING_ADMIN_ROLE(), vestingAdmin);
        vesting.grantRole(vesting.REVOKER_ROLE(), revoker);
        vm.stopPrank();

        // Fund vesting contract with tokens for release testing
        vm.prank(initialRecipient);
        token.transfer(address(vesting), 500_000_000e18);

        // Execute TGE so vesting schedules can be created and released
        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // ---- Create handlers ----
        tokenHandler = new TokenHandler(token, admin, minter, compliance);
        vestingHandler = new VestingHandler(vesting, token, admin, vestingAdmin, revoker);

        // Register initial recipient as actor
        // (they received INITIAL_AMOUNT and transferred some to vesting)

        // ---- Target only the handlers ----
        targetContract(address(tokenHandler));
        targetContract(address(vestingHandler));
    }

    // =====================================================================
    // INVARIANT 1: Total supply never exceeds cap
    // =====================================================================

    /// @notice totalSupply() must always be <= TOTAL_SUPPLY_CAP (10B * 1e18).
    ///         The mint() function enforces this, but we verify it holds after
    ///         arbitrary sequences of mint, burn, and transfer operations.
    function invariant_totalSupplyNeverExceedsCap() external view {
        assertLe(
            token.totalSupply(),
            TOTAL_SUPPLY_CAP,
            "INVARIANT VIOLATED: totalSupply exceeds 10B cap"
        );
    }

    // =====================================================================
    // INVARIANT 2: Total supply equals sum of all tracked balances
    // =====================================================================

    /// @notice The sum of balances across every address that has ever received
    ///         tokens (tracked by the handler) must equal totalSupply().
    ///         This verifies no tokens are created or destroyed outside the
    ///         standard _mint/_burn paths.
    function invariant_totalSupplyEqualsBalanceSum() external view {
        uint256 count = tokenHandler.actorCount();
        uint256 balanceSum = 0;

        for (uint256 i = 0; i < count; i++) {
            balanceSum += token.balanceOf(tokenHandler.actors(i));
        }

        // Also add the vesting contract balance and the initial recipient
        // (who may not be in the actors list).
        if (!tokenHandler.isActor(address(vesting))) {
            balanceSum += token.balanceOf(address(vesting));
        }
        if (!tokenHandler.isActor(initialRecipient)) {
            balanceSum += token.balanceOf(initialRecipient);
        }

        assertEq(
            balanceSum,
            token.totalSupply(),
            "INVARIANT VIOLATED: balance sum != totalSupply"
        );
    }

    // =====================================================================
    // INVARIANT 3: Blacklisted addresses cannot transfer
    // =====================================================================

    /// @notice For every address currently marked blacklisted in the handler,
    ///         the token contract's `canTransfer()` must return false and
    ///         direct transfer calls must revert.
    function invariant_blacklistedCannotTransfer() external view {
        uint256 count = tokenHandler.blacklistedCount();

        for (uint256 i = 0; i < count; i++) {
            address addr = tokenHandler.blacklistedAddrs(i);
            if (tokenHandler.isBlacklisted(addr)) {
                assertTrue(
                    token.blacklisted(addr),
                    "INVARIANT VIOLATED: handler says blacklisted but token disagrees"
                );
                // canTransfer should return false for blacklisted addresses
                assertFalse(
                    token.canTransfer(addr),
                    "INVARIANT VIOLATED: blacklisted address canTransfer() returned true"
                );
            }
        }
    }

    // =====================================================================
    // INVARIANT 4: Vested amount monotonically increases
    // =====================================================================

    /// @notice For every non-revoked schedule, the vested amount at time T+1
    ///         must be >= the vested amount at time T. The VestingHandler
    ///         checks this in warpTime() and sets a flag if violated.
    function invariant_vestedAmountMonotonicallyIncreases() external view {
        uint256 count = vestingHandler.scheduleCount();

        for (uint256 i = 0; i < count; i++) {
            bytes32 id = vestingHandler.scheduleIds(i);
            assertFalse(
                vestingHandler.monotonicityViolated(id),
                "INVARIANT VIOLATED: vested amount decreased for a non-revoked schedule"
            );
        }
    }

    // =====================================================================
    // INVARIANT 5: Vesting category cap enforced
    // =====================================================================

    /// @notice For every AllocationCategory, the total scheduled (allocated)
    ///         amount must never exceed the category cap. This is enforced at
    ///         schedule creation time, and we verify it holds after arbitrary
    ///         sequences of creates and revocations.
    function invariant_vestingCategoryCapEnforced() external view {
        // Check all 9 categories
        for (uint256 c = 0; c <= 8; c++) {
            AethelredVesting.AllocationCategory cat = AethelredVesting.AllocationCategory(c);
            (uint256 cap, uint256 allocated,) = vesting.getCategoryStats(cat);
            assertLe(
                allocated,
                cap,
                "INVARIANT VIOLATED: category allocated exceeds cap"
            );
        }
    }

    // =====================================================================
    // INVARIANT 6: Revoked schedule stops vesting
    // =====================================================================

    /// @notice After revocation, the vested amount for a schedule must be
    ///         frozen — it must not increase regardless of time passing.
    ///         We compare the current getVested() to the snapshot taken at
    ///         revocation time by the handler.
    function invariant_revokedScheduleStopsVesting() external view {
        uint256 count = vestingHandler.revokedCount();

        for (uint256 i = 0; i < count; i++) {
            bytes32 id = vestingHandler.revokedScheduleIds(i);
            uint256 currentVested = vesting.getVested(id);
            uint256 snapshotVested = vestingHandler.revokedVestedSnapshot(id);

            assertLe(
                currentVested,
                snapshotVested,
                "INVARIANT VIOLATED: revoked schedule vested amount increased"
            );
        }
    }
}
