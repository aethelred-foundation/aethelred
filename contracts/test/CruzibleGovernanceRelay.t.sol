// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/vault/Cruzible.sol";
import "../contracts/vault/StAETHEL.sol";
import "../contracts/vault/VaultTEEVerifier.sol";
import "../contracts/vault/PlatformVerifiers.sol";
import "../contracts/vault/ICruzible.sol";
import "../contracts/mocks/MockTimelockController.sol";
import "./helpers/CruzibleCompat.sol";

/**
 * @title MockAETHEL
 * @notice Minimal ERC20 mock for testing.
 */
contract MockAETHELGovernanceRelay {
    string public name = "Aethelred";
    string public symbol = "AETHEL";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

/**
 * @title CruzibleTest
 * @notice Comprehensive test suite for Cruzible liquid staking protocol.
 *
 * Test Categories:
 * 1. Initialization & Setup
 * 2. Staking Operations
 * 3. Unstaking & Withdrawal
 * 4. Validator Management (TEE-verified)
 * 5. Reward Distribution (TEE-verified)
 * 6. MEV Revenue Redistribution
 * 7. Exchange Rate Mechanics
 * 8. TEE Attestation Verification
 * 9. Access Control & Permissions
 * 10. Edge Cases & Security
 * 11. Rate Limiting
 * 12. Batch Operations
 */
contract CruzibleGovernanceRelayTest is Test {
    using CruzibleCompat for Cruzible;

    // =========================================================================
    // STATE
    // =========================================================================

    Cruzible public vaultImpl;
    Cruzible public vault;
    StAETHEL public stAethelImpl;
    StAETHEL public stAethel;
    VaultTEEVerifier public verifierImpl;
    VaultTEEVerifier public verifier;
    MockAETHELGovernanceRelay public aethel;
    SgxVerifier public sgxVerifier;

    address public admin = address(0xAD);
    address public oracle = address(0x0AC1E);
    address public guardian = address(0x6AAD);
    address public treasury = address(0x72EA);
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);
    address public charlie = address(0xC4A);

    // TEE operator key pair (for signing attestations — secp256k1)
    uint256 internal operatorPrivKey = 0xA11CE;
    address internal operatorAddr;

    // P-256 platform key pair for TEE evidence signing
    // Private key = 1 => public key = generator point G
    uint256 internal constant P256_PRIV_KEY = 1;
    uint256 internal constant P256_PUB_X =
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 internal constant P256_PUB_Y =
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;

    // Attestation constants
    bytes32 internal constant ENCLAVE_HASH = keccak256("cruzible-enclave-v1");
    bytes32 internal constant SIGNER_HASH = keccak256("cruzible-signer-v1");

    // Selection policy hash — must be set on-chain before updateValidatorSet.
    // In production, this is SHA-256(SelectionConfig fields). In tests we use a
    // deterministic placeholder; the contract only checks equality.
    bytes32 internal constant TEST_POLICY_HASH = keccak256("test-selection-policy-v1");

    // Eligible-universe hash — placeholder for tests.  In production, this is
    // SHA-256 of sorted eligible validator addresses (null-byte separated),
    // computed by the L1 keeper's computeEligibleUniverseHash().
    bytes32 internal constant TEST_UNIVERSE_HASH = keccak256("test-eligible-universe-v1");

    // Stake snapshot hash — placeholder for tests.  In production, this is
    // domain-separated SHA-256 of sorted staker records, computed by the L1
    // keeper's computeStakeSnapshotHash().
    bytes32 internal constant TEST_SNAPSHOT_HASH = keccak256("test-stake-snapshot-v1");

    // Vendor root P-256 key pair (private key = 2)
    // In production these are Intel/AWS/AMD hardware root keys
    uint256 internal constant VENDOR_ROOT_PRIV = 2;
    uint256 internal constant VENDOR_ROOT_X =
        0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978;
    uint256 internal constant VENDOR_ROOT_Y =
        0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event Staked(
        address indexed user, uint256 aethelAmount, uint256 sharesIssued, uint256 referralCode
    );
    event UnstakeRequested(
        address indexed user,
        uint256 shares,
        uint256 aethelAmount,
        uint256 indexed withdrawalId,
        uint256 completionTime
    );
    event Withdrawn(address indexed user, uint256 indexed withdrawalId, uint256 aethelAmount);
    event RewardsDistributed(
        uint256 indexed epoch,
        uint256 totalRewards,
        uint256 protocolFee,
        bytes32 rewardsMerkleRoot,
        bytes32 teeAttestationHash
    );
    event ValidatorSetUpdated(
        uint256 indexed epoch,
        uint256 validatorCount,
        bytes32 selectionProofHash,
        bytes32 eligibleUniverseHash
    );

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        operatorAddr = vm.addr(operatorPrivKey);

        // Deploy mock AETHEL
        aethel = new MockAETHELGovernanceRelay();

        // Deploy VaultTEEVerifier (implementation + proxy)
        verifierImpl = new VaultTEEVerifier();
        bytes memory verifierInit = abi.encodeCall(VaultTEEVerifier.initialize, (admin));
        ERC1967Proxy verifierProxy = new ERC1967Proxy(address(verifierImpl), verifierInit);
        verifier = VaultTEEVerifier(address(verifierProxy));

        // Deploy StAETHEL (implementation, proxy after vault)
        stAethelImpl = new StAETHEL();

        // Deploy Cruzible implementation
        vaultImpl = new Cruzible();

        // Deploy StAETHEL proxy (needs vault address, so deploy vault first as predicted)
        // We'll use create2-style ordering: deploy vault proxy, then stAethel proxy with vault addr
        // Actually, let's deploy vault proxy with a temporary stAethel, then update

        // Step 1: Deploy vault proxy
        bytes memory vaultInit = abi.encodeCall(
            Cruzible.initialize,
            (admin, address(aethel), address(0xDEAD), address(verifier), treasury)
        );
        // We need the vault address to initialize stAETHEL, and stAETHEL address to init vault.
        // Solution: pre-compute addresses or use two-step setup.

        // Pre-compute vault proxy address
        address predictedVault = _predictProxyAddress(address(vaultImpl), vaultInit);

        // Deploy stAETHEL proxy with predicted vault address
        bytes memory stAethelInit = abi.encodeCall(StAETHEL.initialize, (admin, predictedVault));
        ERC1967Proxy stAethelProxy = new ERC1967Proxy(address(stAethelImpl), stAethelInit);
        stAethel = StAETHEL(address(stAethelProxy));

        // Now deploy vault proxy with correct stAETHEL address
        vaultInit = abi.encodeCall(
            Cruzible.initialize,
            (admin, address(aethel), address(stAethel), address(verifier), treasury)
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInit);
        vault = Cruzible(address(vaultProxy));

        // Grant stAETHEL VAULT_ROLE to the actual vault (update from predicted)
        // Cache the role hash before vm.prank to avoid prank being consumed by the view call
        bytes32 vaultRole = stAethel.VAULT_ROLE();
        vm.prank(admin);
        stAethel.grantRole(vaultRole, address(vault));

        // Setup roles
        vm.startPrank(admin);
        vault.grantRole(vault.ORACLE_ROLE(), oracle);
        vault.grantRole(vault.GUARDIAN_ROLE(), guardian);

        // Set vendor root key for SGX platform FIRST (needed by registerEnclave)
        verifier.setVendorRootKey(0, VENDOR_ROOT_X, VENDOR_ROOT_Y);

        // Generate vendor key attestation: vendor root signs the enclave's platform key
        bytes32 keyAttestMsg = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(0)));
        (bytes32 vendorR, bytes32 vendorS) = vm.signP256(VENDOR_ROOT_PRIV, keyAttestMsg);

        // Register TEE enclave with its per-enclave platform key + vendor attestation
        verifier.registerEnclave(
            ENCLAVE_HASH,
            SIGNER_HASH,
            bytes32(0),
            0,
            "Cruzible SGX Enclave v1",
            P256_PUB_X,
            P256_PUB_Y,
            uint256(vendorR),
            uint256(vendorS)
        );
        bytes32 enclaveId = keccak256(abi.encodePacked(ENCLAVE_HASH, uint8(0)));
        verifier.registerOperator(operatorAddr, enclaveId, "Test TEE Operator");

        // Deploy and register stateless SGX platform verifier (logic-only, no key storage)
        sgxVerifier = new SgxVerifier();
        verifier.setPlatformVerifier(0, address(sgxVerifier));

        // Set the approved selection policy hash for validator set updates.
        // Without this, updateValidatorSet reverts with SelectionPolicyMismatch.
        vault.setSelectionPolicyHash(TEST_POLICY_HASH);

        // Commit the eligible-universe hash (epoch-scoped, immutable).
        // Without this, updateValidatorSet reverts with EligibleUniverseMismatch.
        vault.commitUniverseHash(1, TEST_UNIVERSE_HASH);

        // Commit the stake snapshot hash for reward distribution (epoch-scoped).
        // Without this, distributeRewards reverts with StakeSnapshotMismatch.
        // The third arg anchors the commitment to the on-chain total share supply.
        vault.commitStakeSnapshot(1, TEST_SNAPSHOT_HASH, vault.getTotalShares());
        vm.stopPrank();

        // Fund test users
        aethel.mint(alice, 1_000_000 ether);
        aethel.mint(bob, 1_000_000 ether);
        aethel.mint(charlie, 1_000_000 ether);
        // Approve vault
        vm.prank(alice);
        aethel.approve(address(vault), type(uint256).max);
        vm.prank(bob);
        aethel.approve(address(vault), type(uint256).max);
        vm.prank(charlie);
        aethel.approve(address(vault), type(uint256).max);

        // Deposit keeper bond for admin (who has KEEPER_ROLE) so
        // commitDelegationSnapshot succeeds.
        _depositKeeperBond(admin);
    }

    /// @notice Deposit the minimum keeper bond for the given address.
    function _depositKeeperBond(address keeper) internal {
        uint256 bondAmount = vault.KEEPER_BOND_MINIMUM();
        aethel.mint(keeper, bondAmount);
        vm.startPrank(keeper);
        aethel.approve(address(vault), bondAmount);
        vault.depositKeeperBond(bondAmount);
        vm.stopPrank();
    }

    /// @notice Helper to pre-compute proxy address (simplified for tests).
    function _predictProxyAddress(address, bytes memory) internal pure returns (address) {
        // In tests, we use a two-step approach instead of prediction.
        // The stAETHEL VAULT_ROLE is granted after vault deployment.
        return address(0xDEAD);
    }

    // =========================================================================
    // 1. INITIALIZATION TESTS
    // =========================================================================


    function _createAttestation(bytes memory payload) internal view returns (bytes memory) {
        uint8 platformId = 0; // SGX
        uint256 timestamp = block.timestamp;
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, block.number, payload));

        // Build tagged SHA-256 digest (matches Go native verifier & Rust TEE producer)
        bytes32 payloadHash = sha256(payload);
        bytes32 digest = sha256(
            abi.encodePacked(
                "CruzibleTEEAttestation",
                platformId,
                uint64(timestamp),
                nonce,
                ENCLAVE_HASH,
                SIGNER_HASH,
                payloadHash
            )
        );

        // Generate mock raw hardware report hash (per-attestation binding to fresh hardware report)
        // In production: SHA-256 of actual SGX DCAP quote / Nitro document / SEV report
        bytes32 rawReportHash =
            sha256(abi.encodePacked("MOCK_HW_REPORT_V1", ENCLAVE_HASH, SIGNER_HASH, digest));

        // Compute binding hash: ties the raw hardware report to these specific measurements.
        // Both Rust TEE and on-chain verifiers compute this independently.
        bytes32 bindingHash = sha256(abi.encodePacked(rawReportHash, ENCLAVE_HASH, SIGNER_HASH));

        // Build report body and sign with P-256 platform key (uses bindingHash for measurement binding)
        bytes32 reportHash = sha256(
            abi.encodePacked(ENCLAVE_HASH, SIGNER_HASH, digest, uint16(1), uint16(1), bindingHash)
        );
        (bytes32 p256r, bytes32 p256s) = vm.signP256(P256_PRIV_KEY, reportHash);

        // Generate SGX platform evidence bound to this attestation
        // Evidence stores rawReportHash; verifier computes bindingHash independently
        bytes memory evidence = abi.encode(
            ENCLAVE_HASH, // mrenclave (from hardware report)
            SIGNER_HASH, // mrsigner (from hardware report)
            digest, // reportData = attestation digest (data binding)
            uint16(1), // isvProdId
            uint16(1), // isvSvn
            rawReportHash, // SHA-256 commitment to fresh hardware attestation report
            uint256(p256r), // P-256 signature r
            uint256(p256s) // P-256 signature s
        );

        // Sign with operator private key (secp256k1)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        return abi.encode(
            platformId, timestamp, nonce, ENCLAVE_HASH, SIGNER_HASH, payload, evidence, signature
        );
    }

    /// @notice Build a valid TEE attestation for commitDelegationSnapshot().
    /// The payload is 96 bytes: abi.encode(epoch, delegationRoot, stakerRegistryRoot).
    function _createDelegationAttestation(
        uint256 epoch,
        bytes32 delegationRoot,
        bytes32 stakerRegistryRoot
    )
        internal
        view
        returns (bytes memory)
    {
        bytes memory payload = abi.encode(epoch, delegationRoot, stakerRegistryRoot);
        return _createAttestation(payload);
    }


    function test_guardianRevoke_freezesQuorumAttestors() public {
        address attestor1 = makeAddr("freezeAttestor1");
        address attestor2 = makeAddr("freezeAttestor2");
        bytes32 attestorRole = vault.DELEGATION_ATTESTOR_ROLE();

        // Grant attestor role and deposit keeper bonds for both attestors.
        vm.startPrank(admin);
        vault.grantRole(attestorRole, attestor1);
        vault.grantRole(attestorRole, attestor2);
        vm.stopPrank();
        _depositKeeperBond(attestor1);
        _depositKeeperBond(attestor2);

        // Enable quorum mode (attestor quorum instead of single-keeper).
        vm.prank(admin);
        vault.setDelegationQuorumEnabled(true);

        // Both attestors vote for the same root — reaching quorum and auto-committing.
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("quorum-freeze-root");
        bytes memory delAtt1 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor1);
        vault.submitDelegationVote(delAtt1, 1, delRoot, snapPre.stakerRegistryRoot, 5);

        vm.warp(block.timestamp + 1);
        bytes memory delAtt2 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor2);
        vault.submitDelegationVote(delAtt2, 1, delRoot, snapPre.stakerRegistryRoot, 5);

        // Confirm root was committed via quorum.
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, delRoot);

        // Verify getDelegationEpochAttestors returns both attestors.
        address[] memory attestors = vault.getDelegationEpochAttestors(1);
        assertEq(attestors.length, 2);

        // Neither should be frozen before guardian action.
        assertFalse(vault.keeperBondFrozen(attestor1));
        assertFalse(vault.keeperBondFrozen(attestor2));

        // Guardian revokes the fraudulent delegation snapshot — should freeze both attestors.
        vm.prank(admin);
        vault.revokeDelegationSnapshot(1);

        // Both attestors' bonds must be frozen.
        assertTrue(vault.keeperBondFrozen(attestor1), "attestor1 bond not frozen after revocation");
        assertTrue(vault.keeperBondFrozen(attestor2), "attestor2 bond not frozen after revocation");

        // Neither can withdraw while frozen.
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(attestor1);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondIsFrozen.selector, attestor1));
        vault.withdrawKeeperBond(bondMinimum);

        vm.prank(attestor2);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondIsFrozen.selector, attestor2));
        vault.withdrawKeeperBond(bondMinimum);

        // Slash attestor1 — clears freeze, allows withdrawal of remainder.
        uint256 slashAmount = bondMinimum / 2;
        vm.prank(admin);
        vault.slashKeeperBond(attestor1, slashAmount, treasury);
        assertFalse(vault.keeperBondFrozen(attestor1));

        vm.prank(attestor1);
        vault.withdrawKeeperBond(bondMinimum - slashAmount);
        assertEq(vault.keeperBonds(attestor1), 0);

        // Release attestor2 without slashing — guardian decides not to slash.
        vm.prank(admin);
        vault.releaseKeeperBondFreeze(attestor2);
        assertFalse(vault.keeperBondFrozen(attestor2));

        vm.prank(attestor2);
        vault.withdrawKeeperBond(bondMinimum);
        assertEq(vault.keeperBonds(attestor2), 0);
    }

    /// @notice confirmDelegationFraud also freezes quorum attestors after auto-revoke.
    function test_confirmDelegationFraud_freezesQuorumAttestors() public {
        address attestor1 = makeAddr("fraudFreezeA1");
        address attestor2 = makeAddr("fraudFreezeA2");
        bytes32 attestorRole = vault.DELEGATION_ATTESTOR_ROLE();

        vm.startPrank(admin);
        vault.grantRole(attestorRole, attestor1);
        vault.grantRole(attestorRole, attestor2);
        vm.stopPrank();
        _depositKeeperBond(attestor1);
        _depositKeeperBond(attestor2);

        vm.prank(admin);
        vault.setDelegationQuorumEnabled(true);

        // Quorum commit via two attestors.
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("fraud-quorum-root");
        bytes memory delAtt1 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor1);
        vault.submitDelegationVote(delAtt1, 1, delRoot, snapPre.stakerRegistryRoot, 3);

        vm.warp(block.timestamp + 1);
        bytes memory delAtt2 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor2);
        vault.submitDelegationVote(delAtt2, 1, delRoot, snapPre.stakerRegistryRoot, 3);

        // Trigger auto-revoke via three challengers.
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Auto-revoked but not yet fraud-confirmed — attestors not frozen.
        assertFalse(vault.keeperBondFrozen(attestor1));
        assertFalse(vault.keeperBondFrozen(attestor2));

        // Guardian confirms fraud — should freeze both quorum attestors.
        vm.prank(admin);
        vault.confirmDelegationFraud(1);

        assertTrue(
            vault.keeperBondFrozen(attestor1), "attestor1 not frozen after fraud confirmation"
        );
        assertTrue(
            vault.keeperBondFrozen(attestor2), "attestor2 not frozen after fraud confirmation"
        );

        // Neither can withdraw.
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(attestor1);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondIsFrozen.selector, attestor1));
        vault.withdrawKeeperBond(bondMinimum);

        vm.prank(attestor2);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondIsFrozen.selector, attestor2));
        vault.withdrawKeeperBond(bondMinimum);
    }

    /// @notice Keeper bond remains locked during adjudication period after auto-revoke.
    function test_withdrawKeeperBond_lockedDuringAdjudication() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("adjudication-lock-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Trigger auto-revoke
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Root is zero (auto-revoked) but adjudication is pending
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, bytes32(0));
        assertTrue(vault.delegationAutoRevokedAt(1) > 0);

        // Keeper bond should still be locked during adjudication
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondLocked.selector));
        vault.withdrawKeeperBond(bondMinimum);

        // Fast-forward past adjudication period — bond unlocks
        vm.warp(block.timestamp + vault.CHALLENGE_ADJUDICATION_PERIOD() + 1);

        vm.prank(admin);
        vault.withdrawKeeperBond(bondMinimum);
        assertEq(vault.keeperBonds(admin), 0);
    }

    /// @notice commitDelegationSnapshot requires keeper bond.
    function test_commitDelegationSnapshot_requiresBond() public {
        // Create a new keeper with KEEPER_ROLE but no bond
        address unbondedKeeper = makeAddr("unbonded-keeper");
        bytes32 keeperRole = vault.KEEPER_ROLE();
        vm.prank(admin);
        vault.grantRole(keeperRole, unbondedKeeper);

        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("bond-required");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(unbondedKeeper);
        vm.expectRevert(
            abi.encodeWithSelector(
                Cruzible.InsufficientKeeperBond.selector, uint256(0), bondMinimum
            )
        );
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);
    }

    /// @notice Guardian can slash a keeper's bond.
    function test_slashKeeperBond() public {
        address keeper = makeAddr("slashable-keeper");
        uint256 bondAmount = vault.KEEPER_BOND_MINIMUM();
        aethel.mint(keeper, bondAmount);
        vm.startPrank(keeper);
        aethel.approve(address(vault), bondAmount);
        vault.depositKeeperBond(bondAmount);
        vm.stopPrank();

        uint256 slashAmount = 50_000 ether;
        uint256 treasuryBefore = aethel.balanceOf(treasury);

        vm.prank(admin); // admin has GUARDIAN_ROLE granted in setUp
        vault.slashKeeperBond(keeper, slashAmount, treasury);

        assertEq(vault.keeperBonds(keeper), bondAmount - slashAmount);
        assertEq(aethel.balanceOf(treasury), treasuryBefore + slashAmount);
    }

    /// @notice Only guardian can slash keeper bonds.
    function test_slashKeeperBond_onlyGuardian() public {
        vm.prank(alice);
        vm.expectRevert();
        vault.slashKeeperBond(admin, 1 ether, treasury);
    }

    // --- Permissionless challenge ---

    /// @notice Anyone can challenge a delegation commitment during the challenge period (with bond).
    function test_challengeDelegationCommitment() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("challenge-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 aliceBefore = aethel.balanceOf(alice);
        uint256 challengeBond = vault.CHALLENGE_BOND();

        // Alice challenges (bond is transferred)
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        assertEq(vault.delegationChallengeCount(1), 1);
        assertTrue(vault.delegationChallengers(1, alice));
        assertEq(vault.challengerBonds(1, alice), challengeBond);
        assertEq(aethel.balanceOf(alice), aliceBefore - challengeBond);

        // Root is still committed (threshold not reached).
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, delRoot);
    }

    /// @notice Challenge auto-revokes when threshold is reached; bonds are NOT auto-refunded.
    function test_challengeDelegationCommitment_autoRevokes() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("auto-revoke-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 challengeBond = vault.CHALLENGE_BOND();

        // Three independent bonded challengers (meets DELEGATION_CHALLENGE_THRESHOLD = 3)
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Root is auto-revoked (circuit-breaker).
        assertEq(vault.delegationChallengeCount(1), 3);
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, bytes32(0));
        assertEq(vault.delegationCommitTimestamp(1), 0);
        assertEq(vault.delegatingStakerCount(1), 0);

        // Auto-revocation does NOT confirm fraud — bonds are held pending adjudication.
        assertFalse(vault.delegationChallengeSucceeded(1));
        assertTrue(vault.delegationAutoRevokedAt(1) > 0);
        assertEq(vault.totalChallengerBonds(), challengeBond * 3);
    }

    /// @notice Cannot challenge the same epoch twice from the same address.
    function test_challengeDelegationCommitment_rejectsDoubleChallenge() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("double-challenge");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        vm.prank(alice);
        vault.challengeDelegationCommitment(1);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.AlreadyChallenged.selector, uint256(1), alice)
        );
        vault.challengeDelegationCommitment(1);
    }

    /// @notice Cannot challenge after the challenge period expires.
    function test_challengeDelegationCommitment_rejectsAfterPeriod() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("late-challenge");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Fast-forward past challenge period
        vm.warp(block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD() + 1);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ChallengeOutsidePeriod.selector, uint256(1))
        );
        vault.challengeDelegationCommitment(1);
    }

    /// @notice Cannot challenge when no delegation is committed.
    function test_challengeDelegationCommitment_rejectsWhenNotCommitted() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.DelegationNotCommitted.selector, uint256(1))
        );
        vault.challengeDelegationCommitment(1);
    }

    // --- Challenger bond lifecycle ---

    /// @notice Guardian direct revocation confirms fraud — bonds refundable immediately.
    function test_claimChallengerBond_refundOnGuardianRevocation() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("refund-test");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 challengeBond = vault.CHALLENGE_BOND();
        uint256 aliceBefore = aethel.balanceOf(alice);

        // Alice challenges
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        assertEq(aethel.balanceOf(alice), aliceBefore - challengeBond);

        // Guardian revokes directly (explicit fraud confirmation)
        vm.prank(admin);
        vault.revokeDelegationSnapshot(1);
        assertTrue(vault.delegationChallengeSucceeded(1));

        // Alice claims refund
        vm.prank(alice);
        vault.claimChallengerBond(1);
        assertEq(aethel.balanceOf(alice), aliceBefore);
        assertEq(vault.challengerBonds(1, alice), 0);
        assertEq(vault.totalChallengerBonds(), 0);
    }

    /// @notice Challenger bonds are slashed when commitment survives (no revocation).
    function test_claimChallengerBond_slashOnSurvival() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("slash-test");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 challengeBond = vault.CHALLENGE_BOND();
        uint256 aliceBefore = aethel.balanceOf(alice);
        uint256 treasuryBefore = aethel.balanceOf(treasury);

        // Alice challenges (incorrectly — the commitment is valid)
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);

        // Fast-forward past challenge period (commitment survives)
        vm.warp(block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD() + 1);

        // Alice claims — bond is slashed to treasury
        vm.prank(alice);
        vault.claimChallengerBond(1);
        assertEq(aethel.balanceOf(alice), aliceBefore - challengeBond);
        assertEq(aethel.balanceOf(treasury), treasuryBefore + challengeBond);
        assertEq(vault.challengerBonds(1, alice), 0);
    }

    /// @notice Auto-revocation WITHOUT guardian confirmation → bonds slashed after adjudication.
    function test_claimChallengerBond_slashOnAutoRevokeWithoutConfirmation() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("auto-revoke-slash");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 challengeBond = vault.CHALLENGE_BOND();
        uint256 aliceBefore = aethel.balanceOf(alice);
        uint256 treasuryBefore = aethel.balanceOf(treasury);

        // Three challengers trigger auto-revoke (griefing a valid commitment)
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Auto-revoked but NOT confirmed as fraud
        assertFalse(vault.delegationChallengeSucceeded(1));
        assertTrue(vault.delegationAutoRevokedAt(1) > 0);

        // Cannot claim during adjudication period
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ChallengeClaimTooEarly.selector, uint256(1))
        );
        vault.claimChallengerBond(1);

        // Fast-forward past adjudication period — guardian did NOT confirm
        vm.warp(block.timestamp + vault.CHALLENGE_ADJUDICATION_PERIOD() + 1);

        // All three bonds are slashed to treasury (griefing was punished)
        vm.prank(alice);
        vault.claimChallengerBond(1);
        vm.prank(bob);
        vault.claimChallengerBond(1);
        vm.prank(charlie);
        vault.claimChallengerBond(1);

        assertEq(aethel.balanceOf(alice), aliceBefore - challengeBond);
        assertEq(aethel.balanceOf(treasury), treasuryBefore + challengeBond * 3);
        assertEq(vault.totalChallengerBonds(), 0);
    }

    /// @notice Auto-revocation WITH guardian confirmation → bonds refunded.
    function test_claimChallengerBond_refundOnAutoRevokeWithConfirmation() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("auto-revoke-confirm");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 challengeBond = vault.CHALLENGE_BOND();
        uint256 aliceBefore = aethel.balanceOf(alice);
        uint256 bobBefore = aethel.balanceOf(bob);
        uint256 charlieBefore = aethel.balanceOf(charlie);

        // Three challengers trigger auto-revoke
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        assertFalse(vault.delegationChallengeSucceeded(1));

        // Guardian confirms fraud within adjudication period
        vm.prank(admin);
        vault.confirmDelegationFraud(1);
        assertTrue(vault.delegationChallengeSucceeded(1));

        // All three claim refunds
        vm.prank(alice);
        vault.claimChallengerBond(1);
        vm.prank(bob);
        vault.claimChallengerBond(1);
        vm.prank(charlie);
        vault.claimChallengerBond(1);

        assertEq(aethel.balanceOf(alice), aliceBefore);
        assertEq(aethel.balanceOf(bob), bobBefore);
        assertEq(aethel.balanceOf(charlie), charlieBefore);
        assertEq(vault.totalChallengerBonds(), 0);
    }

    /// @notice confirmDelegationFraud rejects if not auto-revoked.
    function test_confirmDelegationFraud_rejectsIfNotAutoRevoked() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.NotAutoRevoked.selector, uint256(1)));
        vault.confirmDelegationFraud(1);
    }

    /// @notice confirmDelegationFraud rejects after adjudication period expires.
    function test_confirmDelegationFraud_rejectsAfterAdjudicationExpires() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("adjudication-expired");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Trigger auto-revoke
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Fast-forward past adjudication period
        vm.warp(block.timestamp + vault.CHALLENGE_ADJUDICATION_PERIOD() + 1);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.AdjudicationPeriodExpired.selector, uint256(1))
        );
        vault.confirmDelegationFraud(1);
    }

    /// @notice Only guardian can call confirmDelegationFraud.
    function test_confirmDelegationFraud_onlyGuardian() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("only-guardian");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Trigger auto-revoke
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Non-guardian cannot confirm
        vm.prank(alice);
        vm.expectRevert();
        vault.confirmDelegationFraud(1);
    }

    /// @notice Cannot claim challenger bond before outcome is known (challenge period active).
    function test_claimChallengerBond_rejectsTooEarly() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("too-early");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        vm.prank(alice);
        vault.challengeDelegationCommitment(1);

        // Try to claim while challenge period is still active
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ChallengeClaimTooEarly.selector, uint256(1))
        );
        vault.claimChallengerBond(1);
    }

    /// @notice Cannot claim bond if none was deposited.
    function test_claimChallengerBond_rejectsNoBond() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.NoChallengerBond.selector, uint256(1), alice)
        );
        vault.claimChallengerBond(1);
    }

    /// @notice Cannot double-claim a challenger bond.
    function test_claimChallengerBond_rejectsDoubleClaim() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("double-claim");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        vm.prank(alice);
        vault.challengeDelegationCommitment(1);

        // Guardian revokes (confirms fraud)
        vm.prank(admin);
        vault.revokeDelegationSnapshot(1);

        // First claim succeeds
        vm.prank(alice);
        vault.claimChallengerBond(1);

        // Second claim fails
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.NoChallengerBond.selector, uint256(1), alice)
        );
        vault.claimChallengerBond(1);
    }

    /// @notice Cannot claim during adjudication period after auto-revoke.
    function test_claimChallengerBond_rejectsDuringAdjudication() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("adjudication-pending");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Trigger auto-revoke
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Try to claim during adjudication period (before guardian decides)
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ChallengeClaimTooEarly.selector, uint256(1))
        );
        vault.claimChallengerBond(1);
    }

    // --- Governance ---

    /// @notice Only admin can toggle quorum mode.
    function test_setDelegationQuorumEnabled_onlyAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        vault.setDelegationQuorumEnabled(true);
    }

    /// @notice Admin can toggle quorum mode.
    function test_setDelegationQuorumEnabled() public {
        assertFalse(vault.delegationQuorumEnabled());
        vm.prank(admin);
        vault.setDelegationQuorumEnabled(true);
        assertTrue(vault.delegationQuorumEnabled());
    }

    // =========================================================================
    // ATTESTATION RELAY GOVERNANCE TESTS
    //
    // These tests exercise the relay registration, time-locked key rotation,
    // liveness challenges, and emergency revocation controls added to
    // VaultTEEVerifier.sol to close the P2 relay-rooted trust gap.
    // =========================================================================

    // Relay test key (P-256 private key = 3, public key = 3*G)
    uint256 internal constant RELAY_PRIV = 3;
    uint256 internal constant RELAY_PUB_X =
        0x5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C;
    uint256 internal constant RELAY_PUB_Y =
        0x8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032;

    // Rotated relay key (P-256 private key = 4, public key = 4*G)
    uint256 internal constant ROTATED_RELAY_PRIV = 4;
    uint256 internal constant ROTATED_RELAY_X =
        0xE2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852;
    uint256 internal constant ROTATED_RELAY_Y =
        0xE0F1575A4C633CC719DFEE5FDA862D764EFC96C3F30EE0055C42C23F184ED8C6;

    /// @notice Register an attestation relay and verify state.
    function test_registerAttestationRelay() public {
        vm.startPrank(admin);

        // Register relay for Nitro (platform 1) — SGX already has vendor root set in setUp
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Aethelred Nitro Relay v1");

        // Verify relay is active
        assertTrue(verifier.isRelayActive(1));

        // Verify relay state
        (
            uint256 pubX,
            uint256 pubY,
            uint256 registeredAt,
            uint256 lastRotated,
            uint256 attestCount,
            bool active,
            uint256 pendingX,
            uint256 pendingY,
            uint256 rotationUnlocks,
            bytes32 challenge,
            uint256 challengeDeadline,
            string memory desc
        ) = verifier.attestationRelays(1);
        assertEq(pubX, RELAY_PUB_X);
        assertEq(pubY, RELAY_PUB_Y);
        assertGt(registeredAt, 0);
        assertEq(lastRotated, registeredAt);
        assertEq(attestCount, 0);
        assertTrue(active);
        assertEq(pendingX, 0);
        assertEq(pendingY, 0);
        assertEq(rotationUnlocks, 0);
        assertEq(challenge, bytes32(0));
        assertEq(challengeDeadline, 0);
        assertEq(desc, "Aethelred Nitro Relay v1");

        // Vendor root key should also be set for backward compatibility
        assertEq(verifier.vendorRootKeyX(1), RELAY_PUB_X);
        assertEq(verifier.vendorRootKeyY(1), RELAY_PUB_Y);

        vm.stopPrank();
    }

    /// @notice Duplicate relay registration reverts.
    function test_registerAttestationRelay_duplicateReverts() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        vm.expectRevert(
            abi.encodeWithSelector(VaultTEEVerifier.RelayAlreadyRegistered.selector, uint8(1))
        );
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v2");
        vm.stopPrank();
    }

    /// @notice Full relay key rotation lifecycle: initiate → wait → finalize.
    function test_relayRotation_fullLifecycle() public {
        vm.startPrank(admin);

        // Register relay
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        // Initiate rotation
        verifier.initiateRelayRotation(1, ROTATED_RELAY_X, ROTATED_RELAY_Y);

        // Verify pending state
        (bool pending, uint256 unlocksAt) = verifier.hasPendingRotation(1);
        assertTrue(pending);
        assertGt(unlocksAt, block.timestamp);

        // Finalize before timelock must revert
        vm.expectRevert(
            abi.encodeWithSelector(
                VaultTEEVerifier.RotationTimelockActive.selector, uint8(1), unlocksAt
            )
        );
        verifier.finalizeRelayRotation(1);

        // Advance past 48 hours
        vm.warp(block.timestamp + 48 hours + 1);

        // Finalize should succeed
        verifier.finalizeRelayRotation(1);

        // Verify new key is active
        (uint256 newX, uint256 newY,,,,,,,,,,) = verifier.attestationRelays(1);
        assertEq(newX, ROTATED_RELAY_X);
        assertEq(newY, ROTATED_RELAY_Y);

        // Pending should be cleared
        (pending,) = verifier.hasPendingRotation(1);
        assertFalse(pending);

        // Vendor root key should be updated too
        assertEq(verifier.vendorRootKeyX(1), ROTATED_RELAY_X);
        assertEq(verifier.vendorRootKeyY(1), ROTATED_RELAY_Y);

        vm.stopPrank();
    }

    /// @notice Cancel a pending relay key rotation.
    function test_relayRotation_cancel() public {
        vm.startPrank(admin);

        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        verifier.initiateRelayRotation(1, ROTATED_RELAY_X, ROTATED_RELAY_Y);

        // Cancel
        verifier.cancelRelayRotation(1);

        // Pending should be cleared
        (bool pending,) = verifier.hasPendingRotation(1);
        assertFalse(pending);

        // Original key should be unchanged
        (uint256 x, uint256 y,,,,,,,,,,) = verifier.attestationRelays(1);
        assertEq(x, RELAY_PUB_X);
        assertEq(y, RELAY_PUB_Y);

        // Cancel with nothing pending should revert
        vm.expectRevert(
            abi.encodeWithSelector(VaultTEEVerifier.NoRotationPending.selector, uint8(1))
        );
        verifier.cancelRelayRotation(1);

        vm.stopPrank();
    }

    /// @notice Emergency relay revocation clears all state.
    function test_revokeRelay() public {
        vm.startPrank(admin);

        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        assertTrue(verifier.isRelayActive(1));

        // Revoke
        verifier.revokeRelay(1);
        assertFalse(verifier.isRelayActive(1));

        // Vendor root key should be cleared
        assertEq(verifier.vendorRootKeyX(1), 0);
        assertEq(verifier.vendorRootKeyY(1), 0);

        vm.stopPrank();
    }

    /// @notice Revoking unregistered relay reverts.
    function test_revokeRelay_unregisteredReverts() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(VaultTEEVerifier.RelayNotRegistered.selector, uint8(2))
        );
        verifier.revokeRelay(2);
    }

    /// @notice Relay liveness challenge with valid P-256 response.
    function test_relayChallenge_successfulResponse() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        // Issue challenge
        bytes32 challenge = keccak256("governance-challenge-1");
        verifier.challengeRelay(1, challenge);

        // Verify challenge is pending
        assertTrue(verifier.hasUnexpiredChallenge(1));
        vm.stopPrank();

        // Respond with valid P-256 signature (anyone can submit)
        bytes32 challengeHash = sha256(abi.encodePacked(challenge));
        (bytes32 sigR, bytes32 sigS) = vm.signP256(RELAY_PRIV, challengeHash);

        verifier.respondRelayChallenge(1, uint256(sigR), uint256(sigS));

        // Challenge should be cleared
        assertFalse(verifier.hasUnexpiredChallenge(1));
    }

    /// @notice Relay challenge response with wrong key reverts.
    function test_relayChallenge_wrongKeyReverts() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        bytes32 challenge = keccak256("governance-challenge-2");
        verifier.challengeRelay(1, challenge);
        vm.stopPrank();

        // Sign with wrong key (vendor root, not relay)
        bytes32 challengeHash = sha256(abi.encodePacked(challenge));
        (bytes32 sigR, bytes32 sigS) = vm.signP256(VENDOR_ROOT_PRIV, challengeHash);

        vm.expectRevert(
            abi.encodeWithSelector(VaultTEEVerifier.ChallengeResponseInvalid.selector, uint8(1))
        );
        verifier.respondRelayChallenge(1, uint256(sigR), uint256(sigS));
    }

    /// @notice Relay challenge response after deadline reverts.
    function test_relayChallenge_expiredReverts() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        bytes32 challenge = keccak256("governance-challenge-3");
        verifier.challengeRelay(1, challenge);
        vm.stopPrank();

        // Advance past the 1-hour window
        vm.warp(block.timestamp + 1 hours + 1);

        bytes32 challengeHash = sha256(abi.encodePacked(challenge));
        (bytes32 sigR, bytes32 sigS) = vm.signP256(RELAY_PRIV, challengeHash);

        vm.expectRevert(
            abi.encodeWithSelector(VaultTEEVerifier.ChallengeExpired.selector, uint8(1))
        );
        verifier.respondRelayChallenge(1, uint256(sigR), uint256(sigS));
    }

    /// @notice Responding without a pending challenge reverts.
    function test_relayChallenge_noPendingReverts() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        vm.stopPrank();

        vm.expectRevert(
            abi.encodeWithSelector(VaultTEEVerifier.NoPendingChallenge.selector, uint8(1))
        );
        verifier.respondRelayChallenge(1, 1, 1);
    }

    /// @notice Registering enclaves increments relay attestation count.
    function test_relayAttestationCount_incrementsOnEnclaveRegister() public {
        vm.startPrank(admin);

        // Register relay for SGX (platform 0) — requires clearing existing vendor root first
        // We'll use Nitro (platform 1) to avoid conflicting with setUp's SGX config
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Nitro Relay");

        // Initial count should be 0
        (,,,, uint256 countBefore,,,,,,,) = verifier.attestationRelays(1);
        assertEq(countBefore, 0);

        // Register an enclave on the Nitro platform using relay as the vendor root
        bytes32 nitroEncHash = keccak256("nitro-enclave-v1");
        bytes32 nitroSignerHash = keccak256("nitro-signer-v1");

        // Sign platform key attestation with relay private key
        bytes32 keyAttestMsg = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(1)));
        (bytes32 attestR, bytes32 attestS) = vm.signP256(RELAY_PRIV, keyAttestMsg);

        verifier.registerEnclave(
            nitroEncHash,
            nitroSignerHash,
            keccak256("nitro-app-v1"),
            1,
            "Nitro Enclave v1",
            P256_PUB_X,
            P256_PUB_Y,
            uint256(attestR),
            uint256(attestS)
        );

        // Count should now be 1
        (,,,, uint256 countAfter,,,,,,,) = verifier.attestationRelays(1);
        assertEq(countAfter, 1);

        vm.stopPrank();
    }

    /// @notice Operations on a revoked relay revert appropriately.
    function test_revokedRelay_operationsRevert() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        verifier.revokeRelay(1);

        // Rotation on revoked relay should revert
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.RelayNotActive.selector, uint8(1)));
        verifier.initiateRelayRotation(1, ROTATED_RELAY_X, ROTATED_RELAY_Y);

        // Challenge on revoked relay should revert
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.RelayNotActive.selector, uint8(1)));
        verifier.challengeRelay(1, keccak256("challenge"));

        vm.stopPrank();
    }

    /// @notice Non-admin cannot register relay.
    function test_registerAttestationRelay_nonAdminReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Unauthorized");
    }

    /// @notice setVendorRootKey reverts while an active relay exists.
    function test_setVendorRootKey_blockedWhileRelayActive() public {
        vm.startPrank(admin);

        // Register relay for Nitro (platform 1)
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        // Direct override must revert
        vm.expectRevert(
            abi.encodeWithSelector(
                VaultTEEVerifier.DirectOverrideWhileRelayActive.selector, uint8(1)
            )
        );
        verifier.setVendorRootKey(1, VENDOR_ROOT_X, VENDOR_ROOT_Y);

        // Vendor root key should still be the relay key
        assertEq(verifier.vendorRootKeyX(1), RELAY_PUB_X);
        assertEq(verifier.vendorRootKeyY(1), RELAY_PUB_Y);

        vm.stopPrank();
    }

    /// @notice setVendorRootKey works again after relay revocation.
    function test_setVendorRootKey_allowedAfterRelayRevocation() public {
        vm.startPrank(admin);

        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        verifier.revokeRelay(1);

        // Direct set should work after relay is revoked
        verifier.setVendorRootKey(1, VENDOR_ROOT_X, VENDOR_ROOT_Y);
        assertEq(verifier.vendorRootKeyX(1), VENDOR_ROOT_X);
        assertEq(verifier.vendorRootKeyY(1), VENDOR_ROOT_Y);

        vm.stopPrank();
    }

    /// @notice setVendorRootKey works on platforms with no relay registered.
    function test_setVendorRootKey_allowedWithoutRelay() public {
        vm.startPrank(admin);

        // Platform 2 (SEV) has no relay — direct set should work
        verifier.setVendorRootKey(2, VENDOR_ROOT_X, VENDOR_ROOT_Y);
        assertEq(verifier.vendorRootKeyX(2), VENDOR_ROOT_X);

        vm.stopPrank();
    }

    /// @notice Relay rotation still works despite the direct override guard.
    function test_relayRotation_notBlockedByGuard() public {
        vm.startPrank(admin);

        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        // Rotation should work — relay methods bypass the guard
        verifier.initiateRelayRotation(1, ROTATED_RELAY_X, ROTATED_RELAY_Y);
        vm.warp(block.timestamp + 48 hours + 1);
        verifier.finalizeRelayRotation(1);

        // Key should be the rotated key
        assertEq(verifier.vendorRootKeyX(1), ROTATED_RELAY_X);
        assertEq(verifier.vendorRootKeyY(1), ROTATED_RELAY_Y);

        vm.stopPrank();
    }

    /// @notice A revoked relay can be replaced with a fresh registration.
    function test_registerAttestationRelay_afterRevocation() public {
        vm.startPrank(admin);

        // Register and revoke relay v1
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        verifier.revokeRelay(1);
        assertFalse(verifier.isRelayActive(1));

        // Register a replacement relay v2 with a different key
        verifier.registerAttestationRelay(1, ROTATED_RELAY_X, ROTATED_RELAY_Y, "Relay v2");

        // Verify replacement relay is active with fresh state
        assertTrue(verifier.isRelayActive(1));
        (
            uint256 pubX,
            uint256 pubY,
            uint256 registeredAt,,
            uint256 attestCount,
            bool active,
            uint256 pendingX,
            uint256 pendingY,
            uint256 rotationUnlocks,
            bytes32 challenge,
            uint256 challengeDeadline,
            string memory desc
        ) = verifier.attestationRelays(1);
        assertEq(pubX, ROTATED_RELAY_X);
        assertEq(pubY, ROTATED_RELAY_Y);
        assertGt(registeredAt, 0);
        assertEq(attestCount, 0, "attestation count must reset on re-registration");
        assertTrue(active);
        assertEq(pendingX, 0, "stale pending rotation must be cleared");
        assertEq(pendingY, 0);
        assertEq(rotationUnlocks, 0);
        assertEq(challenge, bytes32(0), "stale challenge must be cleared");
        assertEq(challengeDeadline, 0);
        assertEq(desc, "Relay v2");

        // Vendor root key should be the new relay's key
        assertEq(verifier.vendorRootKeyX(1), ROTATED_RELAY_X);
        assertEq(verifier.vendorRootKeyY(1), ROTATED_RELAY_Y);

        // Direct override should be blocked again (new relay is active)
        vm.expectRevert(
            abi.encodeWithSelector(
                VaultTEEVerifier.DirectOverrideWhileRelayActive.selector, uint8(1)
            )
        );
        verifier.setVendorRootKey(1, VENDOR_ROOT_X, VENDOR_ROOT_Y);

        vm.stopPrank();
    }

    /// @notice Replacement relay can register enclaves and track attestation count.
    function test_replacementRelay_registersEnclaves() public {
        vm.startPrank(admin);

        // Register, revoke, re-register
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        verifier.revokeRelay(1);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v2");

        // Register an enclave using the replacement relay
        bytes32 nitroEncHash = keccak256("nitro-enclave-v2");
        bytes32 nitroSignerHash = keccak256("nitro-signer-v2");
        bytes32 keyAttestMsg = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(1)));
        (bytes32 attestR, bytes32 attestS) = vm.signP256(RELAY_PRIV, keyAttestMsg);

        verifier.registerEnclave(
            nitroEncHash,
            nitroSignerHash,
            keccak256("nitro-app-v2"),
            1,
            "Nitro v2",
            P256_PUB_X,
            P256_PUB_Y,
            uint256(attestR),
            uint256(attestS)
        );

        // Attestation count should be 1
        (,,,, uint256 count,,,,,,,) = verifier.attestationRelays(1);
        assertEq(count, 1);

        vm.stopPrank();
    }
}
