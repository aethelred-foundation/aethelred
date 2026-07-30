// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "./Cruzible.t.sol";
import "../contracts/SovereignGovernanceTimelock.sol";

contract ReentrantTEEVerifier {
    address public target;
    bytes public callbackData;
    bytes public responsePayload;
    bool public callbackAttempted;
    bool public callbackSucceeded;
    bytes public callbackReturnData;
    bool private entered;

    function configure(address target_, bytes calldata callbackData_, bytes calldata responsePayload_)
        external
    {
        target = target_;
        callbackData = callbackData_;
        responsePayload = responsePayload_;
        callbackAttempted = false;
        callbackSucceeded = false;
        delete callbackReturnData;
        entered = false;
    }

    function verifyAttestation(bytes calldata)
        external
        returns (bool valid, bytes memory payload, uint8 platform)
    {
        if (!entered) {
            entered = true;
            callbackAttempted = true;
            (callbackSucceeded, callbackReturnData) = target.call(callbackData);
            entered = false;
        }
        return (true, responsePayload, 0);
    }
}

contract CruzibleReentrancyRegressionTest is CruzibleTest {
    using CruzibleCompat for Cruzible;

    bytes4 private constant REENTRANCY_SELECTOR =
        bytes4(keccak256("ReentrancyGuardReentrantCall()"));

    function test_distributeRewards_reentrantVerifierCallbackRejected() public {
        uint256 epoch = vault.currentEpoch();
        uint256 totalRewards = 10 ether;
        uint256 protocolFee = (totalRewards * 500) / 10_000;
        bytes32 merkleRoot = keccak256("reentrancy-rewards-root");

        Cruzible.EpochSnapshot memory snapshot = vault.getEpochSnapshot(epoch);
        bytes memory delegationAttestation =
            _createDelegationAttestation(epoch, bytes32(0), snapshot.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(
            delegationAttestation, epoch, bytes32(0), snapshot.stakerRegistryRoot, 0
        );

        snapshot = vault.getEpochSnapshot(epoch);
        bytes memory payload = abi.encode(
            epoch,
            totalRewards,
            merkleRoot,
            protocolFee,
            snapshot.stakeSnapshotHash,
            snapshot.validatorSetHash,
            snapshot.stakerRegistryRoot,
            snapshot.delegationRegistryRoot
        );

        ReentrantTEEVerifier maliciousVerifier = new ReentrantTEEVerifier();
        maliciousVerifier.configure(
            address(vault),
            abi.encodeCall(
                Cruzible.distributeRewards,
                (hex"01", epoch, totalRewards, merkleRoot, protocolFee)
            ),
            payload
        );
        vm.prank(admin);
        vault.setTEEVerifier(address(maliciousVerifier));

        _fundOracleForIngestion(totalRewards);
        vm.prank(oracle);
        vault.distributeRewards(hex"01", epoch, totalRewards, merkleRoot, protocolFee);

        _assertReentrancyRejected(maliciousVerifier);
        Cruzible.EpochSnapshot memory finalized = vault.getEpochSnapshot(epoch);
        assertTrue(finalized.finalized);
        assertLt(epoch, vault.currentEpoch());
    }

    function test_commitDelegationSnapshot_reentrantVerifierCallbackRejected() public {
        uint256 epoch = vault.currentEpoch();
        bytes32 root = keccak256("reentrant-direct-commit");
        Cruzible.EpochSnapshot memory snapshot = vault.getEpochSnapshot(epoch);
        bytes memory payload = abi.encode(epoch, root, snapshot.stakerRegistryRoot);

        ReentrantTEEVerifier maliciousVerifier = new ReentrantTEEVerifier();
        maliciousVerifier.configure(
            address(vault),
            abi.encodeCall(
                Cruzible.commitDelegationSnapshot,
                (hex"01", epoch, root, snapshot.stakerRegistryRoot, 1)
            ),
            payload
        );
        vm.prank(admin);
        vault.setTEEVerifier(address(maliciousVerifier));

        vm.prank(admin);
        vault.commitDelegationSnapshot(
            hex"01", epoch, root, snapshot.stakerRegistryRoot, 1
        );

        _assertReentrancyRejected(maliciousVerifier);
        assertEq(vault.getEpochSnapshot(epoch).delegationRegistryRoot, root);
    }

    function test_submitDelegationVote_reentrantVerifierCallbackRejected() public {
        uint256 epoch = vault.currentEpoch();
        bytes32 root = keccak256("reentrant-quorum-vote");
        Cruzible.EpochSnapshot memory snapshot = vault.getEpochSnapshot(epoch);
        bytes memory payload = abi.encode(epoch, root, snapshot.stakerRegistryRoot);

        vm.startPrank(admin);
        vault.grantRole(vault.DELEGATION_ATTESTOR_ROLE(), admin);
        vault.setDelegationQuorumEnabled(true);
        vm.stopPrank();

        ReentrantTEEVerifier maliciousVerifier = new ReentrantTEEVerifier();
        maliciousVerifier.configure(
            address(vault),
            abi.encodeCall(
                Cruzible.submitDelegationVote,
                (hex"01", epoch, root, snapshot.stakerRegistryRoot, 1)
            ),
            payload
        );
        vm.prank(admin);
        vault.setTEEVerifier(address(maliciousVerifier));

        vm.prank(admin);
        vault.submitDelegationVote(hex"01", epoch, root, snapshot.stakerRegistryRoot, 1);

        _assertReentrancyRejected(maliciousVerifier);
        assertEq(vault.delegationVoteCount(epoch, root), 1);
    }

    function test_challengeDelegationCommitment_callbackCannotDuplicateChallenge() public {
        uint256 epoch = vault.currentEpoch();
        bytes32 root = keccak256("reentrant-challenge");
        Cruzible.EpochSnapshot memory snapshot = vault.getEpochSnapshot(epoch);
        bytes memory delegationAttestation =
            _createDelegationAttestation(epoch, root, snapshot.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(
            delegationAttestation, epoch, root, snapshot.stakerRegistryRoot, 1
        );

        uint256 challengeBond = vault.CHALLENGE_BOND();
        aethel.mint(address(aethel), challengeBond);
        vm.prank(address(aethel));
        aethel.approve(address(vault), challengeBond);
        aethel.configureTransferFromCallback(
            address(vault),
            abi.encodeCall(Cruzible.challengeDelegationCommitment, (epoch))
        );

        vm.prank(address(aethel));
        vault.challengeDelegationCommitment(epoch);

        assertTrue(aethel.callbackAttempted());
        assertFalse(aethel.callbackSucceeded());
        assertEq(
            _selector(aethel.callbackReturnData()),
            Cruzible.AlreadyChallenged.selector
        );
        assertEq(vault.delegationChallengeCount(epoch), 1);
        assertEq(vault.challengerBonds(epoch, address(aethel)), challengeBond);
        assertEq(vault.totalChallengerBonds(), challengeBond);
    }

    function _assertReentrancyRejected(ReentrantTEEVerifier verifier_) internal view {
        assertTrue(verifier_.callbackAttempted());
        assertFalse(verifier_.callbackSucceeded());
        assertEq(_selector(verifier_.callbackReturnData()), REENTRANCY_SELECTOR);
    }

    function _selector(bytes memory revertData) internal pure returns (bytes4 selector) {
        if (revertData.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            selector := mload(add(revertData, 32))
        }
    }
}

contract ReentrantGovernanceBridge is IInstitutionalBridgeGovernance {
    address public override issuerGovernanceKey;
    address public override issuerRecoveryGovernanceKey;
    address public override foundationGovernanceKey;
    address public override auditorGovernanceKey;
    address public override guardianGovernanceKey;

    address public timelock;
    bytes32 public operationId;
    bool public callbackAttempted;
    bool public callbackSucceeded;
    bytes public callbackReturnData;

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

    function configureCallback(address timelock_, bytes32 operationId_) external {
        timelock = timelock_;
        operationId = operationId_;
    }

    function setGovernanceKeys(
        address issuerKey,
        address foundationKey,
        address auditorKey
    )
        external
        override
    {
        callbackAttempted = true;
        (callbackSucceeded, callbackReturnData) = timelock.call(
            abi.encodeCall(SovereignGovernanceTimelock.executeKeyRotation, (operationId))
        );
        issuerGovernanceKey = issuerKey;
        foundationGovernanceKey = foundationKey;
        auditorGovernanceKey = auditorKey;
    }

    function setSovereignUnpauseKeys(
        address issuerRecoveryKey,
        address guardianKey
    )
        external
        override
    {
        issuerRecoveryGovernanceKey = issuerRecoveryKey;
        guardianGovernanceKey = guardianKey;
    }
}

contract GovernanceReentrancyRegressionTest is Test {
    using MessageHashUtils for bytes32;

    uint256 internal constant ISSUER_PRIV_KEY = 0x1111;
    uint256 internal constant FOUNDATION_PRIV_KEY = 0x2222;
    uint256 internal constant AUDITOR_PRIV_KEY = 0x3333;
    uint256 internal constant ISSUER_RECOVERY_PRIV_KEY = 0x4444;
    uint256 internal constant GUARDIAN_PRIV_KEY = 0x5555;

    SovereignGovernanceTimelock internal timelock;
    address internal issuerAddr;
    address internal issuerRecoveryAddr;
    address internal foundationAddr;
    address internal auditorAddr;
    address internal guardianAddr;
    address internal proposer = address(0xBEEF);
    address internal executor = address(0xCAFE);

    function setUp() public {
        issuerAddr = vm.addr(ISSUER_PRIV_KEY);
        issuerRecoveryAddr = vm.addr(ISSUER_RECOVERY_PRIV_KEY);
        foundationAddr = vm.addr(FOUNDATION_PRIV_KEY);
        auditorAddr = vm.addr(AUDITOR_PRIV_KEY);
        guardianAddr = vm.addr(GUARDIAN_PRIV_KEY);

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;
        timelock = new SovereignGovernanceTimelock(
            7 days, proposers, executors, address(this)
        );
        timelock.grantRole(timelock.PROPOSER_ROLE(), address(timelock));
        timelock.grantRole(timelock.EXECUTOR_ROLE(), address(timelock));
    }

    function test_executeKeyRotation_reentrantBridgeCallbackRejected() public {
        ReentrantGovernanceBridge maliciousBridge = new ReentrantGovernanceBridge(
            issuerAddr,
            issuerRecoveryAddr,
            foundationAddr,
            auditorAddr,
            guardianAddr
        );
        timelock.grantRole(timelock.EXECUTOR_ROLE(), address(maliciousBridge));

        address newAuditor = address(0xA0D170);
        bytes32 predecessor = bytes32(0);
        bytes32 salt = keccak256("reentrant-governance-rotation");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = keccak256(
            abi.encode(
                "AETHELRED_ROTATE_KEY_V1",
                address(timelock),
                block.chainid,
                address(maliciousBridge),
                SovereignGovernanceTimelock.KeyType.Auditor,
                newAuditor,
                predecessor,
                salt,
                deadline
            )
        ).toEthSignedMessageHash();

        (uint8 issuerV, bytes32 issuerR, bytes32 issuerS) = vm.sign(ISSUER_PRIV_KEY, digest);
        (uint8 foundationV, bytes32 foundationR, bytes32 foundationS) =
            vm.sign(FOUNDATION_PRIV_KEY, digest);

        vm.prank(proposer);
        bytes32 operationId = timelock.rotateKey(
            address(maliciousBridge),
            SovereignGovernanceTimelock.KeyType.Auditor,
            newAuditor,
            predecessor,
            salt,
            deadline,
            abi.encodePacked(issuerR, issuerS, issuerV),
            abi.encodePacked(foundationR, foundationS, foundationV)
        );
        maliciousBridge.configureCallback(address(timelock), operationId);

        vm.warp(block.timestamp + timelock.getMinDelay() + 1);
        vm.prank(executor);
        timelock.executeKeyRotation(operationId);

        assertTrue(maliciousBridge.callbackAttempted());
        assertFalse(maliciousBridge.callbackSucceeded());
        assertEq(
            _selector(maliciousBridge.callbackReturnData()),
            SovereignGovernanceTimelock.OperationAlreadyExecuted.selector
        );
        assertEq(maliciousBridge.auditorGovernanceKey(), newAuditor);
    }

    function _selector(bytes memory revertData) internal pure returns (bytes4 selector) {
        if (revertData.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            selector := mload(add(revertData, 32))
        }
    }
}
