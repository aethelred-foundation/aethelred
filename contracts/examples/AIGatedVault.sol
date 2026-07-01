// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.20;

import "../../precompiles/seal/ISeal.sol";

/// @title AIGatedVault — reference contract gating value on a Digital Seal
/// @notice Escrows funds that release ONLY when a PoUW job completes with a
///         Digital Seal that (a) is ACTIVE, (b) certifies the expected model,
///         and (c) satisfies the confidentiality policy fixed at deployment
///         (e.g. "ran under TEE or FHE, vendor-root silicon, inside the EU").
///         The policy verdict comes from the ISeal precompile — the SAME
///         consensus logic that enforced the policy when the seal was minted.
///         No oracle, no off-chain attestation service, no trusted relayer.
/// @dev    Reference implementation for ADR-0001 Phase 2. Release is
///         permissionless by design: the seal itself is the authorization.
///         Checks-effects-interactions ordering; single-shot release.
contract AIGatedVault {
    /// @dev The ISeal precompile at its fixed address (see precompiles/seal).
    ISeal internal constant SEAL =
        ISeal(0x0000000000000000000000000000000000000900);

    /// @notice The account that funded the vault.
    address public immutable depositor;
    /// @notice The account paid when the gated computation is proven.
    address payable public immutable beneficiary;
    /// @notice The model commitment the seal must certify.
    bytes32 public immutable modelCommitment;
    /// @notice Whether the vault has already released.
    bool public released;

    // Confidentiality policy, fixed at deployment (CEAP, ADR-0003).
    string[] private allowedBackends;
    string private minVerification;
    string[] private allowedPlatforms;
    bool private immutable requireVendorRoot;
    string[] private dataResidency;

    event Deposited(address indexed from, uint256 amount);
    event Released(string jobId, string sealId, uint256 amount);

    error AlreadyReleased();
    error SealNotActive(string sealId);
    error ModelMismatch(bytes32 got, bytes32 want);
    error PolicyNotSatisfied(string reason);
    error NothingToRelease();
    error TransferFailed();

    constructor(
        address payable _beneficiary,
        bytes32 _modelCommitment,
        string[] memory _allowedBackends,
        string memory _minVerification,
        string[] memory _allowedPlatforms,
        bool _requireVendorRoot,
        string[] memory _dataResidency
    ) {
        depositor = msg.sender;
        beneficiary = _beneficiary;
        modelCommitment = _modelCommitment;
        allowedBackends = _allowedBackends;
        minVerification = _minVerification;
        allowedPlatforms = _allowedPlatforms;
        requireVendorRoot = _requireVendorRoot;
        dataResidency = _dataResidency;
    }

    /// @notice Fund the vault.
    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Release the escrowed funds against a completed, policy-
    ///         compliant job. Permissionless: the Digital Seal is the
    ///         authorization, not the caller's identity.
    /// @param jobId The PoUW job whose seal gates this vault.
    function release(string calldata jobId) external {
        if (released) revert AlreadyReleased();

        // Resolve and validate the seal. getSealIdByJob reverts when the job
        // has no seal (job incomplete or unknown) — fail closed.
        string memory sealId = SEAL.getSealIdByJob(jobId);
        if (!SEAL.verifySeal(sealId)) revert SealNotActive(sealId);

        // The seal must certify the exact model this vault was funded for.
        (bytes32 gotModel, , , , , , , , ) = SEAL.getSeal(sealId);
        if (gotModel != modelCommitment)
            revert ModelMismatch(gotModel, modelCommitment);

        // Consensus-parity confidentiality gating (CEAP Satisfies).
        (bool ok, string memory reason) = SEAL.requireConfidentiality(
            sealId,
            allowedBackends,
            minVerification,
            allowedPlatforms,
            requireVendorRoot,
            dataResidency
        );
        if (!ok) revert PolicyNotSatisfied(reason);

        uint256 amount = address(this).balance;
        if (amount == 0) revert NothingToRelease();

        // Effects before interaction; single-shot.
        released = true;
        emit Released(jobId, sealId, amount);

        (bool sent, ) = beneficiary.call{value: amount}("");
        if (!sent) revert TransferFailed();
    }
}
