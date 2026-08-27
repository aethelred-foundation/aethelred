// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.18;

/// @title IPoUW — the Aethelred Proof-of-Useful-Work precompile
/// @notice Read access to the PoUW job registry: job lifecycle facts (status,
///         commitments, the seal that certified completion) and the on-chain
///         model registry. Combined with ISeal (0x0900), a contract can walk
///         job → seal → confidentiality attestation without any oracle.
/// @dev    Precompiled contract at address 0x0000000000000000000000000000000000000902.
///         Read-only: job submission and model registration are chain
///         transactions (x/pouw); EVM-originated writes arrive with the
///         cosmos/evm transaction layer (ADR-0001 Phase 1).
interface IPoUW {
    /// @notice Job lifecycle facts.
    /// @param jobId The PoUW job identifier.
    function getJob(string calldata jobId)
        external
        view
        returns (
            uint8 status, // 0 unspecified, 1 pending, 2 processing, 3 completed, 4 failed, 5 expired
            bytes32 modelHash,
            bytes32 inputHash,
            bytes32 outputHash,
            string memory requestedBy,
            string memory sealId, // empty until completed
            int64 blockHeight,
            uint64 usefulWorkUnits
        );

    /// @notice Registered-model facts.
    /// @param modelHash The model's canonical hash.
    function getModel(bytes32 modelHash)
        external
        view
        returns (
            bool active,
            string memory modelId,
            string memory name,
            string memory version,
            string memory owner,
            bytes32 circuitHash,
            bytes32 verifyingKeyHash
        );

    /// @notice True iff the model exists and is active. Missing models return
    ///         false (no revert) — the gating form.
    function isModelActive(bytes32 modelHash) external view returns (bool);

    /// @notice True iff the job exists and reached COMPLETED (a seal exists).
    function isJobCompleted(string calldata jobId) external view returns (bool);
}
