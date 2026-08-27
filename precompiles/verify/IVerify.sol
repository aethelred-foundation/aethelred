// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.18;

/// @title IVerify — the Aethelred zkML verification-registry precompile
/// @notice Read access to the on-chain zkML registry: which circuits and
///         Groth16 verifying keys are registered, active, and bound to which
///         model. A contract can require that a result was proven against a
///         REGISTERED circuit before acting on it — closing the loop between
///         a Digital Seal's zkML claim and the key material that backs it.
/// @dev    Precompiled contract at address 0x0000000000000000000000000000000000000901.
///         Read-only: circuit / verifying-key registration is a chain
///         transaction (x/verify), not an EVM call. Heavy pairing checks stay
///         in the PoUW verification path (asynchronous), never synchronous in
///         a precompile — a deliberate DoS-surface decision (ADR-0001).
interface IVerify {
    /// @notice Registered-circuit facts.
    /// @param circuitHash The circuit's canonical hash.
    function getCircuit(bytes32 circuitHash)
        external
        view
        returns (
            bool active,
            string memory proofSystem, // e.g. "groth16-bn254"
            bytes32 modelHash, // model this circuit encodes
            string memory registeredBy,
            uint64 registeredAt
        );

    /// @notice Registered verifying-key facts.
    /// @param vkHash The verifying key's canonical hash.
    function getVerifyingKey(bytes32 vkHash)
        external
        view
        returns (
            bool active,
            string memory proofSystem,
            bytes32 circuitHash,
            bytes32 modelHash,
            string memory registeredBy,
            uint64 registeredAt
        );

    /// @notice True iff the circuit exists and is active. Missing circuits
    ///         return false (no revert) — the gating form.
    function isCircuitActive(bytes32 circuitHash) external view returns (bool);
}
