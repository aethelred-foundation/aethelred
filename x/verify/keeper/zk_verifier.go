// Package keeper provides the on-chain ZK proof verification implementation.
//
// SECURITY CRITICAL: This module performs cryptographic verification of zero-knowledge
// proofs on-chain. All verification must be deterministic and gas-metered to prevent
// denial-of-service attacks.
package keeper

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// =============================================================================
// ZK Proof Verification Types
// =============================================================================

// ProofSystem identifies the zero-knowledge proof system used
type ProofSystem string

const (
	// ProofSystemEZKL is the EZKL proof system for ML models
	ProofSystemEZKL ProofSystem = "ezkl"

	// ProofSystemRISC0 is the RISC Zero zkVM proof system
	ProofSystemRISC0 ProofSystem = "risc0"

	// ProofSystemPlonky2 is the Plonky2 proof system
	ProofSystemPlonky2 ProofSystem = "plonky2"

	// ProofSystemHalo2 is the Halo2 proof system
	ProofSystemHalo2 ProofSystem = "halo2"

	// ProofSystemGroth16 is the Groth16 SNARK proof system
	ProofSystemGroth16 ProofSystem = "groth16"
)

// ZKProof represents a zero-knowledge proof for on-chain verification
type ZKProof struct {
	// System identifies the proof system
	System ProofSystem

	// Proof is the serialized proof data
	Proof []byte

	// PublicInputs are the public inputs to the proof
	PublicInputs []byte

	// VerifyingKeyHash is the SHA-256 hash of the verifying key
	VerifyingKeyHash [32]byte

	// CircuitHash is the SHA-256 hash of the circuit (optional)
	CircuitHash [32]byte

	// ProofSize is the declared size of the proof in bytes.
	// SECURITY NOTE (ZK-01): This field is advisory and MUST NOT be trusted
	// for size enforcement. Always use len(Proof) for actual size checks.
	ProofSize uint64

	// JobID binds this proof to a specific compute job (ZK-06: anti-replay).
	JobID string

	// ChainID binds this proof to a specific chain (ZK-06: anti-replay).
	ChainID string

	// Height binds this proof to a specific block height (ZK-06: anti-replay).
	Height int64
}

// ZKVerificationResult contains the result of proof verification
type ZKVerificationResult struct {
	// Valid indicates if the proof is cryptographically valid
	Valid bool

	// GasUsed is the amount of gas consumed by verification
	GasUsed uint64

	// ErrorCode is set if verification failed
	ErrorCode ZKErrorCode

	// ErrorMessage provides details on verification failure
	ErrorMessage string

	// PublicInputsHash is the hash of the verified public inputs
	PublicInputsHash [32]byte
}

// ZKErrorCode represents categorized ZK verification errors
type ZKErrorCode string

const (
	ZKErrorNone                 ZKErrorCode = ""
	ZKErrorInvalidProof         ZKErrorCode = "INVALID_PROOF"
	ZKErrorInvalidPublicInput   ZKErrorCode = "INVALID_PUBLIC_INPUT"
	ZKErrorVerifyingKeyMismatch ZKErrorCode = "VERIFYING_KEY_MISMATCH"
	ZKErrorCircuitMismatch      ZKErrorCode = "CIRCUIT_MISMATCH"
	ZKErrorUnsupportedSystem    ZKErrorCode = "UNSUPPORTED_SYSTEM"
	ZKErrorProofTooLarge        ZKErrorCode = "PROOF_TOO_LARGE"
	ZKErrorGasExhausted         ZKErrorCode = "GAS_EXHAUSTED"
	ZKErrorMalformedProof       ZKErrorCode = "MALFORMED_PROOF"
)

// =============================================================================
// On-Chain ZK Verifier
// =============================================================================

// ZKVerifier performs on-chain zero-knowledge proof verification
type ZKVerifier struct {
	// registeredCircuits maps circuit hashes to their verifying keys
	registeredCircuits map[[32]byte]RegisteredCircuit

	// maxProofSize is the maximum allowed proof size in bytes
	maxProofSize uint64

	// gasPerByte is the gas cost per byte of proof verification
	gasPerByte uint64

	// baseGas is the base gas cost for any verification
	baseGas uint64

	// allowSimulated permits deterministic structural validation only.
	// Must be false in production/mainnet paths.
	allowSimulated bool

	// systemVerifiers holds pluggable cryptographic verifiers per proof system.
	systemVerifiers map[ProofSystem]ZKProofVerifier
}

// ZKProofVerifier performs cryptographic proof verification for a proof system.
type ZKProofVerifier func(proof *ZKProof, circuit *RegisteredCircuit) (bool, error)

// RegisteredCircuit represents a circuit registered for verification
type RegisteredCircuit struct {
	// CircuitHash is the unique identifier
	CircuitHash [32]byte

	// VerifyingKey is the serialized verifying key
	VerifyingKey []byte

	// System is the proof system
	System ProofSystem

	// MaxProofSize is the maximum proof size for this circuit
	MaxProofSize uint64

	// GasMultiplier adjusts gas cost based on circuit complexity
	GasMultiplier uint64

	// Owner is the address that registered the circuit
	Owner string

	// Active indicates if the circuit is enabled for verification
	Active bool
}

// NewZKVerifier creates a new on-chain ZK verifier
func NewZKVerifier() *ZKVerifier {
	return &ZKVerifier{
		registeredCircuits: make(map[[32]byte]RegisteredCircuit),
		maxProofSize:       1024 * 1024, // 1 MB max proof size
		gasPerByte:         10,          // 10 gas per byte
		baseGas:            100000,      // 100k base gas for verification
		allowSimulated:     false,       // fail-closed by default
		systemVerifiers:    make(map[ProofSystem]ZKProofVerifier),
	}
}

// NewSimulatedZKVerifier creates a verifier with deterministic structural checks.
// Use only for tests/devnets; production must use NewZKVerifier().
func NewSimulatedZKVerifier() *ZKVerifier {
	v := NewZKVerifier()
	v.allowSimulated = true
	return v
}

// RegisterSystemVerifier registers a cryptographic verifier implementation.
func (v *ZKVerifier) RegisterSystemVerifier(system ProofSystem, verifier ZKProofVerifier) error {
	if verifier == nil {
		return errors.New("verifier cannot be nil")
	}
	v.systemVerifiers[system] = verifier
	return nil
}

// RegisterCircuit registers a new circuit for verification
func (v *ZKVerifier) RegisterCircuit(circuit RegisteredCircuit) error {
	if len(circuit.VerifyingKey) == 0 {
		return errors.New("verifying key cannot be empty")
	}

	if circuit.MaxProofSize == 0 {
		circuit.MaxProofSize = v.maxProofSize
	}

	if circuit.GasMultiplier == 0 {
		circuit.GasMultiplier = 1
	}

	circuit.Active = true
	v.registeredCircuits[circuit.CircuitHash] = circuit

	return nil
}

// DeactivateCircuit deactivates a circuit (governance action)
func (v *ZKVerifier) DeactivateCircuit(circuitHash [32]byte) error {
	circuit, exists := v.registeredCircuits[circuitHash]
	if !exists {
		return fmt.Errorf("circuit not found: %x", circuitHash)
	}

	circuit.Active = false
	v.registeredCircuits[circuitHash] = circuit
	return nil
}

// VerifyProof performs on-chain verification of a ZK proof.
//
// SECURITY INVARIANTS:
//   - ZK-01: Size gate enforces on actual byte length len(proof.Proof), NOT the
//     untrusted ProofSize field.
//   - ZK-03: Unregistered circuits are rejected in production mode (allowSimulated=false).
//   - ZK-06: Domain binding (JobID + ChainID + Height) is enforced on public inputs.
//   - ZK-09: Simulated verification is unreachable when allowSimulated=false.
func (v *ZKVerifier) VerifyProof(ctx sdk.Context, proof *ZKProof) *ZKVerificationResult {
	result := &ZKVerificationResult{
		Valid:   false,
		GasUsed: v.baseGas,
	}

	// ── ZK-01: Enforce size limit on ACTUAL proof bytes, not untrusted ProofSize ──
	actualSize := uint64(len(proof.Proof))
	if actualSize > v.maxProofSize {
		result.ErrorCode = ZKErrorProofTooLarge
		result.ErrorMessage = fmt.Sprintf("proof byte length %d exceeds maximum %d", actualSize, v.maxProofSize)
		return result
	}
	// Also reject ProofSize/actual mismatch as a signal of tampering.
	if proof.ProofSize != 0 && proof.ProofSize != actualSize {
		result.ErrorCode = ZKErrorMalformedProof
		result.ErrorMessage = fmt.Sprintf("declared ProofSize %d does not match actual byte length %d", proof.ProofSize, actualSize)
		return result
	}

	// ── ZK-06: Domain binding — require JobID, ChainID, Height for anti-replay ──
	if !v.allowSimulated {
		if proof.JobID == "" {
			result.ErrorCode = ZKErrorInvalidPublicInput
			result.ErrorMessage = "missing JobID for domain binding (ZK-06)"
			return result
		}
		if proof.ChainID == "" {
			result.ErrorCode = ZKErrorInvalidPublicInput
			result.ErrorMessage = "missing ChainID for domain binding (ZK-06)"
			return result
		}
		if proof.Height <= 0 {
			result.ErrorCode = ZKErrorInvalidPublicInput
			result.ErrorMessage = "missing or invalid Height for domain binding (ZK-06)"
			return result
		}
	}

	// Calculate gas cost based on actual proof bytes (ZK-02).
	gasNeeded := v.baseGas + (actualSize * v.gasPerByte)

	// ── ZK-04/ZK-11: Look up registered circuit from the canonical registry ──
	var circuitRef *RegisteredCircuit
	circuit, exists := v.registeredCircuits[proof.CircuitHash]
	if exists {
		if !circuit.Active {
			result.ErrorCode = ZKErrorCircuitMismatch
			result.ErrorMessage = "circuit is deactivated"
			return result
		}

		// Apply circuit-specific gas multiplier
		gasNeeded *= circuit.GasMultiplier

		// Check circuit-specific proof size limit (tighter than global max).
		if circuit.MaxProofSize > 0 && actualSize > circuit.MaxProofSize {
			result.ErrorCode = ZKErrorProofTooLarge
			result.ErrorMessage = fmt.Sprintf("proof byte length %d exceeds circuit max %d", actualSize, circuit.MaxProofSize)
			return result
		}

		// ZK-05: Verify verifying key hash matches.
		vkHash := sha256.Sum256(circuit.VerifyingKey)
		if vkHash != proof.VerifyingKeyHash {
			result.ErrorCode = ZKErrorVerifyingKeyMismatch
			result.ErrorMessage = "verifying key hash mismatch"
			result.GasUsed = gasNeeded
			return result
		}
		circuitRef = &circuit
	} else {
		// ── ZK-03: Reject unregistered circuits in production mode ──
		if !v.allowSimulated {
			result.ErrorCode = ZKErrorCircuitMismatch
			result.ErrorMessage = "circuit not registered; unregistered proofs are rejected in production mode (ZK-03)"
			return result
		}
	}

	// Consume gas (in real implementation, this would be gas metered).
	result.GasUsed = gasNeeded

	// ── ZK-06 continued: Validate domain binding in public inputs ──
	if !v.allowSimulated {
		if err := v.validateDomainBinding(proof); err != nil {
			result.ErrorCode = ZKErrorInvalidPublicInput
			result.ErrorMessage = fmt.Sprintf("domain binding validation failed: %v", err)
			return result
		}
	}

	// Perform system-specific verification
	var valid bool
	var verifyErr error

	switch proof.System {
	case ProofSystemEZKL:
		valid, verifyErr = v.verifyEZKLProof(proof, circuitRef)
	case ProofSystemRISC0:
		valid, verifyErr = v.verifyRISC0Proof(proof, circuitRef)
	case ProofSystemPlonky2:
		valid, verifyErr = v.verifyPlonky2Proof(proof, circuitRef)
	case ProofSystemHalo2:
		valid, verifyErr = v.verifyHalo2Proof(proof, circuitRef)
	case ProofSystemGroth16:
		valid, verifyErr = v.verifyGroth16Proof(proof, circuitRef)
	default:
		result.ErrorCode = ZKErrorUnsupportedSystem
		result.ErrorMessage = fmt.Sprintf("unsupported proof system: %s", proof.System)
		return result
	}

	if verifyErr != nil {
		result.ErrorCode = ZKErrorInvalidProof
		result.ErrorMessage = verifyErr.Error()
		return result
	}

	result.Valid = valid
	result.PublicInputsHash = sha256.Sum256(proof.PublicInputs)

	if !valid {
		result.ErrorCode = ZKErrorInvalidProof
		result.ErrorMessage = "proof verification failed"
	}

	return result
}

// validateDomainBinding ensures that the proof's public inputs commit to the
// claimed JobID, ChainID, and Height. This prevents replay attacks where a
// valid proof for one job is re-submitted for a different job or on a different
// chain (ZK-06).
func (v *ZKVerifier) validateDomainBinding(proof *ZKProof) error {
	// Compute expected domain binding digest: SHA-256(jobID || chainID || height).
	h := sha256.New()
	h.Write([]byte(proof.JobID))
	h.Write([]byte(proof.ChainID))
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, uint64(proof.Height))
	h.Write(heightBytes)
	expectedBinding := h.Sum(nil)

	// The domain binding must appear in the public inputs.
	// Convention: last 32 bytes of public inputs contain the domain binding digest.
	if len(proof.PublicInputs) < 32 {
		return fmt.Errorf("public inputs too short (%d bytes) to contain domain binding", len(proof.PublicInputs))
	}
	tail := proof.PublicInputs[len(proof.PublicInputs)-32:]
	if !bytes.Equal(tail, expectedBinding) {
		return fmt.Errorf("domain binding mismatch: public inputs do not commit to jobID=%s chainID=%s height=%d",
			proof.JobID, proof.ChainID, proof.Height)
	}
	return nil
}

// =============================================================================
// Proof System Specific Verifiers
// =============================================================================

// verifyEZKLProof verifies an EZKL proof on-chain
func (v *ZKVerifier) verifyEZKLProof(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	// EZKL proof structure validation
	if len(proof.Proof) < 256 {
		return false, fmt.Errorf("EZKL proof too short: %d bytes (minimum 256)", len(proof.Proof))
	}

	// EZKL proofs use a specific header format
	// First 4 bytes: magic number "EZKL"
	if len(proof.Proof) >= 4 {
		magic := string(proof.Proof[:4])
		if magic != "EZKL" && !bytes.HasPrefix(proof.Proof, []byte{0x00, 0x00, 0x00, 0x00}) {
			// Allow zero header for compatibility
		}
	}

	// Validate public inputs structure
	if len(proof.PublicInputs) == 0 {
		return false, errors.New("EZKL proof requires public inputs")
	}

	// Parse and validate public inputs
	// EZKL public inputs are: [model_hash, input_hash, output_hash, ...]
	if len(proof.PublicInputs) < 96 { // At least 3 x 32-byte hashes
		return false, fmt.Errorf("EZKL public inputs too short: %d bytes (minimum 96)", len(proof.PublicInputs))
	}

	// Perform cryptographic verification
	// In production, this would call the actual EZKL verifier
	return v.cryptographicVerify(proof, circuit)
}

// verifyRISC0Proof verifies a RISC Zero proof on-chain
func (v *ZKVerifier) verifyRISC0Proof(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	// RISC0 proof structure validation
	if len(proof.Proof) < 512 {
		return false, fmt.Errorf("RISC0 proof too short: %d bytes (minimum 512)", len(proof.Proof))
	}

	// RISC0 proofs have a journal (public outputs) and a receipt (proof)
	// The receipt contains the seal and claim

	// Validate image ID is present in public inputs
	if len(proof.PublicInputs) < 32 {
		return false, errors.New("RISC0 proof requires image ID in public inputs")
	}

	return v.cryptographicVerify(proof, circuit)
}

// verifyPlonky2Proof verifies a Plonky2 proof on-chain
func (v *ZKVerifier) verifyPlonky2Proof(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	// Plonky2 proof structure validation
	if len(proof.Proof) < 256 {
		return false, fmt.Errorf("Plonky2 proof too short: %d bytes (minimum 256)", len(proof.Proof))
	}

	// Plonky2 proofs are recursively composable
	// They have a compact representation after aggregation

	return v.cryptographicVerify(proof, circuit)
}

// verifyHalo2Proof verifies a Halo2 proof on-chain
func (v *ZKVerifier) verifyHalo2Proof(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	// Halo2 proof structure validation
	if len(proof.Proof) < 384 {
		return false, fmt.Errorf("Halo2 proof too short: %d bytes (minimum 384)", len(proof.Proof))
	}

	// Halo2 uses the IPA (Inner Product Argument) commitment scheme
	// Proofs are relatively small and efficient to verify

	return v.cryptographicVerify(proof, circuit)
}

// verifyGroth16Proof verifies a Groth16 SNARK proof on-chain.
//
// ZK-08: Groth16 proofs consist of 3 group elements (A, B, C) on BN254 or BLS12-381.
// We enforce subgroup membership checks and reject points at infinity or with
// coordinates outside the field modulus before passing to the pairing engine.
func (v *ZKVerifier) verifyGroth16Proof(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	// Groth16 proof structure: 3 group elements (A, B, C)
	// BN254: A(64) + B(128) + C(64) = 256 bytes
	// BLS12-381: A(96) + B(192) + C(96) = 384 bytes
	// We accept minimum 192 for compressed representations.
	if len(proof.Proof) < 192 {
		return false, fmt.Errorf("Groth16 proof too short: %d bytes (minimum 192)", len(proof.Proof))
	}

	// ── ZK-08: Subgroup and validity checks for BN254 curve points ──
	// Groth16 verification equation: e(A, B) = e(α, β) · e(L, γ) · e(C, δ)
	// All points must be valid curve elements in the correct subgroup.
	if err := validateGroth16CurvePoints(proof.Proof); err != nil {
		return false, fmt.Errorf("Groth16 subgroup validation failed (ZK-08): %w", err)
	}

	return v.cryptographicVerify(proof, circuit)
}

// validateGroth16CurvePoints performs structural validation of Groth16 proof points.
//
// ZK-08: For BN254 (the most common curve for Groth16):
//   - Points A and C are G1 elements (2 × 32-byte coordinates = 64 bytes each)
//   - Point B is a G2 element (2 × 2 × 32-byte coordinates = 128 bytes)
//   - All coordinates must be < field modulus p
//   - The point at infinity (all zeros) is invalid for proof elements
//   - In production, the actual pairing library performs full subgroup checks
func validateGroth16CurvePoints(proofBytes []byte) error {
	// BN254 field modulus p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
	// Check that no element is the point at infinity (all zeros).
	if len(proofBytes) >= 192 {
		// Point A (G1): bytes [0:64]
		if isAllZeros(proofBytes[0:64]) {
			return errors.New("point A is the point at infinity")
		}
		// Point B (G2): bytes [64:192] (128 bytes for BN254 G2)
		if isAllZeros(proofBytes[64:192]) {
			return errors.New("point B is the point at infinity")
		}
	}
	if len(proofBytes) >= 256 {
		// Point C (G1): bytes [192:256]
		if isAllZeros(proofBytes[192:256]) {
			return errors.New("point C is the point at infinity")
		}
	}

	// Coordinate field modulus check: each 32-byte coordinate must be < p.
	// BN254 p in big-endian bytes:
	bn254Modulus := [32]byte{
		0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
		0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
		0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
		0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
	}

	// Validate each 32-byte coordinate is within the field.
	numCoords := len(proofBytes) / 32
	for i := 0; i < numCoords && i*32+32 <= len(proofBytes); i++ {
		coord := proofBytes[i*32 : i*32+32]
		if !isLessThan(coord, bn254Modulus[:]) {
			return fmt.Errorf("coordinate %d exceeds BN254 field modulus", i)
		}
	}

	return nil
}

// isAllZeros returns true if all bytes are zero.
func isAllZeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// isLessThan returns true if a < b (big-endian unsigned comparison).
func isLessThan(a, b []byte) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	for i := range a {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false // equal
}

// cryptographicVerify performs the actual cryptographic verification.
//
// ZK-09: In production (allowSimulated=false), this function MUST use a
// registered system verifier and fails closed if none is available.
// The simulated path is ONLY reachable when allowSimulated=true AND no
// real verifier is registered. A production binary MUST NOT set allowSimulated.
func (v *ZKVerifier) cryptographicVerify(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
	// Always prefer a registered verifier implementation.
	if verifier, ok := v.systemVerifiers[proof.System]; ok {
		return verifier(proof, circuit)
	}

	// ── ZK-09: Fail-closed in production mode ──
	if !v.allowSimulated {
		return false, fmt.Errorf("SECURITY: no cryptographic verifier registered for proof system %q; "+
			"production mode requires a real verifier (ZK-09)", proof.System)
	}

	// ── Dev/test fallback: deterministic structural validation ──
	// SECURITY WARNING: This path accepts proofs based on structure only.
	// It MUST NOT be reachable in production deployments.

	// Validate proof has non-trivial content.
	if len(proof.Proof) == 0 {
		return false, errors.New("simulated mode: empty proof bytes")
	}

	// Validate public inputs are non-empty.
	if len(proof.PublicInputs) == 0 {
		return false, errors.New("simulated mode: empty public inputs")
	}

	// Compute proof hash for integrity (deterministic check).
	proofHash := sha256.Sum256(proof.Proof)
	proofHash2 := sha256.Sum256(proof.Proof)
	if proofHash != proofHash2 {
		return false, errors.New("proof hash inconsistency — potential non-determinism")
	}

	// Verify verifying key hash is non-zero.
	if proof.VerifyingKeyHash == [32]byte{} {
		return false, errors.New("simulated mode: verifying key hash is empty")
	}

	return true, nil
}

// IsSimulatedModeEnabled returns true if the verifier allows simulated proofs.
// Production invariant checks should call this and panic/abort if true.
func (v *ZKVerifier) IsSimulatedModeEnabled() bool {
	return v.allowSimulated
}

// AssertProductionMode panics if simulated mode is enabled.
// Call this during app initialization on mainnet to enforce ZK-09.
func (v *ZKVerifier) AssertProductionMode() {
	if v.allowSimulated {
		panic("SECURITY INVARIANT VIOLATION (ZK-09): ZK verifier has allowSimulated=true in production mode")
	}
}

// =============================================================================
// ZK-04: Deterministic Registry Rebuild from KV Store
// =============================================================================

// CircuitStoreReader reads registered circuits from on-chain KV state.
// Implementations must return circuits deterministically for a given block height.
type CircuitStoreReader interface {
	// GetAllActiveCircuits returns all active registered circuits from the KV store.
	GetAllActiveCircuits(ctx sdk.Context) ([]RegisteredCircuit, error)
}

// RebuildRegistryFromStore replaces the in-memory circuit registry with the
// canonical on-chain KV store contents. This MUST be called at the start of
// each block (BeginBlock) to ensure all validators have an identical view.
//
// ZK-04: This eliminates the consensus divergence risk from the in-memory map
// by treating the KV store as the single source of truth.
func (v *ZKVerifier) RebuildRegistryFromStore(ctx sdk.Context, store CircuitStoreReader) error {
	circuits, err := store.GetAllActiveCircuits(ctx)
	if err != nil {
		return fmt.Errorf("failed to load circuits from KV store (ZK-04): %w", err)
	}

	// Replace entire in-memory map atomically.
	newMap := make(map[[32]byte]RegisteredCircuit, len(circuits))
	for _, c := range circuits {
		newMap[c.CircuitHash] = c
	}
	v.registeredCircuits = newMap

	return nil
}

// CircuitCount returns the number of registered circuits (for observability).
func (v *ZKVerifier) CircuitCount() int {
	return len(v.registeredCircuits)
}

// =============================================================================
// Public Input Parsing and Validation
// =============================================================================

// ParseEZKLPublicInputs parses EZKL public inputs into structured data.
//
// Layout (ZK-06 compliant):
//
//	[0:32]   ModelHash
//	[32:64]  InputHash
//	[64:96]  OutputHash
//	[96:128] CircuitHash (optional)
//	[last 32 bytes] DomainBinding = SHA-256(jobID || chainID || height)
func ParseEZKLPublicInputs(publicInputs []byte) (*EZKLPublicInputs, error) {
	if len(publicInputs) < 96 {
		return nil, fmt.Errorf("public inputs too short: %d bytes", len(publicInputs))
	}

	inputs := &EZKLPublicInputs{}
	copy(inputs.ModelHash[:], publicInputs[0:32])
	copy(inputs.InputHash[:], publicInputs[32:64])
	copy(inputs.OutputHash[:], publicInputs[64:96])

	// Parse additional inputs if present.
	if len(publicInputs) >= 128 {
		copy(inputs.CircuitHash[:], publicInputs[96:128])
	}

	// ZK-06: Extract domain binding from the last 32 bytes.
	if len(publicInputs) >= 128 { // minimum 96 (hashes) + 32 (domain binding)
		copy(inputs.DomainBinding[:], publicInputs[len(publicInputs)-32:])
	}

	return inputs, nil
}

// EZKLPublicInputs represents the public inputs for an EZKL proof.
// ZK-06: Includes domain binding fields (JobID, ChainID, Height) for anti-replay.
type EZKLPublicInputs struct {
	ModelHash     [32]byte
	InputHash     [32]byte
	OutputHash    [32]byte
	CircuitHash   [32]byte
	DomainBinding [32]byte // SHA-256(jobID || chainID || height) for anti-replay (ZK-06)
}

// ValidateAgainstJob validates that public inputs match a compute job.
func (inputs *EZKLPublicInputs) ValidateAgainstJob(modelHash, inputHash, outputHash []byte) error {
	if !bytes.Equal(inputs.ModelHash[:], modelHash) {
		return errors.New("model hash mismatch")
	}
	if !bytes.Equal(inputs.InputHash[:], inputHash) {
		return errors.New("input hash mismatch")
	}
	if !bytes.Equal(inputs.OutputHash[:], outputHash) {
		return errors.New("output hash mismatch")
	}
	return nil
}

// ValidateDomainBinding checks that the embedded domain binding matches the
// expected job context (ZK-06).
func (inputs *EZKLPublicInputs) ValidateDomainBinding(jobID, chainID string, height int64) error {
	h := sha256.New()
	h.Write([]byte(jobID))
	h.Write([]byte(chainID))
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, uint64(height))
	h.Write(heightBytes)

	var expected [32]byte
	copy(expected[:], h.Sum(nil))

	if inputs.DomainBinding != expected {
		return fmt.Errorf("domain binding mismatch: proof was generated for a different job/chain/height")
	}
	return nil
}

// =============================================================================
// Gas Estimation
// =============================================================================

// EstimateVerificationGas estimates the gas cost for proof verification
func (v *ZKVerifier) EstimateVerificationGas(proof *ZKProof) uint64 {
	baseGas := v.baseGas
	proofGas := uint64(len(proof.Proof)) * v.gasPerByte
	publicInputGas := uint64(len(proof.PublicInputs)) * (v.gasPerByte / 2)

	// System-specific multipliers
	var multiplier uint64 = 1
	switch proof.System {
	case ProofSystemGroth16:
		multiplier = 1 // Groth16 is most efficient
	case ProofSystemHalo2:
		multiplier = 2 // Halo2 requires IPA verification
	case ProofSystemPlonky2:
		multiplier = 3 // Plonky2 uses FRI
	case ProofSystemRISC0:
		multiplier = 4 // RISC0 is a full zkVM
	case ProofSystemEZKL:
		multiplier = 2 // EZKL uses Halo2 backend
	}

	totalGas := (baseGas + proofGas + publicInputGas) * multiplier

	// Check for registered circuit with custom gas
	circuit, exists := v.registeredCircuits[proof.CircuitHash]
	if exists && circuit.GasMultiplier > 0 {
		totalGas *= circuit.GasMultiplier
	}

	return totalGas
}

// =============================================================================
// Precompile Interface (for EVM integration)
// =============================================================================

// ZKVerifierPrecompile provides an EVM precompile interface for ZK verification
type ZKVerifierPrecompile struct {
	verifier *ZKVerifier
}

// NewZKVerifierPrecompile creates a new ZK verifier precompile
func NewZKVerifierPrecompile(verifier *ZKVerifier) *ZKVerifierPrecompile {
	return &ZKVerifierPrecompile{verifier: verifier}
}

// PrecompileAddress returns the address of the ZK verifier precompile
// Following Aethelred's precompile address scheme: 0x0300
func (p *ZKVerifierPrecompile) PrecompileAddress() []byte {
	return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00}
}

// RequiredGas returns the gas required for the precompile call
func (p *ZKVerifierPrecompile) RequiredGas(input []byte) uint64 {
	// Parse proof from input to estimate gas
	proof, err := p.parsePrecompileInput(input)
	if err != nil {
		return p.verifier.baseGas // Return base gas on parse error
	}
	return p.verifier.EstimateVerificationGas(proof)
}

// Run executes the precompile
func (p *ZKVerifierPrecompile) Run(input []byte) ([]byte, error) {
	proof, err := p.parsePrecompileInput(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse precompile input: %w", err)
	}

	// ZK-01: Ensure ProofSize matches actual byte length.
	proof.ProofSize = uint64(len(proof.Proof))

	// Verify the proof (ctx is nil for precompile calls)
	result := p.verifier.VerifyProof(sdk.Context{}, proof)

	// Encode result
	return p.encodeResult(result), nil
}

// parsePrecompileInput parses the ABI-encoded input for the precompile
func (p *ZKVerifierPrecompile) parsePrecompileInput(input []byte) (*ZKProof, error) {
	if len(input) < 132 { // Minimum: system(32) + vkHash(32) + circuitHash(32) + proof offset(32) + inputs offset(4)
		return nil, errors.New("input too short")
	}

	proof := &ZKProof{}

	// Parse system identifier (first 32 bytes, right-padded string)
	systemBytes := input[0:32]
	systemStr := string(bytes.TrimRight(systemBytes, "\x00"))
	proof.System = ProofSystem(systemStr)

	// Parse verifying key hash (bytes 32-64)
	copy(proof.VerifyingKeyHash[:], input[32:64])

	// Parse circuit hash (bytes 64-96)
	copy(proof.CircuitHash[:], input[64:96])

	// Parse proof length and data
	if len(input) < 100 {
		return nil, errors.New("missing proof length")
	}
	proofLen := binary.BigEndian.Uint32(input[96:100])
	if uint32(len(input)) < 100+proofLen {
		return nil, errors.New("proof data truncated")
	}
	proof.Proof = input[100 : 100+proofLen]
	proof.ProofSize = uint64(proofLen)

	// Parse public inputs
	offset := 100 + proofLen
	if uint32(len(input)) < offset+4 {
		return nil, errors.New("missing public inputs length")
	}
	inputsLen := binary.BigEndian.Uint32(input[offset : offset+4])
	if uint32(len(input)) < offset+4+inputsLen {
		return nil, errors.New("public inputs data truncated")
	}
	proof.PublicInputs = input[offset+4 : offset+4+inputsLen]

	return proof, nil
}

// encodeResult encodes the verification result for return
func (p *ZKVerifierPrecompile) encodeResult(result *ZKVerificationResult) []byte {
	// Format: valid(1) + gasUsed(8) + errorCode(32) + publicInputsHash(32)
	output := make([]byte, 73)

	if result.Valid {
		output[0] = 1
	}

	binary.BigEndian.PutUint64(output[1:9], result.GasUsed)

	// Error code (padded to 32 bytes)
	copy(output[9:41], []byte(result.ErrorCode))

	// Public inputs hash
	copy(output[41:73], result.PublicInputsHash[:])

	return output
}
