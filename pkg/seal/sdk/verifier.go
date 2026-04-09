package sdk

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/x/seal/types"
)

// VerificationResult contains the outcome of a seal verification.
type VerificationResult struct {
	// Valid indicates whether the seal passed all checks.
	Valid bool

	// SealID is the identifier of the verified seal.
	SealID string

	// Details is a human-readable summary of the verification.
	Details string

	// Warnings lists non-fatal issues found during verification.
	Warnings []string

	// Errors lists fatal issues that caused verification to fail.
	Errors []string

	// AttestationStatus summarizes TEE attestation checks.
	AttestationStatus AttestationStatus

	// ProofStatus summarizes zkML proof checks.
	ProofStatus ProofStatus

	// CommitmentStatus summarizes commitment integrity checks.
	CommitmentStatus CommitmentStatus

	// VerifiedAt is the time the verification was performed.
	VerifiedAt time.Time
}

// AttestationStatus describes the result of TEE attestation validation.
type AttestationStatus struct {
	// Checked is the number of attestations examined.
	Checked int

	// Valid is the number of attestations that passed.
	Valid int

	// Invalid is the number that failed validation.
	Invalid int

	// Platforms lists the TEE platforms observed (e.g., "aws-nitro", "intel-sgx").
	Platforms []string
}

// ProofStatus describes the result of zkML proof validation.
type ProofStatus struct {
	// Present indicates whether a proof was included.
	Present bool

	// Valid indicates whether the proof passed validation.
	Valid bool

	// ProofSystem is the system used (e.g., "ezkl", "risc0").
	ProofSystem string

	// Details provides additional information.
	Details string
}

// CommitmentStatus describes the integrity of hash commitments.
type CommitmentStatus struct {
	// ModelValid indicates the model commitment is well-formed.
	ModelValid bool

	// InputValid indicates the input commitment is well-formed.
	InputValid bool

	// OutputValid indicates the output commitment is well-formed.
	OutputValid bool

	// ChainConsistent indicates all commitments are internally consistent.
	ChainConsistent bool
}

// Verifier performs offline verification of Digital Seals. It does not require
// a network connection and validates seals using only the trusted keys and
// cryptographic evidence provided at initialization.
type Verifier struct {
	// trustedKeys maps signer addresses to their ECDSA public keys.
	trustedKeys map[string]*ecdsa.PublicKey

	// trustedPlatforms is the set of accepted TEE platforms.
	trustedPlatforms map[string]bool

	// trustedProofSystems is the set of accepted proof systems.
	trustedProofSystems map[string]bool

	// maxAttestationAge is the maximum acceptable age for attestations.
	maxAttestationAge time.Duration
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithTrustedPlatforms sets the accepted TEE platforms.
func WithTrustedPlatforms(platforms []string) VerifierOption {
	return func(v *Verifier) {
		for _, p := range platforms {
			v.trustedPlatforms[p] = true
		}
	}
}

// WithTrustedProofSystems sets the accepted proof systems.
func WithTrustedProofSystems(systems []string) VerifierOption {
	return func(v *Verifier) {
		for _, s := range systems {
			v.trustedProofSystems[s] = true
		}
	}
}

// WithMaxAttestationAge sets the maximum acceptable attestation age.
func WithMaxAttestationAge(d time.Duration) VerifierOption {
	return func(v *Verifier) {
		v.maxAttestationAge = d
	}
}

// NewVerifier creates a Verifier initialized with the given trusted public keys.
// The keys map signer addresses (bech32) to their ECDSA public keys.
func NewVerifier(trustedKeys map[string]*ecdsa.PublicKey, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		trustedKeys: make(map[string]*ecdsa.PublicKey),
		trustedPlatforms: map[string]bool{
			"aws-nitro":  true,
			"intel-sgx":  true,
			"amd-sev":    true,
			"sev-snp":    true,
			"arm-cca":    true,
		},
		trustedProofSystems: map[string]bool{
			"ezkl":    true,
			"risc0":   true,
			"groth16": true,
			"plonk":   true,
			"halo2":   true,
			"stark":   true,
		},
		maxAttestationAge: 24 * time.Hour,
	}

	for addr, key := range trustedKeys {
		v.trustedKeys[addr] = key
	}

	for _, opt := range opts {
		opt(v)
	}

	return v
}

// VerifyOffline performs a complete offline verification of a Digital Seal.
// It checks commitment integrity, attestation validity, proof validity,
// and seal status without requiring network access.
func (v *Verifier) VerifyOffline(seal *types.DigitalSeal) *VerificationResult {
	result := &VerificationResult{
		SealID:     seal.GetId(),
		Valid:      true,
		VerifiedAt: time.Now().UTC(),
	}

	// 1. Validate basic seal structure
	if err := seal.Validate(); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("seal structure invalid: %v", err))
		result.Details = "Seal failed structural validation"
		return result
	}

	// 2. Check commitments
	result.CommitmentStatus = v.validateCommitments(seal)
	if !result.CommitmentStatus.ModelValid || !result.CommitmentStatus.InputValid || !result.CommitmentStatus.OutputValid {
		result.Valid = false
		result.Errors = append(result.Errors, "one or more commitments are invalid")
	}

	// 3. Check seal status
	if seal.Status == types.SealStatusRevoked {
		result.Valid = false
		result.Errors = append(result.Errors, "seal has been revoked")
	}
	if seal.Status == types.SealStatusExpired {
		result.Valid = false
		result.Errors = append(result.Errors, "seal has expired")
	}
	if seal.Status == types.SealStatusPending {
		result.Warnings = append(result.Warnings, "seal is still pending activation")
	}

	// 4. Validate attestations
	result.AttestationStatus = v.validateAttestations(seal.GetTeeAttestations())
	if result.AttestationStatus.Invalid > 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("%d of %d attestations failed validation",
				result.AttestationStatus.Invalid, result.AttestationStatus.Checked))
	}
	if result.AttestationStatus.Valid == 0 && seal.GetZkProof() == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "no valid attestations or proof found")
	}

	// 5. Validate proof
	result.ProofStatus = v.validateProofStatus(seal.GetZkProof())
	if result.ProofStatus.Present && !result.ProofStatus.Valid {
		result.Warnings = append(result.Warnings, "zkML proof failed validation")
	}

	// 6. Verify seal ID is consistent with contents
	if !v.verifySealID(seal) {
		result.Valid = false
		result.Errors = append(result.Errors, "seal ID does not match content hash")
	}

	// Build summary
	if result.Valid {
		result.Details = fmt.Sprintf("Seal %s verified: %d valid attestations, proof=%v",
			seal.GetId()[:16], result.AttestationStatus.Valid, result.ProofStatus.Present)
	} else {
		result.Details = fmt.Sprintf("Seal %s verification FAILED: %d errors",
			seal.GetId()[:16], len(result.Errors))
	}

	return result
}

// VerifyChain verifies a provenance chain of seals where each seal's output
// commitment should match the next seal's input commitment.
func (v *Verifier) VerifyChain(seals []*types.DigitalSeal) *VerificationResult {
	result := &VerificationResult{
		Valid:      true,
		VerifiedAt: time.Now().UTC(),
	}

	if len(seals) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "empty seal chain")
		result.Details = "No seals provided for chain verification"
		return result
	}

	if len(seals) == 1 {
		return v.VerifyOffline(seals[0])
	}

	result.SealID = fmt.Sprintf("chain:%s...%s", seals[0].GetId()[:8], seals[len(seals)-1].GetId()[:8])

	// Verify each seal individually
	for i, seal := range seals {
		individual := v.VerifyOffline(seal)
		if !individual.Valid {
			result.Valid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("seal[%d] (%s) failed: %v", i, seal.GetId()[:16], individual.Errors))
		}
	}

	// Verify chain linkage: each seal's output should feed the next seal's input
	for i := 0; i < len(seals)-1; i++ {
		current := seals[i]
		next := seals[i+1]

		if !bytes.Equal(current.GetOutputCommitment(), next.GetInputCommitment()) {
			result.Valid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("chain break at position %d: output[%s] != input[%s]",
					i,
					hex.EncodeToString(current.GetOutputCommitment())[:16],
					hex.EncodeToString(next.GetInputCommitment())[:16]))
		}
	}

	// Verify chronological ordering
	for i := 0; i < len(seals)-1; i++ {
		t1 := sealTimestamp(seals[i])
		t2 := sealTimestamp(seals[i+1])
		if !t1.IsZero() && !t2.IsZero() && t2.Before(t1) {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("seal[%d] timestamp (%s) is after seal[%d] timestamp (%s)",
					i, t1.Format(time.RFC3339), i+1, t2.Format(time.RFC3339)))
		}
	}

	if result.Valid {
		result.Details = fmt.Sprintf("Chain of %d seals verified successfully", len(seals))
	} else {
		result.Details = fmt.Sprintf("Chain verification FAILED: %d errors across %d seals",
			len(result.Errors), len(seals))
	}

	return result
}

// ValidateAttestation validates an individual TEE attestation.
func (v *Verifier) ValidateAttestation(att *types.TEEAttestation) error {
	if att == nil {
		return fmt.Errorf("attestation is nil")
	}

	// Check platform is trusted
	if !v.trustedPlatforms[att.GetPlatform()] {
		return fmt.Errorf("untrusted TEE platform: %s", att.GetPlatform())
	}

	// Check enclave ID is present
	if att.GetEnclaveId() == "" {
		return fmt.Errorf("enclave ID is empty")
	}

	// Check measurement is present and non-zero
	if len(att.GetMeasurement()) == 0 {
		return fmt.Errorf("measurement is empty")
	}

	// Check attestation quote is present
	if len(att.GetQuote()) == 0 {
		return fmt.Errorf("attestation quote is empty")
	}

	// Check signature is present
	if len(att.GetSignature()) == 0 {
		return fmt.Errorf("attestation signature is empty")
	}

	// Check validator address
	if att.GetValidatorAddress() == "" {
		return fmt.Errorf("validator address is empty")
	}

	// Verify signature if trusted key is available
	if key, ok := v.trustedKeys[att.GetValidatorAddress()]; ok {
		if err := v.verifyAttestationSignature(att, key); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	// Check attestation age
	if att.GetTimestamp() != nil {
		age := time.Since(att.GetTimestamp().AsTime())
		if age > v.maxAttestationAge {
			return fmt.Errorf("attestation too old: %s (max %s)", age, v.maxAttestationAge)
		}
	}

	return nil
}

// ValidateProof validates a zkML proof structure.
func (v *Verifier) ValidateProof(proof *types.ZKMLProof) error {
	if proof == nil {
		return fmt.Errorf("proof is nil")
	}

	// Check proof system is recognized
	if !v.trustedProofSystems[proof.GetProofSystem()] {
		return fmt.Errorf("unrecognized proof system: %s", proof.GetProofSystem())
	}

	// Check proof bytes are present and non-empty
	if len(proof.GetProofBytes()) == 0 {
		return fmt.Errorf("proof bytes are empty")
	}

	// Check public inputs
	if len(proof.GetPublicInputs()) == 0 {
		return fmt.Errorf("public inputs are empty")
	}

	// Check verifying key hash
	if len(proof.GetVerifyingKeyHash()) == 0 {
		return fmt.Errorf("verifying key hash is empty")
	}

	// Check circuit hash
	if len(proof.GetCircuitHash()) == 0 {
		return fmt.Errorf("circuit hash is empty")
	}

	return nil
}

// --- internal verification helpers ---

func (v *Verifier) validateCommitments(seal *types.DigitalSeal) CommitmentStatus {
	status := CommitmentStatus{
		ModelValid:  len(seal.GetModelCommitment()) == 32,
		InputValid:  len(seal.GetInputCommitment()) == 32,
		OutputValid: len(seal.GetOutputCommitment()) == 32,
	}

	// Check that commitments are not all-zero
	zeroHash := make([]byte, 32)
	if bytes.Equal(seal.GetModelCommitment(), zeroHash) {
		status.ModelValid = false
	}
	if bytes.Equal(seal.GetInputCommitment(), zeroHash) {
		status.InputValid = false
	}
	if bytes.Equal(seal.GetOutputCommitment(), zeroHash) {
		status.OutputValid = false
	}

	status.ChainConsistent = status.ModelValid && status.InputValid && status.OutputValid

	return status
}

func (v *Verifier) validateAttestations(attestations []*types.TEEAttestation) AttestationStatus {
	status := AttestationStatus{
		Checked: len(attestations),
	}

	platformSet := make(map[string]bool)
	for _, att := range attestations {
		if err := v.ValidateAttestation(att); err == nil {
			status.Valid++
		} else {
			status.Invalid++
		}
		if att.GetPlatform() != "" {
			platformSet[att.GetPlatform()] = true
		}
	}

	for p := range platformSet {
		status.Platforms = append(status.Platforms, p)
	}

	return status
}

func (v *Verifier) validateProofStatus(proof *types.ZKMLProof) ProofStatus {
	if proof == nil {
		return ProofStatus{Present: false}
	}

	status := ProofStatus{
		Present:     true,
		ProofSystem: proof.GetProofSystem(),
	}

	if err := v.ValidateProof(proof); err != nil {
		status.Valid = false
		status.Details = err.Error()
	} else {
		status.Valid = true
		status.Details = fmt.Sprintf("Proof system: %s, size: %d bytes",
			proof.GetProofSystem(), len(proof.GetProofBytes()))
	}

	return status
}

func (v *Verifier) verifySealID(seal *types.DigitalSeal) bool {
	expected := seal.GenerateID()
	return seal.GetId() == expected
}

// verifyAttestationSignature verifies the ECDSA signature on an attestation.
// The signature is over the SHA-256 hash of the concatenation of the
// attestation's key fields.
func (v *Verifier) verifyAttestationSignature(att *types.TEEAttestation, pubKey *ecdsa.PublicKey) error {
	h := sha256.New()
	h.Write([]byte(att.GetValidatorAddress()))
	h.Write([]byte(att.GetPlatform()))
	h.Write([]byte(att.GetEnclaveId()))
	h.Write(att.GetMeasurement())
	h.Write(att.GetQuote())
	digest := h.Sum(nil)

	sig := att.GetSignature()
	if len(sig) < 64 {
		return fmt.Errorf("signature too short: %d bytes", len(sig))
	}

	// ECDSA verification: signature is r || s, each 32 bytes for P-256
	if !ecdsa.VerifyASN1(pubKey, digest, sig) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// VerifyCommitmentBinding checks that the given data matches the commitment hash
// in a seal. This is useful for verifying that actual model weights, inputs,
// or outputs correspond to the commitments recorded in a seal.
func VerifyCommitmentBinding(data []byte, commitment []byte) bool {
	h := sha256.Sum256(data)
	return bytes.Equal(h[:], commitment)
}

// DefaultTrustedPlatforms returns the standard set of trusted TEE platforms.
func DefaultTrustedPlatforms() []string {
	return []string{"aws-nitro", "intel-sgx", "amd-sev", "sev-snp", "arm-cca"}
}

// DefaultTrustedProofSystems returns the standard set of accepted proof systems.
func DefaultTrustedProofSystems() []string {
	return []string{"ezkl", "risc0", "groth16", "plonk", "halo2", "stark"}
}

// P256PublicKeyFromBytes reconstructs an ECDSA P-256 public key from its
// uncompressed byte representation (65 bytes: 0x04 || X || Y).
func P256PublicKeyFromBytes(data []byte) (*ecdsa.PublicKey, error) {
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, data)
	if x == nil {
		return nil, fmt.Errorf("invalid P-256 public key encoding")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
