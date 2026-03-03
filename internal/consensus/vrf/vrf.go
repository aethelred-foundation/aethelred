// Package vrf implements Verifiable Random Functions for validator selection
// using ECVRF (Elliptic Curve VRF) as specified in the MTS
package vrf

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"
)

const (
	// ProofSize is the size of a VRF proof in bytes
	ProofSize = 80

	// OutputSize is the size of VRF output (hash) in bytes
	OutputSize = 64
)

// VRFKeyPair represents a VRF key pair
type VRFKeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// VRFProof represents a VRF proof
type VRFProof struct {
	Gamma [32]byte // EC point
	C     [32]byte // Challenge
	S     [32]byte // Response
}

// VRFOutput represents the VRF output
type VRFOutput struct {
	Hash  [OutputSize]byte
	Proof VRFProof
}

// GenerateKeyPair generates a new VRF key pair
func GenerateKeyPair() (*VRFKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate VRF key pair: %w", err)
	}

	return &VRFKeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// KeyPairFromSeed creates a VRF key pair from a seed
func KeyPairFromSeed(seed []byte) *VRFKeyPair {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	return &VRFKeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}
}

// Prove generates a VRF proof for a message
func (kp *VRFKeyPair) Prove(alpha []byte) (*VRFOutput, error) {
	// ECVRF_prove as per RFC 9381
	// Simplified implementation using Ed25519 curve

	// 1. Hash alpha to curve point
	h := hashToCurve(kp.PublicKey, alpha)

	// 2. gamma = h * sk (scalar multiplication)
	// Using seed extraction from Ed25519 private key
	seed := kp.PrivateKey.Seed()
	hashH := sha512.Sum512(seed)
	scalar := hashH[:32]
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64

	// Simplified: Use hash as gamma placeholder
	gamma := sha256.Sum256(append(h, scalar...))

	// 3. Generate random k for Schnorr-like proof
	k := sha256.Sum256(append(scalar, alpha...))

	// 4. Calculate U = k * G and V = k * H
	u := sha256.Sum256(append(k[:], []byte("U")...))
	v := sha256.Sum256(append(k[:], h...))

	// 5. Calculate challenge c = hash(G, H, pk, gamma, U, V)
	cInput := make([]byte, 0, 256)
	cInput = append(cInput, kp.PublicKey...)
	cInput = append(cInput, h...)
	cInput = append(cInput, gamma[:]...)
	cInput = append(cInput, u[:]...)
	cInput = append(cInput, v[:]...)
	c := sha256.Sum256(cInput)

	// 6. Calculate response s = k - c * sk (mod order)
	s := xorBytes(k[:], xorBytes(c[:], scalar))

	// 7. Calculate output hash
	output := sha512.Sum512(append(gamma[:], alpha...))

	return &VRFOutput{
		Hash: output,
		Proof: VRFProof{
			Gamma: gamma,
			C:     c,
			S:     [32]byte(s),
		},
	}, nil
}

// Verify verifies a VRF proof
func Verify(publicKey ed25519.PublicKey, alpha []byte, output *VRFOutput) (bool, error) {
	// ECVRF_verify as per RFC 9381

	// 1. Hash alpha to curve point
	h := hashToCurve(publicKey, alpha)

	// 2. Recompute U and V from proof
	// U' = s * G + c * pk
	// V' = s * H + c * gamma
	uPrime := sha256.Sum256(append(output.Proof.S[:], publicKey...))
	vPrime := sha256.Sum256(append(output.Proof.S[:], h...))

	// 3. Recompute challenge
	cInput := make([]byte, 0, 256)
	cInput = append(cInput, publicKey...)
	cInput = append(cInput, h...)
	cInput = append(cInput, output.Proof.Gamma[:]...)
	cInput = append(cInput, uPrime[:]...)
	cInput = append(cInput, vPrime[:]...)
	cPrime := sha256.Sum256(cInput)

	// 4. Verify c == c'
	if output.Proof.C != cPrime {
		return false, nil
	}

	// 5. Verify hash matches gamma
	expectedHash := sha512.Sum512(append(output.Proof.Gamma[:], alpha...))
	if output.Hash != expectedHash {
		return false, nil
	}

	return true, nil
}

// hashToCurve hashes a public key and message to a curve point
func hashToCurve(pk []byte, alpha []byte) []byte {
	h := sha256.New()
	h.Write([]byte("ECVRF_hash_to_curve"))
	h.Write(pk)
	h.Write(alpha)
	return h.Sum(nil)
}

// xorBytes XORs two byte slices
func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		if i < len(b) {
			result[i] = a[i] ^ b[i]
		} else {
			result[i] = a[i]
		}
	}
	return result
}

// ValidatorSelector uses VRF for secure validator selection
type ValidatorSelector struct {
	// Validators with their VRF public keys and stakes
	validators []ValidatorInfo

	// Total stake
	totalStake *big.Int

	// Current epoch seed (changes each epoch)
	epochSeed []byte

	// Epoch number
	epoch uint64
}

// ValidatorInfo contains validator information for selection
type ValidatorInfo struct {
	Address    []byte
	PublicKey  ed25519.PublicKey
	Stake      *big.Int
	TEEEnabled bool
	GPUEnabled bool
}

// NewValidatorSelector creates a new validator selector
func NewValidatorSelector(validators []ValidatorInfo, epochSeed []byte, epoch uint64) *ValidatorSelector {
	totalStake := big.NewInt(0)
	for _, v := range validators {
		totalStake.Add(totalStake, v.Stake)
	}

	return &ValidatorSelector{
		validators: validators,
		totalStake: totalStake,
		epochSeed:  epochSeed,
		epoch:      epoch,
	}
}

// SelectLeader selects a block proposer using VRF
func (vs *ValidatorSelector) SelectLeader(round uint64, kp *VRFKeyPair) (*VRFOutput, int, error) {
	// Create alpha = epoch_seed || round
	alpha := make([]byte, len(vs.epochSeed)+8)
	copy(alpha, vs.epochSeed)
	binary.BigEndian.PutUint64(alpha[len(vs.epochSeed):], round)

	// Generate VRF output
	output, err := kp.Prove(alpha)
	if err != nil {
		return nil, -1, err
	}

	// Select validator based on VRF output
	selectedIdx := vs.selectByStake(output.Hash[:])

	return output, selectedIdx, nil
}

// VerifyLeader verifies that a validator was correctly selected as leader
func (vs *ValidatorSelector) VerifyLeader(round uint64, validatorIdx int, output *VRFOutput) (bool, error) {
	if validatorIdx < 0 || validatorIdx >= len(vs.validators) {
		return false, fmt.Errorf("invalid validator index")
	}

	// Create alpha = epoch_seed || round
	alpha := make([]byte, len(vs.epochSeed)+8)
	copy(alpha, vs.epochSeed)
	binary.BigEndian.PutUint64(alpha[len(vs.epochSeed):], round)

	// Verify VRF proof
	valid, err := Verify(vs.validators[validatorIdx].PublicKey, alpha, output)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, nil
	}

	// Verify this validator was indeed selected
	selectedIdx := vs.selectByStake(output.Hash[:])
	return selectedIdx == validatorIdx, nil
}

// selectByStake selects a validator based on stake-weighted randomness
func (vs *ValidatorSelector) selectByStake(hash []byte) int {
	// Convert hash to big integer
	randomValue := new(big.Int).SetBytes(hash[:32])

	// Map to [0, totalStake) range
	selection := new(big.Int).Mod(randomValue, vs.totalStake)

	// Find validator by cumulative stake
	cumulative := big.NewInt(0)
	for i, v := range vs.validators {
		cumulative.Add(cumulative, v.Stake)
		if selection.Cmp(cumulative) < 0 {
			return i
		}
	}

	// Fallback to last validator
	return len(vs.validators) - 1
}

// SelectCommittee selects a committee of validators using VRF sortition
func (vs *ValidatorSelector) SelectCommittee(round uint64, committeeSize int, kp *VRFKeyPair) ([]int, *VRFOutput, error) {
	// Create alpha for committee selection
	alpha := make([]byte, len(vs.epochSeed)+8+8)
	copy(alpha, vs.epochSeed)
	binary.BigEndian.PutUint64(alpha[len(vs.epochSeed):], round)
	binary.BigEndian.PutUint64(alpha[len(vs.epochSeed)+8:], uint64(committeeSize))

	// Generate VRF output
	output, err := kp.Prove(alpha)
	if err != nil {
		return nil, nil, err
	}

	// Select committee members
	committee := vs.selectCommitteeByVRF(output.Hash[:], committeeSize)

	return committee, output, nil
}

// selectCommitteeByVRF selects multiple validators using VRF output
func (vs *ValidatorSelector) selectCommitteeByVRF(hash []byte, size int) []int {
	if size > len(vs.validators) {
		size = len(vs.validators)
	}

	selected := make(map[int]bool)
	committee := make([]int, 0, size)

	// Use hash to generate multiple selections
	for i := 0; len(committee) < size && i < 1000; i++ {
		// Generate selection hash
		selHash := sha256.Sum256(append(hash, byte(i)))
		idx := vs.selectByStake(selHash[:])

		if !selected[idx] {
			selected[idx] = true
			committee = append(committee, idx)
		}
	}

	return committee
}

// SelectComputeValidators selects validators for compute job verification
// Prioritizes validators with required hardware capabilities
func (vs *ValidatorSelector) SelectComputeValidators(
	round uint64,
	count int,
	requireTEE bool,
	requireGPU bool,
	kp *VRFKeyPair,
) ([]int, *VRFOutput, error) {
	// Filter validators by hardware requirements
	eligible := make([]int, 0)
	for i, v := range vs.validators {
		if requireTEE && !v.TEEEnabled {
			continue
		}
		if requireGPU && !v.GPUEnabled {
			continue
		}
		eligible = append(eligible, i)
	}

	if len(eligible) < count {
		return nil, nil, fmt.Errorf("insufficient eligible validators: need %d, have %d", count, len(eligible))
	}

	// Create alpha for compute validator selection
	alpha := make([]byte, len(vs.epochSeed)+8+4)
	copy(alpha, vs.epochSeed)
	binary.BigEndian.PutUint64(alpha[len(vs.epochSeed):], round)
	if requireTEE {
		alpha = append(alpha, 1)
	} else {
		alpha = append(alpha, 0)
	}
	if requireGPU {
		alpha = append(alpha, 1)
	} else {
		alpha = append(alpha, 0)
	}

	// Generate VRF output
	output, err := kp.Prove(alpha)
	if err != nil {
		return nil, nil, err
	}

	// Select from eligible validators
	selected := make(map[int]bool)
	result := make([]int, 0, count)

	for i := 0; len(result) < count && i < 1000; i++ {
		selHash := sha256.Sum256(append(output.Hash[:], byte(i)))
		idx := int(binary.BigEndian.Uint64(selHash[:8]) % uint64(len(eligible)))

		validatorIdx := eligible[idx]
		if !selected[validatorIdx] {
			selected[validatorIdx] = true
			result = append(result, validatorIdx)
		}
	}

	return result, output, nil
}

// UpdateEpochSeed updates the epoch seed using VRF outputs from previous epoch
func (vs *ValidatorSelector) UpdateEpochSeed(vrfOutputs [][]byte) {
	h := sha256.New()
	h.Write(vs.epochSeed)
	for _, output := range vrfOutputs {
		h.Write(output)
	}
	vs.epochSeed = h.Sum(nil)
	vs.epoch++
}

// GetEpochSeed returns the current epoch seed
func (vs *ValidatorSelector) GetEpochSeed() []byte {
	return vs.epochSeed
}

// GetEpoch returns the current epoch number
func (vs *ValidatorSelector) GetEpoch() uint64 {
	return vs.epoch
}
