// bn254_pairing.go holds the public Groth16 entry point and verifying-key
// validation. The real cryptographic verification (BN254 pairing with on-curve
// and prime-order-subgroup checks) lives in bn254_gnark.go, backed by
// github.com/consensys/gnark-crypto.
package groth16

import "errors"

// VerifyGroth16WithPairing verifies a Groth16 proof using a real BN254 pairing.
// It validates the proof and verifying key, then checks
//
//	e(A, B) = e(α, β) · e(vk_x, γ) · e(C, δ)
//
// via verifyGroth16Gnark (see bn254_gnark.go).
func VerifyGroth16WithPairing(proof *Proof, vk *VerifyingKey, inputs *PublicInputs) (bool, error) {
	if err := proof.Validate(); err != nil {
		return false, err
	}
	if err := validateVerifyingKey(vk); err != nil {
		return false, err
	}
	if len(inputs.Values) != vk.NumInputs {
		return false, errors.New("input count mismatch")
	}
	return verifyGroth16Gnark(proof, vk, inputs.Values)
}

// validateVerifyingKey validates a verifying key's structure.
func validateVerifyingKey(vk *VerifyingKey) error {
	if vk == nil {
		return errors.New("verifying key is nil")
	}
	if vk.Alpha == nil || vk.Beta == nil || vk.Gamma == nil || vk.Delta == nil {
		return errors.New("verifying key has nil elements")
	}
	if len(vk.IC) == 0 {
		return errors.New("verifying key has no IC points")
	}
	return nil
}

// EstimateGroth16GasCost estimates the gas cost for Groth16 verification, based
// on Ethereum EIP-1108 repriced precompiles (ECADD 150, ECMUL 6000, pairing
// 45000 + 34000·k).
func EstimateGroth16GasCost(numInputs int) uint64 {
	const (
		ecMulCost          = uint64(6000)
		ecAddCost          = uint64(150)
		pairingBaseCost    = uint64(45000)
		pairingPerPairCost = uint64(34000)
	)
	// vk_x: numInputs scalar muls + numInputs point adds; pairing check: 4 pairs.
	vkXCost := uint64(numInputs)*ecMulCost + uint64(numInputs)*ecAddCost
	pairingCost := pairingBaseCost + 4*pairingPerPairCost
	return vkXCost + pairingCost
}
