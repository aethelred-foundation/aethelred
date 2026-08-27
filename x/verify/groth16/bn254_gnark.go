package groth16

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// This file provides the real BN254 pairing-based Groth16 verification, backed
// by github.com/consensys/gnark-crypto. It replaces the previous fail-closed
// stub (ErrPairingBackendUnavailable).
//
// Soundness note: every proof and verifying-key point is checked to be on the
// curve AND in the prime-order subgroup before pairing. Skipping the subgroup
// check would expose the verifier to small-subgroup / invalid-curve attacks, so
// these checks are mandatory, not optional.
//
// G2 coordinate convention: a G2Point's X = [A0, A1] and Y = [A0, A1], matching
// gnark-crypto's Fp2 element E2 = A0 + A1·u. Any prover serializing proofs into
// this verifier's Proof/VerifyingKey JSON format MUST use the same ordering.

// toAffineG1 converts an affine (x,y) big.Int point to a gnark G1Affine,
// rejecting points off the curve or outside the prime-order subgroup.
func toAffineG1(x, y *big.Int) (bn254.G1Affine, error) {
	var p bn254.G1Affine
	if x == nil || y == nil {
		return p, errors.New("nil G1 coordinate")
	}
	p.X.SetBigInt(x)
	p.Y.SetBigInt(y)
	if !p.IsOnCurve() {
		return p, errors.New("G1 point not on curve")
	}
	if !p.IsInSubGroup() {
		return p, errors.New("G1 point not in prime-order subgroup")
	}
	return p, nil
}

// toAffineG2 converts an affine Fp2 (x,y) point to a gnark G2Affine, rejecting
// points off the curve or outside the prime-order subgroup.
func toAffineG2(x, y [2]*big.Int) (bn254.G2Affine, error) {
	var p bn254.G2Affine
	if x[0] == nil || x[1] == nil || y[0] == nil || y[1] == nil {
		return p, errors.New("nil G2 coordinate")
	}
	p.X.A0.SetBigInt(x[0])
	p.X.A1.SetBigInt(x[1])
	p.Y.A0.SetBigInt(y[0])
	p.Y.A1.SetBigInt(y[1])
	if !p.IsOnCurve() {
		return p, errors.New("G2 point not on curve")
	}
	if !p.IsInSubGroup() {
		return p, errors.New("G2 point not in prime-order subgroup")
	}
	return p, nil
}

// computeVkXGnark returns vk_x = IC[0] + Σ(inputs[i] · IC[i+1]) using real group
// operations.
func computeVkXGnark(ic []*G1Point, inputs []*big.Int) (bn254.G1Affine, error) {
	var acc bn254.G1Affine
	if len(ic) == 0 {
		return acc, errors.New("verifying key IC is empty")
	}
	if len(inputs) != len(ic)-1 {
		return acc, fmt.Errorf("input count %d does not match IC length %d", len(inputs), len(ic)-1)
	}
	acc, err := toAffineG1(ic[0].X, ic[0].Y)
	if err != nil {
		return acc, fmt.Errorf("IC[0]: %w", err)
	}
	for i, in := range inputs {
		if in == nil || in.Sign() == 0 {
			continue
		}
		base, err := toAffineG1(ic[i+1].X, ic[i+1].Y)
		if err != nil {
			return acc, fmt.Errorf("IC[%d]: %w", i+1, err)
		}
		var scaled, sum bn254.G1Affine
		scaled.ScalarMultiplication(&base, in)
		sum.Add(&acc, &scaled)
		acc = sum
	}
	return acc, nil
}

// verifyGroth16Gnark performs the real Groth16 pairing check:
//
//	e(A, B) == e(α, β) · e(vk_x, γ) · e(C, δ)
//
// rearranged to a single product that must equal the identity:
//
//	e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
func verifyGroth16Gnark(proof *Proof, vk *VerifyingKey, inputs []*big.Int) (bool, error) {
	if proof == nil || proof.A == nil || proof.B == nil || proof.C == nil {
		return false, errors.New("proof is incomplete")
	}
	if vk == nil || vk.Alpha == nil || vk.Beta == nil || vk.Gamma == nil || vk.Delta == nil {
		return false, errors.New("verifying key is incomplete")
	}

	a, err := toAffineG1(proof.A.X, proof.A.Y)
	if err != nil {
		return false, fmt.Errorf("proof.A: %w", err)
	}
	c, err := toAffineG1(proof.C.X, proof.C.Y)
	if err != nil {
		return false, fmt.Errorf("proof.C: %w", err)
	}
	alpha, err := toAffineG1(vk.Alpha.X, vk.Alpha.Y)
	if err != nil {
		return false, fmt.Errorf("vk.Alpha: %w", err)
	}
	b, err := toAffineG2(proof.B.X, proof.B.Y)
	if err != nil {
		return false, fmt.Errorf("proof.B: %w", err)
	}
	beta, err := toAffineG2(vk.Beta.X, vk.Beta.Y)
	if err != nil {
		return false, fmt.Errorf("vk.Beta: %w", err)
	}
	gamma, err := toAffineG2(vk.Gamma.X, vk.Gamma.Y)
	if err != nil {
		return false, fmt.Errorf("vk.Gamma: %w", err)
	}
	delta, err := toAffineG2(vk.Delta.X, vk.Delta.Y)
	if err != nil {
		return false, fmt.Errorf("vk.Delta: %w", err)
	}

	vkx, err := computeVkXGnark(vk.IC, inputs)
	if err != nil {
		return false, fmt.Errorf("vk_x: %w", err)
	}

	var negA bn254.G1Affine
	negA.Neg(&a)

	ok, err := bn254.PairingCheck(
		[]bn254.G1Affine{negA, alpha, vkx, c},
		[]bn254.G2Affine{b, beta, gamma, delta},
	)
	if err != nil {
		return false, fmt.Errorf("pairing check: %w", err)
	}
	return ok, nil
}
