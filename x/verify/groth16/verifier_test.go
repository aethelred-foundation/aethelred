package groth16

import (
	"math/big"
	"testing"
)

func testG1(x, y int64) *G1Point {
	return &G1Point{X: big.NewInt(x), Y: big.NewInt(y)}
}

func testG2(x0, x1, y0, y1 int64) *G2Point {
	return &G2Point{
		X: [2]*big.Int{big.NewInt(x0), big.NewInt(x1)},
		Y: [2]*big.Int{big.NewInt(y0), big.NewInt(y1)},
	}
}

func testProof() *Proof {
	return &Proof{
		A: testG1(1, 2),
		B: testG2(1, 2, 3, 4),
		C: testG1(1, 2),
	}
}

func testVerifyingKey() *VerifyingKey {
	return &VerifyingKey{
		Alpha:     testG1(1, 2),
		Beta:      testG2(1, 2, 3, 4),
		Gamma:     testG2(5, 6, 7, 8),
		Delta:     testG2(9, 10, 11, 12),
		IC:        []*G1Point{testG1(1, 2)},
		NumInputs: 0,
	}
}

func testInputs() *PublicInputs {
	return &PublicInputs{
		Values: []*big.Int{},
	}
}

// testProof()'s points are placeholders that are not valid BN254 group
// elements, so the real pairing backend must reject them (the verifier no
// longer fails closed — it actually verifies, and invalid points fail the
// on-curve / subgroup checks). A genuine valid-proof acceptance test lives in
// bn254_gnark_test.go.
func TestVerifierRejectsInvalidProofPoints(t *testing.T) {
	verifier := NewVerifier()

	verified, err := verifier.Verify(testProof(), testVerifyingKey(), testInputs())
	if verified {
		t.Fatal("verifier accepted a proof with invalid (off-curve) points")
	}
	if err == nil {
		t.Fatal("expected an error rejecting the invalid proof, got nil")
	}
}

func TestVerifyGroth16WithPairingRejectsInvalidProofPoints(t *testing.T) {
	verified, err := VerifyGroth16WithPairing(testProof(), testVerifyingKey(), testInputs())
	if verified {
		t.Fatal("VerifyGroth16WithPairing accepted a proof with invalid (off-curve) points")
	}
	if err == nil {
		t.Fatal("expected an error rejecting the invalid proof, got nil")
	}
}
