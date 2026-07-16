package groth16

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func g1ToPoint(p bn254.G1Affine) *G1Point {
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	return &G1Point{X: &x, Y: &y}
}

func g2ToPoint(p bn254.G2Affine) *G2Point {
	var x0, x1, y0, y1 big.Int
	p.X.A0.BigInt(&x0)
	p.X.A1.BigInt(&x1)
	p.Y.A0.BigInt(&y0)
	p.Y.A1.BigInt(&y1)
	return &G2Point{X: [2]*big.Int{&x0, &x1}, Y: [2]*big.Int{&y0, &y1}}
}

// buildInstance constructs a real Groth16 (proof, vk) by satisfying the
// verification equation in the exponent. With
//
//	A=[a]g1, B=[b]g2, α=[s]g1, β=[t]g2, vk_x=[x]g1, γ=[y]g2, C=[c]g1, δ=[z]g2
//
// the check e(A,B) = e(α,β)·e(vk_x,γ)·e(C,δ) holds iff a·b = s·t + x·y + c·z
// (mod r). We use 0 public inputs so vk_x = IC[0] = [x]g1. Every point is a real
// BN254 group element (on-curve, in the prime-order subgroup), so this exercises
// the real pairing — no circuit/prover required.
func buildInstance(a, b, s, tt, x, y, c, z *big.Int) (*Proof, *VerifyingKey) {
	_, _, g1, g2 := bn254.Generators()
	sg1 := func(k *big.Int) bn254.G1Affine { var p bn254.G1Affine; p.ScalarMultiplication(&g1, k); return p }
	sg2 := func(k *big.Int) bn254.G2Affine { var p bn254.G2Affine; p.ScalarMultiplication(&g2, k); return p }

	proof := &Proof{
		A: g1ToPoint(sg1(a)),
		B: g2ToPoint(sg2(b)),
		C: g1ToPoint(sg1(c)),
	}
	vk := &VerifyingKey{
		Alpha:     g1ToPoint(sg1(s)),
		Beta:      g2ToPoint(sg2(tt)),
		Gamma:     g2ToPoint(sg2(y)),
		Delta:     g2ToPoint(sg2(z)),
		IC:        []*G1Point{g1ToPoint(sg1(x))},
		NumInputs: 0,
	}
	return proof, vk
}

func TestGroth16RealPairing_AcceptsValid_RejectsTampered(t *testing.T) {
	r := fr.Modulus()
	s := big.NewInt(3)
	tt := big.NewInt(5)
	x := big.NewInt(7)
	y := big.NewInt(11)
	c := big.NewInt(13)
	z := big.NewInt(17)
	// a = 1, b = (s*t + x*y + c*z) mod r  =>  a*b = s*t + x*y + c*z
	b := new(big.Int).Mul(s, tt)
	b.Add(b, new(big.Int).Mul(x, y))
	b.Add(b, new(big.Int).Mul(c, z))
	b.Mod(b, r)
	a := big.NewInt(1)

	proof, vk := buildInstance(a, b, s, tt, x, y, c, z)
	inputs := &PublicInputs{Values: []*big.Int{}}

	v := NewVerifier()

	// 1) A valid proof verifies via the public Verifier path.
	ok, err := v.Verify(proof, vk, inputs)
	if err != nil {
		t.Fatalf("Verify returned error on a valid proof: %v", err)
	}
	if !ok {
		t.Fatal("a valid Groth16 proof was REJECTED — pairing backend is wrong")
	}

	// 2) And via the alternate entry point.
	ok2, err := VerifyGroth16WithPairing(proof, vk, inputs)
	if err != nil || !ok2 {
		t.Fatalf("VerifyGroth16WithPairing rejected a valid proof: ok=%v err=%v", ok2, err)
	}

	// 3) A tampered proof (a=2, breaking a*b = s*t+x*y+c*z) must be rejected.
	//    All points remain on-curve and in-subgroup; only the relation breaks.
	tampered, _ := buildInstance(big.NewInt(2), b, s, tt, x, y, c, z)
	bad, err := v.Verify(tampered, vk, inputs)
	if err != nil {
		t.Fatalf("Verify returned error on a tampered proof: %v", err)
	}
	if bad {
		t.Fatal("a tampered Groth16 proof was ACCEPTED — verifier is unsound")
	}
}
