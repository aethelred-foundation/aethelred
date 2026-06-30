// Command aethelred-zkml-demo demonstrates the real BN254 Groth16 zkML proof
// verification end to end. It constructs a mathematically valid proof, verifies
// it with the chain's verifier, then shows that a tampered proof and an
// off-curve point are rejected. No circuit/prover or hardware is required — the
// proof is built algebraically so the focus is the real pairing verification
// the chain runs on-chain.
package main

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/aethelred/aethelred/x/verify/groth16"
)

func g1ToPoint(p bn254.G1Affine) *groth16.G1Point {
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	return &groth16.G1Point{X: &x, Y: &y}
}

func g2ToPoint(p bn254.G2Affine) *groth16.G2Point {
	var x0, x1, y0, y1 big.Int
	p.X.A0.BigInt(&x0)
	p.X.A1.BigInt(&x1)
	p.Y.A0.BigInt(&y0)
	p.Y.A1.BigInt(&y1)
	return &groth16.G2Point{X: [2]*big.Int{&x0, &x1}, Y: [2]*big.Int{&y0, &y1}}
}

// buildInstance constructs a real Groth16 (proof, vk) satisfying the
// verification equation in the exponent: with A=[a]g1, B=[b]g2, α=[s]g1,
// β=[t]g2, vk_x=[x]g1, γ=[y]g2, C=[c]g1, δ=[z]g2 the check holds iff
// a·b = s·t + x·y + c·z (mod r). 0 public inputs ⇒ vk_x = IC[0].
func buildInstance(a, b, s, tt, x, y, c, z *big.Int) (*groth16.Proof, *groth16.VerifyingKey) {
	_, _, g1, g2 := bn254.Generators()
	sg1 := func(k *big.Int) bn254.G1Affine { var p bn254.G1Affine; p.ScalarMultiplication(&g1, k); return p }
	sg2 := func(k *big.Int) bn254.G2Affine { var p bn254.G2Affine; p.ScalarMultiplication(&g2, k); return p }
	proof := &groth16.Proof{A: g1ToPoint(sg1(a)), B: g2ToPoint(sg2(b)), C: g1ToPoint(sg1(c))}
	vk := &groth16.VerifyingKey{
		Alpha:     g1ToPoint(sg1(s)),
		Beta:      g2ToPoint(sg2(tt)),
		Gamma:     g2ToPoint(sg2(y)),
		Delta:     g2ToPoint(sg2(z)),
		IC:        []*groth16.G1Point{g1ToPoint(sg1(x))},
		NumInputs: 0,
	}
	return proof, vk
}

func verdict(ok bool, err error, wantAccept bool) string {
	accepted := ok && err == nil
	if accepted != wantAccept {
		return fmt.Sprintf("UNEXPECTED (ok=%v err=%v)", ok, err)
	}
	if accepted {
		return "ACCEPTED  ✓"
	}
	if err != nil {
		return "REJECTED (" + err.Error() + ")  ✓"
	}
	return "REJECTED  ✓"
}

func main() {
	r := fr.Modulus()
	s, tt, x, y, c, z := big.NewInt(3), big.NewInt(5), big.NewInt(7), big.NewInt(11), big.NewInt(13), big.NewInt(17)
	b := new(big.Int).Mul(s, tt)
	b.Add(b, new(big.Int).Mul(x, y))
	b.Add(b, new(big.Int).Mul(c, z))
	b.Mod(b, r)
	a := big.NewInt(1)

	proof, vk := buildInstance(a, b, s, tt, x, y, c, z)
	inputs := &groth16.PublicInputs{Values: []*big.Int{}}
	v := groth16.NewVerifier()

	fmt.Println("======================================================================")
	fmt.Println("Aethelred zkML — real BN254 Groth16 proof verification (gnark-crypto)")
	fmt.Println("======================================================================")

	ok, err := v.Verify(proof, vk, inputs)
	fmt.Printf("  Valid proof            : %s\n", verdict(ok, err, true))

	tampered, _ := buildInstance(big.NewInt(2), b, s, tt, x, y, c, z)
	okT, errT := v.Verify(tampered, vk, inputs)
	fmt.Printf("  Tampered proof (a=2)   : %s\n", verdict(okT, errT, false))

	offCurve, _ := buildInstance(a, b, s, tt, x, y, c, z)
	offCurve.A = &groth16.G1Point{X: big.NewInt(1), Y: big.NewInt(1)} // (1,1) ∉ y²=x³+3
	okO, errO := v.Verify(offCurve, vk, inputs)
	fmt.Printf("  Off-curve proof point  : %s\n", verdict(okO, errO, false))

	if ok && err == nil && !okT && !okO {
		fmt.Println("\nReal pairing verification confirmed: valid proof accepted; tampered and")
		fmt.Println("off-curve proofs rejected (on-curve + prime-order-subgroup checks enforced).")
		fmt.Println("In production a prover/circuit supplies the proofs; the chain verifies them")
		fmt.Println("with this exact code. Trust boundary = the circuit's verifying key.")
		return
	}
	fmt.Fprintln(os.Stderr, "\nUNEXPECTED RESULT — verification did not behave as expected.")
	os.Exit(1)
}
