package keeper

import (
	"bytes"
	"testing"
	"time"

	"github.com/aethelred/aethelred/crypto/pqc"
	"github.com/aethelred/aethelred/x/seal/types"
)

// TestHybridSealSignatureVerifier proves the verifier accepts a genuine hybrid
// quorum signature over the seal's canonical claim and rejects every tampering:
// a mutated signature, a non-hybrid algorithm, a signature over a different
// claim, and a nil seal. The crypto is real (Cloudflare circl ML-DSA + secp256k1
// via crypto/pqc) — no simulation.
func TestHybridSealSignatureVerifier(t *testing.T) {
	w, err := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	if err != nil {
		t.Fatalf("new dual-key wallet: %v", err)
	}

	seal := &types.EnhancedDigitalSeal{JobID: "job-7", ChainID: "aethelred-testnet-1"}
	seal.ModelCommitment = bytes.Repeat([]byte{0x11}, 32)
	seal.InputCommitment = bytes.Repeat([]byte{0x22}, 32)
	seal.OutputCommitment = bytes.Repeat([]byte{0x33}, 32)

	sigBytes, err := w.SignHybrid(seal.SealClaim().SigningBytes())
	if err != nil {
		t.Fatalf("sign hybrid: %v", err)
	}
	good := types.NewValidatorSealSignature(
		"aethelvaloper1xyz", w.HybridPublicKey(), sigBytes, time.Unix(0, 0).UTC(),
	)

	// 1. Genuine signature verifies.
	if !HybridSealSignatureVerifier(good, seal) {
		t.Fatal("genuine hybrid seal signature should verify")
	}

	// 2. A single flipped byte in the signature is rejected.
	tampered := good
	tampered.Signature = append([]byte(nil), good.Signature...)
	tampered.Signature[0] ^= 0xFF
	if HybridSealSignatureVerifier(tampered, seal) {
		t.Fatal("tampered signature must be rejected")
	}

	// 3. A non-hybrid algorithm label is rejected (out of scope for this hook).
	wrongAlgo := good
	wrongAlgo.Algorithm = "ed25519"
	if HybridSealSignatureVerifier(wrongAlgo, seal) {
		t.Fatal("non-hybrid algorithm must be rejected")
	}

	// 4. The same signature against a seal with a different output commitment
	//    (i.e. a different claim) is rejected — binding the seal to its output.
	mutated := &types.EnhancedDigitalSeal{JobID: seal.JobID, ChainID: seal.ChainID}
	mutated.ModelCommitment = seal.ModelCommitment
	mutated.InputCommitment = seal.InputCommitment
	mutated.OutputCommitment = bytes.Repeat([]byte{0x44}, 32)
	if HybridSealSignatureVerifier(good, mutated) {
		t.Fatal("signature over a different claim must be rejected")
	}

	// 5. A nil seal is rejected rather than panicking.
	if HybridSealSignatureVerifier(good, nil) {
		t.Fatal("nil seal must be rejected")
	}
}
