package app

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/aethelred/aethelred/crypto/pqc"
)

func mkSealVerification(jobID string, success bool) ComputeVerification {
	return ComputeVerification{
		JobID:           jobID,
		ModelHash:       bytes.Repeat([]byte{0x11}, 32),
		InputHash:       bytes.Repeat([]byte{0x22}, 32),
		OutputHash:      bytes.Repeat([]byte{0x33}, 32),
		AttestationType: AttestationTypeTEE,
		Success:         success,
		ExecutionTimeMs: 5,
		Nonce:           bytes.Repeat([]byte{0x44}, 32),
	}
}

func TestSignAndVerifySealClaims(t *testing.T) {
	wallet, err := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	const chainID = "aethelred-testnet-1"

	ve := NewVoteExtensionAtBlockTime(100, []byte("val-addr"), time.Unix(1000, 0))
	ve.AddVerification(mkSealVerification("job-ok", true))
	ve.AddVerification(mkSealVerification("job-fail", false))

	if err := SignSealClaims(ve, wallet, chainID); err != nil {
		t.Fatal(err)
	}

	pub := wallet.HybridPublicKey()
	okv := &ve.Verifications[0]
	if len(okv.SealClaimSignature) == 0 {
		t.Fatal("successful verification missing claim signature")
	}
	if ok, err := VerifySealClaimSignature(okv, chainID, pub); err != nil || !ok {
		t.Fatalf("claim signature verify: ok=%v err=%v", ok, err)
	}

	// Failed verification must carry no claim signature.
	if len(ve.Verifications[1].SealClaimSignature) != 0 {
		t.Fatal("failed verification should have no claim signature")
	}

	// The claim binds chain and key: changing either must fail.
	if ok, _ := VerifySealClaimSignature(okv, "other-chain", pub); ok {
		t.Fatal("verified under wrong chain id")
	}
	other, _ := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	if ok, _ := VerifySealClaimSignature(okv, chainID, other.HybridPublicKey()); ok {
		t.Fatal("verified under wrong key")
	}
}

// TestClaimSigCoveredByExtensionSignature proves the per-verification hybrid
// claim signatures are bound into ComputeHash, so the ed25519 extension
// signature authenticates them — they cannot be swapped without detection.
func TestClaimSigCoveredByExtensionSignature(t *testing.T) {
	wallet, _ := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x07}, 32))
	pub := priv.Public().(ed25519.PublicKey)

	ve := NewVoteExtensionAtBlockTime(100, []byte("val-addr"), time.Unix(1000, 0))
	ve.AddVerification(mkSealVerification("job-ok", true))
	if err := SignSealClaims(ve, wallet, "chain"); err != nil {
		t.Fatal(err)
	}
	if err := SignVoteExtension(ve, priv); err != nil {
		t.Fatal(err)
	}

	if !VerifyVoteExtensionSignature(ve, pub) {
		t.Fatal("extension signature should verify")
	}

	// Tampering the claim signature must invalidate the extension signature.
	ve.Verifications[0].SealClaimSignature[0] ^= 0xFF
	if VerifyVoteExtensionSignature(ve, pub) {
		t.Fatal("tampered claim signature must invalidate the extension signature")
	}
}

// TestValidatorHybridKeyDerivationStable proves the hybrid key derived from an
// ed25519 seed is stable — a validator can re-derive and register the same key.
func TestValidatorHybridKeyDerivationStable(t *testing.T) {
	seed := bytes.Repeat([]byte{0x5e}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)

	a, err := pqc.NewDualKeyWalletFromMasterSeed(priv.Seed(), pqc.DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	b, err := pqc.NewDualKeyWalletFromMasterSeed(priv.Seed(), pqc.DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.HybridPublicKey(), b.HybridPublicKey()) {
		t.Fatal("hybrid key derived from ed25519 seed is not stable")
	}
}
