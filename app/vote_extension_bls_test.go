package app

import (
	"testing"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/crypto/bls"
)

// ---------------------------------------------------------------------------
// BLSVoteExtensionSigner
// ---------------------------------------------------------------------------

func TestBLSVoteExtensionSigner_Init(t *testing.T) {
	signer := NewBLSVoteExtensionSigner(log.NewNopLogger(), "aethelred-test-1")
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
	if signer.PublicKeyBytes() != nil {
		t.Fatal("public key should be nil before key generation")
	}
}

func TestBLSVoteExtensionSigner_GenerateAndSetKey(t *testing.T) {
	signer := NewBLSVoteExtensionSigner(log.NewNopLogger(), "aethelred-test-1")
	if err := signer.GenerateAndSetKey(); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pk := signer.PublicKeyBytes()
	if len(pk) != bls.PublicKeySize {
		t.Fatalf("expected %d byte public key, got %d", bls.PublicKeySize, len(pk))
	}
}

func TestBLSVoteExtensionSigner_SetKey(t *testing.T) {
	priv, pub, err := bls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer := NewBLSVoteExtensionSigner(log.NewNopLogger(), "aethelred-test-1")
	signer.SetKey(priv, pub)

	if len(signer.PublicKeyBytes()) != bls.PublicKeySize {
		t.Fatal("expected valid public key after SetKey")
	}
}

func TestBLSVoteExtensionSigner_Sign(t *testing.T) {
	signer := NewBLSVoteExtensionSigner(log.NewNopLogger(), "aethelred-test-1")
	if err := signer.GenerateAndSetKey(); err != nil {
		t.Fatal(err)
	}

	ext := NewVoteExtension(100, []byte("validator-1"))
	ext.ExtensionHash = ext.ComputeHash()

	sig, err := signer.SignExtensionBLS(ext)
	if err != nil {
		t.Fatalf("BLS signing failed: %v", err)
	}
	if len(sig) != bls.SignatureSize {
		t.Fatalf("expected %d byte signature, got %d", bls.SignatureSize, len(sig))
	}
}

func TestBLSVoteExtensionSigner_Sign_NoKey(t *testing.T) {
	signer := NewBLSVoteExtensionSigner(log.NewNopLogger(), "aethelred-test-1")
	ext := NewVoteExtension(100, []byte("validator-1"))
	ext.ExtensionHash = ext.ComputeHash()

	_, err := signer.SignExtensionBLS(ext)
	if err == nil {
		t.Fatal("expected error when signing without key")
	}
}

// ---------------------------------------------------------------------------
// Sign + Verify round-trip
// ---------------------------------------------------------------------------

func TestBLSVoteExtension_SignAndVerify(t *testing.T) {
	chainID := "aethelred-test-1"

	signer := NewBLSVoteExtensionSigner(log.NewNopLogger(), chainID)
	if err := signer.GenerateAndSetKey(); err != nil {
		t.Fatal(err)
	}

	ext := NewVoteExtension(200, []byte("validator-2"))
	ext.ExtensionHash = ext.ComputeHash()

	sigBytes, err := signer.SignExtensionBLS(ext)
	if err != nil {
		t.Fatal(err)
	}

	// Manually verify: build the message the same way the signer does.
	msg := buildBLSExtensionMessage(chainID, ext.Height, ext.ComputeHash())

	pk, err := bls.PublicKeyFromBytes(signer.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bls.SignatureFromBytes(sigBytes)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := bls.Verify(pk, msg, sig)
	if err != nil {
		t.Fatalf("verification error: %v", err)
	}
	if !valid {
		t.Fatal("BLS signature should verify")
	}
}

func TestBLSVoteExtension_InvalidSignature(t *testing.T) {
	chainID := "aethelred-test-1"

	signer := NewBLSVoteExtensionSigner(log.NewNopLogger(), chainID)
	if err := signer.GenerateAndSetKey(); err != nil {
		t.Fatal(err)
	}

	ext := NewVoteExtension(300, []byte("validator-3"))
	ext.ExtensionHash = ext.ComputeHash()

	sigBytes, err := signer.SignExtensionBLS(ext)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the signature.
	corruptSig := make([]byte, len(sigBytes))
	copy(corruptSig, sigBytes)
	corruptSig[0] ^= 0xFF

	msg := buildBLSExtensionMessage(chainID, ext.Height, ext.ComputeHash())
	pk, _ := bls.PublicKeyFromBytes(signer.PublicKeyBytes())

	corruptedSigObj, err := bls.SignatureFromBytes(corruptSig)
	if err != nil {
		// If bytes are invalid for deserialization, that also counts as rejection.
		return
	}

	valid, _ := bls.Verify(pk, msg, corruptedSigObj)
	if valid {
		t.Fatal("corrupted signature should not verify")
	}
}

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

func TestAggregateBLSVoteExtensions_Empty(t *testing.T) {
	_, err := AggregateBLSVoteExtensions("chain", 100, nil, log.NewNopLogger())
	if err == nil {
		t.Fatal("expected error for empty extensions")
	}
}

func TestAggregateBLSVoteExtensions_SingleSigner(t *testing.T) {
	chainID := "aethelred-test-1"
	height := int64(100)
	logger := log.NewNopLogger()

	signer := NewBLSVoteExtensionSigner(logger, chainID)
	if err := signer.GenerateAndSetKey(); err != nil {
		t.Fatal(err)
	}

	ext := NewVoteExtension(height, []byte("v1"))
	ext.ExtensionHash = ext.ComputeHash()

	sigBytes, err := signer.SignExtensionBLS(ext)
	if err != nil {
		t.Fatal(err)
	}

	blsExt := BLSSignedVoteExtension{
		Extension:    ext,
		BLSSignature: sigBytes,
		BLSPubKey:    signer.PublicKeyBytes(),
	}

	agg, err := AggregateBLSVoteExtensions(chainID, height, []BLSSignedVoteExtension{blsExt}, logger)
	if err != nil {
		t.Fatalf("aggregation failed: %v", err)
	}
	if agg.SignerCount != 1 {
		t.Fatalf("expected 1 signer, got %d", agg.SignerCount)
	}
	if len(agg.AggregateSignature) != bls.SignatureSize {
		t.Fatalf("expected %d byte aggregate sig, got %d", bls.SignatureSize, len(agg.AggregateSignature))
	}
}

func TestAggregateBLSVoteExtensions_MultipleSigners(t *testing.T) {
	chainID := "aethelred-test-1"
	height := int64(500)
	logger := log.NewNopLogger()

	var exts []BLSSignedVoteExtension

	for i := 0; i < 5; i++ {
		signer := NewBLSVoteExtensionSigner(logger, chainID)
		if err := signer.GenerateAndSetKey(); err != nil {
			t.Fatal(err)
		}

		ext := NewVoteExtension(height, []byte("validator"))
		ext.ExtensionHash = ext.ComputeHash()

		sigBytes, err := signer.SignExtensionBLS(ext)
		if err != nil {
			t.Fatal(err)
		}

		exts = append(exts, BLSSignedVoteExtension{
			Extension:    ext,
			BLSSignature: sigBytes,
			BLSPubKey:    signer.PublicKeyBytes(),
		})
	}

	agg, err := AggregateBLSVoteExtensions(chainID, height, exts, logger)
	if err != nil {
		t.Fatalf("aggregation failed: %v", err)
	}
	if agg.SignerCount != 5 {
		t.Fatalf("expected 5 signers, got %d", agg.SignerCount)
	}
}

func TestAggregateBLSVoteExtensions_SkipsInvalidSigSize(t *testing.T) {
	chainID := "aethelred-test-1"
	height := int64(100)
	logger := log.NewNopLogger()

	// One valid, one with bad sig size.
	signer := NewBLSVoteExtensionSigner(logger, chainID)
	if err := signer.GenerateAndSetKey(); err != nil {
		t.Fatal(err)
	}
	ext := NewVoteExtension(height, []byte("v1"))
	ext.ExtensionHash = ext.ComputeHash()
	sigBytes, _ := signer.SignExtensionBLS(ext)

	exts := []BLSSignedVoteExtension{
		{
			Extension:    ext,
			BLSSignature: []byte("short"),
			BLSPubKey:    signer.PublicKeyBytes(),
		},
		{
			Extension:    ext,
			BLSSignature: sigBytes,
			BLSPubKey:    signer.PublicKeyBytes(),
		},
	}

	agg, err := AggregateBLSVoteExtensions(chainID, height, exts, logger)
	if err != nil {
		t.Fatalf("aggregation should succeed with at least 1 valid: %v", err)
	}
	if agg.SignerCount != 1 {
		t.Fatalf("expected 1 valid signer, got %d", agg.SignerCount)
	}
}

// ---------------------------------------------------------------------------
// Verify aggregate
// ---------------------------------------------------------------------------

func TestVerifyBLSAggregateVoteExtensions_Nil(t *testing.T) {
	valid, err := VerifyBLSAggregateVoteExtensions(nil)
	if err == nil {
		t.Fatal("expected error for nil aggregate")
	}
	if valid {
		t.Fatal("should not be valid")
	}
}

func TestVerifyBLSAggregateVoteExtensions_EmptySigners(t *testing.T) {
	agg := &BLSAggregateVoteExtension{
		AggregateSignature: make([]byte, bls.SignatureSize),
		SignerPubKeys:      nil,
	}
	_, err := VerifyBLSAggregateVoteExtensions(agg)
	if err == nil {
		t.Fatal("expected error for empty signer pub keys")
	}
}

func TestVerifyBLSAggregateVoteExtensions_MismatchedLengths(t *testing.T) {
	agg := &BLSAggregateVoteExtension{
		AggregateSignature: make([]byte, bls.SignatureSize),
		SignerPubKeys:      [][]byte{make([]byte, bls.PublicKeySize)},
		ExtensionHashes:    nil, // mismatched with SignerPubKeys
	}
	_, err := VerifyBLSAggregateVoteExtensions(agg)
	if err == nil {
		t.Fatal("expected error for mismatched signer/extension counts")
	}
}

// ---------------------------------------------------------------------------
// BFT threshold (67%)
// ---------------------------------------------------------------------------

func TestBLSVoteExtension_ThresholdVerification(t *testing.T) {
	chainID := "aethelred-test-1"
	height := int64(100)
	logger := log.NewNopLogger()

	totalValidators := 10
	// Need at least 67% = 7 signers for BFT safety.
	var exts []BLSSignedVoteExtension

	for i := 0; i < totalValidators; i++ {
		signer := NewBLSVoteExtensionSigner(logger, chainID)
		if err := signer.GenerateAndSetKey(); err != nil {
			t.Fatal(err)
		}
		ext := NewVoteExtension(height, []byte("validator"))
		ext.ExtensionHash = ext.ComputeHash()
		sig, _ := signer.SignExtensionBLS(ext)

		exts = append(exts, BLSSignedVoteExtension{
			Extension:    ext,
			BLSSignature: sig,
			BLSPubKey:    signer.PublicKeyBytes(),
		})
	}

	// Aggregate only 7/10 (70% > 67% threshold).
	agg, err := AggregateBLSVoteExtensions(chainID, height, exts[:7], logger)
	if err != nil {
		t.Fatalf("aggregation failed: %v", err)
	}

	threshold := float64(agg.SignerCount) / float64(totalValidators)
	if threshold < 0.67 {
		t.Fatalf("expected >= 67%% threshold, got %.2f%%", threshold*100)
	}

	// Aggregate only 6/10 (60% < 67% threshold) -- should succeed in aggregation
	// but application layer would reject this.
	agg6, err := AggregateBLSVoteExtensions(chainID, height, exts[:6], logger)
	if err != nil {
		t.Fatalf("aggregation should still succeed: %v", err)
	}
	subThreshold := float64(agg6.SignerCount) / float64(totalValidators)
	if subThreshold >= 0.67 {
		t.Fatal("6/10 should be below BFT threshold")
	}
}

// ---------------------------------------------------------------------------
// buildBLSExtensionMessage determinism
// ---------------------------------------------------------------------------

func TestBuildBLSExtensionMessage_Deterministic(t *testing.T) {
	msg1 := buildBLSExtensionMessage("chain-1", 100, []byte("hash-a"))
	msg2 := buildBLSExtensionMessage("chain-1", 100, []byte("hash-a"))

	if len(msg1) != 32 {
		t.Fatalf("expected 32-byte SHA-256 output, got %d", len(msg1))
	}
	for i := range msg1 {
		if msg1[i] != msg2[i] {
			t.Fatal("same inputs should produce same message")
		}
	}

	// Different height -> different message.
	msg3 := buildBLSExtensionMessage("chain-1", 101, []byte("hash-a"))
	same := true
	for i := range msg1 {
		if msg1[i] != msg3[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different heights should produce different messages")
	}
}
