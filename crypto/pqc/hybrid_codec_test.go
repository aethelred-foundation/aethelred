package pqc

import (
	"bytes"
	"testing"
)

func TestHybridCodecRoundtrip(t *testing.T) {
	w, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	pub := w.HybridPublicKey()
	msg := []byte("seal core claim: chain|job|model|input|output|height")

	sig, err := w.SignHybrid(msg)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyHybrid(pub, msg, sig)
	if err != nil || !ok {
		t.Fatalf("verify: ok=%v err=%v", ok, err)
	}

	// Tampered message must fail.
	bad := append([]byte(nil), msg...)
	bad[0] ^= 0xFF
	if ok, _ := VerifyHybrid(pub, bad, sig); ok {
		t.Error("tampered message verified")
	}

	// Tampered signature (flip a byte in the ML-DSA component) must fail.
	badSig := append([]byte(nil), sig...)
	badSig[len(badSig)-1] ^= 0xFF
	if ok, _ := VerifyHybrid(pub, msg, badSig); ok {
		t.Error("tampered signature verified")
	}

	// Tampered ECDSA component must fail.
	badSig2 := append([]byte(nil), sig...)
	badSig2[0] ^= 0xFF
	if ok, _ := VerifyHybrid(pub, msg, badSig2); ok {
		t.Error("tampered ECDSA component verified")
	}

	// Wrong key must fail.
	other, _ := NewDualKeyWallet(DilithiumLevel3)
	if ok, _ := VerifyHybrid(other.HybridPublicKey(), msg, sig); ok {
		t.Error("signature verified under wrong key")
	}
}

func TestHybridCodecDeterministicPubKey(t *testing.T) {
	seedMaster := bytes.Repeat([]byte{0x9c}, 64)
	a, err := NewDualKeyWalletFromMasterSeed(seedMaster, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDualKeyWalletFromMasterSeed(seedMaster, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	// Same seed → identical serialized hybrid public key (so a registered key is
	// stable across recovery).
	if !bytes.Equal(a.HybridPublicKey(), b.HybridPublicKey()) {
		t.Fatal("hybrid public key not stable across deterministic recovery")
	}

	// A signature from the recovered wallet verifies under the registered key.
	msg := []byte("recovered validator signs")
	sig, err := b.SignHybrid(msg)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyHybrid(a.HybridPublicKey(), msg, sig); err != nil || !ok {
		t.Fatalf("recovered-key verify failed: ok=%v err=%v", ok, err)
	}
}
