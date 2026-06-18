package pqc

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestSizeConstantsMatchBackend guards against drift between the package's
// exported size constants and the real circl ML-DSA / ML-KEM sizes.
func TestSizeConstantsMatchBackend(t *testing.T) {
	cases := []struct {
		level       int
		pk, sk, sig int
	}{
		{DilithiumLevel2, Dilithium2PublicKeySize, Dilithium2PrivateKeySize, Dilithium2SignatureSize},
		{DilithiumLevel3, Dilithium3PublicKeySize, Dilithium3PrivateKeySize, Dilithium3SignatureSize},
		{DilithiumLevel5, Dilithium5PublicKeySize, Dilithium5PrivateKeySize, Dilithium5SignatureSize},
	}
	for _, c := range cases {
		pk, sk, sig, seed, err := mldsaSizes(c.level)
		if err != nil {
			t.Fatalf("mldsaSizes(%d): %v", c.level, err)
		}
		if pk != c.pk || sk != c.sk || sig != c.sig {
			t.Errorf("ML-DSA level %d size drift: backend (pk=%d sk=%d sig=%d) vs consts (pk=%d sk=%d sig=%d)",
				c.level, pk, sk, sig, c.pk, c.sk, c.sig)
		}
		if seed != 32 {
			t.Errorf("ML-DSA level %d seed size = %d, want 32", c.level, seed)
		}
	}

	kemCases := []struct {
		level      int
		pk, sk, ct int
	}{
		{KyberLevel512, Kyber512PublicKeySize, Kyber512PrivateKeySize, Kyber512CiphertextSize},
		{KyberLevel768, Kyber768PublicKeySize, Kyber768PrivateKeySize, Kyber768CiphertextSize},
		{KyberLevel1024, Kyber1024PublicKeySize, Kyber1024PrivateKeySize, Kyber1024CiphertextSize},
	}
	for _, c := range kemCases {
		pk, sk, ct, ss, err := mlkemSizes(c.level)
		if err != nil {
			t.Fatalf("mlkemSizes(%d): %v", c.level, err)
		}
		if pk != c.pk || sk != c.sk || ct != c.ct {
			t.Errorf("ML-KEM level %d size drift: backend (pk=%d sk=%d ct=%d) vs consts (pk=%d sk=%d ct=%d)",
				c.level, pk, sk, ct, c.pk, c.sk, c.ct)
		}
		if ss != 32 {
			t.Errorf("ML-KEM level %d shared secret = %d, want 32", c.level, ss)
		}
	}
}

func TestMLDSASignVerifyAllLevels(t *testing.T) {
	for _, level := range []int{DilithiumLevel2, DilithiumLevel3, DilithiumLevel5} {
		kp, err := GenerateDilithiumKeyPair(level)
		if err != nil {
			t.Fatalf("level %d keygen: %v", level, err)
		}
		_, _, sigSize, _, _ := mldsaSizes(level)
		msg := []byte("aethelred ml-dsa roundtrip")

		sig, err := kp.Sign(msg)
		if err != nil {
			t.Fatalf("level %d sign: %v", level, err)
		}
		if len(sig.Signature) != sigSize {
			t.Errorf("level %d signature size = %d, want %d", level, len(sig.Signature), sigSize)
		}

		ok, err := VerifyDilithium(kp.PublicKey, msg, sig)
		if err != nil || !ok {
			t.Fatalf("level %d verify: ok=%v err=%v", level, ok, err)
		}

		// Tampered message must fail.
		bad := append([]byte(nil), msg...)
		bad[0] ^= 0xFF
		if ok, _ := VerifyDilithium(kp.PublicKey, bad, sig); ok {
			t.Errorf("level %d: tampered message verified", level)
		}

		// Tampered signature must fail.
		badSig := &DilithiumSignature{Level: level, Signature: append([]byte(nil), sig.Signature...)}
		badSig.Signature[10] ^= 0xFF
		if ok, _ := VerifyDilithium(kp.PublicKey, msg, badSig); ok {
			t.Errorf("level %d: tampered signature verified", level)
		}

		// Wrong key must fail.
		other, _ := GenerateDilithiumKeyPair(level)
		if ok, _ := VerifyDilithium(other.PublicKey, msg, sig); ok {
			t.Errorf("level %d: signature verified under wrong key", level)
		}
	}
}

func TestMLDSADeterministicDerivation(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	a, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, seed)
	if err != nil {
		t.Fatalf("derive a: %v", err)
	}
	b, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, seed)
	if err != nil {
		t.Fatalf("derive b: %v", err)
	}
	if !bytes.Equal(a.PublicKey, b.PublicKey) || !bytes.Equal(a.PrivateKey, b.PrivateKey) {
		t.Fatal("same seed produced different ML-DSA keys")
	}

	// A different seed must produce different keys.
	seed2 := make([]byte, 32)
	copy(seed2, seed)
	seed2[0] ^= 0xFF
	c, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, seed2)
	if err != nil {
		t.Fatalf("derive c: %v", err)
	}
	if bytes.Equal(a.PublicKey, c.PublicKey) {
		t.Fatal("different seeds produced identical ML-DSA public keys")
	}

	// The derived key must actually sign and verify (the old mock failed here).
	msg := []byte("derived-key signing")
	sig, err := a.Sign(msg)
	if err != nil {
		t.Fatalf("sign with derived key: %v", err)
	}
	if ok, err := VerifyDilithium(a.PublicKey, msg, sig); err != nil || !ok {
		t.Fatalf("derived key sign/verify failed: ok=%v err=%v", ok, err)
	}
}

func TestMLKEMRoundtripAllLevels(t *testing.T) {
	for _, level := range []int{KyberLevel512, KyberLevel768, KyberLevel1024} {
		kp, err := GenerateKyberKeyPair(level)
		if err != nil {
			t.Fatalf("level %d keygen: %v", level, err)
		}
		ss1, ct, err := Encapsulate(level, kp.PublicKey)
		if err != nil {
			t.Fatalf("level %d encapsulate: %v", level, err)
		}
		ss2, err := kp.Decapsulate(ct)
		if err != nil {
			t.Fatalf("level %d decapsulate: %v", level, err)
		}
		if !bytes.Equal(ss1, ss2) {
			t.Errorf("level %d: shared secrets disagree", level)
		}
		if len(ss1) != 32 {
			t.Errorf("level %d: shared secret = %d bytes, want 32", level, len(ss1))
		}
	}
}

func TestMLKEMDeterministicDerivation(t *testing.T) {
	want, _ := mlkemSeedSize(KyberLevel768)
	seed := make([]byte, want)
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	a, err := GenerateKyberKeyPairFromSeed(KyberLevel768, seed)
	if err != nil {
		t.Fatalf("derive a: %v", err)
	}
	b, err := GenerateKyberKeyPairFromSeed(KyberLevel768, seed)
	if err != nil {
		t.Fatalf("derive b: %v", err)
	}
	if !bytes.Equal(a.PublicKey, b.PublicKey) || !bytes.Equal(a.PrivateKey, b.PrivateKey) {
		t.Fatal("same seed produced different ML-KEM keys")
	}
}

func TestHybridKeyExchangeAgreement(t *testing.T) {
	alice, err := NewHybridKeyExchange(KyberLevel768)
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err := NewHybridKeyExchange(KyberLevel768)
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	// Alice encapsulates to Bob.
	secretA, ct, err := alice.EncapsulateHybrid(bob.ECDHPublic, bob.KyberKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	// Bob decapsulates.
	secretB, err := bob.DecapsulateHybrid(ct)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if !bytes.Equal(secretA, secretB) {
		t.Fatal("hybrid KEX secrets disagree")
	}
}

func TestSelfTestsAndDefaults(t *testing.T) {
	if !IsCirclAvailable() {
		t.Fatal("IsCirclAvailable() = false, want true (circl is compiled in)")
	}
	if GetPQCMode() != PQCModeHybrid {
		t.Errorf("default PQC mode = %v, want Hybrid", GetPQCMode())
	}
	if err := RunPQCSelfTests(); err != nil {
		t.Fatalf("RunPQCSelfTests: %v", err)
	}
}

// TestNoFakeCryptoSmoke is a coarse sanity check that two independently
// generated keys never collide (which the old SHA-expansion mock could do for
// structured seeds).
func TestNoFakeCryptoSmoke(t *testing.T) {
	a, _ := GenerateDilithiumKeyPair(DilithiumLevel3)
	b, _ := GenerateDilithiumKeyPair(DilithiumLevel3)
	if bytes.Equal(a.PublicKey, b.PublicKey) {
		t.Fatal("two random ML-DSA keys collided")
	}
	r := make([]byte, 16)
	if _, err := rand.Read(r); err != nil {
		t.Fatal(err)
	}
}
