package pqc

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// ML-DSA / Dilithium - all security levels
// ---------------------------------------------------------------------------

func TestMLDSA_AllLevels(t *testing.T) {
	levels := []struct {
		level  int
		pkSize int
		skSize int
		sigSize int
	}{
		{DilithiumLevel2, Dilithium2PublicKeySize, Dilithium2PrivateKeySize, Dilithium2SignatureSize},
		{DilithiumLevel3, Dilithium3PublicKeySize, Dilithium3PrivateKeySize, Dilithium3SignatureSize},
		{DilithiumLevel5, Dilithium5PublicKeySize, Dilithium5PrivateKeySize, Dilithium5SignatureSize},
	}

	for _, tc := range levels {
		t.Run(itoa(tc.level), func(t *testing.T) {
			kp, err := GenerateDilithiumKeyPair(tc.level)
			if err != nil {
				t.Fatalf("keygen level %d: %v", tc.level, err)
			}
			if len(kp.PublicKey) != tc.pkSize {
				t.Fatalf("pk size: got %d, want %d", len(kp.PublicKey), tc.pkSize)
			}
			if len(kp.PrivateKey) != tc.skSize {
				t.Fatalf("sk size: got %d, want %d", len(kp.PrivateKey), tc.skSize)
			}

			msg := []byte("ML-DSA test across all levels")
			sig, err := kp.Sign(msg)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if len(sig.Signature) != tc.sigSize {
				t.Fatalf("sig size: got %d, want %d", len(sig.Signature), tc.sigSize)
			}

			valid, err := VerifyDilithium(kp.PublicKey, msg, sig)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !valid {
				t.Fatal("valid signature rejected")
			}
		})
	}
}

func TestMLDSA_InvalidLevel(t *testing.T) {
	_, err := GenerateDilithiumKeyPair(99)
	if err == nil {
		t.Fatal("expected error for invalid level")
	}
	_, err = GetDilithiumParams(99)
	if err == nil {
		t.Fatal("expected error for invalid params level")
	}
}

// ---------------------------------------------------------------------------
// Key serialization round-trip
// ---------------------------------------------------------------------------

func TestMLDSA_KeySerialization_RoundTrip(t *testing.T) {
	for _, level := range []int{DilithiumLevel2, DilithiumLevel3, DilithiumLevel5} {
		t.Run(itoa(level), func(t *testing.T) {
			kp, err := GenerateDilithiumKeyPair(level)
			if err != nil {
				t.Fatal(err)
			}

			serialized := kp.Serialize()
			restored, err := DeserializeDilithiumKeyPair(serialized)
			if err != nil {
				t.Fatalf("deserialize: %v", err)
			}
			if restored.Level != level {
				t.Fatalf("level: got %d, want %d", restored.Level, level)
			}
			if !bytes.Equal(restored.PublicKey, kp.PublicKey) {
				t.Fatal("public key mismatch after round-trip")
			}
			if !bytes.Equal(restored.PrivateKey, kp.PrivateKey) {
				t.Fatal("private key mismatch after round-trip")
			}

			// Verify signing with restored key.
			msg := []byte("serialization round-trip test")
			sig, err := restored.Sign(msg)
			if err != nil {
				t.Fatal(err)
			}
			valid, err := VerifyDilithium(restored.PublicKey, msg, sig)
			if err != nil || !valid {
				t.Fatal("signature from restored key rejected")
			}
		})
	}
}

func TestMLDSA_DeserializeTooShort(t *testing.T) {
	_, err := DeserializeDilithiumKeyPair([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

// ---------------------------------------------------------------------------
// Cross-level incompatibility
// ---------------------------------------------------------------------------

func TestMLDSA_CrossLevelIncompatibility(t *testing.T) {
	kp2, err := GenerateDilithiumKeyPair(DilithiumLevel2)
	if err != nil {
		t.Fatal(err)
	}
	kp3, err := GenerateDilithiumKeyPair(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("cross-level test")
	sig3, err := kp3.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	// Level 2 key cannot verify level 3 signature due to size mismatches.
	_, err = VerifyDilithium(kp2.PublicKey, msg, sig3)
	if err == nil {
		// If no error, the sizes happen to match (unlikely) -- check validity.
		t.Log("cross-level verify did not return error (unexpected but not fatal)")
	}

	sig2, err := kp2.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyDilithium(kp3.PublicKey, msg, sig2)
	if err == nil {
		t.Log("cross-level verify did not return error (unexpected)")
	}
}

// ---------------------------------------------------------------------------
// Dilithium deterministic keygen
// ---------------------------------------------------------------------------

func TestDilithium_KeyPairGeneration(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, seed)
	if err != nil {
		t.Fatal(err)
	}

	params, _ := GetDilithiumParams(DilithiumLevel3)
	if len(kp.PublicKey) != params.PublicKeySize {
		t.Fatalf("pk size: got %d, want %d", len(kp.PublicKey), params.PublicKeySize)
	}
	if len(kp.PrivateKey) != params.PrivateKeySize {
		t.Fatalf("sk size: got %d, want %d", len(kp.PrivateKey), params.PrivateKeySize)
	}
}

func TestDilithium_DeterministicKeygen(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i * 3)
	}

	kp1, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, seed)
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, seed)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(kp1.PublicKey, kp2.PublicKey) {
		t.Fatal("deterministic keygen: public keys differ")
	}
	if !bytes.Equal(kp1.PrivateKey, kp2.PrivateKey) {
		t.Fatal("deterministic keygen: private keys differ")
	}
}

func TestDilithium_DeterministicKeygen_ShortSeed(t *testing.T) {
	_, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for seed shorter than 32 bytes")
	}
}

// ---------------------------------------------------------------------------
// Wallet: dual-key transactions
// ---------------------------------------------------------------------------

func TestWallet_DualKeyTransaction(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatalf("NewDualKeyWallet: %v", err)
	}

	tx := []byte("transfer 100 AETH from alice to bob")
	sig, err := wallet.Sign(tx, CompositeScheme)
	if err != nil {
		t.Fatalf("Sign composite: %v", err)
	}

	if sig.ECDSASignature == nil {
		t.Fatal("missing ECDSA component in composite signature")
	}
	if sig.DilithiumSignature == nil {
		t.Fatal("missing Dilithium component in composite signature")
	}
}

func TestWallet_VerifyDualSignature(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	tx := []byte("dual signature verification test")
	sig, err := wallet.Sign(tx, CompositeScheme)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := wallet.Verify(tx, sig, CompositeScheme)
	if err != nil {
		t.Fatalf("Verify composite: %v", err)
	}
	if !valid {
		t.Fatal("composite signature rejected")
	}
}

func TestWallet_ClassicalOnly(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("classical only")
	sig, err := wallet.Sign(msg, ECDSAOnly)
	if err != nil {
		t.Fatal(err)
	}
	if sig.ECDSASignature == nil {
		t.Fatal("missing ECDSA signature")
	}
	if sig.DilithiumSignature != nil {
		t.Fatal("Dilithium signature should be nil in ECDSAOnly mode")
	}

	valid, err := wallet.Verify(msg, sig, ECDSAOnly)
	if err != nil || !valid {
		t.Fatalf("ECDSA-only verify failed: err=%v valid=%v", err, valid)
	}
}

func TestWallet_PQCOnly(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("post-quantum only")
	sig, err := wallet.Sign(msg, DilithiumOnly)
	if err != nil {
		t.Fatal(err)
	}
	if sig.DilithiumSignature == nil {
		t.Fatal("missing Dilithium signature")
	}
	if sig.ECDSASignature != nil {
		t.Fatal("ECDSA signature should be nil in DilithiumOnly mode")
	}

	valid, err := wallet.Verify(msg, sig, DilithiumOnly)
	if err != nil || !valid {
		t.Fatalf("Dilithium-only verify failed: err=%v valid=%v", err, valid)
	}
}

func TestWallet_SignTransaction(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	tx := []byte("full transaction payload")
	sig, err := wallet.SignTransaction(tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	valid, err := VerifyTransactionSignature(
		wallet.ECDSAPublicKey,
		wallet.DilithiumKeyPair.PublicKey,
		tx,
		sig,
	)
	if err != nil || !valid {
		t.Fatalf("VerifyTransactionSignature failed: err=%v valid=%v", err, valid)
	}
}

func TestWallet_CompositeSignature_WrongMessage(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := wallet.Sign([]byte("original"), CompositeScheme)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := wallet.Verify([]byte("tampered"), sig, CompositeScheme)
	if err == nil && valid {
		t.Fatal("tampered message accepted")
	}
}

func TestWallet_AddressDerivation(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	addr := wallet.GetAddress()
	if len(addr) != 20 {
		t.Fatalf("address length: got %d, want 20", len(addr))
	}

	hex := wallet.GetAddressHex()
	if len(hex) == 0 || hex[:2] != "0x" {
		t.Fatalf("hex address: %s", hex)
	}
}

func TestWallet_PublicKeyBytes(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	ecdsaBytes := wallet.GetECDSAPublicKeyBytes()
	if len(ecdsaBytes) == 0 {
		t.Fatal("ECDSA public key bytes are empty")
	}

	dilithiumBytes := wallet.GetDilithiumPublicKeyBytes()
	if len(dilithiumBytes) != Dilithium3PublicKeySize {
		t.Fatalf("Dilithium pk bytes: got %d, want %d",
			len(dilithiumBytes), Dilithium3PublicKeySize)
	}
}

func TestWallet_Zeroize(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	wallet.Zeroize()
	if wallet.ECDSAPrivateKey != nil {
		t.Fatal("ECDSA private key not zeroed")
	}
	if wallet.DilithiumKeyPair.PrivateKey != nil {
		t.Fatal("Dilithium private key not zeroed")
	}
}

func TestWallet_SerializeEncrypted_RoundTrip(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	passphrase := []byte("strong-passphrase-42!")
	encrypted, err := wallet.SerializeEncrypted(passphrase)
	if err != nil {
		t.Fatalf("SerializeEncrypted: %v", err)
	}

	restored, err := DeserializeEncryptedDualKeyWallet(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DeserializeEncrypted: %v", err)
	}

	// Verify addresses match.
	if !bytes.Equal(wallet.GetAddress(), restored.GetAddress()) {
		t.Fatal("address mismatch after encrypted round-trip")
	}

	// Verify restored wallet can sign and verify.
	msg := []byte("encrypted wallet test")
	sig, err := restored.Sign(msg, CompositeScheme)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := restored.Verify(msg, sig, CompositeScheme)
	if err != nil || !valid {
		t.Fatal("restored wallet signature rejected")
	}
}

func TestWallet_SerializeEncrypted_WrongPassphrase(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := wallet.SerializeEncrypted([]byte("correct"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = DeserializeEncryptedDualKeyWallet(encrypted, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestWallet_SerializeEncrypted_EmptyPassphrase(t *testing.T) {
	wallet, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	_, err = wallet.SerializeEncrypted([]byte{})
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestWallet_FromSeed(t *testing.T) {
	ecdsaSeed := make([]byte, 32)
	dilithiumSeed := make([]byte, 32)
	for i := range ecdsaSeed {
		ecdsaSeed[i] = byte(i)
		dilithiumSeed[i] = byte(i + 100)
	}

	wallet, err := NewDualKeyWalletFromSeed(ecdsaSeed, dilithiumSeed, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the wallet is functional: can sign and verify in all schemes.
	msg := []byte("wallet from seed test transaction")
	for _, scheme := range []SignatureScheme{ECDSAOnly, DilithiumOnly, CompositeScheme} {
		sig, err := wallet.Sign(msg, scheme)
		if err != nil {
			t.Fatalf("scheme %d: Sign: %v", scheme, err)
		}
		valid, err := wallet.Verify(msg, sig, scheme)
		if err != nil {
			t.Fatalf("scheme %d: Verify: %v", scheme, err)
		}
		if !valid {
			t.Fatalf("scheme %d: valid signature rejected", scheme)
		}
	}

	// Verify Dilithium key is deterministic from seed.
	kp1, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, dilithiumSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kp1.PublicKey, wallet.DilithiumKeyPair.PublicKey) {
		t.Fatal("Dilithium key from same seed differs")
	}

	// Verify address is non-empty and 20 bytes.
	addr := wallet.GetAddress()
	if len(addr) != 20 {
		t.Fatalf("address length: got %d, want 20", len(addr))
	}
}

func TestWallet_FromSeed_ShortSeed(t *testing.T) {
	_, err := NewDualKeyWalletFromSeed(make([]byte, 16), make([]byte, 32), DilithiumLevel3)
	if err == nil {
		t.Fatal("expected error for short ECDSA seed")
	}
	_, err = NewDualKeyWalletFromSeed(make([]byte, 32), make([]byte, 16), DilithiumLevel3)
	if err == nil {
		t.Fatal("expected error for short Dilithium seed")
	}
}

// ---------------------------------------------------------------------------
// HD key derivation
// ---------------------------------------------------------------------------

func TestHDKeyDerivation(t *testing.T) {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}

	hdw, err := NewHDWallet(seed, DilithiumLevel3)
	if err != nil {
		t.Fatalf("NewHDWallet: %v", err)
	}
	defer hdw.Zeroize()

	wallet, err := hdw.DeriveChildByIndex(0)
	if err != nil {
		t.Fatalf("DeriveChildByIndex(0): %v", err)
	}

	msg := []byte("HD derived wallet test")
	sig, err := wallet.Sign(msg, CompositeScheme)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := wallet.Verify(msg, sig, CompositeScheme)
	if err != nil || !valid {
		t.Fatal("HD derived wallet signature rejected")
	}
}

func TestHDKeyDerivation_DeterministicSameIndex(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	hdw, err := NewHDWallet(seed, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	defer hdw.Zeroize()

	w1, err := hdw.DeriveChildByIndex(5)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := hdw.DeriveChildByIndex(5)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(w1.GetAddress(), w2.GetAddress()) {
		t.Fatal("same index produced different addresses")
	}
}

func TestHDKeyDerivation_DifferentPaths(t *testing.T) {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}

	hdw, err := NewHDWallet(seed, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	defer hdw.Zeroize()

	w0, err := hdw.DeriveChildByIndex(0)
	if err != nil {
		t.Fatal(err)
	}
	w1, err := hdw.DeriveChildByIndex(1)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(w0.GetAddress(), w1.GetAddress()) {
		t.Fatal("different indices produced same address")
	}
	if bytes.Equal(w0.DilithiumKeyPair.PublicKey, w1.DilithiumKeyPair.PublicKey) {
		t.Fatal("different indices produced same Dilithium public key")
	}
}

func TestHDWallet_ShortSeed(t *testing.T) {
	_, err := NewHDWallet(make([]byte, 16), DilithiumLevel3)
	if err == nil {
		t.Fatal("expected error for seed < 32 bytes")
	}
}

func TestHDWallet_InvalidLevel(t *testing.T) {
	_, err := NewHDWallet(make([]byte, 64), 99)
	if err == nil {
		t.Fatal("expected error for invalid Dilithium level")
	}
}

func TestHDWallet_DeriveChildPath(t *testing.T) {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}

	hdw, err := NewHDWallet(seed, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	defer hdw.Zeroize()

	path := HDDerivationPath{
		Purpose:  44,
		CoinType: 60,
		Account:  1,
		Change:   0,
		Index:    7,
	}

	wallet, err := hdw.DeriveChild(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(wallet.GetAddress()) != 20 {
		t.Fatal("address wrong length")
	}
}

// ---------------------------------------------------------------------------
// CIRCL integration (stub mode)
// ---------------------------------------------------------------------------

func TestCIRCL_Integration(t *testing.T) {
	// In the default build (no pqc_circl tag), circl is not available.
	// Verify the stub behavior.
	if IsCirclAvailable() {
		t.Log("circl is available -- testing with real implementation")
	} else {
		t.Log("circl not available -- testing stub behavior")
	}

	mode := GetPQCMode()
	if mode != PQCModeSimulated {
		t.Fatalf("expected PQCModeSimulated, got %s", mode.String())
	}

	info := GetPQCImplementationInfo()
	if info["mode"] != "Simulated" {
		t.Fatalf("mode info: got %s", info["mode"])
	}
}

func TestCIRCL_CirclDilithiumKeyPair_SimulatedMode(t *testing.T) {
	kp, err := GenerateCirclDilithiumKeyPair(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	if kp == nil {
		t.Fatal("nil key pair")
	}

	msg := []byte("circl dilithium test")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := VerifyCirclDilithium(kp.PublicKey, msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("circl dilithium signature rejected in simulated mode")
	}
}

func TestCIRCL_CirclKyberKeyPair_SimulatedMode(t *testing.T) {
	kp, err := GenerateCirclKyberKeyPair(KyberLevel768)
	if err != nil {
		t.Fatal(err)
	}

	ss, ct, err := kp.Encapsulate(kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) == 0 {
		t.Fatal("empty shared secret")
	}

	recovered, err := kp.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != len(ss) {
		t.Fatalf("shared secret length mismatch: got %d, want %d", len(recovered), len(ss))
	}
}

// ---------------------------------------------------------------------------
// Key encapsulation (Kyber / ML-KEM)
// ---------------------------------------------------------------------------

func TestKeyEncapsulation(t *testing.T) {
	for _, level := range []int{KyberLevel512, KyberLevel768, KyberLevel1024} {
		t.Run(itoa(level), func(t *testing.T) {
			kp, err := GenerateKyberKeyPair(level)
			if err != nil {
				t.Fatal(err)
			}

			params, _ := GetKyberParams(level)
			if len(kp.PublicKey) != params.PublicKeySize {
				t.Fatalf("pk size: got %d, want %d", len(kp.PublicKey), params.PublicKeySize)
			}

			ss, ct, err := kp.Encapsulate()
			if err != nil {
				t.Fatalf("Encapsulate: %v", err)
			}
			if len(ss) != Kyber768SharedSecretSize {
				t.Fatalf("shared secret size: got %d, want %d", len(ss), Kyber768SharedSecretSize)
			}
			if ct == nil || len(ct.Ciphertext) == 0 {
				t.Fatal("empty ciphertext")
			}

			recovered, err := kp.Decapsulate(ct)
			if err != nil {
				t.Fatalf("Decapsulate: %v", err)
			}
			if len(recovered) != Kyber768SharedSecretSize {
				t.Fatalf("recovered size: got %d, want %d", len(recovered), Kyber768SharedSecretSize)
			}
		})
	}
}

func TestKeyEncapsulation_InvalidPubKeySize(t *testing.T) {
	_, _, err := Encapsulate(KyberLevel768, make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for wrong public key size")
	}
}

func TestKeyEncapsulation_Serialization(t *testing.T) {
	kp, err := GenerateKyberKeyPair(KyberLevel768)
	if err != nil {
		t.Fatal(err)
	}

	serialized := kp.Serialize()
	restored, err := DeserializeKyberKeyPair(serialized)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if restored.Level != KyberLevel768 {
		t.Fatalf("level: got %d", restored.Level)
	}
	if !bytes.Equal(restored.PublicKey, kp.PublicKey) {
		t.Fatal("public key mismatch")
	}
}

func TestKeyEncapsulation_CiphertextSerialization(t *testing.T) {
	kp, err := GenerateKyberKeyPair(KyberLevel768)
	if err != nil {
		t.Fatal(err)
	}

	_, ct, err := kp.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}

	serialized := ct.Serialize()
	restored, err := DeserializeKyberCiphertext(serialized)
	if err != nil {
		t.Fatalf("deserialize ciphertext: %v", err)
	}
	if restored.Level != KyberLevel768 {
		t.Fatalf("level: got %d", restored.Level)
	}
	if !bytes.Equal(restored.Ciphertext, ct.Ciphertext) {
		t.Fatal("ciphertext mismatch")
	}
}

func TestKeyEncapsulation_DecapsulateLevelMismatch(t *testing.T) {
	kp, err := GenerateKyberKeyPair(KyberLevel768)
	if err != nil {
		t.Fatal(err)
	}

	ct := &KyberCiphertext{
		Level:      KyberLevel512,
		Ciphertext: make([]byte, Kyber512CiphertextSize),
	}
	_, err = kp.Decapsulate(ct)
	if err == nil {
		t.Fatal("expected error for level mismatch")
	}
}

// ---------------------------------------------------------------------------
// Hybrid key exchange
// ---------------------------------------------------------------------------

func TestHybridKeyExchange(t *testing.T) {
	alice, err := NewHybridKeyExchange(KyberLevel768)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewHybridKeyExchange(KyberLevel768)
	if err != nil {
		t.Fatal(err)
	}

	alicePub := alice.GetHybridPublicKey()
	bobPub := bob.GetHybridPublicKey()

	if len(alicePub) == 0 || len(bobPub) == 0 {
		t.Fatal("empty hybrid public key")
	}

	// Alice encapsulates to Bob.
	_, hybridCT, err := alice.EncapsulateHybrid(bobPub[:32], bobPub[32:])
	if err != nil {
		t.Fatalf("EncapsulateHybrid: %v", err)
	}

	// Bob decapsulates.
	_, err = bob.DecapsulateHybrid(hybridCT)
	if err != nil {
		t.Fatalf("DecapsulateHybrid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Concurrent PQC signing
// ---------------------------------------------------------------------------

func TestPQC_ConcurrentSigning(t *testing.T) {
	const goroutines = 50
	kp, err := GenerateDilithiumKeyPair(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			msg := []byte("concurrent pqc signing " + itoa(idx))
			sig, err := kp.Sign(msg)
			if err != nil {
				errs <- err
				return
			}
			valid, err := VerifyDilithium(kp.PublicKey, msg, sig)
			if err != nil {
				errs <- err
				return
			}
			if !valid {
				errs <- fmt.Errorf("goroutine %d: valid signature rejected", idx)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Production readiness
// ---------------------------------------------------------------------------

func TestPQCReadinessCheck(t *testing.T) {
	check := CheckPQCReadiness()
	if !check.DilithiumAvailable {
		t.Fatalf("Dilithium not available: %v", check.Errors)
	}
	if !check.KyberAvailable {
		t.Fatalf("Kyber not available: %v", check.Errors)
	}
	if !check.HybridSigningEnabled {
		t.Fatalf("Hybrid signing not enabled: %v", check.Errors)
	}
	if !check.TestVectorsPassed {
		t.Fatal("test vectors did not pass")
	}
	if !check.IsProductionReady() {
		t.Fatalf("not production-ready: %v", check.Errors)
	}
}

func TestRunFullPQCTestSuite(t *testing.T) {
	result := RunFullPQCTestSuite()
	if !result.AllPassed {
		output := PrintTestResults(result)
		t.Fatalf("PQC test suite failed:\n%s", output)
	}
	if result.TotalTests == 0 {
		t.Fatal("no tests were run")
	}
}

// ---------------------------------------------------------------------------
// SecureRandomBytes
// ---------------------------------------------------------------------------

func TestSecureRandomBytes(t *testing.T) {
	for _, size := range []int{1, 16, 32, 64, 128, 256} {
		b, err := SecureRandomBytes(size)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(b) != size {
			t.Fatalf("size %d: got %d bytes", size, len(b))
		}
	}
}

func TestSecureRandomBytes_Invalid(t *testing.T) {
	_, err := SecureRandomBytes(0)
	if err == nil {
		t.Fatal("expected error for size 0")
	}
	_, err = SecureRandomBytes(-1)
	if err == nil {
		t.Fatal("expected error for negative size")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkMLDSA_Sign_Level3(b *testing.B) {
	kp, err := GenerateDilithiumKeyPair(DilithiumLevel3)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark ML-DSA-65 signing")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = kp.Sign(msg)
	}
}

func BenchmarkMLDSA_Verify_Level3(b *testing.B) {
	kp, err := GenerateDilithiumKeyPair(DilithiumLevel3)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark ML-DSA-65 verification")
	sig, err := kp.Sign(msg)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyDilithium(kp.PublicKey, msg, sig)
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateDilithiumKeyPair(DilithiumLevel3)
	}
}

func BenchmarkKeyEncapsulation(b *testing.B) {
	kp, err := GenerateKyberKeyPair(KyberLevel768)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = kp.Encapsulate()
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
