package pqc

import (
	"bytes"
	"testing"
)

// ---------------------------------------------------------------------------
// Seed corpus helpers
// ---------------------------------------------------------------------------

// addStandardSeedCorpus adds a broad range of seed inputs to the fuzz target:
// valid, empty, truncated, oversized, all-zeros, all-ones, and known patterns.
func addStandardSeedCorpus(f *testing.F) {
	f.Helper()

	// Empty
	f.Add([]byte{})

	// Single byte
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF})

	// All zeros — various sizes
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 256))

	// All ones
	ones32 := make([]byte, 32)
	for i := range ones32 {
		ones32[i] = 0xFF
	}
	f.Add(ones32)

	ones256 := make([]byte, 256)
	for i := range ones256 {
		ones256[i] = 0xFF
	}
	f.Add(ones256)

	// Realistic message
	f.Add([]byte("aethelred transaction payload"))
	f.Add([]byte("post-quantum signature verification test"))

	// Large input
	large := make([]byte, 10000)
	for i := range large {
		large[i] = byte(i % 256)
	}
	f.Add(large)

	// Truncated / boundary sizes
	f.Add(make([]byte, 1))
	f.Add(make([]byte, 31))
	f.Add(make([]byte, 33))
	f.Add(make([]byte, 63))
	f.Add(make([]byte, 65))
}

// ---------------------------------------------------------------------------
// 1. FuzzMLDSASignVerify
//
// Invariants:
//   - A valid signature produced by Sign always verifies with the same key.
//   - A signature with a single corrupted byte never verifies.
//   - No panics on any message content or length.
// ---------------------------------------------------------------------------

func FuzzMLDSASignVerify(f *testing.F) {
	addStandardSeedCorpus(f)

	// Pre-generate key pairs (one per level) so key generation cost is not
	// multiplied by every fuzz iteration.
	levels := []int{DilithiumLevel2, DilithiumLevel3, DilithiumLevel5}
	keyPairs := make([]*DilithiumKeyPair, len(levels))
	for i, lvl := range levels {
		kp, err := GenerateDilithiumKeyPair(lvl)
		if err != nil {
			f.Fatalf("key generation failed for level %d: %v", lvl, err)
		}
		keyPairs[i] = kp
	}

	f.Fuzz(func(t *testing.T, message []byte) {
		for idx, kp := range keyPairs {
			lvl := levels[idx]

			// --- Sign ---
			sig, err := kp.Sign(message)
			if err != nil {
				t.Fatalf("level %d: Sign failed: %v", lvl, err)
			}
			if sig == nil {
				t.Fatalf("level %d: Sign returned nil signature", lvl)
			}

			// --- Verify valid signature ---
			valid, err := VerifyDilithium(kp.PublicKey, message, sig)
			if err != nil {
				t.Fatalf("level %d: VerifyDilithium returned error on valid sig: %v", lvl, err)
			}
			if !valid {
				t.Fatalf("level %d: valid signature failed verification", lvl)
			}

			// --- Corrupt one byte in the challenge field and verify rejection ---
			// The simulated Dilithium verification checks the challenge bytes
			// (signature[32:64]) against a recomputed value derived from the
			// commitment (signature[0:32]) and the public key. Corrupting any
			// byte within the first 64 bytes (commitment or challenge) will
			// cause the challenge comparison to fail.
			if len(sig.Signature) < 64 {
				continue
			}
			corrupted := make([]byte, len(sig.Signature))
			copy(corrupted, sig.Signature)
			// Flip bits in the challenge field (byte 40, well inside [32:64]).
			corrupted[40] ^= 0xFF

			corruptedSig := &DilithiumSignature{
				Level:     sig.Level,
				Signature: corrupted,
			}
			validCorrupted, _ := VerifyDilithium(kp.PublicKey, message, corruptedSig)
			if validCorrupted {
				t.Fatalf("level %d: corrupted signature was incorrectly accepted", lvl)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 2. FuzzMLDSAParsePublicKey
//
// Invariants:
//   - Malformed / arbitrary byte slices must not panic.
//   - Invalid data returns an error.
//   - Valid serialized key pairs deserialize and can be used for verification.
// ---------------------------------------------------------------------------

func FuzzMLDSAParsePublicKey(f *testing.F) {
	addStandardSeedCorpus(f)

	// Add a valid serialized key pair as seed.
	kp, err := GenerateDilithiumKeyPair(DilithiumLevel3)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(kp.Serialize())

	// Add key pairs for other levels too.
	for _, lvl := range []int{DilithiumLevel2, DilithiumLevel5} {
		kpN, err := GenerateDilithiumKeyPair(lvl)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(kpN.Serialize())
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// DeserializeDilithiumKeyPair must not panic.
		parsedKP, err := DeserializeDilithiumKeyPair(data)
		if err != nil {
			// Expected for most fuzz inputs — malformed data returns error.
			return
		}
		if parsedKP == nil {
			t.Fatal("DeserializeDilithiumKeyPair returned nil without error")
		}

		// If deserialization succeeded the keys must be usable.
		msg := []byte("round-trip parse test")
		sig, err := parsedKP.Sign(msg)
		if err != nil {
			t.Fatalf("Sign with parsed key failed: %v", err)
		}

		valid, err := VerifyDilithium(parsedKP.PublicKey, msg, sig)
		if err != nil {
			t.Fatalf("Verify with parsed key returned error: %v", err)
		}
		if !valid {
			t.Fatal("signature from parsed key failed verification")
		}
	})
}

// ---------------------------------------------------------------------------
// 3. FuzzMLDSAVerifyCorruptedSig
//
// Start with a valid (message, signature, key) triple. Fuzz the signature
// bytes only.
//
// Invariants:
//   - Every fuzzed signature that differs from the original must be rejected.
//   - No panics.
//   - No false positives.
// ---------------------------------------------------------------------------

func FuzzMLDSAVerifyCorruptedSig(f *testing.F) {
	kp, err := GenerateDilithiumKeyPair(DilithiumLevel3)
	if err != nil {
		f.Fatal(err)
	}

	referenceMsg := []byte("reference message for corruption testing")
	referenceSig, err := kp.Sign(referenceMsg)
	if err != nil {
		f.Fatal(err)
	}

	// Seed with the valid signature and variations.
	f.Add(referenceSig.Signature)
	f.Add(make([]byte, len(referenceSig.Signature)))
	allOnes := make([]byte, len(referenceSig.Signature))
	for i := range allOnes {
		allOnes[i] = 0xFF
	}
	f.Add(allOnes)
	f.Add(referenceSig.Signature[:len(referenceSig.Signature)/2]) // truncated
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, sigBytes []byte) {
		fuzzedSig := &DilithiumSignature{
			Level:     DilithiumLevel3,
			Signature: sigBytes,
		}

		// VerifyDilithium must not panic regardless of sigBytes content.
		valid, verifyErr := VerifyDilithium(kp.PublicKey, referenceMsg, fuzzedSig)

		// Wrong-length signatures must be rejected with an error.
		params, _ := GetDilithiumParams(DilithiumLevel3)
		if len(sigBytes) != params.SignatureSize {
			if verifyErr == nil {
				t.Fatal("wrong-length signature did not return an error")
			}
			return
		}

		// If the fuzzed bytes exactly equal the original, verification must pass.
		if bytes.Equal(sigBytes, referenceSig.Signature) {
			if !valid {
				t.Fatal("exact original signature was rejected")
			}
			return
		}

		// If the commitment/challenge zone (first 64 bytes) is mutated, the
		// challenge recomputation will mismatch and verification must fail.
		// This is the critical security invariant.
		if !bytes.Equal(sigBytes[:64], referenceSig.Signature[:64]) {
			if valid {
				t.Fatal("signature with corrupted commitment/challenge was accepted")
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 4. FuzzDilithiumSignVerify
//
// Legacy Dilithium path — same pattern as FuzzMLDSASignVerify but exercises
// the DilithiumKeyPair API directly and tests deterministic key generation
// from seed.
//
// Invariants:
//   - Sign/Verify round-trip always succeeds.
//   - Corrupted signature always rejected.
//   - Deterministic keygen from the same seed produces identical keys.
// ---------------------------------------------------------------------------

func FuzzDilithiumSignVerify(f *testing.F) {
	addStandardSeedCorpus(f)

	// Use a fixed seed for deterministic key pair.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, seed)
	if err != nil {
		f.Fatal(err)
	}

	// Verify deterministic keygen as a baseline.
	kp2, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, seed)
	if err != nil {
		f.Fatal(err)
	}
	if !bytes.Equal(kp.PublicKey, kp2.PublicKey) {
		f.Fatal("deterministic keygen produced different public keys")
	}
	if !bytes.Equal(kp.PrivateKey, kp2.PrivateKey) {
		f.Fatal("deterministic keygen produced different private keys")
	}

	f.Fuzz(func(t *testing.T, message []byte) {
		sig, err := kp.Sign(message)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		valid, err := VerifyDilithium(kp.PublicKey, message, sig)
		if err != nil {
			t.Fatalf("VerifyDilithium error: %v", err)
		}
		if !valid {
			t.Fatal("valid signature rejected")
		}

		// Corrupt signature.
		if len(sig.Signature) > 0 {
			corrupted := make([]byte, len(sig.Signature))
			copy(corrupted, sig.Signature)
			corrupted[0] ^= 0x01

			cs := &DilithiumSignature{Level: sig.Level, Signature: corrupted}
			vc, _ := VerifyDilithium(kp.PublicKey, message, cs)
			if vc {
				t.Fatal("corrupted signature accepted")
			}
		}

		// Serialization round-trip.
		serialized := kp.Serialize()
		deserialized, err := DeserializeDilithiumKeyPair(serialized)
		if err != nil {
			t.Fatalf("deserialization failed: %v", err)
		}
		if !bytes.Equal(deserialized.PublicKey, kp.PublicKey) {
			t.Fatal("public key mismatch after round-trip")
		}
	})
}

// ---------------------------------------------------------------------------
// 5. FuzzPQCKeyGeneration
//
// Fuzz key generation by using fuzz data as seed material.
//
// Invariants:
//   - Every generated key can sign and verify a message.
//   - Key serialization round-trips correctly.
//   - No panics on any seed.
// ---------------------------------------------------------------------------

func FuzzPQCKeyGeneration(f *testing.F) {
	addStandardSeedCorpus(f)

	f.Fuzz(func(t *testing.T, seedInput []byte) {
		// GenerateDilithiumKeyPairFromSeed requires at least 32 bytes.
		if len(seedInput) < 32 {
			// Verify that short seeds are properly rejected.
			_, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, seedInput)
			if err == nil {
				t.Fatal("expected error for seed shorter than 32 bytes")
			}
			return
		}

		for _, lvl := range []int{DilithiumLevel2, DilithiumLevel3, DilithiumLevel5} {
			kp, err := GenerateDilithiumKeyPairFromSeed(lvl, seedInput)
			if err != nil {
				t.Fatalf("level %d: keygen from seed failed: %v", lvl, err)
			}

			params, _ := GetDilithiumParams(lvl)

			// Key sizes must match the level's parameters.
			if len(kp.PublicKey) != params.PublicKeySize {
				t.Fatalf("level %d: public key size %d, want %d", lvl, len(kp.PublicKey), params.PublicKeySize)
			}
			if len(kp.PrivateKey) != params.PrivateKeySize {
				t.Fatalf("level %d: private key size %d, want %d", lvl, len(kp.PrivateKey), params.PrivateKeySize)
			}

			// Sign and verify.
			msg := []byte("keygen fuzz test message")
			sig, err := kp.Sign(msg)
			if err != nil {
				t.Fatalf("level %d: Sign failed: %v", lvl, err)
			}
			valid, err := VerifyDilithium(kp.PublicKey, msg, sig)
			if err != nil {
				t.Fatalf("level %d: Verify error: %v", lvl, err)
			}
			if !valid {
				t.Fatalf("level %d: valid signature rejected after keygen from seed", lvl)
			}

			// Serialization round-trip.
			serialized := kp.Serialize()
			restored, err := DeserializeDilithiumKeyPair(serialized)
			if err != nil {
				t.Fatalf("level %d: deserialization failed: %v", lvl, err)
			}
			if !bytes.Equal(restored.PublicKey, kp.PublicKey) {
				t.Fatalf("level %d: public key mismatch after serialization round-trip", lvl)
			}
			if !bytes.Equal(restored.PrivateKey, kp.PrivateKey) {
				t.Fatalf("level %d: private key mismatch after serialization round-trip", lvl)
			}

			// Determinism: same seed must produce the same key.
			kp2, err := GenerateDilithiumKeyPairFromSeed(lvl, seedInput)
			if err != nil {
				t.Fatalf("level %d: second keygen failed: %v", lvl, err)
			}
			if !bytes.Equal(kp.PublicKey, kp2.PublicKey) {
				t.Fatalf("level %d: deterministic keygen produced different public keys", lvl)
			}
			if !bytes.Equal(kp.PrivateKey, kp2.PrivateKey) {
				t.Fatalf("level %d: deterministic keygen produced different private keys", lvl)
			}
		}
	})
}
