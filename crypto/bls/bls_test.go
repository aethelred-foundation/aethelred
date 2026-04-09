package bls

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

func TestNewPrivateKey(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if sk == nil || sk.scalar == nil {
		t.Fatal("private key is nil")
	}
	if pk == nil || pk.point == nil {
		t.Fatal("public key is nil")
	}

	skBytes := sk.Bytes()
	if len(skBytes) != PrivateKeySize {
		t.Fatalf("private key size: got %d, want %d", len(skBytes), PrivateKeySize)
	}

	pkBytes := pk.Bytes()
	if len(pkBytes) != PublicKeySize {
		t.Fatalf("public key size: got %d, want %d", len(pkBytes), PublicKeySize)
	}

	// Ensure two key generations produce distinct keys.
	sk2, pk2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("second GenerateKeyPair failed: %v", err)
	}
	if bytes.Equal(sk.Bytes(), sk2.Bytes()) {
		t.Fatal("two generated private keys are identical")
	}
	if bytes.Equal(pk.Bytes(), pk2.Bytes()) {
		t.Fatal("two generated public keys are identical")
	}
}

func TestPrivateKeyFromBytes_RoundTrip(t *testing.T) {
	sk, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw := sk.Bytes()

	restored, err := PrivateKeyFromBytes(raw)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes: %v", err)
	}
	if !bytes.Equal(restored.Bytes(), raw) {
		t.Fatal("round-trip private key mismatch")
	}
}

func TestPrivateKeyFromBytes_InvalidSize(t *testing.T) {
	_, err := PrivateKeyFromBytes(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for invalid private key size")
	}
}

func TestPublicKeyFromBytes_RoundTrip(t *testing.T) {
	_, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw := pk.Bytes()

	restored, err := PublicKeyFromBytes(raw)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes: %v", err)
	}
	if !bytes.Equal(restored.Bytes(), raw) {
		t.Fatal("round-trip public key mismatch")
	}
}

func TestPublicKeyFromBytes_InvalidSize(t *testing.T) {
	_, err := PublicKeyFromBytes(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for invalid public key size")
	}
}

func TestSignatureFromBytes_InvalidSize(t *testing.T) {
	_, err := SignatureFromBytes(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for invalid signature size")
	}
}

// ---------------------------------------------------------------------------
// Sign / Verify round-trip
// ---------------------------------------------------------------------------

func TestSignVerify_RoundTrip(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("vote extension payload for block 42")
	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig == nil {
		t.Fatal("signature is nil")
	}
	if len(sig.Bytes()) != SignatureSize {
		t.Fatalf("signature size: got %d, want %d", len(sig.Bytes()), SignatureSize)
	}

	valid, err := Verify(pk, msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Fatal("valid signature rejected")
	}
}

func TestSignVerify_WrongKey(t *testing.T) {
	sk1, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, pk2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("message signed by key 1")
	sig, err := Sign(sk1, msg)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := Verify(pk2, msg, sig)
	if err != nil {
		t.Fatalf("Verify with wrong key returned error: %v", err)
	}
	if valid {
		t.Fatal("signature verified with wrong public key")
	}
}

func TestSignVerify_CorruptedSignature(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("important vote data")
	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the signature bytes.
	raw := sig.Bytes()
	corrupted := make([]byte, len(raw))
	copy(corrupted, raw)
	corrupted[0] ^= 0xFF
	corrupted[len(corrupted)/2] ^= 0xAA

	corruptedSig, err := SignatureFromBytes(corrupted)
	if err != nil {
		// If deserialization fails, the corrupted data is rejected -- acceptable.
		return
	}
	valid, err := Verify(pk, msg, corruptedSig)
	if err != nil {
		// Verification returning an error on corrupted data is acceptable.
		return
	}
	if valid {
		t.Fatal("corrupted signature was accepted")
	}
}

func TestSignVerify_EmptyMessage(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign(sk, []byte{})
	if err != nil {
		t.Fatalf("Sign empty message: %v", err)
	}

	valid, err := Verify(pk, []byte{}, sig)
	if err != nil {
		t.Fatalf("Verify empty message: %v", err)
	}
	if !valid {
		t.Fatal("empty-message signature rejected")
	}
}

func TestSignVerify_LargeMessage(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// 1 MB payload.
	large := make([]byte, 1<<20)
	if _, err := rand.Read(large); err != nil {
		t.Fatal(err)
	}

	sig, err := Sign(sk, large)
	if err != nil {
		t.Fatalf("Sign large message: %v", err)
	}

	valid, err := Verify(pk, large, sig)
	if err != nil {
		t.Fatalf("Verify large message: %v", err)
	}
	if !valid {
		t.Fatal("large-message signature rejected")
	}
}

func TestSign_NilPrivateKey(t *testing.T) {
	_, err := Sign(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil private key")
	}
}

func TestVerify_NilInputs(t *testing.T) {
	_, err := Verify(nil, []byte("msg"), &Signature{})
	if err == nil {
		t.Fatal("expected error for nil public key")
	}

	_, pk, _ := GenerateKeyPair()
	_, err = Verify(pk, []byte("msg"), nil)
	if err == nil {
		t.Fatal("expected error for nil signature")
	}
}

// ---------------------------------------------------------------------------
// Signature aggregation
// ---------------------------------------------------------------------------

func generateNSigs(t *testing.T, n int, msg []byte) ([]*PrivateKey, []*PublicKey, []*Signature) {
	t.Helper()
	sks := make([]*PrivateKey, n)
	pks := make([]*PublicKey, n)
	sigs := make([]*Signature, n)
	for i := 0; i < n; i++ {
		sk, pk, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := Sign(sk, msg)
		if err != nil {
			t.Fatal(err)
		}
		sks[i], pks[i], sigs[i] = sk, pk, sig
	}
	return sks, pks, sigs
}

func TestAggregateSignatures(t *testing.T) {
	msg := []byte("shared consensus message")

	for _, n := range []int{2, 5, 10, 100} {
		t.Run("n="+itoa(n), func(t *testing.T) {
			_, pks, sigs := generateNSigs(t, n, msg)

			agg, err := AggregateSignatures(sigs)
			if err != nil {
				t.Fatalf("AggregateSignatures(%d): %v", n, err)
			}

			valid, err := VerifyAggregate(pks, msg, agg)
			if err != nil {
				t.Fatalf("VerifyAggregate(%d): %v", n, err)
			}
			if !valid {
				t.Fatalf("aggregate of %d signatures rejected", n)
			}
		})
	}
}

func TestAggregateSignatures_DuplicateSigner(t *testing.T) {
	msg := []byte("duplicate signer message")
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}

	// Aggregate the same signature twice.
	agg, err := AggregateSignatures([]*Signature{sig, sig})
	if err != nil {
		t.Fatalf("AggregateSignatures: %v", err)
	}

	// With naive aggregation, using the same key twice in verification
	// is equivalent to doubling the key point, which should match the
	// doubled signature point. This tests that the aggregation mechanism
	// does not panic and handles the degenerate case.
	valid, err := VerifyAggregate([]*PublicKey{pk, pk}, msg, agg)
	if err != nil {
		t.Fatalf("VerifyAggregate duplicate signer: %v", err)
	}
	if !valid {
		t.Fatal("aggregate with duplicate signer rejected")
	}
}

func TestAggregateSignatures_EmptySet(t *testing.T) {
	_, err := AggregateSignatures([]*Signature{})
	if err == nil {
		t.Fatal("expected error for empty signature set")
	}
}

func TestAggregateSignatures_SingleSignature(t *testing.T) {
	msg := []byte("single signer")
	_, pks, sigs := generateNSigs(t, 1, msg)

	agg, err := AggregateSignatures(sigs)
	if err != nil {
		t.Fatalf("AggregateSignatures(1): %v", err)
	}

	valid, err := VerifyAggregate(pks, msg, agg)
	if err != nil {
		t.Fatalf("VerifyAggregate(1): %v", err)
	}
	if !valid {
		t.Fatal("single-signature aggregate rejected")
	}
}

func TestVerifyAggregate_WrongPublicKeys(t *testing.T) {
	msg := []byte("consensus payload")
	_, _, sigs := generateNSigs(t, 3, msg)

	// Generate a different set of public keys.
	_, wrongPKs, _ := generateNSigs(t, 3, msg)

	agg, err := AggregateSignatures(sigs)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := VerifyAggregate(wrongPKs, msg, agg)
	if err != nil {
		t.Fatalf("VerifyAggregate with wrong keys: %v", err)
	}
	if valid {
		t.Fatal("aggregate verified with wrong public keys")
	}
}

func TestVerifyAggregate_PartialKeySet(t *testing.T) {
	msg := []byte("consensus payload")
	_, pks, sigs := generateNSigs(t, 5, msg)

	agg, err := AggregateSignatures(sigs)
	if err != nil {
		t.Fatal(err)
	}

	// Use only a subset of the public keys.
	valid, err := VerifyAggregate(pks[:3], msg, agg)
	if err != nil {
		t.Fatalf("VerifyAggregate partial keys: %v", err)
	}
	if valid {
		t.Fatal("aggregate verified with partial key set")
	}
}

func TestVerifyAggregate_NilAggSig(t *testing.T) {
	_, pk, _ := GenerateKeyPair()
	_, err := VerifyAggregate([]*PublicKey{pk}, []byte("msg"), nil)
	if err == nil {
		t.Fatal("expected error for nil aggregate signature")
	}
}

func TestVerifyAggregate_EmptyPubKeys(t *testing.T) {
	_, err := VerifyAggregate([]*PublicKey{}, []byte("msg"), &Signature{})
	if err == nil {
		t.Fatal("expected error for empty public key set")
	}
}

func TestVerifyAggregateBytes_RoundTrip(t *testing.T) {
	msg := []byte("bytes round trip")
	_, pks, sigs := generateNSigs(t, 3, msg)

	agg, err := AggregateSignatures(sigs)
	if err != nil {
		t.Fatal(err)
	}

	pkBytes := make([][]byte, len(pks))
	for i, pk := range pks {
		pkBytes[i] = pk.Bytes()
	}

	valid, err := VerifyAggregateBytes(pkBytes, msg, agg.Bytes())
	if err != nil {
		t.Fatalf("VerifyAggregateBytes: %v", err)
	}
	if !valid {
		t.Fatal("VerifyAggregateBytes rejected valid aggregate")
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestBLS_ConcurrentSigning(t *testing.T) {
	// The kilic/bls12-381 library mutates point internals (Affine normalization)
	// so each goroutine must use its own key pair to avoid data races.
	const goroutines = 50
	msg := []byte("concurrent signing test")

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sk, pk, err := GenerateKeyPair()
			if err != nil {
				errs <- err
				return
			}
			sig, err := Sign(sk, msg)
			if err != nil {
				errs <- err
				return
			}
			valid, err := Verify(pk, msg, sig)
			if err != nil {
				errs <- err
				return
			}
			if !valid {
				errs <- fmt.Errorf("concurrent signature rejected")
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent signing error: %v", err)
	}
}

func TestBLS_ConcurrentAggregation(t *testing.T) {
	const goroutines = 10
	const signersPerGroup = 5
	msg := []byte("parallel aggregation")

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			pks := make([]*PublicKey, signersPerGroup)
			sigs := make([]*Signature, signersPerGroup)
			for i := 0; i < signersPerGroup; i++ {
				sk, pk, err := GenerateKeyPair()
				if err != nil {
					errs <- err
					return
				}
				sig, err := Sign(sk, msg)
				if err != nil {
					errs <- err
					return
				}
				pks[i] = pk
				sigs[i] = sig
			}

			agg, err := AggregateSignatures(sigs)
			if err != nil {
				errs <- err
				return
			}
			valid, err := VerifyAggregate(pks, msg, agg)
			if err != nil {
				errs <- err
				return
			}
			if !valid {
				errs <- fmt.Errorf("parallel aggregate rejected")
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent aggregation error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

func TestBLS_Determinism(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("deterministic test")
	sig1, err := Sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := Sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}

	// BLS signatures are deterministic: same key + same message = same signature.
	if !bytes.Equal(sig1.Bytes(), sig2.Bytes()) {
		t.Fatal("same key and message produced different signatures")
	}

	// Verify both are valid.
	for i, sig := range []*Signature{sig1, sig2} {
		valid, err := Verify(pk, msg, sig)
		if err != nil || !valid {
			t.Fatalf("deterministic signature %d rejected: err=%v valid=%v", i, err, valid)
		}
	}
}

func TestBLS_Zeroize(t *testing.T) {
	sk, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sk.Zeroize()
	if sk.scalar != nil {
		t.Fatal("Zeroize did not nil scalar")
	}
}

func TestSignature_BytesRoundTrip(t *testing.T) {
	sk, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, []byte("round trip test"))
	if err != nil {
		t.Fatal(err)
	}

	raw := sig.Bytes()
	restored, err := SignatureFromBytes(raw)
	if err != nil {
		t.Fatalf("SignatureFromBytes: %v", err)
	}
	if !bytes.Equal(restored.Bytes(), raw) {
		t.Fatal("signature round-trip mismatch")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkBLSSign(b *testing.B) {
	sk, _, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark sign message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Sign(sk, msg)
	}
}

func BenchmarkBLSVerify(b *testing.B) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark verify message")
	sig, err := Sign(sk, msg)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Verify(pk, msg, sig)
	}
}

func BenchmarkBLSAggregate_100(b *testing.B) {
	msg := []byte("aggregate benchmark 100")
	sigs := make([]*Signature, 100)
	for i := 0; i < 100; i++ {
		sk, _, err := GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		sig, err := Sign(sk, msg)
		if err != nil {
			b.Fatal(err)
		}
		sigs[i] = sig
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AggregateSignatures(sigs)
	}
}

func BenchmarkBLSAggregate_500(b *testing.B) {
	msg := []byte("aggregate benchmark 500")
	sigs := make([]*Signature, 500)
	for i := 0; i < 500; i++ {
		sk, _, err := GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		sig, err := Sign(sk, msg)
		if err != nil {
			b.Fatal(err)
		}
		sigs[i] = sig
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AggregateSignatures(sigs)
	}
}

// ---------------------------------------------------------------------------
// Fuzz tests
// ---------------------------------------------------------------------------

func FuzzBLSSignVerify(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("hello"))
	f.Add(make([]byte, 256))
	f.Add(make([]byte, 4096))

	sk, pk, err := GenerateKeyPair()
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, msg []byte) {
		sig, err := Sign(sk, msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		valid, err := Verify(pk, msg, sig)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !valid {
			t.Fatal("valid signature rejected under fuzz")
		}
	})
}

func FuzzBLSAggregateVerify(f *testing.F) {
	f.Add([]byte("fuzz aggregate"), uint8(2))
	f.Add([]byte(""), uint8(5))
	f.Add(make([]byte, 1024), uint8(10))

	f.Fuzz(func(t *testing.T, msg []byte, countRaw uint8) {
		count := int(countRaw)%20 + 1 // 1..20 signers
		pks := make([]*PublicKey, count)
		sigs := make([]*Signature, count)
		for i := 0; i < count; i++ {
			sk, pk, err := GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			sig, err := Sign(sk, msg)
			if err != nil {
				t.Fatal(err)
			}
			pks[i] = pk
			sigs[i] = sig
		}

		agg, err := AggregateSignatures(sigs)
		if err != nil {
			t.Fatalf("AggregateSignatures: %v", err)
		}

		valid, err := VerifyAggregate(pks, msg, agg)
		if err != nil {
			t.Fatalf("VerifyAggregate: %v", err)
		}
		if !valid {
			t.Fatal("aggregate rejected under fuzz")
		}
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
