// Package pqc — real post-quantum primitives backed by the Cloudflare circl
// library, compiled unconditionally.
//
// This file is the single source of truth for ML-DSA (FIPS 204) signatures and
// ML-KEM (FIPS 203) key encapsulation. circl is pure Go and a direct module
// dependency, so there is no build tag and no simulated fallback: every keygen,
// sign, verify, encapsulate, and decapsulate in this package routes here.
//
// Algorithm mapping (Aethelred level -> NIST standard -> circl package):
//
//	DilithiumLevel2 -> ML-DSA-44 -> sign/mldsa/mldsa44
//	DilithiumLevel3 -> ML-DSA-65 -> sign/mldsa/mldsa65   (Aethelred default)
//	DilithiumLevel5 -> ML-DSA-87 -> sign/mldsa/mldsa87
//	KyberLevel512   -> ML-KEM-512  -> kem/mlkem/mlkem512
//	KyberLevel768   -> ML-KEM-768  -> kem/mlkem/mlkem768  (Aethelred default)
//	KyberLevel1024  -> ML-KEM-1024 -> kem/mlkem/mlkem1024
//
// NOTE: circl's sign/mldsa packages implement the *standardized* ML-DSA, which
// is NOT wire-compatible with the older round-3 sign/dilithium packages. All
// sizes below are taken from the circl package constants so they can never
// drift from the implementation.
package pqc

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// mldsaCtx is the ML-DSA context string used for every signature. FIPS 204
// allows an application context (max 255 bytes) that is bound into the
// signature. We keep it empty here so signatures stay interoperable with
// standard ML-DSA verifiers; higher layers (e.g. seal signing) add their own
// domain-separation prefix to the message itself.
var mldsaCtx []byte

// =============================================================================
// ML-DSA (FIPS 204) signatures
// =============================================================================

// mldsaSizes returns the public-key, secret-key, signature, and seed sizes for
// the ML-DSA parameter set corresponding to the given Dilithium level.
func mldsaSizes(level int) (pkSize, skSize, sigSize, seedSize int, err error) {
	switch level {
	case DilithiumLevel2:
		return mldsa44.PublicKeySize, mldsa44.PrivateKeySize, mldsa44.SignatureSize, mldsa44.SeedSize, nil
	case DilithiumLevel3:
		return mldsa65.PublicKeySize, mldsa65.PrivateKeySize, mldsa65.SignatureSize, mldsa65.SeedSize, nil
	case DilithiumLevel5:
		return mldsa87.PublicKeySize, mldsa87.PrivateKeySize, mldsa87.SignatureSize, mldsa87.SeedSize, nil
	default:
		return 0, 0, 0, 0, fmt.Errorf("unsupported ML-DSA level: %d", level)
	}
}

// mldsaGenerateKey generates a fresh ML-DSA key pair using the system CSPRNG and
// returns the packed public and secret keys.
func mldsaGenerateKey(level int) (pub, priv []byte, err error) {
	switch level {
	case DilithiumLevel2:
		pk, sk, e := mldsa44.GenerateKey(rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		return pk.Bytes(), sk.Bytes(), nil
	case DilithiumLevel3:
		pk, sk, e := mldsa65.GenerateKey(rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		return pk.Bytes(), sk.Bytes(), nil
	case DilithiumLevel5:
		pk, sk, e := mldsa87.GenerateKey(rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		return pk.Bytes(), sk.Bytes(), nil
	default:
		return nil, nil, fmt.Errorf("unsupported ML-DSA level: %d", level)
	}
}

// mldsaDeriveKey deterministically derives an ML-DSA key pair from a seed
// (FIPS 204 ML-DSA.KeyGen(xi)). The seed must be exactly SeedSize bytes. This is
// the basis for HD/mnemonic wallet recovery: the same seed always yields the
// same key pair.
func mldsaDeriveKey(level int, seed []byte) (pub, priv []byte, err error) {
	_, _, _, seedSize, err := mldsaSizes(level)
	if err != nil {
		return nil, nil, err
	}
	if len(seed) != seedSize {
		return nil, nil, fmt.Errorf("ML-DSA seed must be exactly %d bytes, got %d", seedSize, len(seed))
	}
	switch level {
	case DilithiumLevel2:
		var s [mldsa44.SeedSize]byte
		copy(s[:], seed)
		pk, sk := mldsa44.NewKeyFromSeed(&s)
		return pk.Bytes(), sk.Bytes(), nil
	case DilithiumLevel3:
		var s [mldsa65.SeedSize]byte
		copy(s[:], seed)
		pk, sk := mldsa65.NewKeyFromSeed(&s)
		return pk.Bytes(), sk.Bytes(), nil
	case DilithiumLevel5:
		var s [mldsa87.SeedSize]byte
		copy(s[:], seed)
		pk, sk := mldsa87.NewKeyFromSeed(&s)
		return pk.Bytes(), sk.Bytes(), nil
	default:
		return nil, nil, fmt.Errorf("unsupported ML-DSA level: %d", level)
	}
}

// mldsaSign produces a hedged (randomized) ML-DSA signature over msg. Hedged
// signing is the FIPS 204 recommended default: it mixes fresh randomness into
// the signature for fault- and side-channel resistance while remaining verifiable
// by any standard ML-DSA verifier.
func mldsaSign(level int, privBytes, msg []byte) ([]byte, error) {
	switch level {
	case DilithiumLevel2:
		var sk mldsa44.PrivateKey
		if err := sk.UnmarshalBinary(privBytes); err != nil {
			return nil, fmt.Errorf("invalid ML-DSA-44 private key: %w", err)
		}
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(&sk, msg, mldsaCtx, true, sig); err != nil {
			return nil, fmt.Errorf("ML-DSA-44 signing failed: %w", err)
		}
		return sig, nil
	case DilithiumLevel3:
		var sk mldsa65.PrivateKey
		if err := sk.UnmarshalBinary(privBytes); err != nil {
			return nil, fmt.Errorf("invalid ML-DSA-65 private key: %w", err)
		}
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(&sk, msg, mldsaCtx, true, sig); err != nil {
			return nil, fmt.Errorf("ML-DSA-65 signing failed: %w", err)
		}
		return sig, nil
	case DilithiumLevel5:
		var sk mldsa87.PrivateKey
		if err := sk.UnmarshalBinary(privBytes); err != nil {
			return nil, fmt.Errorf("invalid ML-DSA-87 private key: %w", err)
		}
		sig := make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(&sk, msg, mldsaCtx, true, sig); err != nil {
			return nil, fmt.Errorf("ML-DSA-87 signing failed: %w", err)
		}
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported ML-DSA level: %d", level)
	}
}

// mldsaVerify verifies an ML-DSA signature. It returns (false, nil) for a
// well-formed but invalid signature, and (false, err) when the public key or
// signature is malformed.
func mldsaVerify(level int, pubBytes, msg, sig []byte) (bool, error) {
	if _, _, sigSize, _, err := mldsaSizes(level); err != nil {
		return false, err
	} else if len(sig) != sigSize {
		return false, fmt.Errorf("invalid ML-DSA signature size: expected %d, got %d", sigSize, len(sig))
	}
	switch level {
	case DilithiumLevel2:
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(pubBytes); err != nil {
			return false, fmt.Errorf("invalid ML-DSA-44 public key: %w", err)
		}
		return mldsa44.Verify(&pk, msg, mldsaCtx, sig), nil
	case DilithiumLevel3:
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(pubBytes); err != nil {
			return false, fmt.Errorf("invalid ML-DSA-65 public key: %w", err)
		}
		return mldsa65.Verify(&pk, msg, mldsaCtx, sig), nil
	case DilithiumLevel5:
		var pk mldsa87.PublicKey
		if err := pk.UnmarshalBinary(pubBytes); err != nil {
			return false, fmt.Errorf("invalid ML-DSA-87 public key: %w", err)
		}
		return mldsa87.Verify(&pk, msg, mldsaCtx, sig), nil
	default:
		return false, fmt.Errorf("unsupported ML-DSA level: %d", level)
	}
}

// =============================================================================
// ML-KEM (FIPS 203) key encapsulation
// =============================================================================

// mlkemSizes returns the public-key, secret-key, ciphertext, and shared-secret
// sizes for the ML-KEM parameter set corresponding to the given Kyber level.
func mlkemSizes(level int) (pkSize, skSize, ctSize, ssSize int, err error) {
	switch level {
	case KyberLevel512:
		return mlkem512.PublicKeySize, mlkem512.PrivateKeySize, mlkem512.CiphertextSize, mlkem512.SharedKeySize, nil
	case KyberLevel768:
		return mlkem768.PublicKeySize, mlkem768.PrivateKeySize, mlkem768.CiphertextSize, mlkem768.SharedKeySize, nil
	case KyberLevel1024:
		return mlkem1024.PublicKeySize, mlkem1024.PrivateKeySize, mlkem1024.CiphertextSize, mlkem1024.SharedKeySize, nil
	default:
		return 0, 0, 0, 0, fmt.Errorf("unsupported ML-KEM level: %d", level)
	}
}

// mlkemGenerateKey generates a fresh ML-KEM key pair and returns the packed
// public and secret keys.
func mlkemGenerateKey(level int) (pub, priv []byte, err error) {
	switch level {
	case KyberLevel512:
		pk, sk, e := mlkem512.GenerateKeyPair(rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		return marshalKEM(pk, sk)
	case KyberLevel768:
		pk, sk, e := mlkem768.GenerateKeyPair(rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		return marshalKEM(pk, sk)
	case KyberLevel1024:
		pk, sk, e := mlkem1024.GenerateKeyPair(rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		return marshalKEM(pk, sk)
	default:
		return nil, nil, fmt.Errorf("unsupported ML-KEM level: %d", level)
	}
}

// mlkemSeedSize returns the seed length required by ML-KEM deterministic
// keygen for the given level.
func mlkemSeedSize(level int) (int, error) {
	switch level {
	case KyberLevel512:
		return mlkem512.KeySeedSize, nil
	case KyberLevel768:
		return mlkem768.KeySeedSize, nil
	case KyberLevel1024:
		return mlkem1024.KeySeedSize, nil
	default:
		return 0, fmt.Errorf("unsupported ML-KEM level: %d", level)
	}
}

// mlkemDeriveKey deterministically derives an ML-KEM key pair from a seed. The
// seed must be exactly KeySeedSize bytes for the level.
func mlkemDeriveKey(level int, seed []byte) (pub, priv []byte, err error) {
	want, err := mlkemSeedSize(level)
	if err != nil {
		return nil, nil, err
	}
	if len(seed) != want {
		return nil, nil, fmt.Errorf("ML-KEM seed must be exactly %d bytes, got %d", want, len(seed))
	}
	switch level {
	case KyberLevel512:
		pk, sk := mlkem512.NewKeyFromSeed(seed)
		return marshalKEM(pk, sk)
	case KyberLevel768:
		pk, sk := mlkem768.NewKeyFromSeed(seed)
		return marshalKEM(pk, sk)
	case KyberLevel1024:
		pk, sk := mlkem1024.NewKeyFromSeed(seed)
		return marshalKEM(pk, sk)
	default:
		return nil, nil, fmt.Errorf("unsupported ML-KEM level: %d", level)
	}
}

// binaryMarshaler is the subset of encoding.BinaryMarshaler that circl's ML-KEM
// public and private keys implement; used to flatten key marshaling.
type binaryMarshaler interface{ MarshalBinary() ([]byte, error) }

func marshalKEM(pk, sk binaryMarshaler) (pub, priv []byte, err error) {
	pub, err = pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal ML-KEM public key: %w", err)
	}
	priv, err = sk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal ML-KEM private key: %w", err)
	}
	return pub, priv, nil
}

// mlkemEncapsulate encapsulates a fresh shared secret to the given public key,
// returning the shared secret and ciphertext.
func mlkemEncapsulate(level int, pubBytes []byte) (sharedSecret, ciphertext []byte, err error) {
	switch level {
	case KyberLevel512:
		var pk mlkem512.PublicKey
		if err := pk.Unpack(pubBytes); err != nil {
			return nil, nil, fmt.Errorf("invalid ML-KEM-512 public key: %w", err)
		}
		ct := make([]byte, mlkem512.CiphertextSize)
		ss := make([]byte, mlkem512.SharedKeySize)
		pk.EncapsulateTo(ct, ss, nil)
		return ss, ct, nil
	case KyberLevel768:
		var pk mlkem768.PublicKey
		if err := pk.Unpack(pubBytes); err != nil {
			return nil, nil, fmt.Errorf("invalid ML-KEM-768 public key: %w", err)
		}
		ct := make([]byte, mlkem768.CiphertextSize)
		ss := make([]byte, mlkem768.SharedKeySize)
		pk.EncapsulateTo(ct, ss, nil)
		return ss, ct, nil
	case KyberLevel1024:
		var pk mlkem1024.PublicKey
		if err := pk.Unpack(pubBytes); err != nil {
			return nil, nil, fmt.Errorf("invalid ML-KEM-1024 public key: %w", err)
		}
		ct := make([]byte, mlkem1024.CiphertextSize)
		ss := make([]byte, mlkem1024.SharedKeySize)
		pk.EncapsulateTo(ct, ss, nil)
		return ss, ct, nil
	default:
		return nil, nil, fmt.Errorf("unsupported ML-KEM level: %d", level)
	}
}

// mlkemDecapsulate recovers the shared secret from a ciphertext. ML-KEM uses
// implicit rejection, so a malformed ciphertext yields a pseudorandom secret
// rather than an error; callers must bind the secret to a transcript.
func mlkemDecapsulate(level int, privBytes, ciphertext []byte) ([]byte, error) {
	switch level {
	case KyberLevel512:
		if len(ciphertext) != mlkem512.CiphertextSize {
			return nil, fmt.Errorf("invalid ML-KEM-512 ciphertext size: expected %d, got %d", mlkem512.CiphertextSize, len(ciphertext))
		}
		var sk mlkem512.PrivateKey
		if err := sk.Unpack(privBytes); err != nil {
			return nil, fmt.Errorf("invalid ML-KEM-512 private key: %w", err)
		}
		ss := make([]byte, mlkem512.SharedKeySize)
		sk.DecapsulateTo(ss, ciphertext)
		return ss, nil
	case KyberLevel768:
		if len(ciphertext) != mlkem768.CiphertextSize {
			return nil, fmt.Errorf("invalid ML-KEM-768 ciphertext size: expected %d, got %d", mlkem768.CiphertextSize, len(ciphertext))
		}
		var sk mlkem768.PrivateKey
		if err := sk.Unpack(privBytes); err != nil {
			return nil, fmt.Errorf("invalid ML-KEM-768 private key: %w", err)
		}
		ss := make([]byte, mlkem768.SharedKeySize)
		sk.DecapsulateTo(ss, ciphertext)
		return ss, nil
	case KyberLevel1024:
		if len(ciphertext) != mlkem1024.CiphertextSize {
			return nil, fmt.Errorf("invalid ML-KEM-1024 ciphertext size: expected %d, got %d", mlkem1024.CiphertextSize, len(ciphertext))
		}
		var sk mlkem1024.PrivateKey
		if err := sk.Unpack(privBytes); err != nil {
			return nil, fmt.Errorf("invalid ML-KEM-1024 private key: %w", err)
		}
		ss := make([]byte, mlkem1024.SharedKeySize)
		sk.DecapsulateTo(ss, ciphertext)
		return ss, nil
	default:
		return nil, fmt.Errorf("unsupported ML-KEM level: %d", level)
	}
}
