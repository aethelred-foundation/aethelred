//go:build pqc_circl

// Package pqc provides the production post-quantum backend backed by
// Cloudflare CIRCL.
package pqc

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func circlAvailableImpl() bool {
	return true
}

// =============================================================================
// ML-DSA (FIPS 204)
// =============================================================================

func generateCirclDilithiumReal(level int) (*CirclDilithiumKeyPair, error) {
	var publicKey, privateKey []byte

	switch level {
	case DilithiumLevel2:
		pk, sk, err := mldsa44.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-44 key generation failed: %w", err)
		}
		publicKey, privateKey = pk.Bytes(), sk.Bytes()
	case DilithiumLevel3:
		pk, sk, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-65 key generation failed: %w", err)
		}
		publicKey, privateKey = pk.Bytes(), sk.Bytes()
	case DilithiumLevel5:
		pk, sk, err := mldsa87.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-87 key generation failed: %w", err)
		}
		publicKey, privateKey = pk.Bytes(), sk.Bytes()
	default:
		return nil, fmt.Errorf("unsupported Dilithium level: %d", level)
	}

	return &CirclDilithiumKeyPair{
		Level:      level,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		useCircl:   true,
	}, nil
}

func signCirclDilithiumReal(kp *CirclDilithiumKeyPair, message []byte) (*DilithiumSignature, error) {
	if kp == nil {
		return nil, errors.New("Dilithium key pair is nil")
	}

	var signature []byte

	switch kp.Level {
	case DilithiumLevel2:
		var sk mldsa44.PrivateKey
		if err := sk.UnmarshalBinary(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("invalid ML-DSA-44 private key: %w", err)
		}
		signature = make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(&sk, message, nil, true, signature); err != nil {
			return nil, fmt.Errorf("ML-DSA-44 signing failed: %w", err)
		}
	case DilithiumLevel3:
		var sk mldsa65.PrivateKey
		if err := sk.UnmarshalBinary(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("invalid ML-DSA-65 private key: %w", err)
		}
		signature = make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(&sk, message, nil, true, signature); err != nil {
			return nil, fmt.Errorf("ML-DSA-65 signing failed: %w", err)
		}
	case DilithiumLevel5:
		var sk mldsa87.PrivateKey
		if err := sk.UnmarshalBinary(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("invalid ML-DSA-87 private key: %w", err)
		}
		signature = make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(&sk, message, nil, true, signature); err != nil {
			return nil, fmt.Errorf("ML-DSA-87 signing failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported Dilithium level: %d", kp.Level)
	}

	return &DilithiumSignature{Level: kp.Level, Signature: signature}, nil
}

func verifyCirclDilithiumReal(publicKey, message []byte, sig *DilithiumSignature) (bool, error) {
	if sig == nil {
		return false, errors.New("Dilithium signature is nil")
	}

	switch sig.Level {
	case DilithiumLevel2:
		if len(sig.Signature) != mldsa44.SignatureSize {
			return false, signatureSizeError(mldsa44.SignatureSize, len(sig.Signature))
		}
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("invalid ML-DSA-44 public key: %w", err)
		}
		return mldsa44.Verify(&pk, message, nil, sig.Signature), nil
	case DilithiumLevel3:
		if len(sig.Signature) != mldsa65.SignatureSize {
			return false, signatureSizeError(mldsa65.SignatureSize, len(sig.Signature))
		}
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("invalid ML-DSA-65 public key: %w", err)
		}
		return mldsa65.Verify(&pk, message, nil, sig.Signature), nil
	case DilithiumLevel5:
		if len(sig.Signature) != mldsa87.SignatureSize {
			return false, signatureSizeError(mldsa87.SignatureSize, len(sig.Signature))
		}
		var pk mldsa87.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("invalid ML-DSA-87 public key: %w", err)
		}
		return mldsa87.Verify(&pk, message, nil, sig.Signature), nil
	default:
		return false, fmt.Errorf("unsupported Dilithium level: %d", sig.Level)
	}
}

func signatureSizeError(expected, actual int) error {
	return fmt.Errorf("invalid ML-DSA signature size: expected %d, got %d", expected, actual)
}

// =============================================================================
// ML-KEM (FIPS 203)
// =============================================================================

type binaryMarshaler interface {
	MarshalBinary() ([]byte, error)
}

func marshalCirclKEMKeyPair(level int, publicKey, privateKey binaryMarshaler) (*CirclKyberKeyPair, error) {
	publicBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ML-KEM public key: %w", err)
	}
	privateBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ML-KEM private key: %w", err)
	}

	return &CirclKyberKeyPair{
		Level:      level,
		PublicKey:  publicBytes,
		PrivateKey: privateBytes,
		useCircl:   true,
	}, nil
}

func generateCirclKyberReal(level int) (*CirclKyberKeyPair, error) {
	switch level {
	case KyberLevel512:
		pk, sk, err := mlkem512.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ML-KEM-512 key generation failed: %w", err)
		}
		return marshalCirclKEMKeyPair(level, pk, sk)
	case KyberLevel768:
		pk, sk, err := mlkem768.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ML-KEM-768 key generation failed: %w", err)
		}
		return marshalCirclKEMKeyPair(level, pk, sk)
	case KyberLevel1024:
		pk, sk, err := mlkem1024.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ML-KEM-1024 key generation failed: %w", err)
		}
		return marshalCirclKEMKeyPair(level, pk, sk)
	default:
		return nil, fmt.Errorf("unsupported Kyber level: %d", level)
	}
}

func encapsulateCirclKyberReal(level int, publicKey []byte) ([]byte, *KyberCiphertext, error) {
	var sharedSecret, ciphertext []byte

	switch level {
	case KyberLevel512:
		var pk mlkem512.PublicKey
		if err := pk.Unpack(publicKey); err != nil {
			return nil, nil, fmt.Errorf("invalid ML-KEM-512 public key: %w", err)
		}
		sharedSecret = make([]byte, mlkem512.SharedKeySize)
		ciphertext = make([]byte, mlkem512.CiphertextSize)
		pk.EncapsulateTo(ciphertext, sharedSecret, nil)
	case KyberLevel768:
		var pk mlkem768.PublicKey
		if err := pk.Unpack(publicKey); err != nil {
			return nil, nil, fmt.Errorf("invalid ML-KEM-768 public key: %w", err)
		}
		sharedSecret = make([]byte, mlkem768.SharedKeySize)
		ciphertext = make([]byte, mlkem768.CiphertextSize)
		pk.EncapsulateTo(ciphertext, sharedSecret, nil)
	case KyberLevel1024:
		var pk mlkem1024.PublicKey
		if err := pk.Unpack(publicKey); err != nil {
			return nil, nil, fmt.Errorf("invalid ML-KEM-1024 public key: %w", err)
		}
		sharedSecret = make([]byte, mlkem1024.SharedKeySize)
		ciphertext = make([]byte, mlkem1024.CiphertextSize)
		pk.EncapsulateTo(ciphertext, sharedSecret, nil)
	default:
		return nil, nil, fmt.Errorf("unsupported Kyber level: %d", level)
	}

	return sharedSecret, &KyberCiphertext{Level: level, Ciphertext: ciphertext}, nil
}

func decapsulateCirclKyberReal(kp *CirclKyberKeyPair, ciphertext *KyberCiphertext) ([]byte, error) {
	if kp == nil {
		return nil, errors.New("Kyber key pair is nil")
	}
	if ciphertext == nil {
		return nil, errors.New("Kyber ciphertext is nil")
	}
	if ciphertext.Level != kp.Level {
		return nil, fmt.Errorf("ciphertext level mismatch: expected %d, got %d", kp.Level, ciphertext.Level)
	}

	switch kp.Level {
	case KyberLevel512:
		if len(ciphertext.Ciphertext) != mlkem512.CiphertextSize {
			return nil, ciphertextSizeError(mlkem512.CiphertextSize, len(ciphertext.Ciphertext))
		}
		var sk mlkem512.PrivateKey
		if err := sk.Unpack(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("invalid ML-KEM-512 private key: %w", err)
		}
		sharedSecret := make([]byte, mlkem512.SharedKeySize)
		sk.DecapsulateTo(sharedSecret, ciphertext.Ciphertext)
		return sharedSecret, nil
	case KyberLevel768:
		if len(ciphertext.Ciphertext) != mlkem768.CiphertextSize {
			return nil, ciphertextSizeError(mlkem768.CiphertextSize, len(ciphertext.Ciphertext))
		}
		var sk mlkem768.PrivateKey
		if err := sk.Unpack(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("invalid ML-KEM-768 private key: %w", err)
		}
		sharedSecret := make([]byte, mlkem768.SharedKeySize)
		sk.DecapsulateTo(sharedSecret, ciphertext.Ciphertext)
		return sharedSecret, nil
	case KyberLevel1024:
		if len(ciphertext.Ciphertext) != mlkem1024.CiphertextSize {
			return nil, ciphertextSizeError(mlkem1024.CiphertextSize, len(ciphertext.Ciphertext))
		}
		var sk mlkem1024.PrivateKey
		if err := sk.Unpack(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("invalid ML-KEM-1024 private key: %w", err)
		}
		sharedSecret := make([]byte, mlkem1024.SharedKeySize)
		sk.DecapsulateTo(sharedSecret, ciphertext.Ciphertext)
		return sharedSecret, nil
	default:
		return nil, fmt.Errorf("unsupported Kyber level: %d", kp.Level)
	}
}

func ciphertextSizeError(expected, actual int) error {
	return fmt.Errorf("invalid ML-KEM ciphertext size: expected %d, got %d", expected, actual)
}
