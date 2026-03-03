//go:build pqc_circl
// +build pqc_circl

// Package pqc provides production PQC using Cloudflare's circl library.
//
// This file is only compiled when the pqc_circl build tag is set.
// It provides real NIST FIPS 204 (ML-DSA/Dilithium) and FIPS 203 (ML-KEM/Kyber)
// implementations using the Cloudflare circl library.
//
// Build with: go build -tags=pqc_circl
//
// Prerequisites:
//   go get github.com/cloudflare/circl@latest
package pqc

import (
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

func init() {
	// Override the default implementations with real circl versions
	circlAvailableImpl = func() bool { return true }
}

// =============================================================================
// Real Dilithium (ML-DSA) Implementation using circl
// =============================================================================

// generateCirclDilithiumReal generates a real Dilithium key pair using circl.
func generateCirclDilithiumReal(level int) (*CirclDilithiumKeyPair, error) {
	switch level {
	case DilithiumLevel2:
		pk, sk, err := mode2.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("circl mode2 key generation failed: %w", err)
		}
		pkBytes, err := pk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		skBytes, err := sk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		return &CirclDilithiumKeyPair{
			Level:      level,
			PublicKey:  pkBytes,
			PrivateKey: skBytes,
			useCircl:   true,
		}, nil

	case DilithiumLevel3:
		pk, sk, err := mode3.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("circl mode3 key generation failed: %w", err)
		}
		pkBytes, err := pk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		skBytes, err := sk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		return &CirclDilithiumKeyPair{
			Level:      level,
			PublicKey:  pkBytes,
			PrivateKey: skBytes,
			useCircl:   true,
		}, nil

	case DilithiumLevel5:
		pk, sk, err := mode5.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("circl mode5 key generation failed: %w", err)
		}
		pkBytes, err := pk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		skBytes, err := sk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		return &CirclDilithiumKeyPair{
			Level:      level,
			PublicKey:  pkBytes,
			PrivateKey: skBytes,
			useCircl:   true,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported Dilithium level: %d", level)
	}
}

// signCirclDilithiumReal signs a message using real circl Dilithium.
func signCirclDilithiumReal(kp *CirclDilithiumKeyPair, message []byte) (*DilithiumSignature, error) {
	switch kp.Level {
	case DilithiumLevel2:
		var sk mode2.PrivateKey
		if err := sk.UnmarshalBinary(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
		}
		sig := mode2.Sign(&sk, message)
		return &DilithiumSignature{
			Level:     kp.Level,
			Signature: sig,
		}, nil

	case DilithiumLevel3:
		var sk mode3.PrivateKey
		if err := sk.UnmarshalBinary(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
		}
		sig := mode3.Sign(&sk, message)
		return &DilithiumSignature{
			Level:     kp.Level,
			Signature: sig,
		}, nil

	case DilithiumLevel5:
		var sk mode5.PrivateKey
		if err := sk.UnmarshalBinary(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
		}
		sig := mode5.Sign(&sk, message)
		return &DilithiumSignature{
			Level:     kp.Level,
			Signature: sig,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported Dilithium level: %d", kp.Level)
	}
}

// verifyCirclDilithiumReal verifies a signature using real circl Dilithium.
func verifyCirclDilithiumReal(publicKey []byte, message []byte, sig *DilithiumSignature) (bool, error) {
	switch sig.Level {
	case DilithiumLevel2:
		var pk mode2.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("failed to unmarshal public key: %w", err)
		}
		return mode2.Verify(&pk, message, sig.Signature), nil

	case DilithiumLevel3:
		var pk mode3.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("failed to unmarshal public key: %w", err)
		}
		return mode3.Verify(&pk, message, sig.Signature), nil

	case DilithiumLevel5:
		var pk mode5.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("failed to unmarshal public key: %w", err)
		}
		return mode5.Verify(&pk, message, sig.Signature), nil

	default:
		return false, fmt.Errorf("unsupported Dilithium level: %d", sig.Level)
	}
}

// =============================================================================
// Real Kyber (ML-KEM) Implementation using circl
// =============================================================================

// generateCirclKyberReal generates a real Kyber key pair using circl.
func generateCirclKyberReal(level int) (*CirclKyberKeyPair, error) {
	switch level {
	case KyberLevel512:
		pk, sk, err := kyber512.GenerateKeyPair(nil)
		if err != nil {
			return nil, fmt.Errorf("circl kyber512 key generation failed: %w", err)
		}
		pkBytes, err := pk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		skBytes, err := sk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		return &CirclKyberKeyPair{
			Level:      level,
			PublicKey:  pkBytes,
			PrivateKey: skBytes,
			useCircl:   true,
		}, nil

	case KyberLevel768:
		pk, sk, err := kyber768.GenerateKeyPair(nil)
		if err != nil {
			return nil, fmt.Errorf("circl kyber768 key generation failed: %w", err)
		}
		pkBytes, err := pk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		skBytes, err := sk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		return &CirclKyberKeyPair{
			Level:      level,
			PublicKey:  pkBytes,
			PrivateKey: skBytes,
			useCircl:   true,
		}, nil

	case KyberLevel1024:
		pk, sk, err := kyber1024.GenerateKeyPair(nil)
		if err != nil {
			return nil, fmt.Errorf("circl kyber1024 key generation failed: %w", err)
		}
		pkBytes, err := pk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		skBytes, err := sk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		return &CirclKyberKeyPair{
			Level:      level,
			PublicKey:  pkBytes,
			PrivateKey: skBytes,
			useCircl:   true,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported Kyber level: %d", level)
	}
}

// encapsulateCirclKyberReal performs real encapsulation using circl Kyber.
func encapsulateCirclKyberReal(level int, publicKey []byte) ([]byte, *KyberCiphertext, error) {
	switch level {
	case KyberLevel512:
		var pk kyber512.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal public key: %w", err)
		}
		ct, ss, err := kyber512.Encapsulate(&pk)
		if err != nil {
			return nil, nil, fmt.Errorf("kyber512 encapsulation failed: %w", err)
		}
		ctBytes, err := ct.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal ciphertext: %w", err)
		}
		return ss, &KyberCiphertext{Level: level, Ciphertext: ctBytes}, nil

	case KyberLevel768:
		var pk kyber768.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal public key: %w", err)
		}
		ct, ss, err := kyber768.Encapsulate(&pk)
		if err != nil {
			return nil, nil, fmt.Errorf("kyber768 encapsulation failed: %w", err)
		}
		ctBytes, err := ct.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal ciphertext: %w", err)
		}
		return ss, &KyberCiphertext{Level: level, Ciphertext: ctBytes}, nil

	case KyberLevel1024:
		var pk kyber1024.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal public key: %w", err)
		}
		ct, ss, err := kyber1024.Encapsulate(&pk)
		if err != nil {
			return nil, nil, fmt.Errorf("kyber1024 encapsulation failed: %w", err)
		}
		ctBytes, err := ct.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal ciphertext: %w", err)
		}
		return ss, &KyberCiphertext{Level: level, Ciphertext: ctBytes}, nil

	default:
		return nil, nil, fmt.Errorf("unsupported Kyber level: %d", level)
	}
}

// decapsulateCirclKyberReal performs real decapsulation using circl Kyber.
func decapsulateCirclKyberReal(kp *CirclKyberKeyPair, ciphertext *KyberCiphertext) ([]byte, error) {
	switch kp.Level {
	case KyberLevel512:
		var sk kyber512.PrivateKey
		if err := sk.UnmarshalBinary(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
		}
		var ct kyber512.Ciphertext
		if err := ct.UnmarshalBinary(ciphertext.Ciphertext); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ciphertext: %w", err)
		}
		ss, err := kyber512.Decapsulate(&sk, &ct)
		if err != nil {
			return nil, fmt.Errorf("kyber512 decapsulation failed: %w", err)
		}
		return ss, nil

	case KyberLevel768:
		var sk kyber768.PrivateKey
		if err := sk.UnmarshalBinary(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
		}
		var ct kyber768.Ciphertext
		if err := ct.UnmarshalBinary(ciphertext.Ciphertext); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ciphertext: %w", err)
		}
		ss, err := kyber768.Decapsulate(&sk, &ct)
		if err != nil {
			return nil, fmt.Errorf("kyber768 decapsulation failed: %w", err)
		}
		return ss, nil

	case KyberLevel1024:
		var sk kyber1024.PrivateKey
		if err := sk.UnmarshalBinary(kp.PrivateKey); err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
		}
		var ct kyber1024.Ciphertext
		if err := ct.UnmarshalBinary(ciphertext.Ciphertext); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ciphertext: %w", err)
		}
		ss, err := kyber1024.Decapsulate(&sk, &ct)
		if err != nil {
			return nil, fmt.Errorf("kyber1024 decapsulation failed: %w", err)
		}
		return ss, nil

	default:
		return nil, fmt.Errorf("unsupported Kyber level: %d", kp.Level)
	}
}
