// Package pqc provides post-quantum cryptography integration for Aethelred.
//
// This file exposes the public ML-DSA (FIPS 204) and ML-KEM (FIPS 203) surface
// used by the rest of the codebase. All operations are backed by the real
// Cloudflare circl primitives in circl_backend.go — circl is pure Go and a
// direct dependency, so the implementation is always available. There is no
// build tag and no simulated-crypto fallback.
//
// PQCMode (see production.go) controls signature *policy* — e.g. whether
// composite (classical + PQC) signatures are mandatory — not whether the
// cryptography is real.
package pqc

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
)

// CirclIntegration tracks one-time initialization state for the PQC backend.
type CirclIntegration struct {
	mu          sync.RWMutex
	initialized bool
	mode        PQCMode
}

// Global circl integration instance
var circlInstance = &CirclIntegration{}

// InitCircl initializes the PQC backend. It is idempotent and records the
// active mode for diagnostics.
func InitCircl() error {
	circlInstance.mu.Lock()
	defer circlInstance.mu.Unlock()

	if circlInstance.initialized {
		return nil
	}

	circlInstance.initialized = true
	circlInstance.mode = GetPQCMode()

	return nil
}

// IsCirclAvailable reports whether real PQC primitives are compiled in. circl is
// an unconditional dependency, so this is always true; the function is retained
// for callers and readiness checks that historically gated on it.
func IsCirclAvailable() bool {
	return true
}

// pqcRequiresCircl reports whether the mode mandates composite/PQC signatures.
// Real PQC is always available regardless of mode; this only affects policy.
func pqcRequiresCircl(mode PQCMode) bool {
	return mode == PQCModeProduction || mode == PQCModeHybrid
}

// =============================================================================
// Dilithium (ML-DSA) Integration
// =============================================================================

// CirclDilithiumKeyPair wraps a packed ML-DSA key pair.
type CirclDilithiumKeyPair struct {
	// Level is the NIST security level (2, 3, or 5).
	Level int
	// PublicKey is the packed ML-DSA public key.
	PublicKey []byte
	// PrivateKey is the packed ML-DSA private key.
	PrivateKey []byte
}

// GenerateCirclDilithiumKeyPair generates a new ML-DSA key pair.
func GenerateCirclDilithiumKeyPair(level int) (*CirclDilithiumKeyPair, error) {
	pub, priv, err := mldsaGenerateKey(level)
	if err != nil {
		return nil, err
	}
	return &CirclDilithiumKeyPair{Level: level, PublicKey: pub, PrivateKey: priv}, nil
}

// Sign creates an ML-DSA signature over the message.
func (kp *CirclDilithiumKeyPair) Sign(message []byte) (*DilithiumSignature, error) {
	sig, err := mldsaSign(kp.Level, kp.PrivateKey, message)
	if err != nil {
		return nil, err
	}
	return &DilithiumSignature{Level: kp.Level, Signature: sig}, nil
}

// VerifyCirclDilithium verifies an ML-DSA signature.
func VerifyCirclDilithium(publicKey []byte, message []byte, sig *DilithiumSignature) (bool, error) {
	return mldsaVerify(sig.Level, publicKey, message, sig.Signature)
}

// =============================================================================
// Kyber (ML-KEM) Integration
// =============================================================================

// CirclKyberKeyPair wraps a packed ML-KEM key pair.
type CirclKyberKeyPair struct {
	// Level is the NIST security level (512, 768, or 1024).
	Level int
	// PublicKey is the packed ML-KEM encapsulation key.
	PublicKey []byte
	// PrivateKey is the packed ML-KEM decapsulation key.
	PrivateKey []byte
}

// GenerateCirclKyberKeyPair generates a new ML-KEM key pair.
func GenerateCirclKyberKeyPair(level int) (*CirclKyberKeyPair, error) {
	pub, priv, err := mlkemGenerateKey(level)
	if err != nil {
		return nil, err
	}
	return &CirclKyberKeyPair{Level: level, PublicKey: pub, PrivateKey: priv}, nil
}

// Encapsulate performs key encapsulation against the recipient's public key.
func (kp *CirclKyberKeyPair) Encapsulate(recipientPublicKey []byte) (sharedSecret []byte, ciphertext *KyberCiphertext, err error) {
	ss, ct, err := mlkemEncapsulate(kp.Level, recipientPublicKey)
	if err != nil {
		return nil, nil, err
	}
	return ss, &KyberCiphertext{Level: kp.Level, Ciphertext: ct}, nil
}

// Decapsulate recovers the shared secret from a ciphertext.
func (kp *CirclKyberKeyPair) Decapsulate(ciphertext *KyberCiphertext) ([]byte, error) {
	return mlkemDecapsulate(kp.Level, kp.PrivateKey, ciphertext.Ciphertext)
}

// =============================================================================
// Production Mode Enforcement
// =============================================================================

// EnforceProductionMode sets the PQC mode to Production and runs the NIST
// self-tests. This should be called during mainnet/testnet initialization.
func EnforceProductionMode() error {
	SetPQCMode(PQCModeProduction)

	if err := RunPQCSelfTests(); err != nil {
		return fmt.Errorf("PQC self-tests failed: %w", err)
	}

	return nil
}

// RunPQCSelfTests runs power-on self-tests for the PQC algorithms: an ML-DSA
// sign/verify round-trip and an ML-KEM encapsulate/decapsulate round-trip with
// shared-secret agreement. It returns an error if any primitive misbehaves.
func RunPQCSelfTests() error {
	// ML-DSA: sign/verify round-trip.
	kp, err := GenerateCirclDilithiumKeyPair(DilithiumLevel3)
	if err != nil {
		return fmt.Errorf("ML-DSA key generation failed: %w", err)
	}

	testMessage := make([]byte, 64)
	if _, err := rand.Read(testMessage); err != nil {
		return fmt.Errorf("failed to generate test message: %w", err)
	}

	sig, err := kp.Sign(testMessage)
	if err != nil {
		return fmt.Errorf("ML-DSA signing failed: %w", err)
	}

	valid, err := VerifyCirclDilithium(kp.PublicKey, testMessage, sig)
	if err != nil {
		return fmt.Errorf("ML-DSA verification failed: %w", err)
	}
	if !valid {
		return errors.New("ML-DSA self-test: signature verification returned false")
	}

	// Negative control: a tampered message must fail.
	tampered := append([]byte(nil), testMessage...)
	tampered[0] ^= 0xFF
	if bad, _ := VerifyCirclDilithium(kp.PublicKey, tampered, sig); bad {
		return errors.New("ML-DSA self-test: tampered message verified as valid")
	}

	// ML-KEM: encapsulate/decapsulate round-trip.
	kyberKP, err := GenerateCirclKyberKeyPair(KyberLevel768)
	if err != nil {
		return fmt.Errorf("ML-KEM key generation failed: %w", err)
	}

	sharedSecret1, ct, err := kyberKP.Encapsulate(kyberKP.PublicKey)
	if err != nil {
		return fmt.Errorf("ML-KEM encapsulation failed: %w", err)
	}

	sharedSecret2, err := kyberKP.Decapsulate(ct)
	if err != nil {
		return fmt.Errorf("ML-KEM decapsulation failed: %w", err)
	}

	if len(sharedSecret1) != len(sharedSecret2) || subtle.ConstantTimeCompare(sharedSecret1, sharedSecret2) != 1 {
		return errors.New("ML-KEM self-test: shared secret mismatch")
	}

	return nil
}

// GetPQCImplementationInfo returns information about the active PQC backend.
func GetPQCImplementationInfo() map[string]interface{} {
	return map[string]interface{}{
		"mode":            GetPQCMode().String(),
		"backend":         "cloudflare/circl",
		"circl_available": true,
		"dilithium_levels": []int{
			DilithiumLevel2,
			DilithiumLevel3,
			DilithiumLevel5,
		},
		"kyber_levels": []int{
			KyberLevel512,
			KyberLevel768,
			KyberLevel1024,
		},
		"fips_204_compliant": true,
		"fips_203_compliant": true,
	}
}

// String returns a string representation of the PQC mode.
func (m PQCMode) String() string {
	switch m {
	case PQCModeSimulated:
		return "Permissive"
	case PQCModeProduction:
		return "Production"
	case PQCModeHybrid:
		return "Hybrid"
	default:
		return fmt.Sprintf("Unknown(%d)", m)
	}
}
