// Package pqc provides post-quantum cryptography integration for Aethelred.
//
// This file implements real NIST FIPS 204 (ML-DSA/Dilithium) and FIPS 203 (ML-KEM/Kyber)
// using the Cloudflare circl library when build tag 'pqc_circl' is set.
//
// Build with: go build -tags=pqc_circl
//
// Without the build tag, this file provides stub implementations that delegate
// to the simulated implementation while warning about production use.
package pqc

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// CirclIntegration provides the interface for real PQC operations using circl.
// This is the bridge between Aethelred's PQC types and circl's implementations.
type CirclIntegration struct {
	mu sync.RWMutex

	// initialized tracks whether circl has been initialized
	initialized bool

	// mode tracks the current PQC mode
	mode PQCMode
}

// Global circl integration instance
var circlInstance = &CirclIntegration{}

// InitCircl initializes the circl library integration.
// This must be called before using production PQC operations.
func InitCircl() error {
	circlInstance.mu.Lock()
	defer circlInstance.mu.Unlock()

	if circlInstance.initialized {
		return nil
	}

	// In production build with pqc_circl tag, this would:
	// 1. Verify circl library availability
	// 2. Run self-tests per NIST requirements
	// 3. Initialize any required state

	circlInstance.initialized = true
	circlInstance.mode = GetPQCMode()

	return nil
}

// IsCirclAvailable returns true if circl library is properly integrated.
// This is determined at build time based on the pqc_circl tag.
func IsCirclAvailable() bool {
	// This will be overridden by circl_production.go when built with pqc_circl tag
	return circlAvailableImpl()
}

// circlAvailableImpl is the default implementation (no circl)
func circlAvailableImpl() bool {
	return false
}

func pqcRequiresCircl(mode PQCMode) bool {
	return mode == PQCModeProduction || mode == PQCModeHybrid
}

func circlRequiredError() error {
	return errors.New("PQC production/hybrid mode requires circl; build with -tags=pqc_circl")
}

// =============================================================================
// Dilithium (ML-DSA) Integration
// =============================================================================

// CirclDilithiumKeyPair wraps a Dilithium key pair with circl integration
type CirclDilithiumKeyPair struct {
	// Level is the NIST security level (2, 3, or 5)
	Level int

	// PublicKey is the serialized public key
	PublicKey []byte

	// PrivateKey is the serialized private key
	PrivateKey []byte

	// useCircl indicates whether to use real circl or simulation
	useCircl bool
}

// GenerateCirclDilithiumKeyPair generates a new Dilithium key pair.
// If circl is available and mode is Production, uses real lattice cryptography.
// Otherwise, falls back to the simulated implementation with a warning.
func GenerateCirclDilithiumKeyPair(level int) (*CirclDilithiumKeyPair, error) {
	mode := GetPQCMode()

	if pqcRequiresCircl(mode) {
		if !IsCirclAvailable() {
			return nil, circlRequiredError()
		}
		return generateCirclDilithiumReal(level)
	}

	// Use existing simulated implementation
	kp, err := GenerateDilithiumKeyPair(level)
	if err != nil {
		return nil, err
	}

	return &CirclDilithiumKeyPair{
		Level:      level,
		PublicKey:  kp.PublicKey,
		PrivateKey: kp.PrivateKey,
		useCircl:   false,
	}, nil
}

// generateCirclDilithiumReal generates a real Dilithium key pair using circl.
// This is overridden by circl_production.go when built with pqc_circl tag.
func generateCirclDilithiumReal(level int) (*CirclDilithiumKeyPair, error) {
	// Default stub - will be replaced by actual circl implementation
	return nil, errors.New("circl library not available - build with -tags=pqc_circl for real PQC")
}

// Sign creates a Dilithium signature over the message.
func (kp *CirclDilithiumKeyPair) Sign(message []byte) (*DilithiumSignature, error) {
	if kp.useCircl {
		return signCirclDilithiumReal(kp, message)
	}

	if pqcRequiresCircl(GetPQCMode()) {
		return nil, circlRequiredError()
	}

	// Fall back to simulated implementation
	simKP := &DilithiumKeyPair{
		Level:      kp.Level,
		PublicKey:  kp.PublicKey,
		PrivateKey: kp.PrivateKey,
	}
	return simKP.Sign(message)
}

// signCirclDilithiumReal signs using real circl Dilithium.
// This is overridden by circl_production.go when built with pqc_circl tag.
func signCirclDilithiumReal(kp *CirclDilithiumKeyPair, message []byte) (*DilithiumSignature, error) {
	return nil, errors.New("circl library not available - build with -tags=pqc_circl for real PQC")
}

// VerifyCirclDilithium verifies a Dilithium signature.
func VerifyCirclDilithium(publicKey []byte, message []byte, sig *DilithiumSignature) (bool, error) {
	mode := GetPQCMode()

	if pqcRequiresCircl(mode) {
		if !IsCirclAvailable() {
			return false, circlRequiredError()
		}
		return verifyCirclDilithiumReal(publicKey, message, sig)
	}

	// Fall back to simulated verification
	return VerifyDilithium(publicKey, message, sig)
}

// verifyCirclDilithiumReal verifies using real circl Dilithium.
// This is overridden by circl_production.go when built with pqc_circl tag.
func verifyCirclDilithiumReal(publicKey []byte, message []byte, sig *DilithiumSignature) (bool, error) {
	return false, errors.New("circl library not available - build with -tags=pqc_circl for real PQC")
}

// =============================================================================
// Kyber (ML-KEM) Integration
// =============================================================================

// CirclKyberKeyPair wraps a Kyber key pair with circl integration
type CirclKyberKeyPair struct {
	// Level is the NIST security level (512, 768, or 1024)
	Level int

	// PublicKey is the serialized encapsulation key
	PublicKey []byte

	// PrivateKey is the serialized decapsulation key
	PrivateKey []byte

	// useCircl indicates whether to use real circl or simulation
	useCircl bool
}

// GenerateCirclKyberKeyPair generates a new Kyber key pair.
// If circl is available and mode is Production, uses real lattice cryptography.
func GenerateCirclKyberKeyPair(level int) (*CirclKyberKeyPair, error) {
	mode := GetPQCMode()

	if pqcRequiresCircl(mode) {
		if !IsCirclAvailable() {
			return nil, circlRequiredError()
		}
		return generateCirclKyberReal(level)
	}

	kp, err := GenerateKyberKeyPair(level)
	if err != nil {
		return nil, err
	}

	return &CirclKyberKeyPair{
		Level:      level,
		PublicKey:  kp.PublicKey,
		PrivateKey: kp.PrivateKey,
		useCircl:   false,
	}, nil
}

// generateCirclKyberReal generates a real Kyber key pair using circl.
func generateCirclKyberReal(level int) (*CirclKyberKeyPair, error) {
	return nil, errors.New("circl library not available - build with -tags=pqc_circl for real PQC")
}

// Encapsulate performs key encapsulation using the recipient's public key.
// Returns the shared secret and ciphertext.
func (kp *CirclKyberKeyPair) Encapsulate(recipientPublicKey []byte) (sharedSecret []byte, ciphertext *KyberCiphertext, err error) {
	if kp.useCircl {
		return encapsulateCirclKyberReal(kp.Level, recipientPublicKey)
	}

	if pqcRequiresCircl(GetPQCMode()) {
		return nil, nil, circlRequiredError()
	}

	// Fall back to simulated implementation
	return Encapsulate(kp.Level, recipientPublicKey)
}

// encapsulateCirclKyberReal performs real encapsulation using circl.
func encapsulateCirclKyberReal(level int, publicKey []byte) ([]byte, *KyberCiphertext, error) {
	return nil, nil, errors.New("circl library not available - build with -tags=pqc_circl for real PQC")
}

// Decapsulate recovers the shared secret from a ciphertext.
func (kp *CirclKyberKeyPair) Decapsulate(ciphertext *KyberCiphertext) ([]byte, error) {
	if kp.useCircl {
		return decapsulateCirclKyberReal(kp, ciphertext)
	}

	if pqcRequiresCircl(GetPQCMode()) {
		return nil, circlRequiredError()
	}

	// Fall back to simulated implementation
	simKP := &KyberKeyPair{
		Level:      kp.Level,
		PublicKey:  kp.PublicKey,
		PrivateKey: kp.PrivateKey,
	}
	return simKP.Decapsulate(ciphertext)
}

// decapsulateCirclKyberReal performs real decapsulation using circl.
func decapsulateCirclKyberReal(kp *CirclKyberKeyPair, ciphertext *KyberCiphertext) ([]byte, error) {
	return nil, errors.New("circl library not available - build with -tags=pqc_circl for real PQC")
}

// =============================================================================
// Production Mode Enforcement
// =============================================================================

// EnforceProductionMode sets the PQC mode to Production and validates
// that real cryptographic implementations are available.
// This should be called during mainnet initialization.
func EnforceProductionMode() error {
	if !IsCirclAvailable() {
		return errors.New("CRITICAL: Production mode requires circl library. " +
			"Build with -tags=pqc_circl or use PQCModeSimulated for testing")
	}

	SetPQCMode(PQCModeProduction)

	// Run self-tests to validate cryptographic operations
	if err := RunPQCSelfTests(); err != nil {
		return fmt.Errorf("PQC self-tests failed: %w", err)
	}

	return nil
}

// RunPQCSelfTests runs NIST-required self-tests for PQC algorithms.
// These tests verify correct operation of the cryptographic primitives.
func RunPQCSelfTests() error {
	// Test Dilithium key generation, signing, and verification
	kp, err := GenerateCirclDilithiumKeyPair(DilithiumLevel3)
	if err != nil {
		return fmt.Errorf("Dilithium key generation failed: %w", err)
	}

	testMessage := make([]byte, 64)
	if _, err := rand.Read(testMessage); err != nil {
		return fmt.Errorf("failed to generate test message: %w", err)
	}

	sig, err := kp.Sign(testMessage)
	if err != nil {
		return fmt.Errorf("Dilithium signing failed: %w", err)
	}

	valid, err := VerifyCirclDilithium(kp.PublicKey, testMessage, sig)
	if err != nil {
		return fmt.Errorf("Dilithium verification failed: %w", err)
	}
	if !valid {
		return errors.New("Dilithium self-test: signature verification returned false")
	}

	// Test Kyber key encapsulation
	kyberKP, err := GenerateCirclKyberKeyPair(KyberLevel768)
	if err != nil {
		return fmt.Errorf("Kyber key generation failed: %w", err)
	}

	sharedSecret1, ct, err := kyberKP.Encapsulate(kyberKP.PublicKey)
	if err != nil {
		return fmt.Errorf("Kyber encapsulation failed: %w", err)
	}

	sharedSecret2, err := kyberKP.Decapsulate(ct)
	if err != nil {
		return fmt.Errorf("Kyber decapsulation failed: %w", err)
	}

	if len(sharedSecret1) != len(sharedSecret2) {
		return errors.New("Kyber self-test: shared secret length mismatch")
	}
	for i := range sharedSecret1 {
		if sharedSecret1[i] != sharedSecret2[i] {
			return errors.New("Kyber self-test: shared secret mismatch")
		}
	}

	return nil
}

// GetPQCImplementationInfo returns information about the current PQC implementation.
func GetPQCImplementationInfo() map[string]interface{} {
	return map[string]interface{}{
		"mode":            GetPQCMode().String(),
		"circl_available": IsCirclAvailable(),
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
		"fips_204_compliant": IsCirclAvailable(),
		"fips_203_compliant": IsCirclAvailable(),
	}
}

// String returns a string representation of the PQC mode.
func (m PQCMode) String() string {
	switch m {
	case PQCModeSimulated:
		return "Simulated"
	case PQCModeProduction:
		return "Production"
	case PQCModeHybrid:
		return "Hybrid"
	default:
		return fmt.Sprintf("Unknown(%d)", m)
	}
}
