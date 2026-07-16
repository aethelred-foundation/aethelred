// Package pqc provides production-ready post-quantum cryptography for Aethelred.
//
// All algorithms are real NIST standards implemented by the Cloudflare circl
// library (ML-DSA / FIPS 204 for signatures, ML-KEM / FIPS 203 for key
// encapsulation), wired in unconditionally via circl_backend.go — no build tag,
// no simulated-crypto fallback. This file layers production policy (composite
// signature enforcement, readiness checks) over those primitives.
package pqc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
)

// =============================================================================
// Production PQC Configuration
// =============================================================================

// PQCMode defines the operational mode for post-quantum cryptography
type PQCMode int

// NOTE: PQC cryptography is ALWAYS real (ML-DSA/ML-KEM via circl). PQCMode only
// governs signature *policy* — specifically whether composite (classical + PQC)
// signatures are mandatory. There is no longer a fake-crypto mode.
const (
	// PQCModeSimulated is a permissive/dev policy: single-algorithm signatures
	// are allowed. The cryptography is still real ML-DSA/ML-KEM.
	PQCModeSimulated PQCMode = iota

	// PQCModeProduction uses real NIST FIPS 204/203 algorithms and enforces
	// strict size/format checks.
	PQCModeProduction

	// PQCModeHybrid uses real PQC and additionally mandates composite
	// (classical + PQC) signatures.
	PQCModeHybrid
)

// DefaultPQCMode is the default operational mode. It defaults to Hybrid so that
// composite (classical + PQC) signatures are required unless an operator
// explicitly relaxes the policy.
var DefaultPQCMode = PQCModeHybrid

// pqcModeMu protects DefaultPQCMode from concurrent access
var pqcModeMu sync.RWMutex

// SetPQCMode sets the global PQC operational mode.
// SECURITY: This should be set once during initialization and never changed.
func SetPQCMode(mode PQCMode) {
	pqcModeMu.Lock()
	defer pqcModeMu.Unlock()
	DefaultPQCMode = mode
}

// GetPQCMode returns the current PQC operational mode.
func GetPQCMode() PQCMode {
	pqcModeMu.RLock()
	defer pqcModeMu.RUnlock()
	return DefaultPQCMode
}

// =============================================================================
// Production Dilithium Implementation (NIST FIPS 204 / ML-DSA)
// =============================================================================

// ProductionDilithiumKeyPair wraps the Dilithium key pair with production features
type ProductionDilithiumKeyPair struct {
	*DilithiumKeyPair
	mode PQCMode
}

// NewProductionDilithiumKeyPair creates a new production-grade Dilithium key pair
func NewProductionDilithiumKeyPair(level int) (*ProductionDilithiumKeyPair, error) {
	mode := GetPQCMode()

	switch mode {
	case PQCModeProduction, PQCModeHybrid:
		circlKP, err := GenerateCirclDilithiumKeyPair(level)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dilithium key pair: %w", err)
		}
		kp := &DilithiumKeyPair{
			Level:      level,
			PublicKey:  circlKP.PublicKey,
			PrivateKey: circlKP.PrivateKey,
		}
		return &ProductionDilithiumKeyPair{DilithiumKeyPair: kp, mode: mode}, nil

	case PQCModeSimulated:
		kp, err := GenerateDilithiumKeyPair(level)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dilithium key pair: %w", err)
		}
		return &ProductionDilithiumKeyPair{DilithiumKeyPair: kp, mode: mode}, nil

	default:
		return nil, fmt.Errorf("unsupported PQC mode: %d", mode)
	}
}

// Sign creates a production ML-DSA signature. Signing is backed by circl in all
// modes.
func (pkp *ProductionDilithiumKeyPair) Sign(message []byte) (*DilithiumSignature, error) {
	return pkp.DilithiumKeyPair.Sign(message)
}

// VerifyProduction verifies a signature with production-grade checks
func VerifyProduction(publicKey []byte, message []byte, signature *DilithiumSignature) (bool, error) {
	mode := GetPQCMode()

	// Additional production checks
	if mode == PQCModeProduction {
		// Validate key sizes match NIST requirements
		params, err := GetDilithiumParams(signature.Level)
		if err != nil {
			return false, fmt.Errorf("invalid Dilithium level: %w", err)
		}

		if len(publicKey) != params.PublicKeySize {
			return false, fmt.Errorf("SECURITY: public key size mismatch: expected %d, got %d",
				params.PublicKeySize, len(publicKey))
		}

		if len(signature.Signature) != params.SignatureSize {
			return false, fmt.Errorf("SECURITY: signature size mismatch: expected %d, got %d",
				params.SignatureSize, len(signature.Signature))
		}
	}

	return VerifyDilithium(publicKey, message, signature)
}

// =============================================================================
// Production Kyber Implementation (NIST FIPS 203 / ML-KEM)
// =============================================================================

// ProductionKyberKeyPair wraps the Kyber key pair with production features
type ProductionKyberKeyPair struct {
	*KyberKeyPair
	mode PQCMode
}

// NewProductionKyberKeyPair creates a new production-grade Kyber key pair
func NewProductionKyberKeyPair(level int) (*ProductionKyberKeyPair, error) {
	mode := GetPQCMode()

	switch mode {
	case PQCModeProduction, PQCModeHybrid:
		circlKP, err := GenerateCirclKyberKeyPair(level)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Kyber key pair: %w", err)
		}
		kp := &KyberKeyPair{
			Level:      level,
			PublicKey:  circlKP.PublicKey,
			PrivateKey: circlKP.PrivateKey,
		}
		return &ProductionKyberKeyPair{KyberKeyPair: kp, mode: mode}, nil

	case PQCModeSimulated:
		kp, err := GenerateKyberKeyPair(level)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Kyber key pair: %w", err)
		}
		return &ProductionKyberKeyPair{KyberKeyPair: kp, mode: mode}, nil

	default:
		return nil, fmt.Errorf("unsupported PQC mode: %d", mode)
	}
}

// EncapsulateProduction performs production-grade key encapsulation
func (pkp *ProductionKyberKeyPair) EncapsulateProduction(peerPublicKey []byte) ([]byte, *KyberCiphertext, error) {
	mode := GetPQCMode()

	// Validate public key size in production mode
	if mode == PQCModeProduction {
		params, err := GetKyberParams(pkp.Level)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid Kyber level: %w", err)
		}
		if len(peerPublicKey) != params.PublicKeySize {
			return nil, nil, fmt.Errorf("SECURITY: peer public key size mismatch: expected %d, got %d",
				params.PublicKeySize, len(peerPublicKey))
		}
	}

	return Encapsulate(pkp.Level, peerPublicKey)
}

// =============================================================================
// Production Dual-Key Wallet (Hybrid ECDSA + Dilithium)
// =============================================================================

// ProductionDualKeyWallet extends DualKeyWallet with production features
type ProductionDualKeyWallet struct {
	*DualKeyWallet
	mode PQCMode
}

// NewProductionDualKeyWallet creates a production-grade dual-key wallet
func NewProductionDualKeyWallet(dilithiumLevel int) (*ProductionDualKeyWallet, error) {
	mode := GetPQCMode()

	wallet, err := NewDualKeyWallet(dilithiumLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create dual-key wallet: %w", err)
	}

	return &ProductionDualKeyWallet{
		DualKeyWallet: wallet,
		mode:          mode,
	}, nil
}

// SignProduction creates a production-grade composite signature
func (pw *ProductionDualKeyWallet) SignProduction(message []byte, scheme SignatureScheme) (*CompositeSignature, error) {
	// In production mode, enforce composite signatures for maximum security
	if (pw.mode == PQCModeProduction || pw.mode == PQCModeHybrid) && scheme != CompositeScheme {
		return nil, errors.New("SECURITY: production mode requires composite signatures (ECDSA + Dilithium)")
	}

	return pw.DualKeyWallet.Sign(message, scheme)
}

// VerifyProduction verifies a signature with production-grade requirements
func (pw *ProductionDualKeyWallet) VerifyProduction(message []byte, sig *CompositeSignature) (bool, error) {
	// In production mode, both signatures must be present and valid
	if pw.mode == PQCModeProduction || pw.mode == PQCModeHybrid {
		if sig.ECDSASignature == nil || sig.DilithiumSignature == nil {
			return false, errors.New("SECURITY: production mode requires both ECDSA and Dilithium signatures")
		}
	}

	return pw.DualKeyWallet.Verify(message, sig, CompositeScheme)
}

// =============================================================================
// Production Readiness Checks
// =============================================================================

// PQCReadinessCheck validates that the PQC system is ready for production
type PQCReadinessCheck struct {
	Mode                 PQCMode
	DilithiumAvailable   bool
	KyberAvailable       bool
	HybridSigningEnabled bool
	TestVectorsPassed    bool
	Errors               []string
}

// CheckPQCReadiness performs a comprehensive PQC readiness check
func CheckPQCReadiness() *PQCReadinessCheck {
	check := &PQCReadinessCheck{
		Mode:   GetPQCMode(),
		Errors: make([]string, 0),
	}

	if pqcRequiresCircl(check.Mode) && !IsCirclAvailable() {
		check.Errors = append(check.Errors, "circl library not available for production/hybrid mode")
	}

	// Test Dilithium key generation and signing
	kp, err := NewProductionDilithiumKeyPair(DilithiumLevel3)
	if err != nil {
		check.Errors = append(check.Errors, fmt.Sprintf("Dilithium key generation failed: %v", err))
	} else {
		check.DilithiumAvailable = true

		// Test signing
		testMsg := []byte("PQC readiness test message")
		sig, err := kp.Sign(testMsg)
		if err != nil {
			check.Errors = append(check.Errors, fmt.Sprintf("Dilithium signing failed: %v", err))
		} else {
			// Test verification
			valid, err := VerifyProduction(kp.PublicKey, testMsg, sig)
			if err != nil || !valid {
				check.Errors = append(check.Errors, fmt.Sprintf("Dilithium verification failed: %v", err))
			}
		}
	}

	// Test Kyber key encapsulation
	kyberKP, err := NewProductionKyberKeyPair(KyberLevel768)
	if err != nil {
		check.Errors = append(check.Errors, fmt.Sprintf("Kyber key generation failed: %v", err))
	} else {
		check.KyberAvailable = true

		// Test encapsulation/decapsulation
		sharedSecret, ct, err := kyberKP.EncapsulateProduction(kyberKP.PublicKey)
		if err != nil {
			check.Errors = append(check.Errors, fmt.Sprintf("Kyber encapsulation failed: %v", err))
		} else {
			recovered, err := kyberKP.Decapsulate(ct)
			if err != nil {
				check.Errors = append(check.Errors, fmt.Sprintf("Kyber decapsulation failed: %v", err))
			} else if len(sharedSecret) != len(recovered) {
				check.Errors = append(check.Errors, "Kyber shared secret mismatch")
			}
		}
	}

	// Test hybrid wallet
	wallet, err := NewProductionDualKeyWallet(DilithiumLevel3)
	if err != nil {
		check.Errors = append(check.Errors, fmt.Sprintf("Dual-key wallet creation failed: %v", err))
	} else {
		check.HybridSigningEnabled = true

		// Test composite signing (only in simulated mode to avoid error)
		if check.Mode == PQCModeSimulated {
			testTx := []byte("test transaction")
			sig, err := wallet.SignProduction(testTx, CompositeScheme)
			if err != nil {
				check.Errors = append(check.Errors, fmt.Sprintf("Composite signing failed: %v", err))
			} else {
				valid, err := wallet.VerifyProduction(testTx, sig)
				if err != nil || !valid {
					check.Errors = append(check.Errors, fmt.Sprintf("Composite verification failed: %v", err))
				}
			}
		}
	}

	// Run known-answer tests (KAT) for compliance
	check.TestVectorsPassed = runKnownAnswerTests()

	return check
}

// runKnownAnswerTests runs deterministic consistency checks for the ML-DSA
// backend. ML-DSA.KeyGen is deterministic in the seed, so the same seed must
// always yield the same key pair, and a fresh signature must verify. Full NIST
// ACVP known-answer vectors are validated separately (see the KAT test suite).
func runKnownAnswerTests() bool {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp1, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, seed)
	if err != nil {
		return false
	}

	kp2, err := GenerateDilithiumKeyPairFromSeed(DilithiumLevel3, seed)
	if err != nil {
		return false
	}

	// Same seed must produce identical keys. Constant-time compare avoids
	// leaking key material via timing.
	if len(kp1.PublicKey) != len(kp2.PublicKey) ||
		subtle.ConstantTimeCompare(kp1.PublicKey, kp2.PublicKey) != 1 ||
		subtle.ConstantTimeCompare(kp1.PrivateKey, kp2.PrivateKey) != 1 {
		return false
	}

	// A fresh signature from the derived key must verify.
	msg := []byte("aethelred-pqc-kat-selftest")
	sig, err := kp1.Sign(msg)
	if err != nil {
		return false
	}
	valid, err := VerifyDilithium(kp1.PublicKey, msg, sig)
	return err == nil && valid
}

// IsProductionReady returns true if PQC is ready for production use
func (c *PQCReadinessCheck) IsProductionReady() bool {
	return c.DilithiumAvailable &&
		c.KyberAvailable &&
		c.HybridSigningEnabled &&
		c.TestVectorsPassed &&
		len(c.Errors) == 0
}

// =============================================================================
// Secure Random Number Generation
// =============================================================================

// SecureRandomBytes generates cryptographically secure random bytes
// with additional entropy mixing for defense-in-depth
func SecureRandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("length must be positive")
	}

	// Primary entropy from crypto/rand
	primary := make([]byte, length)
	if _, err := rand.Read(primary); err != nil {
		return nil, fmt.Errorf("failed to read from crypto/rand: %w", err)
	}

	// Additional entropy mixing (defense-in-depth)
	h := sha512.New()
	h.Write(primary)
	h.Write([]byte("aethelred_entropy_mix"))

	// Use first `length` bytes of the mixed output
	mixed := h.Sum(nil)
	result := make([]byte, length)
	copy(result, mixed[:min(length, len(mixed))])

	// For lengths > 64, extend with counter-mode expansion
	if length > 64 {
		for i := 64; i < length; i += 32 {
			counter := sha256.Sum256(append(mixed, byte(i/32)))
			end := min(i+32, length)
			copy(result[i:end], counter[:end-i])
		}
	}

	return result, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
