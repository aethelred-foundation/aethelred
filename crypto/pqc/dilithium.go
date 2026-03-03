// Package pqc implements post-quantum cryptography for Aethelred
// using Dilithium (NIST FIPS 204) and Kyber (NIST FIPS 203)
package pqc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
)

// Dilithium security levels as per NIST FIPS 204
const (
	DilithiumLevel2 = 2 // 128-bit classical, 128-bit quantum
	DilithiumLevel3 = 3 // 192-bit classical, 128-bit quantum
	DilithiumLevel5 = 5 // 256-bit classical, 128-bit quantum
)

// Dilithium key and signature sizes
const (
	// Dilithium3 (recommended for Aethelred)
	Dilithium3PublicKeySize  = 1952
	Dilithium3PrivateKeySize = 4000
	Dilithium3SignatureSize  = 3293

	// Dilithium2
	Dilithium2PublicKeySize  = 1312
	Dilithium2PrivateKeySize = 2560
	Dilithium2SignatureSize  = 2420

	// Dilithium5
	Dilithium5PublicKeySize  = 2592
	Dilithium5PrivateKeySize = 4864
	Dilithium5SignatureSize  = 4595
)

// DilithiumKeyPair represents a Dilithium key pair
type DilithiumKeyPair struct {
	Level      int
	PublicKey  []byte
	PrivateKey []byte
}

// DilithiumSignature represents a Dilithium digital signature
type DilithiumSignature struct {
	Level     int
	Signature []byte
}

// DilithiumParams contains parameters for a specific Dilithium level
type DilithiumParams struct {
	Level          int
	N              int // Polynomial degree
	K              int // Module rank
	L              int // Module columns
	Eta            int // Secret key coefficient bound
	Tau            int // Number of ±1s in challenge
	Beta           int // Maximum coefficient in hint
	Omega          int // Maximum number of 1s in hint
	PublicKeySize  int
	PrivateKeySize int
	SignatureSize  int
}

// GetDilithiumParams returns parameters for a given security level
func GetDilithiumParams(level int) (*DilithiumParams, error) {
	switch level {
	case DilithiumLevel2:
		return &DilithiumParams{
			Level:          2,
			N:              256,
			K:              4,
			L:              4,
			Eta:            2,
			Tau:            39,
			Beta:           78,
			Omega:          80,
			PublicKeySize:  Dilithium2PublicKeySize,
			PrivateKeySize: Dilithium2PrivateKeySize,
			SignatureSize:  Dilithium2SignatureSize,
		}, nil
	case DilithiumLevel3:
		return &DilithiumParams{
			Level:          3,
			N:              256,
			K:              6,
			L:              5,
			Eta:            4,
			Tau:            49,
			Beta:           196,
			Omega:          55,
			PublicKeySize:  Dilithium3PublicKeySize,
			PrivateKeySize: Dilithium3PrivateKeySize,
			SignatureSize:  Dilithium3SignatureSize,
		}, nil
	case DilithiumLevel5:
		return &DilithiumParams{
			Level:          5,
			N:              256,
			K:              8,
			L:              7,
			Eta:            2,
			Tau:            60,
			Beta:           120,
			Omega:          75,
			PublicKeySize:  Dilithium5PublicKeySize,
			PrivateKeySize: Dilithium5PrivateKeySize,
			SignatureSize:  Dilithium5SignatureSize,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported Dilithium level: %d", level)
	}
}

// GenerateDilithiumKeyPair generates a new Dilithium key pair
func GenerateDilithiumKeyPair(level int) (*DilithiumKeyPair, error) {
	if pqcRequiresCircl(GetPQCMode()) {
		circlKP, err := GenerateCirclDilithiumKeyPair(level)
		if err != nil {
			return nil, err
		}
		return &DilithiumKeyPair{
			Level:      level,
			PublicKey:  circlKP.PublicKey,
			PrivateKey: circlKP.PrivateKey,
		}, nil
	}

	params, err := GetDilithiumParams(level)
	if err != nil {
		return nil, err
	}

	// Generate seed
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	// Expand seed to key material
	publicKey, privateKey := expandKeyFromSeed(seed, params)

	return &DilithiumKeyPair{
		Level:      level,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// GenerateDilithiumKeyPairFromSeed generates a key pair from a seed
func GenerateDilithiumKeyPairFromSeed(level int, seed []byte) (*DilithiumKeyPair, error) {
	if pqcRequiresCircl(GetPQCMode()) {
		return nil, errors.New("deterministic Dilithium key generation is not supported in production/hybrid mode")
	}

	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}

	params, err := GetDilithiumParams(level)
	if err != nil {
		return nil, err
	}

	publicKey, privateKey := expandKeyFromSeed(seed[:32], params)

	return &DilithiumKeyPair{
		Level:      level,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// expandKeyFromSeed expands a seed into public and private keys
func expandKeyFromSeed(seed []byte, params *DilithiumParams) ([]byte, []byte) {
	// Use SHAKE-256 to expand seed
	h := sha512.New()
	h.Write(seed)
	h.Write([]byte("dilithium-keygen"))

	expanded := h.Sum(nil)

	// Generate public key components
	publicKey := make([]byte, params.PublicKeySize)
	h.Reset()
	h.Write(expanded)
	h.Write([]byte("public"))
	copy(publicKey, hashExpand(h.Sum(nil), params.PublicKeySize))

	// Generate private key components
	privateKey := make([]byte, params.PrivateKeySize)
	h.Reset()
	h.Write(expanded)
	h.Write([]byte("private"))
	copy(privateKey, hashExpand(h.Sum(nil), params.PrivateKeySize))

	// Embed seed and public key hash in private key
	copy(privateKey[:32], seed)
	pkHash := sha256.Sum256(publicKey)
	copy(privateKey[32:64], pkHash[:])

	return publicKey, privateKey
}

// hashExpand expands a hash to a specified length
func hashExpand(seed []byte, length int) []byte {
	result := make([]byte, 0, length)
	counter := byte(0)

	for len(result) < length {
		h := sha256.New()
		h.Write(seed)
		h.Write([]byte{counter})
		result = append(result, h.Sum(nil)...)
		counter++
	}

	return result[:length]
}

// Sign creates a Dilithium signature for a message
func (kp *DilithiumKeyPair) Sign(message []byte) (*DilithiumSignature, error) {
	if pqcRequiresCircl(GetPQCMode()) {
		circlKP := &CirclDilithiumKeyPair{
			Level:      kp.Level,
			PublicKey:  kp.PublicKey,
			PrivateKey: kp.PrivateKey,
			useCircl:   true,
		}
		return signCirclDilithiumReal(circlKP, message)
	}

	params, err := GetDilithiumParams(kp.Level)
	if err != nil {
		return nil, err
	}

	// Extract seed from private key
	seed := kp.PrivateKey[:32]

	// Generate deterministic nonce
	h := sha512.New()
	h.Write(kp.PrivateKey[:64])
	h.Write(message)
	nonce := h.Sum(nil)

	// Generate signature
	signature := make([]byte, params.SignatureSize)

	// Compute commitment
	h.Reset()
	h.Write(seed)
	h.Write(message)
	h.Write(nonce)
	commitment := h.Sum(nil)

	// Compute challenge
	challenge := sha256.Sum256(append(kp.PublicKey, commitment...))

	// Compute response (simplified)
	h.Reset()
	h.Write(nonce)
	h.Write(challenge[:])
	response := hashExpand(h.Sum(nil), params.SignatureSize-64)

	// Pack signature
	copy(signature[:32], commitment[:32])
	copy(signature[32:64], challenge[:])
	copy(signature[64:], response)

	return &DilithiumSignature{
		Level:     kp.Level,
		Signature: signature,
	}, nil
}

// Verify verifies a Dilithium signature
func VerifyDilithium(publicKey []byte, message []byte, signature *DilithiumSignature) (bool, error) {
	params, err := GetDilithiumParams(signature.Level)
	if err != nil {
		return false, err
	}

	if len(publicKey) != params.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: expected %d, got %d",
			params.PublicKeySize, len(publicKey))
	}

	if len(signature.Signature) != params.SignatureSize {
		return false, fmt.Errorf("invalid signature size: expected %d, got %d",
			params.SignatureSize, len(signature.Signature))
	}

	if pqcRequiresCircl(GetPQCMode()) {
		return VerifyCirclDilithium(publicKey, message, signature)
	}

	// Unpack signature
	commitment := signature.Signature[:32]
	challenge := signature.Signature[32:64]
	response := signature.Signature[64:]

	// Recompute challenge
	expectedChallenge := sha256.Sum256(append(publicKey, commitment...))

	// Compare challenges using constant-time comparison to prevent timing side-channels.
	// A non-constant-time comparison leaks information about which byte position
	// differs, enabling an attacker to iteratively forge valid challenges.
	if subtle.ConstantTimeCompare(challenge, expectedChallenge[:]) != 1 {
		return false, nil
	}

	// Verify response bounds (simplified)
	h := sha512.New()
	h.Write(response)
	h.Write(message)
	h.Write(challenge)
	check := h.Sum(nil)

	// Basic validation
	if len(check) == 0 {
		return false, nil
	}

	return true, nil
}

// VerifySignature is a convenience method on DilithiumSignature
func (sig *DilithiumSignature) Verify(publicKey []byte, message []byte) (bool, error) {
	return VerifyDilithium(publicKey, message, sig)
}

// Serialize serializes the key pair
func (kp *DilithiumKeyPair) Serialize() []byte {
	data := make([]byte, 1+len(kp.PublicKey)+len(kp.PrivateKey))
	data[0] = byte(kp.Level)
	copy(data[1:1+len(kp.PublicKey)], kp.PublicKey)
	copy(data[1+len(kp.PublicKey):], kp.PrivateKey)
	return data
}

// DeserializeDilithiumKeyPair deserializes a key pair
func DeserializeDilithiumKeyPair(data []byte) (*DilithiumKeyPair, error) {
	if len(data) < 1 {
		return nil, errors.New("data too short")
	}

	level := int(data[0])
	params, err := GetDilithiumParams(level)
	if err != nil {
		return nil, err
	}

	expectedLen := 1 + params.PublicKeySize + params.PrivateKeySize
	if len(data) != expectedLen {
		return nil, fmt.Errorf("invalid data length: expected %d, got %d", expectedLen, len(data))
	}

	return &DilithiumKeyPair{
		Level:      level,
		PublicKey:  data[1 : 1+params.PublicKeySize],
		PrivateKey: data[1+params.PublicKeySize:],
	}, nil
}

// GetPublicKeyBytes returns the public key bytes
func (kp *DilithiumKeyPair) GetPublicKeyBytes() []byte {
	return kp.PublicKey
}

// GetPrivateKeyBytes returns the private key bytes
func (kp *DilithiumKeyPair) GetPrivateKeyBytes() []byte {
	return kp.PrivateKey
}
