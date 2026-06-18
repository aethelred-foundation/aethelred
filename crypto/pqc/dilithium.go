// Package pqc implements post-quantum cryptography for Aethelred
// using ML-DSA (NIST FIPS 204) and ML-KEM (NIST FIPS 203).
//
// All Dilithium/ML-DSA operations in this file delegate to the real circl
// backend (see circl_backend.go). The types here (DilithiumKeyPair,
// DilithiumSignature, DilithiumParams) are the package's stable public surface;
// the cryptography underneath is standardized ML-DSA.
package pqc

import (
	"errors"
	"fmt"
)

// Dilithium security levels, mapped to ML-DSA parameter sets (FIPS 204).
const (
	DilithiumLevel2 = 2 // ML-DSA-44
	DilithiumLevel3 = 3 // ML-DSA-65 (recommended for Aethelred)
	DilithiumLevel5 = 5 // ML-DSA-87
)

// ML-DSA key and signature sizes (FIPS 204). These mirror the circl package
// constants; a self-test asserts they stay in sync (see circl_backend_test.go).
const (
	// ML-DSA-65 (Dilithium3, recommended for Aethelred)
	Dilithium3PublicKeySize  = 1952
	Dilithium3PrivateKeySize = 4032
	Dilithium3SignatureSize  = 3309

	// ML-DSA-44 (Dilithium2)
	Dilithium2PublicKeySize  = 1312
	Dilithium2PrivateKeySize = 2560
	Dilithium2SignatureSize  = 2420

	// ML-DSA-87 (Dilithium5)
	Dilithium5PublicKeySize  = 2592
	Dilithium5PrivateKeySize = 4896
	Dilithium5SignatureSize  = 4627
)

// DilithiumKeyPair represents an ML-DSA key pair (packed key bytes).
type DilithiumKeyPair struct {
	Level      int
	PublicKey  []byte
	PrivateKey []byte
}

// DilithiumSignature represents an ML-DSA digital signature.
type DilithiumSignature struct {
	Level     int
	Signature []byte
}

// DilithiumParams contains the descriptive parameters and serialized sizes for
// a specific ML-DSA level. Sizes are sourced from the circl backend so they can
// never drift from the implementation.
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

// GetDilithiumParams returns parameters for a given security level. The size
// fields are taken from the circl ML-DSA backend.
func GetDilithiumParams(level int) (*DilithiumParams, error) {
	pkSize, skSize, sigSize, _, err := mldsaSizes(level)
	if err != nil {
		return nil, err
	}

	params := &DilithiumParams{
		Level:          level,
		N:              256,
		PublicKeySize:  pkSize,
		PrivateKeySize: skSize,
		SignatureSize:  sigSize,
	}

	switch level {
	case DilithiumLevel2:
		params.K, params.L, params.Eta, params.Tau, params.Beta, params.Omega = 4, 4, 2, 39, 78, 80
	case DilithiumLevel3:
		params.K, params.L, params.Eta, params.Tau, params.Beta, params.Omega = 6, 5, 4, 49, 196, 55
	case DilithiumLevel5:
		params.K, params.L, params.Eta, params.Tau, params.Beta, params.Omega = 8, 7, 2, 60, 120, 75
	}

	return params, nil
}

// GenerateDilithiumKeyPair generates a new ML-DSA key pair using the system
// CSPRNG.
func GenerateDilithiumKeyPair(level int) (*DilithiumKeyPair, error) {
	pub, priv, err := mldsaGenerateKey(level)
	if err != nil {
		return nil, err
	}
	return &DilithiumKeyPair{Level: level, PublicKey: pub, PrivateKey: priv}, nil
}

// GenerateDilithiumKeyPairFromSeed deterministically derives an ML-DSA key pair
// from a seed (FIPS 204 ML-DSA.KeyGen). The seed must be at least SeedSize bytes;
// the first SeedSize bytes are used. The same seed always yields the same key
// pair, which is the basis for HD/mnemonic wallet recovery.
func GenerateDilithiumKeyPairFromSeed(level int, seed []byte) (*DilithiumKeyPair, error) {
	_, _, _, seedSize, err := mldsaSizes(level)
	if err != nil {
		return nil, err
	}
	if len(seed) < seedSize {
		return nil, fmt.Errorf("seed must be at least %d bytes, got %d", seedSize, len(seed))
	}

	pub, priv, err := mldsaDeriveKey(level, seed[:seedSize])
	if err != nil {
		return nil, err
	}
	return &DilithiumKeyPair{Level: level, PublicKey: pub, PrivateKey: priv}, nil
}

// Sign creates an ML-DSA signature for a message.
func (kp *DilithiumKeyPair) Sign(message []byte) (*DilithiumSignature, error) {
	sig, err := mldsaSign(kp.Level, kp.PrivateKey, message)
	if err != nil {
		return nil, err
	}
	return &DilithiumSignature{Level: kp.Level, Signature: sig}, nil
}

// VerifyDilithium verifies an ML-DSA signature.
func VerifyDilithium(publicKey []byte, message []byte, signature *DilithiumSignature) (bool, error) {
	pkSize, _, sigSize, _, err := mldsaSizes(signature.Level)
	if err != nil {
		return false, err
	}
	if len(publicKey) != pkSize {
		return false, fmt.Errorf("invalid public key size: expected %d, got %d", pkSize, len(publicKey))
	}
	if len(signature.Signature) != sigSize {
		return false, fmt.Errorf("invalid signature size: expected %d, got %d", sigSize, len(signature.Signature))
	}
	return mldsaVerify(signature.Level, publicKey, message, signature.Signature)
}

// Verify is a convenience method on DilithiumSignature.
func (sig *DilithiumSignature) Verify(publicKey []byte, message []byte) (bool, error) {
	return VerifyDilithium(publicKey, message, sig)
}

// Serialize serializes the key pair as Level || PublicKey || PrivateKey.
func (kp *DilithiumKeyPair) Serialize() []byte {
	data := make([]byte, 1+len(kp.PublicKey)+len(kp.PrivateKey))
	data[0] = byte(kp.Level)
	copy(data[1:1+len(kp.PublicKey)], kp.PublicKey)
	copy(data[1+len(kp.PublicKey):], kp.PrivateKey)
	return data
}

// DeserializeDilithiumKeyPair deserializes a key pair produced by Serialize.
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

	// Copy out of the input buffer: callers (e.g. the encrypted keystore) may
	// zero the source slice after deserialization, so the key material must not
	// alias it.
	pub := make([]byte, params.PublicKeySize)
	copy(pub, data[1:1+params.PublicKeySize])
	priv := make([]byte, params.PrivateKeySize)
	copy(priv, data[1+params.PublicKeySize:])

	return &DilithiumKeyPair{
		Level:      level,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// GetPublicKeyBytes returns the public key bytes.
func (kp *DilithiumKeyPair) GetPublicKeyBytes() []byte {
	return kp.PublicKey
}

// GetPrivateKeyBytes returns the private key bytes.
func (kp *DilithiumKeyPair) GetPrivateKeyBytes() []byte {
	return kp.PrivateKey
}
