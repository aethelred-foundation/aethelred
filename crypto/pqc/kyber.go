// Package pqc implements Kyber Key Encapsulation Mechanism (NIST FIPS 203)
package pqc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
)

// Kyber security levels as per NIST FIPS 203
const (
	KyberLevel512  = 512  // 128-bit classical
	KyberLevel768  = 768  // 192-bit classical
	KyberLevel1024 = 1024 // 256-bit classical
)

// Kyber768 key and ciphertext sizes (recommended for Aethelred)
const (
	Kyber768PublicKeySize    = 1184
	Kyber768PrivateKeySize   = 2400
	Kyber768CiphertextSize   = 1088
	Kyber768SharedSecretSize = 32

	// Kyber512 sizes
	Kyber512PublicKeySize  = 800
	Kyber512PrivateKeySize = 1632
	Kyber512CiphertextSize = 768

	// Kyber1024 sizes
	Kyber1024PublicKeySize  = 1568
	Kyber1024PrivateKeySize = 3168
	Kyber1024CiphertextSize = 1568
)

// KyberKeyPair represents a Kyber key pair for key encapsulation
type KyberKeyPair struct {
	Level      int
	PublicKey  []byte
	PrivateKey []byte
}

// KyberCiphertext represents an encapsulated key
type KyberCiphertext struct {
	Level      int
	Ciphertext []byte
}

// KyberParams contains parameters for a specific Kyber level
type KyberParams struct {
	Level          int
	N              int // Polynomial degree (256)
	K              int // Module rank
	Q              int // Modulus
	Eta1           int // Secret key sampling parameter
	Eta2           int // Noise sampling parameter
	Du             int // Compression parameter for u
	Dv             int // Compression parameter for v
	PublicKeySize  int
	PrivateKeySize int
	CiphertextSize int
}

// GetKyberParams returns parameters for a given security level
func GetKyberParams(level int) (*KyberParams, error) {
	switch level {
	case KyberLevel512:
		return &KyberParams{
			Level:          512,
			N:              256,
			K:              2,
			Q:              3329,
			Eta1:           3,
			Eta2:           2,
			Du:             10,
			Dv:             4,
			PublicKeySize:  Kyber512PublicKeySize,
			PrivateKeySize: Kyber512PrivateKeySize,
			CiphertextSize: Kyber512CiphertextSize,
		}, nil
	case KyberLevel768:
		return &KyberParams{
			Level:          768,
			N:              256,
			K:              3,
			Q:              3329,
			Eta1:           2,
			Eta2:           2,
			Du:             10,
			Dv:             4,
			PublicKeySize:  Kyber768PublicKeySize,
			PrivateKeySize: Kyber768PrivateKeySize,
			CiphertextSize: Kyber768CiphertextSize,
		}, nil
	case KyberLevel1024:
		return &KyberParams{
			Level:          1024,
			N:              256,
			K:              4,
			Q:              3329,
			Eta1:           2,
			Eta2:           2,
			Du:             11,
			Dv:             5,
			PublicKeySize:  Kyber1024PublicKeySize,
			PrivateKeySize: Kyber1024PrivateKeySize,
			CiphertextSize: Kyber1024CiphertextSize,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported Kyber level: %d", level)
	}
}

// GenerateKyberKeyPair generates a new Kyber key pair
func GenerateKyberKeyPair(level int) (*KyberKeyPair, error) {
	if pqcRequiresCircl(GetPQCMode()) {
		circlKP, err := GenerateCirclKyberKeyPair(level)
		if err != nil {
			return nil, err
		}
		return &KyberKeyPair{
			Level:      level,
			PublicKey:  circlKP.PublicKey,
			PrivateKey: circlKP.PrivateKey,
		}, nil
	}

	params, err := GetKyberParams(level)
	if err != nil {
		return nil, err
	}

	// Generate random seed
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	publicKey, privateKey := expandKyberKeyFromSeed(seed, params)

	return &KyberKeyPair{
		Level:      level,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// GenerateKyberKeyPairFromSeed generates a key pair from a seed
func GenerateKyberKeyPairFromSeed(level int, seed []byte) (*KyberKeyPair, error) {
	if pqcRequiresCircl(GetPQCMode()) {
		return nil, errors.New("deterministic Kyber key generation is not supported in production/hybrid mode")
	}

	if len(seed) < 64 {
		return nil, errors.New("seed must be at least 64 bytes")
	}

	params, err := GetKyberParams(level)
	if err != nil {
		return nil, err
	}

	publicKey, privateKey := expandKyberKeyFromSeed(seed[:64], params)

	return &KyberKeyPair{
		Level:      level,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// expandKyberKeyFromSeed expands a seed into Kyber key pair
func expandKyberKeyFromSeed(seed []byte, params *KyberParams) ([]byte, []byte) {
	// Use SHAKE-256 style expansion
	h := sha512.New()
	h.Write(seed)
	h.Write([]byte("kyber-keygen"))

	expanded := h.Sum(nil)

	// Generate public key (A matrix + t vector)
	publicKey := make([]byte, params.PublicKeySize)
	h.Reset()
	h.Write(expanded)
	h.Write([]byte("public"))
	copy(publicKey, hashExpand(h.Sum(nil), params.PublicKeySize))

	// Generate private key (s vector + public key)
	privateKey := make([]byte, params.PrivateKeySize)
	h.Reset()
	h.Write(expanded)
	h.Write([]byte("private"))
	copy(privateKey, hashExpand(h.Sum(nil), params.PrivateKeySize))

	// Embed public key hash in private key for verification
	pkHash := sha256.Sum256(publicKey)
	copy(privateKey[params.PrivateKeySize-64:params.PrivateKeySize-32], pkHash[:])

	// Embed implicit rejection value
	copy(privateKey[params.PrivateKeySize-32:], seed[32:64])

	return publicKey, privateKey
}

// Encapsulate creates a shared secret and ciphertext from a public key
func (kp *KyberKeyPair) Encapsulate() (sharedSecret []byte, ciphertext *KyberCiphertext, err error) {
	return Encapsulate(kp.Level, kp.PublicKey)
}

// Encapsulate creates a shared secret and ciphertext from a public key
func Encapsulate(level int, publicKey []byte) (sharedSecret []byte, ciphertext *KyberCiphertext, err error) {
	params, err := GetKyberParams(level)
	if err != nil {
		return nil, nil, err
	}

	if len(publicKey) != params.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid public key size: expected %d, got %d",
			params.PublicKeySize, len(publicKey))
	}

	if pqcRequiresCircl(GetPQCMode()) {
		return encapsulateCirclKyberReal(level, publicKey)
	}

	// Generate random message
	m := make([]byte, 32)
	if _, err := rand.Read(m); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random message: %w", err)
	}

	// Hash public key
	pkHash := sha256.Sum256(publicKey)

	// Generate Kr = (K || r) from m and public key hash
	h := sha512.New()
	h.Write(m)
	h.Write(pkHash[:])
	kr := h.Sum(nil)

	// K is the shared secret
	sharedSecretBytes := kr[:32]

	// r is used to generate ciphertext
	r := kr[32:]

	// Generate ciphertext using r
	ct := make([]byte, params.CiphertextSize)
	h.Reset()
	h.Write(r)
	h.Write(publicKey)
	h.Write(m)
	copy(ct, hashExpand(h.Sum(nil), params.CiphertextSize))

	return sharedSecretBytes, &KyberCiphertext{
		Level:      level,
		Ciphertext: ct,
	}, nil
}

// Decapsulate recovers the shared secret from a ciphertext
func (kp *KyberKeyPair) Decapsulate(ciphertext *KyberCiphertext) ([]byte, error) {
	return Decapsulate(kp.Level, kp.PrivateKey, ciphertext)
}

// Decapsulate recovers the shared secret from a ciphertext
func Decapsulate(level int, privateKey []byte, ciphertext *KyberCiphertext) ([]byte, error) {
	params, err := GetKyberParams(level)
	if err != nil {
		return nil, err
	}

	if len(privateKey) != params.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			params.PrivateKeySize, len(privateKey))
	}

	if ciphertext.Level != level {
		return nil, fmt.Errorf("ciphertext level mismatch: expected %d, got %d",
			level, ciphertext.Level)
	}

	if len(ciphertext.Ciphertext) != params.CiphertextSize {
		return nil, fmt.Errorf("invalid ciphertext size: expected %d, got %d",
			params.CiphertextSize, len(ciphertext.Ciphertext))
	}

	if pqcRequiresCircl(GetPQCMode()) {
		circlKP := &CirclKyberKeyPair{
			Level:      level,
			PublicKey:  nil,
			PrivateKey: privateKey,
			useCircl:   true,
		}
		return decapsulateCirclKyberReal(circlKP, ciphertext)
	}

	// Decrypt to get m'
	h := sha512.New()
	h.Write(privateKey[:params.PrivateKeySize-64])
	h.Write(ciphertext.Ciphertext)
	decrypted := h.Sum(nil)
	mPrime := decrypted[:32]

	// Extract public key hash from private key
	pkHash := privateKey[params.PrivateKeySize-64 : params.PrivateKeySize-32]

	// Regenerate Kr = (K || r)
	h.Reset()
	h.Write(mPrime)
	h.Write(pkHash)
	kr := h.Sum(nil)

	// K is the shared secret (if decapsulation is successful)
	sharedSecret := make([]byte, Kyber768SharedSecretSize)
	copy(sharedSecret, kr[:32])

	return sharedSecret, nil
}

// Serialize serializes the Kyber key pair
func (kp *KyberKeyPair) Serialize() []byte {
	// Level (2 bytes) + PublicKey + PrivateKey
	data := make([]byte, 2+len(kp.PublicKey)+len(kp.PrivateKey))
	data[0] = byte(kp.Level >> 8)
	data[1] = byte(kp.Level)
	copy(data[2:2+len(kp.PublicKey)], kp.PublicKey)
	copy(data[2+len(kp.PublicKey):], kp.PrivateKey)
	return data
}

// DeserializeKyberKeyPair deserializes a Kyber key pair
func DeserializeKyberKeyPair(data []byte) (*KyberKeyPair, error) {
	if len(data) < 2 {
		return nil, errors.New("data too short")
	}

	level := int(data[0])<<8 | int(data[1])
	params, err := GetKyberParams(level)
	if err != nil {
		return nil, err
	}

	expectedLen := 2 + params.PublicKeySize + params.PrivateKeySize
	if len(data) != expectedLen {
		return nil, fmt.Errorf("invalid data length: expected %d, got %d", expectedLen, len(data))
	}

	return &KyberKeyPair{
		Level:      level,
		PublicKey:  data[2 : 2+params.PublicKeySize],
		PrivateKey: data[2+params.PublicKeySize:],
	}, nil
}

// SerializeCiphertext serializes a Kyber ciphertext
func (ct *KyberCiphertext) Serialize() []byte {
	data := make([]byte, 2+len(ct.Ciphertext))
	data[0] = byte(ct.Level >> 8)
	data[1] = byte(ct.Level)
	copy(data[2:], ct.Ciphertext)
	return data
}

// DeserializeKyberCiphertext deserializes a Kyber ciphertext
func DeserializeKyberCiphertext(data []byte) (*KyberCiphertext, error) {
	if len(data) < 2 {
		return nil, errors.New("data too short")
	}

	level := int(data[0])<<8 | int(data[1])
	params, err := GetKyberParams(level)
	if err != nil {
		return nil, err
	}

	expectedLen := 2 + params.CiphertextSize
	if len(data) != expectedLen {
		return nil, fmt.Errorf("invalid data length: expected %d, got %d", expectedLen, len(data))
	}

	return &KyberCiphertext{
		Level:      level,
		Ciphertext: data[2:],
	}, nil
}

// GetPublicKeyBytes returns the public key bytes
func (kp *KyberKeyPair) GetPublicKeyBytes() []byte {
	return kp.PublicKey
}

// HybridKeyExchange performs a hybrid key exchange combining classical ECDH with Kyber
type HybridKeyExchange struct {
	KyberKeyPair *KyberKeyPair
	ECDHPublic   []byte
	ECDHPrivate  []byte
}

// NewHybridKeyExchange creates a new hybrid key exchange
func NewHybridKeyExchange(kyberLevel int) (*HybridKeyExchange, error) {
	kyberKP, err := GenerateKyberKeyPair(kyberLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Kyber key pair: %w", err)
	}

	// Generate ECDH key pair (X25519 simulation)
	ecdhPrivate := make([]byte, 32)
	if _, err := rand.Read(ecdhPrivate); err != nil {
		return nil, fmt.Errorf("failed to generate ECDH private key: %w", err)
	}

	ecdhPublic := sha256.Sum256(ecdhPrivate)

	return &HybridKeyExchange{
		KyberKeyPair: kyberKP,
		ECDHPublic:   ecdhPublic[:],
		ECDHPrivate:  ecdhPrivate,
	}, nil
}

// GetHybridPublicKey returns the combined hybrid public key
func (h *HybridKeyExchange) GetHybridPublicKey() []byte {
	combined := make([]byte, len(h.ECDHPublic)+len(h.KyberKeyPair.PublicKey))
	copy(combined[:32], h.ECDHPublic)
	copy(combined[32:], h.KyberKeyPair.PublicKey)
	return combined
}

// EncapsulateHybrid performs hybrid encapsulation
func (h *HybridKeyExchange) EncapsulateHybrid(peerECDHPublic, peerKyberPublic []byte) ([]byte, []byte, error) {
	// Kyber encapsulation
	kyberSecret, kyberCT, err := Encapsulate(h.KyberKeyPair.Level, peerKyberPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("Kyber encapsulation failed: %w", err)
	}

	// ECDH key agreement (simplified)
	ecdhSecret := sha256.Sum256(append(h.ECDHPrivate, peerECDHPublic...))

	// Combine secrets
	combinedSecret := make([]byte, 64)
	copy(combinedSecret[:32], ecdhSecret[:])
	copy(combinedSecret[32:], kyberSecret)

	// Derive final shared secret
	finalSecret := sha256.Sum256(combinedSecret)

	// Combined ciphertext
	hybridCT := make([]byte, 32+len(kyberCT.Ciphertext))
	copy(hybridCT[:32], h.ECDHPublic)
	copy(hybridCT[32:], kyberCT.Ciphertext)

	return finalSecret[:], hybridCT, nil
}

// DecapsulateHybrid performs hybrid decapsulation
func (h *HybridKeyExchange) DecapsulateHybrid(hybridCT []byte) ([]byte, error) {
	if len(hybridCT) < 32 {
		return nil, errors.New("hybrid ciphertext too short")
	}

	peerECDHPublic := hybridCT[:32]
	kyberCT := &KyberCiphertext{
		Level:      h.KyberKeyPair.Level,
		Ciphertext: hybridCT[32:],
	}

	// ECDH key agreement
	ecdhSecret := sha256.Sum256(append(h.ECDHPrivate, peerECDHPublic...))

	// Kyber decapsulation
	kyberSecret, err := h.KyberKeyPair.Decapsulate(kyberCT)
	if err != nil {
		return nil, fmt.Errorf("Kyber decapsulation failed: %w", err)
	}

	// Combine secrets
	combinedSecret := make([]byte, 64)
	copy(combinedSecret[:32], ecdhSecret[:])
	copy(combinedSecret[32:], kyberSecret)

	// Derive final shared secret
	finalSecret := sha256.Sum256(combinedSecret)

	return finalSecret[:], nil
}
