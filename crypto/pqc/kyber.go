// Package pqc implements ML-KEM key encapsulation (NIST FIPS 203).
//
// All ML-KEM operations delegate to the real circl backend (see
// circl_backend.go). The hybrid key exchange combines ML-KEM with real X25519
// ECDH (golang.org/x/crypto/curve25519).
package pqc

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Kyber security levels, mapped to ML-KEM parameter sets (FIPS 203).
const (
	KyberLevel512  = 512  // ML-KEM-512
	KyberLevel768  = 768  // ML-KEM-768 (recommended for Aethelred)
	KyberLevel1024 = 1024 // ML-KEM-1024
)

// ML-KEM key and ciphertext sizes (FIPS 203). Mirrored by the circl backend.
const (
	// ML-KEM-768 (recommended for Aethelred)
	Kyber768PublicKeySize    = 1184
	Kyber768PrivateKeySize   = 2400
	Kyber768CiphertextSize   = 1088
	Kyber768SharedSecretSize = 32

	// ML-KEM-512
	Kyber512PublicKeySize  = 800
	Kyber512PrivateKeySize = 1632
	Kyber512CiphertextSize = 768

	// ML-KEM-1024
	Kyber1024PublicKeySize  = 1568
	Kyber1024PrivateKeySize = 3168
	Kyber1024CiphertextSize = 1568
)

// KyberKeyPair represents an ML-KEM key pair for key encapsulation.
type KyberKeyPair struct {
	Level      int
	PublicKey  []byte
	PrivateKey []byte
}

// KyberCiphertext represents an encapsulated key.
type KyberCiphertext struct {
	Level      int
	Ciphertext []byte
}

// KyberParams contains descriptive parameters and serialized sizes for a
// specific ML-KEM level. Sizes are sourced from the circl backend.
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

// GetKyberParams returns parameters for a given security level.
func GetKyberParams(level int) (*KyberParams, error) {
	pkSize, skSize, ctSize, _, err := mlkemSizes(level)
	if err != nil {
		return nil, err
	}

	params := &KyberParams{
		Level:          level,
		N:              256,
		Q:              3329,
		PublicKeySize:  pkSize,
		PrivateKeySize: skSize,
		CiphertextSize: ctSize,
	}

	switch level {
	case KyberLevel512:
		params.K, params.Eta1, params.Eta2, params.Du, params.Dv = 2, 3, 2, 10, 4
	case KyberLevel768:
		params.K, params.Eta1, params.Eta2, params.Du, params.Dv = 3, 2, 2, 10, 4
	case KyberLevel1024:
		params.K, params.Eta1, params.Eta2, params.Du, params.Dv = 4, 2, 2, 11, 5
	}

	return params, nil
}

// GenerateKyberKeyPair generates a new ML-KEM key pair using the system CSPRNG.
func GenerateKyberKeyPair(level int) (*KyberKeyPair, error) {
	pub, priv, err := mlkemGenerateKey(level)
	if err != nil {
		return nil, err
	}
	return &KyberKeyPair{Level: level, PublicKey: pub, PrivateKey: priv}, nil
}

// GenerateKyberKeyPairFromSeed deterministically derives an ML-KEM key pair from
// a seed. The seed must be at least KeySeedSize bytes; the first KeySeedSize
// bytes are used.
func GenerateKyberKeyPairFromSeed(level int, seed []byte) (*KyberKeyPair, error) {
	want, err := mlkemSeedSize(level)
	if err != nil {
		return nil, err
	}
	if len(seed) < want {
		return nil, fmt.Errorf("seed must be at least %d bytes, got %d", want, len(seed))
	}

	pub, priv, err := mlkemDeriveKey(level, seed[:want])
	if err != nil {
		return nil, err
	}
	return &KyberKeyPair{Level: level, PublicKey: pub, PrivateKey: priv}, nil
}

// Encapsulate creates a shared secret and ciphertext using this key pair's own
// public key.
func (kp *KyberKeyPair) Encapsulate() (sharedSecret []byte, ciphertext *KyberCiphertext, err error) {
	return Encapsulate(kp.Level, kp.PublicKey)
}

// Encapsulate creates a shared secret and ciphertext for a recipient public key.
func Encapsulate(level int, publicKey []byte) (sharedSecret []byte, ciphertext *KyberCiphertext, err error) {
	ss, ct, err := mlkemEncapsulate(level, publicKey)
	if err != nil {
		return nil, nil, err
	}
	return ss, &KyberCiphertext{Level: level, Ciphertext: ct}, nil
}

// Decapsulate recovers the shared secret from a ciphertext.
func (kp *KyberKeyPair) Decapsulate(ciphertext *KyberCiphertext) ([]byte, error) {
	return Decapsulate(kp.Level, kp.PrivateKey, ciphertext)
}

// Decapsulate recovers the shared secret from a ciphertext.
func Decapsulate(level int, privateKey []byte, ciphertext *KyberCiphertext) ([]byte, error) {
	if ciphertext.Level != level {
		return nil, fmt.Errorf("ciphertext level mismatch: expected %d, got %d", level, ciphertext.Level)
	}
	return mlkemDecapsulate(level, privateKey, ciphertext.Ciphertext)
}

// Serialize serializes the Kyber key pair as Level(2) || PublicKey || PrivateKey.
func (kp *KyberKeyPair) Serialize() []byte {
	data := make([]byte, 2+len(kp.PublicKey)+len(kp.PrivateKey))
	data[0] = byte(kp.Level >> 8)
	data[1] = byte(kp.Level)
	copy(data[2:2+len(kp.PublicKey)], kp.PublicKey)
	copy(data[2+len(kp.PublicKey):], kp.PrivateKey)
	return data
}

// DeserializeKyberKeyPair deserializes a Kyber key pair produced by Serialize.
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

	// Copy out of the input buffer so the key material does not alias a source
	// slice the caller may zero after deserialization.
	pub := make([]byte, params.PublicKeySize)
	copy(pub, data[2:2+params.PublicKeySize])
	priv := make([]byte, params.PrivateKeySize)
	copy(priv, data[2+params.PublicKeySize:])

	return &KyberKeyPair{
		Level:      level,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// SerializeCiphertext serializes a Kyber ciphertext.
func (ct *KyberCiphertext) Serialize() []byte {
	data := make([]byte, 2+len(ct.Ciphertext))
	data[0] = byte(ct.Level >> 8)
	data[1] = byte(ct.Level)
	copy(data[2:], ct.Ciphertext)
	return data
}

// DeserializeKyberCiphertext deserializes a Kyber ciphertext.
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

	ct := make([]byte, params.CiphertextSize)
	copy(ct, data[2:])

	return &KyberCiphertext{
		Level:      level,
		Ciphertext: ct,
	}, nil
}

// GetPublicKeyBytes returns the public key bytes.
func (kp *KyberKeyPair) GetPublicKeyBytes() []byte {
	return kp.PublicKey
}

// =============================================================================
// Hybrid Key Exchange (X25519 ECDH + ML-KEM)
// =============================================================================

// HybridKeyExchange performs a hybrid key exchange combining classical X25519
// ECDH with ML-KEM. Compromise of either primitive alone does not reveal the
// shared secret.
type HybridKeyExchange struct {
	KyberKeyPair *KyberKeyPair
	ECDHPublic   []byte
	ECDHPrivate  []byte
}

// NewHybridKeyExchange creates a new hybrid key exchange with a fresh X25519 and
// ML-KEM key pair.
func NewHybridKeyExchange(kyberLevel int) (*HybridKeyExchange, error) {
	kyberKP, err := GenerateKyberKeyPair(kyberLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM key pair: %w", err)
	}

	ecdhPrivate := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(ecdhPrivate); err != nil {
		return nil, fmt.Errorf("failed to generate X25519 private key: %w", err)
	}

	ecdhPublic, err := curve25519.X25519(ecdhPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 public key: %w", err)
	}

	return &HybridKeyExchange{
		KyberKeyPair: kyberKP,
		ECDHPublic:   ecdhPublic,
		ECDHPrivate:  ecdhPrivate,
	}, nil
}

// GetHybridPublicKey returns the combined hybrid public key (X25519 || ML-KEM).
func (h *HybridKeyExchange) GetHybridPublicKey() []byte {
	combined := make([]byte, len(h.ECDHPublic)+len(h.KyberKeyPair.PublicKey))
	copy(combined[:len(h.ECDHPublic)], h.ECDHPublic)
	copy(combined[len(h.ECDHPublic):], h.KyberKeyPair.PublicKey)
	return combined
}

// EncapsulateHybrid performs hybrid encapsulation against a peer's X25519 and
// ML-KEM public keys. The final secret binds both the X25519 shared point and
// the ML-KEM shared secret.
func (h *HybridKeyExchange) EncapsulateHybrid(peerECDHPublic, peerKyberPublic []byte) ([]byte, []byte, error) {
	kyberSecret, kyberCT, err := Encapsulate(h.KyberKeyPair.Level, peerKyberPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-KEM encapsulation failed: %w", err)
	}

	ecdhSecret, err := curve25519.X25519(h.ECDHPrivate, peerECDHPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("X25519 agreement failed: %w", err)
	}

	finalSecret := combineHybridSecret(ecdhSecret, kyberSecret)

	hybridCT := make([]byte, len(h.ECDHPublic)+len(kyberCT.Ciphertext))
	copy(hybridCT[:len(h.ECDHPublic)], h.ECDHPublic)
	copy(hybridCT[len(h.ECDHPublic):], kyberCT.Ciphertext)

	return finalSecret, hybridCT, nil
}

// DecapsulateHybrid performs hybrid decapsulation of a ciphertext produced by
// EncapsulateHybrid.
func (h *HybridKeyExchange) DecapsulateHybrid(hybridCT []byte) ([]byte, error) {
	if len(hybridCT) < curve25519.PointSize {
		return nil, errors.New("hybrid ciphertext too short")
	}

	peerECDHPublic := hybridCT[:curve25519.PointSize]
	kyberCT := &KyberCiphertext{
		Level:      h.KyberKeyPair.Level,
		Ciphertext: hybridCT[curve25519.PointSize:],
	}

	ecdhSecret, err := curve25519.X25519(h.ECDHPrivate, peerECDHPublic)
	if err != nil {
		return nil, fmt.Errorf("X25519 agreement failed: %w", err)
	}

	kyberSecret, err := h.KyberKeyPair.Decapsulate(kyberCT)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
	}

	return combineHybridSecret(ecdhSecret, kyberSecret), nil
}

// combineHybridSecret binds the classical and post-quantum shared secrets into a
// single 32-byte key via SHA-256 over a domain-separated transcript.
func combineHybridSecret(ecdhSecret, kyberSecret []byte) []byte {
	h := sha256.New()
	h.Write([]byte("aethelred-hybrid-kem-v1"))
	h.Write(ecdhSecret)
	h.Write(kyberSecret)
	sum := h.Sum(nil)
	return sum
}
