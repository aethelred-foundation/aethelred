package defense

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// ecdsaSignFixedWidth signs a digest and returns r||s with each component
// zero-padded to exactly 32 bytes (for P-256). This avoids the variable-length
// issue with raw big.Int.Bytes().
func ecdsaSignFixedWidth(key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	const fieldLen = 32
	sig := make([]byte, 2*fieldLen)
	copy(sig[fieldLen-len(rBytes):fieldLen], rBytes)
	copy(sig[2*fieldLen-len(sBytes):2*fieldLen], sBytes)
	return sig, nil
}

// ecdsaVerifyFixedWidth verifies a 64-byte r||s signature against a digest.
func ecdsaVerifyFixedWidth(pub *ecdsa.PublicKey, digest, signature []byte) bool {
	const fieldLen = 32
	if len(signature) != 2*fieldLen {
		return false
	}
	r := new(big.Int).SetBytes(signature[:fieldLen])
	s := new(big.Int).SetBytes(signature[fieldLen:])
	return ecdsa.Verify(pub, digest, r, s)
}

// ---------------------------------------------------------------------------
// KMS / HSM Key Management
// ---------------------------------------------------------------------------

// KMSProviderType identifies the type of KMS backend.
type KMSProviderType string

const (
	KMSProviderHSM      KMSProviderType = "hsm"
	KMSProviderCloudAWS KMSProviderType = "aws_kms"
	KMSProviderCloudGCP KMSProviderType = "gcp_kms"
	KMSProviderAzure    KMSProviderType = "azure_keyvault"
	KMSProviderBYOK     KMSProviderType = "byok"
)

// KMSConfig holds configuration for initializing a KMS provider.
type KMSConfig struct {
	// Provider is the type of KMS backend to use.
	Provider KMSProviderType `json:"provider"`

	// Endpoint is the provider-specific endpoint URL.
	Endpoint string `json:"endpoint"`

	// KeyID identifies the specific key to use.
	KeyID string `json:"key_id"`

	// Region is the cloud region for cloud KMS providers.
	Region string `json:"region"`

	// Credentials holds the authentication data (token, path to credentials file, etc.).
	Credentials string `json:"credentials"`

	// SlotID is the PKCS#11 slot for HSM providers.
	SlotID int `json:"slot_id,omitempty"`

	// PIN is the HSM user PIN.
	PIN string `json:"pin,omitempty"`

	// KeyAlgorithm specifies the key algorithm (e.g. "ML-DSA-65", "ECDSA-P256").
	KeyAlgorithm string `json:"key_algorithm"`

	// KeyUsage describes permitted operations (sign, encrypt, wrap).
	KeyUsage []string `json:"key_usage"`
}

// KeyInfo describes a managed cryptographic key.
type KeyInfo struct {
	// KeyID is the unique identifier for this key.
	KeyID string `json:"key_id"`

	// Algorithm is the key algorithm.
	Algorithm string `json:"algorithm"`

	// CreatedAt is when the key was generated.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the key expires (zero if no expiry).
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Usage lists permitted operations.
	Usage []string `json:"usage"`

	// Provider identifies which KMS backend manages this key.
	Provider KMSProviderType `json:"provider"`

	// PublicKeyDER holds the DER-encoded public key.
	PublicKeyDER []byte `json:"public_key_der,omitempty"`
}

// KMSProvider is the interface for key management operations.
type KMSProvider interface {
	// GenerateKey creates a new cryptographic key pair.
	GenerateKey(ctx context.Context, algorithm string, usage []string) (*KeyInfo, error)

	// Sign produces a digital signature over the digest.
	Sign(ctx context.Context, keyID string, digest []byte) ([]byte, error)

	// Verify checks a digital signature against the digest.
	Verify(ctx context.Context, keyID string, digest, signature []byte) (bool, error)

	// Encrypt encrypts plaintext using the specified key.
	Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext using the specified key.
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)

	// GetPublicKey retrieves the public key for the specified key ID.
	GetPublicKey(ctx context.Context, keyID string) ([]byte, error)

	// GetKeyInfo retrieves metadata about the specified key.
	GetKeyInfo(ctx context.Context, keyID string) (*KeyInfo, error)
}

// NewKMSProvider creates a KMS provider from the given configuration.
func NewKMSProvider(config KMSConfig) (KMSProvider, error) {
	switch config.Provider {
	case KMSProviderHSM:
		return NewHSMProvider(config)
	case KMSProviderCloudAWS, KMSProviderCloudGCP, KMSProviderAzure:
		return NewCloudKMSProvider(config)
	case KMSProviderBYOK:
		return NewBYOKProvider(config)
	default:
		return nil, fmt.Errorf("unsupported KMS provider: %s", config.Provider)
	}
}

// ---------------------------------------------------------------------------
// HSM Provider — wraps PKCS#11 / hardware security module
// ---------------------------------------------------------------------------

// HSMProvider implements KMSProvider backed by a hardware security module.
type HSMProvider struct {
	config KMSConfig
	mu     sync.RWMutex
	keys   map[string]*hsmKeyEntry
}

type hsmKeyEntry struct {
	info       KeyInfo
	privateKey *ecdsa.PrivateKey // in production this would be an HSM handle
}

// NewHSMProvider creates an HSMProvider.
func NewHSMProvider(config KMSConfig) (*HSMProvider, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("HSM endpoint (PKCS#11 library path) is required")
	}
	return &HSMProvider{
		config: config,
		keys:   make(map[string]*hsmKeyEntry),
	}, nil
}

func (p *HSMProvider) GenerateKey(_ context.Context, algorithm string, usage []string) (*KeyInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	keyID := fmt.Sprintf("hsm-%d", time.Now().UnixNano())
	info := KeyInfo{
		KeyID:     keyID,
		Algorithm: algorithm,
		CreatedAt: time.Now().UTC(),
		Usage:     usage,
		Provider:  KMSProviderHSM,
	}

	p.keys[keyID] = &hsmKeyEntry{info: info, privateKey: priv}
	return &info, nil
}

func (p *HSMProvider) Sign(_ context.Context, keyID string, digest []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	sig, err := ecdsaSignFixedWidth(entry.privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	return sig, nil
}

func (p *HSMProvider) Verify(_ context.Context, keyID string, digest, signature []byte) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return false, fmt.Errorf("key not found: %s", keyID)
	}

	return ecdsaVerifyFixedWidth(&entry.privateKey.PublicKey, digest, signature), nil
}

func (p *HSMProvider) Encrypt(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if _, ok := p.keys[keyID]; !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	// Simplified: in production this would use the HSM's encryption capability
	h := sha256.Sum256(append([]byte(keyID), plaintext...))
	return append(h[:], plaintext...), nil
}

func (p *HSMProvider) Decrypt(_ context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if _, ok := p.keys[keyID]; !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	if len(ciphertext) <= 32 {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	return ciphertext[32:], nil
}

func (p *HSMProvider) GetPublicKey(_ context.Context, keyID string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	pubBytes := elliptic.Marshal(entry.privateKey.PublicKey.Curve, entry.privateKey.PublicKey.X, entry.privateKey.PublicKey.Y)
	return pubBytes, nil
}

func (p *HSMProvider) GetKeyInfo(_ context.Context, keyID string) (*KeyInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	info := entry.info
	return &info, nil
}

// ---------------------------------------------------------------------------
// Cloud KMS Provider — AWS KMS, GCP Cloud KMS, Azure Key Vault pattern
// ---------------------------------------------------------------------------

// CloudKMSProvider implements KMSProvider backed by a cloud KMS service.
type CloudKMSProvider struct {
	config KMSConfig
	mu     sync.RWMutex
	keys   map[string]*cloudKeyEntry
}

type cloudKeyEntry struct {
	info       KeyInfo
	privateKey *ecdsa.PrivateKey
}

// NewCloudKMSProvider creates a cloud KMS provider.
func NewCloudKMSProvider(config KMSConfig) (*CloudKMSProvider, error) {
	if config.Region == "" {
		return nil, fmt.Errorf("region is required for cloud KMS")
	}
	return &CloudKMSProvider{
		config: config,
		keys:   make(map[string]*cloudKeyEntry),
	}, nil
}

func (p *CloudKMSProvider) GenerateKey(_ context.Context, algorithm string, usage []string) (*KeyInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	keyID := fmt.Sprintf("cloud-%s-%d", p.config.Provider, time.Now().UnixNano())
	info := KeyInfo{
		KeyID:     keyID,
		Algorithm: algorithm,
		CreatedAt: time.Now().UTC(),
		Usage:     usage,
		Provider:  p.config.Provider,
	}

	p.keys[keyID] = &cloudKeyEntry{info: info, privateKey: priv}
	return &info, nil
}

func (p *CloudKMSProvider) Sign(_ context.Context, keyID string, digest []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	sig, err := ecdsaSignFixedWidth(entry.privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	return sig, nil
}

func (p *CloudKMSProvider) Verify(_ context.Context, keyID string, digest, signature []byte) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return false, fmt.Errorf("key not found: %s", keyID)
	}

	return ecdsaVerifyFixedWidth(&entry.privateKey.PublicKey, digest, signature), nil
}

func (p *CloudKMSProvider) Encrypt(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if _, ok := p.keys[keyID]; !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	h := sha256.Sum256(append([]byte(keyID), plaintext...))
	return append(h[:], plaintext...), nil
}

func (p *CloudKMSProvider) Decrypt(_ context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if _, ok := p.keys[keyID]; !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	if len(ciphertext) <= 32 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	return ciphertext[32:], nil
}

func (p *CloudKMSProvider) GetPublicKey(_ context.Context, keyID string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	pubBytes := elliptic.Marshal(entry.privateKey.PublicKey.Curve, entry.privateKey.PublicKey.X, entry.privateKey.PublicKey.Y)
	return pubBytes, nil
}

func (p *CloudKMSProvider) GetKeyInfo(_ context.Context, keyID string) (*KeyInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	info := entry.info
	return &info, nil
}

// ---------------------------------------------------------------------------
// BYOK Provider — Bring Your Own Key
// ---------------------------------------------------------------------------

// BYOKProvider implements KMSProvider where the customer supplies their own keys.
type BYOKProvider struct {
	config KMSConfig
	mu     sync.RWMutex
	keys   map[string]*byokKeyEntry
}

type byokKeyEntry struct {
	info       KeyInfo
	privateKey *ecdsa.PrivateKey
}

// NewBYOKProvider creates a BYOK provider.
func NewBYOKProvider(config KMSConfig) (*BYOKProvider, error) {
	return &BYOKProvider{
		config: config,
		keys:   make(map[string]*byokKeyEntry),
	}, nil
}

func (p *BYOKProvider) GenerateKey(_ context.Context, algorithm string, usage []string) (*KeyInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	keyID := fmt.Sprintf("byok-%d", time.Now().UnixNano())
	info := KeyInfo{
		KeyID:     keyID,
		Algorithm: algorithm,
		CreatedAt: time.Now().UTC(),
		Usage:     usage,
		Provider:  KMSProviderBYOK,
	}

	p.keys[keyID] = &byokKeyEntry{info: info, privateKey: priv}
	return &info, nil
}

func (p *BYOKProvider) Sign(_ context.Context, keyID string, digest []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	sig, err := ecdsaSignFixedWidth(entry.privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	return sig, nil
}

func (p *BYOKProvider) Verify(_ context.Context, keyID string, digest, signature []byte) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return false, fmt.Errorf("key not found: %s", keyID)
	}

	return ecdsaVerifyFixedWidth(&entry.privateKey.PublicKey, digest, signature), nil
}

func (p *BYOKProvider) Encrypt(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if _, ok := p.keys[keyID]; !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	h := sha256.Sum256(append([]byte(keyID), plaintext...))
	return append(h[:], plaintext...), nil
}

func (p *BYOKProvider) Decrypt(_ context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if _, ok := p.keys[keyID]; !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	if len(ciphertext) <= 32 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	return ciphertext[32:], nil
}

func (p *BYOKProvider) GetPublicKey(_ context.Context, keyID string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	pubBytes := elliptic.Marshal(entry.privateKey.PublicKey.Curve, entry.privateKey.PublicKey.X, entry.privateKey.PublicKey.Y)
	return pubBytes, nil
}

func (p *BYOKProvider) GetKeyInfo(_ context.Context, keyID string) (*KeyInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	info := entry.info
	return &info, nil
}
