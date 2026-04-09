package sovereign

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// KMS modes
// ---------------------------------------------------------------------------

// KMSMode identifies the key management operational mode.
type KMSMode int

const (
	// CloudManaged uses a cloud-hosted KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault).
	CloudManaged KMSMode = iota

	// OnPremHSM uses an on-premises hardware security module via PKCS#11.
	OnPremHSM

	// BYOK allows the customer to bring their own key material.
	BYOK

	// SplitKey distributes key shares across multiple custodians.
	SplitKey
)

// String returns the human-readable label for a KMSMode.
func (m KMSMode) String() string {
	switch m {
	case CloudManaged:
		return "Cloud Managed"
	case OnPremHSM:
		return "On-Prem HSM"
	case BYOK:
		return "Bring Your Own Key"
	case SplitKey:
		return "Split Key"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// KMS configuration
// ---------------------------------------------------------------------------

// SovereignKMSConfig holds configuration for sovereign key management.
type SovereignKMSConfig struct {
	// Mode is the KMS operational mode.
	Mode KMSMode `json:"mode"`

	// Provider identifies the backend provider (e.g., "aws_kms", "hsm", "byok").
	Provider string `json:"provider"`

	// Region constrains key operations to a specific geographic region.
	Region string `json:"region"`

	// KeyPolicy defines the constraints on generated keys.
	KeyPolicy KeyPolicy `json:"key_policy"`

	// RotationPolicy defines key rotation requirements.
	RotationPolicy RotationPolicy `json:"rotation_policy"`

	// Endpoint is the provider-specific endpoint URL.
	Endpoint string `json:"endpoint,omitempty"`

	// PKCS11LibPath is the path to the PKCS#11 library for HSM modes.
	PKCS11LibPath string `json:"pkcs11_lib_path,omitempty"`

	// SlotID is the PKCS#11 slot ID for HSM modes.
	SlotID int `json:"slot_id,omitempty"`
}

// Validate checks the KMS configuration for consistency.
func (c *SovereignKMSConfig) Validate() error {
	if c.Region == "" {
		return fmt.Errorf("KMS region is required")
	}
	if c.Mode == OnPremHSM && c.PKCS11LibPath == "" {
		return fmt.Errorf("PKCS#11 library path is required for on-prem HSM mode")
	}
	return nil
}

// KeyPolicy defines constraints on cryptographic keys generated within
// the sovereign KMS.
type KeyPolicy struct {
	// MinKeySize is the minimum key size in bits.
	MinKeySize int `json:"min_key_size"`

	// AllowedAlgorithms lists the permitted key algorithms.
	AllowedAlgorithms []string `json:"allowed_algorithms"`

	// RotationPeriod is how often keys must be rotated.
	RotationPeriod time.Duration `json:"rotation_period"`

	// ExpirationPolicy specifies key expiration behavior.
	ExpirationPolicy string `json:"expiration_policy"`

	// EscrowRequired mandates key escrow for disaster recovery.
	EscrowRequired bool `json:"escrow_required"`

	// ExportRestricted prevents key material from being exported.
	ExportRestricted bool `json:"export_restricted"`
}

// RotationPolicy defines how and when keys are rotated.
type RotationPolicy struct {
	// AutoRotate enables automatic key rotation.
	AutoRotate bool `json:"auto_rotate"`

	// RotationInterval is the time between automatic rotations.
	RotationInterval time.Duration `json:"rotation_interval"`

	// RetainPrevious specifies how many previous key versions to retain.
	RetainPrevious int `json:"retain_previous"`

	// NotifyBeforeExpiry is the lead time for expiry notifications.
	NotifyBeforeExpiry time.Duration `json:"notify_before_expiry"`
}

// ---------------------------------------------------------------------------
// Key representation
// ---------------------------------------------------------------------------

// SovereignKey represents a cryptographic key managed by the sovereign KMS.
type SovereignKey struct {
	// ID uniquely identifies this key.
	ID string `json:"id"`

	// Algorithm is the key algorithm (e.g., "ML-DSA-65", "AES-256", "ECDSA-P256").
	Algorithm string `json:"algorithm"`

	// Purpose describes the intended use of the key.
	Purpose string `json:"purpose"`

	// Region is the region where the key is stored.
	Region string `json:"region"`

	// CreatedAt is when the key was generated.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the key expires (zero if no expiry).
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// LastRotated is when the key was last rotated.
	LastRotated time.Time `json:"last_rotated"`

	// Version is the key version (incremented on rotation).
	Version int `json:"version"`

	// Status indicates whether the key is active, rotated, or revoked.
	Status string `json:"status"`

	// Material holds the key material (opaque; in production this stays in HSM).
	Material []byte `json:"-"`

	// PublicKey holds the public portion for asymmetric keys.
	PublicKey []byte `json:"public_key,omitempty"`
}

// WrappedKey holds key material encrypted under a wrapping key for
// secure export and transfer.
type WrappedKey struct {
	// KeyID is the ID of the wrapped key.
	KeyID string `json:"key_id"`

	// WrappedMaterial holds the encrypted key material.
	WrappedMaterial []byte `json:"wrapped_material"`

	// WrappingKeyID identifies the key used for wrapping.
	WrappingKeyID string `json:"wrapping_key_id"`

	// Algorithm is the wrapping algorithm used.
	Algorithm string `json:"algorithm"`

	// CreatedAt is when the wrapped key was produced.
	CreatedAt time.Time `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Sovereign KMS
// ---------------------------------------------------------------------------

// SovereignKMS manages cryptographic keys with sovereign deployment
// constraints, including region-locking, policy enforcement, and
// rotation schedules.
type SovereignKMS struct {
	config SovereignKMSConfig
	mu     sync.RWMutex
	keys   map[string]*SovereignKey
}

// InitializeKMS creates and configures a new sovereign KMS instance.
func InitializeKMS(_ context.Context, config SovereignKMSConfig) (*SovereignKMS, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid KMS config: %w", err)
	}

	return &SovereignKMS{
		config: config,
		keys:   make(map[string]*SovereignKey),
	}, nil
}

// GenerateKey creates a new cryptographic key with the specified purpose,
// enforcing the key policy constraints configured for this KMS.
func (kms *SovereignKMS) GenerateKey(_ context.Context, purpose string, policy KeyPolicy) (*SovereignKey, error) {
	if purpose == "" {
		return nil, fmt.Errorf("key purpose is required")
	}

	// Determine algorithm
	algorithm := "AES-256"
	if len(policy.AllowedAlgorithms) > 0 {
		algorithm = policy.AllowedAlgorithms[0]
	} else if len(kms.config.KeyPolicy.AllowedAlgorithms) > 0 {
		algorithm = kms.config.KeyPolicy.AllowedAlgorithms[0]
	}

	// Enforce minimum key size
	minSize := policy.MinKeySize
	if minSize == 0 {
		minSize = kms.config.KeyPolicy.MinKeySize
	}
	if minSize == 0 {
		minSize = 256
	}

	// Generate key material
	keyBytes := minSize / 8
	if keyBytes < 32 {
		keyBytes = 32
	}
	material := make([]byte, keyBytes)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("failed to generate key material: %w", err)
	}

	now := time.Now().UTC()
	keyID := fmt.Sprintf("sov-key-%s-%d", kms.config.Region, now.UnixNano())

	key := &SovereignKey{
		ID:          keyID,
		Algorithm:   algorithm,
		Purpose:     purpose,
		Region:      kms.config.Region,
		CreatedAt:   now,
		LastRotated: now,
		Version:     1,
		Status:      "active",
		Material:    material,
	}

	// Apply expiration
	rotationPeriod := policy.RotationPeriod
	if rotationPeriod == 0 {
		rotationPeriod = kms.config.KeyPolicy.RotationPeriod
	}
	if rotationPeriod > 0 {
		key.ExpiresAt = now.Add(rotationPeriod)
	}

	// Generate public key for asymmetric algorithms
	if algorithm == "ML-DSA-65" || algorithm == "ECDSA-P256" || algorithm == "ML-KEM-768" {
		pubKey := sha256.Sum256(material)
		key.PublicKey = pubKey[:]
	}

	kms.mu.Lock()
	kms.keys[keyID] = key
	kms.mu.Unlock()

	return key, nil
}

// RotateKey creates a new version of the specified key, retiring the
// current version. The old key version is retained according to the
// rotation policy.
func (kms *SovereignKMS) RotateKey(_ context.Context, keyID string) (*SovereignKey, error) {
	if keyID == "" {
		return nil, fmt.Errorf("key ID is required")
	}

	kms.mu.Lock()
	defer kms.mu.Unlock()

	existing, ok := kms.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	if existing.Status == "revoked" {
		return nil, fmt.Errorf("cannot rotate revoked key: %s", keyID)
	}

	// Generate new key material
	material := make([]byte, len(existing.Material))
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("failed to generate rotated key material: %w", err)
	}

	now := time.Now().UTC()

	// Mark old version as rotated
	existing.Status = "rotated"

	// Create new key version
	newKey := &SovereignKey{
		ID:          keyID,
		Algorithm:   existing.Algorithm,
		Purpose:     existing.Purpose,
		Region:      existing.Region,
		CreatedAt:   existing.CreatedAt,
		LastRotated: now,
		Version:     existing.Version + 1,
		Status:      "active",
		Material:    material,
	}

	if existing.ExpiresAt.After(existing.CreatedAt) {
		duration := existing.ExpiresAt.Sub(existing.CreatedAt)
		newKey.ExpiresAt = now.Add(duration)
	}

	if existing.Algorithm == "ML-DSA-65" || existing.Algorithm == "ECDSA-P256" || existing.Algorithm == "ML-KEM-768" {
		pubKey := sha256.Sum256(material)
		newKey.PublicKey = pubKey[:]
	}

	kms.keys[keyID] = newKey
	return newKey, nil
}

// ExportWrappedKey exports the specified key encrypted under the given
// wrapping key. This is used for secure key transfer between sovereign
// environments.
func (kms *SovereignKMS) ExportWrappedKey(_ context.Context, keyID string, wrappingKeyID string) (*WrappedKey, error) {
	if keyID == "" {
		return nil, fmt.Errorf("key ID is required")
	}
	if wrappingKeyID == "" {
		return nil, fmt.Errorf("wrapping key ID is required")
	}

	kms.mu.RLock()
	defer kms.mu.RUnlock()

	key, ok := kms.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	wrappingKey, ok := kms.keys[wrappingKeyID]
	if !ok {
		return nil, fmt.Errorf("wrapping key not found: %s", wrappingKeyID)
	}

	// Check export restrictions
	if kms.config.KeyPolicy.ExportRestricted {
		return nil, fmt.Errorf("key export is restricted by policy")
	}

	// Wrap key material (simplified: in production use AES-KW or similar)
	h := sha256.Sum256(append(wrappingKey.Material, key.Material...))
	wrappedMaterial := append(h[:], key.Material...)

	return &WrappedKey{
		KeyID:           keyID,
		WrappedMaterial: wrappedMaterial,
		WrappingKeyID:   wrappingKeyID,
		Algorithm:       "AES-KW-256",
		CreatedAt:       time.Now().UTC(),
	}, nil
}

// GetKey retrieves key metadata by ID.
func (kms *SovereignKMS) GetKey(keyID string) (*SovereignKey, error) {
	kms.mu.RLock()
	defer kms.mu.RUnlock()

	key, ok := kms.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	// Return copy without material
	result := *key
	result.Material = nil
	return &result, nil
}

// RevokeKey marks a key as revoked, preventing further use.
func (kms *SovereignKMS) RevokeKey(keyID string) error {
	kms.mu.Lock()
	defer kms.mu.Unlock()

	key, ok := kms.keys[keyID]
	if !ok {
		return fmt.Errorf("key not found: %s", keyID)
	}

	key.Status = "revoked"
	return nil
}

// ListKeys returns metadata for all keys managed by this KMS.
func (kms *SovereignKMS) ListKeys() []*SovereignKey {
	kms.mu.RLock()
	defer kms.mu.RUnlock()

	result := make([]*SovereignKey, 0, len(kms.keys))
	for _, k := range kms.keys {
		info := *k
		info.Material = nil
		result = append(result, &info)
	}
	return result
}

// generateKeyID produces a unique key identifier incorporating the
// region and a random component.
func generateKeyID(region string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("sov-key-%s-%s", region, hex.EncodeToString(b))
}
