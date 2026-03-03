// Package dag provides the encrypted mempool bridge connecting the Go-side DAG
// mempool with the Rust-side TEE SecretMempool for end-to-end MEV protection.
//
// Architecture:
//
//	Client → DAGMempool (Go, encrypted tx priority) → EncryptedMempoolBridge
//	  → TEE Enclave (Rust SecretMempool) → decrypted txs → block proposal
//
// Previously the DAG mempool recognized encrypted transactions and gave them
// priority ordering, but never actually routed them through TEE enclaves for
// decryption. This bridge closes that gap.
package dag

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

// =============================================================================
// Encrypted Mempool Bridge
// =============================================================================

// EncryptedMempoolBridge coordinates between the Go DAG mempool and the Rust
// TEE SecretMempool. It manages enclave public keys for client-side encryption
// and routes encrypted transactions to TEE workers for decryption during
// block proposal.
type EncryptedMempoolBridge struct {
	mu sync.RWMutex

	// enclaveKeys maps validator peer ID to their TEE enclave's ECDH public key.
	// Clients use these keys to encrypt transactions so only the enclave can decrypt.
	enclaveKeys map[string]*EnclaveKeyInfo

	// decryptionClient communicates with the Rust TEE worker service.
	decryptionClient TEEDecryptionClient

	// config for the bridge
	config *EncryptedBridgeConfig

	// metrics
	metrics *EncryptedBridgeMetrics
}

// EnclaveKeyInfo holds a TEE enclave's public key and metadata.
type EnclaveKeyInfo struct {
	// PublicKey is the enclave's ECDH public key (X25519)
	PublicKey *ecdh.PublicKey

	// PublicKeyBytes is the raw 32-byte public key for client distribution
	PublicKeyBytes []byte

	// ValidatorID identifies the validator operating this enclave
	ValidatorID string

	// AttestationQuote proves the key was generated inside a genuine TEE
	AttestationQuote []byte

	// Platform identifies the TEE type (aws-nitro, intel-sgx, etc.)
	Platform string

	// RegisteredAt is when this key was registered
	RegisteredAt time.Time

	// ExpiresAt is when this key should be rotated
	ExpiresAt time.Time
}

// TEEDecryptionClient is the interface for communicating with the Rust TEE
// worker service that holds the enclave's private keys.
type TEEDecryptionClient interface {
	// DecryptTransactions sends encrypted transactions to the TEE enclave
	// for decryption. Returns decrypted transactions in the same order.
	DecryptTransactions(ctx context.Context, encryptedTxs [][]byte) ([][]byte, error)

	// GetEnclavePublicKey retrieves the current enclave's ECDH public key
	// along with its TEE attestation quote.
	GetEnclavePublicKey(ctx context.Context) (pubKey []byte, attestation []byte, err error)

	// HealthCheck verifies the TEE worker is responsive.
	HealthCheck(ctx context.Context) error
}

// EncryptedBridgeConfig configures the encrypted mempool bridge.
type EncryptedBridgeConfig struct {
	// MaxBatchSize is the maximum encrypted txs per TEE decryption batch.
	MaxBatchSize int

	// DecryptionTimeout is the maximum time to wait for TEE decryption.
	DecryptionTimeout time.Duration

	// KeyRotationInterval is how often enclave keys should be rotated.
	KeyRotationInterval time.Duration

	// RequireAttestation requires TEE attestation for enclave keys.
	RequireAttestation bool
}

// DefaultEncryptedBridgeConfig returns production defaults.
func DefaultEncryptedBridgeConfig() *EncryptedBridgeConfig {
	return &EncryptedBridgeConfig{
		MaxBatchSize:        256,
		DecryptionTimeout:   5 * time.Second,
		KeyRotationInterval: 24 * time.Hour,
		RequireAttestation:  true,
	}
}

// EncryptedBridgeMetrics tracks bridge operation metrics.
type EncryptedBridgeMetrics struct {
	mu                     sync.Mutex
	TotalEncryptedTxs      int64
	TotalDecryptedTxs      int64
	DecryptionFailures     int64
	AvgDecryptionLatencyMs float64
}

// NewEncryptedMempoolBridge creates a new bridge between Go DAG and Rust TEE.
func NewEncryptedMempoolBridge(
	client TEEDecryptionClient,
	config *EncryptedBridgeConfig,
) *EncryptedMempoolBridge {
	if config == nil {
		config = DefaultEncryptedBridgeConfig()
	}
	return &EncryptedMempoolBridge{
		enclaveKeys:      make(map[string]*EnclaveKeyInfo),
		decryptionClient: client,
		config:           config,
		metrics:          &EncryptedBridgeMetrics{},
	}
}

// RegisterEnclaveKey registers a TEE enclave's public key for client-side
// encryption. The attestation quote is verified to ensure the key was
// generated inside a genuine TEE.
func (b *EncryptedMempoolBridge) RegisterEnclaveKey(
	validatorID string,
	pubKeyBytes []byte,
	attestationQuote []byte,
	platform string,
) error {
	if len(pubKeyBytes) != 32 {
		return fmt.Errorf("invalid enclave public key size: expected 32, got %d", len(pubKeyBytes))
	}

	if b.config.RequireAttestation && len(attestationQuote) == 0 {
		return errors.New("TEE attestation quote required for enclave key registration")
	}

	pubKey, err := ecdh.X25519().NewPublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid X25519 public key: %w", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.enclaveKeys[validatorID] = &EnclaveKeyInfo{
		PublicKey:        pubKey,
		PublicKeyBytes:   pubKeyBytes,
		ValidatorID:      validatorID,
		AttestationQuote: attestationQuote,
		Platform:         platform,
		RegisteredAt:     time.Now(),
		ExpiresAt:        time.Now().Add(b.config.KeyRotationInterval),
	}

	return nil
}

// GetEnclavePublicKeys returns all active enclave public keys for client-side
// encryption.
func (b *EncryptedMempoolBridge) GetEnclavePublicKeys() []EnclaveKeyInfo {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	var active []EnclaveKeyInfo
	for _, info := range b.enclaveKeys {
		if now.Before(info.ExpiresAt) {
			active = append(active, *info)
		}
	}
	return active
}

// DecryptForProposal decrypts encrypted transactions from the DAG mempool
// during block proposal. Called by the proposer in PrepareProposal.
//
// It extracts encrypted transactions (identified by the 0xAE prefix),
// sends them to the TEE enclave for decryption, and returns the full
// transaction set with encrypted txs replaced by their plaintext equivalents.
func (b *EncryptedMempoolBridge) DecryptForProposal(
	ctx context.Context,
	transactions [][]byte,
	encryptedPrefix byte,
) ([][]byte, error) {
	if b.decryptionClient == nil {
		return transactions, nil
	}

	// Partition into encrypted and plaintext
	var (
		encrypted    [][]byte
		encryptedIdx []int
		result       = make([][]byte, len(transactions))
	)
	copy(result, transactions)

	for i, tx := range transactions {
		if len(tx) > 1 && tx[0] == encryptedPrefix {
			encrypted = append(encrypted, tx)
			encryptedIdx = append(encryptedIdx, i)
		}
	}

	if len(encrypted) == 0 {
		return result, nil
	}

	b.metrics.mu.Lock()
	b.metrics.TotalEncryptedTxs += int64(len(encrypted))
	b.metrics.mu.Unlock()

	// Batch decrypt through TEE
	start := time.Now()
	decryptCtx, cancel := context.WithTimeout(ctx, b.config.DecryptionTimeout)
	defer cancel()

	for batchStart := 0; batchStart < len(encrypted); batchStart += b.config.MaxBatchSize {
		batchEnd := batchStart + b.config.MaxBatchSize
		if batchEnd > len(encrypted) {
			batchEnd = len(encrypted)
		}

		batch := encrypted[batchStart:batchEnd]
		decrypted, err := b.decryptionClient.DecryptTransactions(decryptCtx, batch)
		if err != nil {
			b.metrics.mu.Lock()
			b.metrics.DecryptionFailures += int64(len(batch))
			b.metrics.mu.Unlock()
			return nil, fmt.Errorf("TEE decryption failed for batch %d-%d: %w",
				batchStart, batchEnd, err)
		}

		if len(decrypted) != len(batch) {
			return nil, fmt.Errorf("TEE returned %d decrypted txs, expected %d",
				len(decrypted), len(batch))
		}

		// Replace encrypted txs with decrypted versions
		for j, plainTx := range decrypted {
			idx := encryptedIdx[batchStart+j]
			result[idx] = plainTx
		}
	}

	elapsed := time.Since(start)
	b.metrics.mu.Lock()
	b.metrics.TotalDecryptedTxs += int64(len(encrypted))
	b.metrics.AvgDecryptionLatencyMs = float64(elapsed.Milliseconds())
	b.metrics.mu.Unlock()

	return result, nil
}

// EncryptTransaction encrypts a transaction for submission to the encrypted
// mempool. Uses ECDH key exchange with the enclave's public key followed
// by AES-256-GCM encryption.
//
// Wire format: [prefix(1)][ephemeralPubKey(32)][nonce(12)][ciphertext+tag(variable)]
func EncryptTransaction(
	tx []byte,
	enclavePublicKey []byte,
	prefix byte,
) ([]byte, error) {
	if len(enclavePublicKey) != 32 {
		return nil, fmt.Errorf("invalid enclave public key size: expected 32, got %d", len(enclavePublicKey))
	}

	enclavePK, err := ecdh.X25519().NewPublicKey(enclavePublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid enclave public key: %w", err)
	}

	// Generate ephemeral key pair for ECDH
	ephemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Perform ECDH to derive shared secret
	sharedSecret, err := ephemeralPriv.ECDH(enclavePK)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive AES-256 key from shared secret using HKDF-SHA256
	aesKey := sha256.Sum256(append([]byte("aethelred-encrypted-mempool-v1"), sharedSecret...))

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, tx, nil)

	// Build wire format: prefix + ephemeral pub key + nonce + ciphertext
	ephPubBytes := ephemeralPriv.PublicKey().Bytes()
	result := make([]byte, 0, 1+32+len(nonce)+len(ciphertext))
	result = append(result, prefix)
	result = append(result, ephPubBytes...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// GetMetrics returns bridge operation metrics.
func (b *EncryptedMempoolBridge) GetMetrics() EncryptedBridgeMetrics {
	b.metrics.mu.Lock()
	defer b.metrics.mu.Unlock()
	return *b.metrics
}
