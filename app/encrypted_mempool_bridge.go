package app

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"sync"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// EncryptedMempoolBridge handles the decryption and filtering of encrypted
// transactions during PrepareProposal. Validators submit encrypted transactions
// to prevent front-running and censorship. The proposer decrypts eligible
// transactions using the threshold-decrypted block key before including them
// in the proposal.
//
// The bridge integrates with the ABCI++ PrepareProposal handler, sitting between
// the raw mempool transactions and the final proposal assembly.
type EncryptedMempoolBridge struct {
	logger log.Logger

	// mu protects the block key state
	mu sync.RWMutex

	// blockKey is the AES-256 symmetric key for the current block, derived
	// from threshold decryption of the proposer's key share. Nil when no
	// encrypted transactions are supported.
	blockKey []byte

	// enabled controls whether encrypted mempool processing is active
	enabled bool

	// maxDecryptedTxSize is the maximum allowed size for a decrypted transaction
	maxDecryptedTxSize int
}

// EncryptedMempoolBridgeConfig holds configuration for the bridge
type EncryptedMempoolBridgeConfig struct {
	Enabled            bool
	MaxDecryptedTxSize int
}

// DefaultEncryptedMempoolBridgeConfig returns the default configuration
func DefaultEncryptedMempoolBridgeConfig() EncryptedMempoolBridgeConfig {
	return EncryptedMempoolBridgeConfig{
		Enabled:            true,
		MaxDecryptedTxSize: 1024 * 1024, // 1MB
	}
}

// NewEncryptedMempoolBridge creates a new EncryptedMempoolBridge instance
func NewEncryptedMempoolBridge(logger log.Logger, cfg EncryptedMempoolBridgeConfig) *EncryptedMempoolBridge {
	return &EncryptedMempoolBridge{
		logger:             logger.With("component", "encrypted_mempool_bridge"),
		enabled:            cfg.Enabled,
		maxDecryptedTxSize: cfg.MaxDecryptedTxSize,
	}
}

// encryptedTxPrefix is the magic byte prefix that identifies encrypted transactions
// in the mempool. Regular transactions do not start with this prefix.
// 0xAE 0x77 0xE0 = "aeth" encrypted marker.
var encryptedTxPrefix = []byte{0xAE, 0x77, 0xE0}

// SetBlockKey sets the symmetric key for decrypting transactions in the
// current block. This should be called with the threshold-decrypted key
// derived from validator key shares during the proposal phase.
func (b *EncryptedMempoolBridge) SetBlockKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("invalid block key length: expected 32 bytes (AES-256), got %d", len(key))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blockKey = make([]byte, 32)
	copy(b.blockKey, key)
	return nil
}

// ClearBlockKey clears the current block key after proposal processing
func (b *EncryptedMempoolBridge) ClearBlockKey() {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Zero out the key material before clearing
	for i := range b.blockKey {
		b.blockKey[i] = 0
	}
	b.blockKey = nil
}

// IsEncryptedTx returns true if the transaction bytes represent an encrypted
// transaction (identified by the magic prefix).
func IsEncryptedTx(txBytes []byte) bool {
	if len(txBytes) < len(encryptedTxPrefix)+aes.BlockSize+1 {
		return false
	}
	for i, b := range encryptedTxPrefix {
		if txBytes[i] != b {
			return false
		}
	}
	return true
}

// ProcessProposalTxs filters and decrypts encrypted transactions from the
// mempool, returning the processed transaction list ready for proposal assembly.
// Encrypted transactions are decrypted in-place; those that fail decryption
// are silently dropped.
func (b *EncryptedMempoolBridge) ProcessProposalTxs(
	ctx sdk.Context,
	req *abci.RequestPrepareProposal,
) [][]byte {
	if !b.enabled {
		return req.Txs
	}

	b.mu.RLock()
	hasKey := len(b.blockKey) == 32
	b.mu.RUnlock()

	if !hasKey {
		// No block key available; pass through only plaintext transactions,
		// dropping any encrypted ones that cannot be decrypted.
		var plainTxs [][]byte
		for _, tx := range req.Txs {
			if !IsEncryptedTx(tx) {
				plainTxs = append(plainTxs, tx)
			}
		}
		if len(plainTxs) != len(req.Txs) {
			b.logger.Warn("Dropping encrypted transactions: no block key available",
				"dropped", len(req.Txs)-len(plainTxs),
				"height", req.Height,
			)
		}
		return plainTxs
	}

	var processed [][]byte
	decrypted := 0

	for _, tx := range req.Txs {
		if !IsEncryptedTx(tx) {
			processed = append(processed, tx)
			continue
		}

		plaintext, err := b.decryptTx(tx)
		if err != nil {
			b.logger.Debug("Failed to decrypt transaction, dropping",
				"error", err,
				"height", req.Height,
			)
			continue
		}

		if len(plaintext) > b.maxDecryptedTxSize {
			b.logger.Warn("Decrypted transaction exceeds size limit, dropping",
				"size", len(plaintext),
				"max", b.maxDecryptedTxSize,
			)
			continue
		}

		processed = append(processed, plaintext)
		decrypted++
	}

	if decrypted > 0 {
		b.logger.Info("Encrypted mempool bridge processed transactions",
			"decrypted", decrypted,
			"total", len(processed),
			"height", req.Height,
		)
	}

	return processed
}

// decryptTx decrypts a single encrypted transaction using AES-256-GCM.
// The encrypted format is: [3-byte prefix][12-byte nonce][ciphertext+tag]
func (b *EncryptedMempoolBridge) decryptTx(encryptedTx []byte) ([]byte, error) {
	b.mu.RLock()
	key := b.blockKey
	b.mu.RUnlock()

	if len(key) != 32 {
		return nil, fmt.Errorf("block key not set")
	}

	// Strip the magic prefix
	payload := encryptedTx[len(encryptedTxPrefix):]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(payload) < nonceSize {
		return nil, fmt.Errorf("encrypted payload too short: %d < %d", len(payload), nonceSize)
	}

	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
