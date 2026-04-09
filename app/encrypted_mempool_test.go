package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeBlockKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func encryptTx(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Format: prefix + nonce + ciphertext
	result := make([]byte, 0, len(encryptedTxPrefix)+len(nonce)+len(ciphertext))
	result = append(result, encryptedTxPrefix...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	return result
}

// ---------------------------------------------------------------------------
// IsEncryptedTx
// ---------------------------------------------------------------------------

func TestIsEncryptedTx_ValidPrefix(t *testing.T) {
	key := makeBlockKey(t)
	enc := encryptTx(t, key, []byte("hello-tx"))
	if !IsEncryptedTx(enc) {
		t.Fatal("expected IsEncryptedTx to return true for valid encrypted tx")
	}
}

func TestIsEncryptedTx_PlainTx(t *testing.T) {
	plain := []byte("regular-transaction-bytes")
	if IsEncryptedTx(plain) {
		t.Fatal("plain transaction should not be detected as encrypted")
	}
}

func TestIsEncryptedTx_TooShort(t *testing.T) {
	short := []byte{0xAE, 0x77}
	if IsEncryptedTx(short) {
		t.Fatal("too-short bytes should not be detected as encrypted")
	}
}

func TestIsEncryptedTx_EmptyBytes(t *testing.T) {
	if IsEncryptedTx(nil) {
		t.Fatal("nil should not be detected as encrypted")
	}
	if IsEncryptedTx([]byte{}) {
		t.Fatal("empty should not be detected as encrypted")
	}
}

// ---------------------------------------------------------------------------
// EncryptedMempoolBridge
// ---------------------------------------------------------------------------

func TestEncryptedMempoolBridge_Encrypt_Decrypt(t *testing.T) {
	key := makeBlockKey(t)
	bridge := NewEncryptedMempoolBridge(log.NewNopLogger(), DefaultEncryptedMempoolBridgeConfig())

	if err := bridge.SetBlockKey(key); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("test-transaction-payload")
	encrypted := encryptTx(t, key, plaintext)

	// Use ProcessProposalTxs to decrypt.
	ctx := sdk.Context{}.WithLogger(log.NewNopLogger())
	req := &abci.RequestPrepareProposal{
		Txs:    [][]byte{encrypted},
		Height: 100,
	}

	result := bridge.ProcessProposalTxs(ctx, req)
	if len(result) != 1 {
		t.Fatalf("expected 1 decrypted tx, got %d", len(result))
	}
	if string(result[0]) != string(plaintext) {
		t.Fatalf("decrypted tx does not match original")
	}
}

func TestEncryptedMempoolBridge_OrderPreservation(t *testing.T) {
	key := makeBlockKey(t)
	bridge := NewEncryptedMempoolBridge(log.NewNopLogger(), DefaultEncryptedMempoolBridgeConfig())
	if err := bridge.SetBlockKey(key); err != nil {
		t.Fatal(err)
	}

	tx1 := []byte("plain-tx-1")
	tx2 := encryptTx(t, key, []byte("encrypted-tx-2"))
	tx3 := []byte("plain-tx-3")
	tx4 := encryptTx(t, key, []byte("encrypted-tx-4"))

	ctx := sdk.Context{}.WithLogger(log.NewNopLogger())
	req := &abci.RequestPrepareProposal{
		Txs:    [][]byte{tx1, tx2, tx3, tx4},
		Height: 200,
	}

	result := bridge.ProcessProposalTxs(ctx, req)
	if len(result) != 4 {
		t.Fatalf("expected 4 transactions, got %d", len(result))
	}
	// Order: plain-tx-1, decrypted(encrypted-tx-2), plain-tx-3, decrypted(encrypted-tx-4)
	if string(result[0]) != "plain-tx-1" {
		t.Fatal("first tx should be plain-tx-1")
	}
	if string(result[1]) != "encrypted-tx-2" {
		t.Fatal("second tx should be decrypted encrypted-tx-2")
	}
	if string(result[2]) != "plain-tx-3" {
		t.Fatal("third tx should be plain-tx-3")
	}
	if string(result[3]) != "encrypted-tx-4" {
		t.Fatal("fourth tx should be decrypted encrypted-tx-4")
	}
}

func TestEncryptedMempoolBridge_FrontRunningPrevention(t *testing.T) {
	key := makeBlockKey(t)
	plaintext := []byte("secret-swap-transaction")
	encrypted := encryptTx(t, key, plaintext)

	// Without the key, the encrypted bytes should not reveal the plaintext.
	if string(encrypted) == string(plaintext) {
		t.Fatal("encrypted tx should not equal plaintext")
	}
	// The encrypted tx should not contain the plaintext as a substring.
	for i := range encrypted {
		if i+len(plaintext) <= len(encrypted) {
			match := true
			for j := range plaintext {
				if encrypted[i+j] != plaintext[j] {
					match = false
					break
				}
			}
			if match {
				t.Fatal("plaintext found in encrypted bytes (front-running vulnerability)")
			}
		}
	}
}

func TestEncryptedMempoolBridge_NoKeyDropsEncrypted(t *testing.T) {
	bridge := NewEncryptedMempoolBridge(log.NewNopLogger(), DefaultEncryptedMempoolBridgeConfig())
	// Do NOT set block key.

	key := makeBlockKey(t)
	enc := encryptTx(t, key, []byte("secret"))

	ctx := sdk.Context{}.WithLogger(log.NewNopLogger())
	req := &abci.RequestPrepareProposal{
		Txs:    [][]byte{[]byte("plain"), enc},
		Height: 300,
	}
	result := bridge.ProcessProposalTxs(ctx, req)
	if len(result) != 1 {
		t.Fatalf("expected 1 (plain only), got %d", len(result))
	}
	if string(result[0]) != "plain" {
		t.Fatal("expected plain tx to pass through")
	}
}

func TestEncryptedMempoolBridge_DisabledPassesAllTxs(t *testing.T) {
	cfg := DefaultEncryptedMempoolBridgeConfig()
	cfg.Enabled = false
	bridge := NewEncryptedMempoolBridge(log.NewNopLogger(), cfg)

	ctx := sdk.Context{}.WithLogger(log.NewNopLogger())
	txs := [][]byte{[]byte("tx1"), []byte("tx2")}
	req := &abci.RequestPrepareProposal{
		Txs:    txs,
		Height: 400,
	}
	result := bridge.ProcessProposalTxs(ctx, req)
	if len(result) != 2 {
		t.Fatalf("disabled bridge should pass all txs, got %d", len(result))
	}
}

func TestEncryptedMempoolBridge_SetBlockKey_InvalidLength(t *testing.T) {
	bridge := NewEncryptedMempoolBridge(log.NewNopLogger(), DefaultEncryptedMempoolBridgeConfig())

	if err := bridge.SetBlockKey([]byte("short")); err == nil {
		t.Fatal("expected error for invalid key length")
	}
	if err := bridge.SetBlockKey(make([]byte, 64)); err == nil {
		t.Fatal("expected error for 64-byte key (only 32 allowed)")
	}
}

func TestEncryptedMempoolBridge_ClearBlockKey(t *testing.T) {
	bridge := NewEncryptedMempoolBridge(log.NewNopLogger(), DefaultEncryptedMempoolBridgeConfig())
	key := makeBlockKey(t)
	if err := bridge.SetBlockKey(key); err != nil {
		t.Fatal(err)
	}
	bridge.ClearBlockKey()

	bridge.mu.RLock()
	hasKey := bridge.blockKey != nil
	bridge.mu.RUnlock()

	if hasKey {
		t.Fatal("block key should be cleared")
	}
}

func TestEncryptedMempoolBridge_OversizedDecryptedTxDropped(t *testing.T) {
	cfg := DefaultEncryptedMempoolBridgeConfig()
	cfg.MaxDecryptedTxSize = 10 // Very small limit.
	bridge := NewEncryptedMempoolBridge(log.NewNopLogger(), cfg)

	key := makeBlockKey(t)
	if err := bridge.SetBlockKey(key); err != nil {
		t.Fatal(err)
	}

	// Create a plaintext larger than the limit.
	bigPayload := make([]byte, 100)
	encrypted := encryptTx(t, key, bigPayload)

	ctx := sdk.Context{}.WithLogger(log.NewNopLogger())
	req := &abci.RequestPrepareProposal{
		Txs:    [][]byte{encrypted},
		Height: 500,
	}
	result := bridge.ProcessProposalTxs(ctx, req)
	if len(result) != 0 {
		t.Fatal("oversized decrypted tx should be dropped")
	}
}

func TestEncryptedMempoolBridge_CorruptedCiphertextDropped(t *testing.T) {
	bridge := NewEncryptedMempoolBridge(log.NewNopLogger(), DefaultEncryptedMempoolBridgeConfig())
	key := makeBlockKey(t)
	if err := bridge.SetBlockKey(key); err != nil {
		t.Fatal(err)
	}

	// Create an encrypted tx then corrupt it.
	enc := encryptTx(t, key, []byte("valid-payload"))
	// Corrupt the ciphertext portion.
	enc[len(enc)-1] ^= 0xFF

	ctx := sdk.Context{}.WithLogger(log.NewNopLogger())
	req := &abci.RequestPrepareProposal{
		Txs:    [][]byte{enc},
		Height: 600,
	}
	result := bridge.ProcessProposalTxs(ctx, req)
	if len(result) != 0 {
		t.Fatal("corrupted ciphertext should be dropped")
	}
}

func TestDefaultEncryptedMempoolBridgeConfig(t *testing.T) {
	cfg := DefaultEncryptedMempoolBridgeConfig()
	if !cfg.Enabled {
		t.Fatal("default config should be enabled")
	}
	if cfg.MaxDecryptedTxSize != 1024*1024 {
		t.Fatalf("expected 1MB max, got %d", cfg.MaxDecryptedTxSize)
	}
}
