package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// ActionReceipt
// ---------------------------------------------------------------------------

// ActionReceipt is a machine-verifiable record of an action taken by an agent.
// Receipts are cryptographically signed and can be anchored to the Aethelred
// blockchain via Digital Seals.
type ActionReceipt struct {
	// ID is the unique receipt identifier.
	ID string `json:"id"`

	// Actor is the DID of the agent that performed the action.
	Actor string `json:"actor"`

	// Action is the operation that was performed.
	Action string `json:"action"`

	// Resource is the target of the action.
	Resource string `json:"resource"`

	// Result is the outcome ("success", "failure", etc.).
	Result string `json:"result"`

	// Timestamp is when the action occurred.
	Timestamp time.Time `json:"timestamp"`

	// DelegationID is the delegation that authorized this action (empty if direct).
	DelegationID string `json:"delegation_id,omitempty"`

	// Evidence holds arbitrary key-value evidence data.
	Evidence map[string]string `json:"evidence,omitempty"`

	// Signature is the hex-encoded ECDSA signature over the receipt hash.
	Signature string `json:"signature"`

	// SealID is the on-chain seal ID (populated after sealing).
	SealID string `json:"seal_id,omitempty"`

	// ContentHash is the SHA-256 hash of the receipt content.
	ContentHash string `json:"content_hash"`
}

// ---------------------------------------------------------------------------
// Receipt operations
// ---------------------------------------------------------------------------

// CreateReceipt creates a signed action receipt.
func CreateReceipt(_ context.Context, actorKey *ecdsa.PrivateKey, actor, action, resource, result string, delegationID string, evidence map[string]string) (*ActionReceipt, error) {
	if actorKey == nil {
		return nil, fmt.Errorf("actor key is required to sign receipts")
	}
	if actor == "" || action == "" {
		return nil, fmt.Errorf("actor and action are required")
	}

	receipt := &ActionReceipt{
		ID:           uuid.New().String(),
		Actor:        actor,
		Action:       action,
		Resource:     resource,
		Result:       result,
		Timestamp:    time.Now().UTC(),
		DelegationID: delegationID,
		Evidence:     evidence,
	}

	// Compute content hash.
	receipt.ContentHash = computeReceiptHash(receipt)

	// Sign the receipt.
	hashBytes, err := hex.DecodeString(receipt.ContentHash)
	if err != nil {
		return nil, fmt.Errorf("invalid content hash: %w", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, actorKey, hashBytes)
	if err != nil {
		return nil, fmt.Errorf("signing receipt: %w", err)
	}

	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	receipt.Signature = hex.EncodeToString(sigBytes)

	return receipt, nil
}

// VerifyReceipt verifies a receipt's signature and content integrity.
func VerifyReceipt(receipt *ActionReceipt, actorPubKey *ecdsa.PublicKey) error {
	if receipt == nil {
		return fmt.Errorf("receipt cannot be nil")
	}
	if actorPubKey == nil {
		return fmt.Errorf("actor public key is required for verification")
	}

	// Verify content hash.
	expectedHash := computeReceiptHash(receipt)
	if receipt.ContentHash != expectedHash {
		return fmt.Errorf("receipt content hash mismatch")
	}

	// Verify signature.
	hashBytes, err := hex.DecodeString(receipt.ContentHash)
	if err != nil {
		return fmt.Errorf("invalid content hash: %w", err)
	}

	sigBytes, err := hex.DecodeString(receipt.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid signature length: expected 64, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(actorPubKey, hashBytes, r, s) {
		return fmt.Errorf("receipt signature verification failed")
	}

	return nil
}

// SealReceipt anchors a receipt by assigning a seal ID. In production this
// would submit to the Aethelred blockchain; here we generate a deterministic
// seal ID from the receipt hash.
func SealReceipt(_ context.Context, receipt *ActionReceipt) error {
	if receipt == nil {
		return fmt.Errorf("receipt cannot be nil")
	}
	if receipt.ContentHash == "" {
		return fmt.Errorf("receipt has no content hash")
	}

	// Generate a seal ID from the receipt hash.
	h := sha256.Sum256([]byte("seal:" + receipt.ContentHash))
	receipt.SealID = "seal_" + hex.EncodeToString(h[:8])

	return nil
}

// ---------------------------------------------------------------------------
// ReceiptChain
// ---------------------------------------------------------------------------

// ReceiptChain links multiple receipts in order for multi-step operations.
type ReceiptChain struct {
	// ID is the chain identifier.
	ID string `json:"id"`

	// Receipts are the ordered receipts in this chain.
	Receipts []*ActionReceipt `json:"receipts"`

	// ChainHash is the hash of all receipt hashes in order.
	ChainHash string `json:"chain_hash"`

	// CreatedAt is when the chain was constructed.
	CreatedAt time.Time `json:"created_at"`
}

// BuildReceiptChain builds an ordered receipt chain from a slice of receipts.
func BuildReceiptChain(_ context.Context, receipts []*ActionReceipt) (*ReceiptChain, error) {
	if len(receipts) == 0 {
		return nil, fmt.Errorf("at least one receipt is required")
	}

	chain := &ReceiptChain{
		ID:        uuid.New().String(),
		Receipts:  receipts,
		CreatedAt: time.Now().UTC(),
	}

	// Compute chain hash from all receipt hashes.
	h := sha256.New()
	for _, r := range receipts {
		h.Write([]byte(r.ContentHash))
	}
	chain.ChainHash = hex.EncodeToString(h.Sum(nil))

	return chain, nil
}

// VerifyReceiptChain verifies the integrity of a receipt chain.
func VerifyReceiptChain(chain *ReceiptChain) error {
	if chain == nil {
		return fmt.Errorf("receipt chain cannot be nil")
	}
	if len(chain.Receipts) == 0 {
		return fmt.Errorf("receipt chain has no receipts")
	}

	h := sha256.New()
	for _, r := range chain.Receipts {
		expectedHash := computeReceiptHash(r)
		if r.ContentHash != expectedHash {
			return fmt.Errorf("receipt %q has invalid content hash", r.ID)
		}
		h.Write([]byte(r.ContentHash))
	}

	expectedChainHash := hex.EncodeToString(h.Sum(nil))
	if chain.ChainHash != expectedChainHash {
		return fmt.Errorf("receipt chain hash mismatch")
	}

	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func computeReceiptHash(r *ActionReceipt) string {
	data, _ := json.Marshal(struct {
		ID           string            `json:"id"`
		Actor        string            `json:"actor"`
		Action       string            `json:"action"`
		Resource     string            `json:"resource"`
		Result       string            `json:"result"`
		Timestamp    string            `json:"timestamp"`
		DelegationID string            `json:"delegation_id"`
		Evidence     map[string]string `json:"evidence"`
	}{
		ID:           r.ID,
		Actor:        r.Actor,
		Action:       r.Action,
		Resource:     r.Resource,
		Result:       r.Result,
		Timestamp:    r.Timestamp.Format(time.RFC3339Nano),
		DelegationID: r.DelegationID,
		Evidence:     r.Evidence,
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
