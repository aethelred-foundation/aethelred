package policy

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

// PolicyReceiptApprovalRequirement is the receipt-safe representation of an
// approval requirement. It uses string fields so exported receipts are both
// stable and readable outside Go code.
type PolicyReceiptApprovalRequirement struct {
	Type     string   `json:"type"`
	MinCount int      `json:"min_count"`
	Roles    []string `json:"roles,omitempty"`
	Deadline string   `json:"deadline,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

// SignedPolicyReceipt is a cryptographically signed policy decision artifact.
// It captures the evaluated request, the resulting decision, and the audit hash
// produced by the policy engine so that downstream systems can verify policy
// authorization independently of the engine process.
type SignedPolicyReceipt struct {
	ID string `json:"id"`

	RequestID string `json:"request_id"`

	Actor    string            `json:"actor"`
	Action   string            `json:"action"`
	Resource string            `json:"resource"`
	Context  map[string]string `json:"context,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`

	Decision          string                             `json:"decision"`
	MatchedRules      []string                           `json:"matched_rules,omitempty"`
	RequiredApprovals []PolicyReceiptApprovalRequirement `json:"required_approvals,omitempty"`
	Conditions        []string                           `json:"conditions,omitempty"`
	AuditTrail        string                             `json:"audit_trail"`
	EvaluatedAt       time.Time                          `json:"evaluated_at"`

	Signer              string `json:"signer"`
	PreviousReceiptHash string `json:"previous_receipt_hash,omitempty"`
	ContentHash         string `json:"content_hash"`
	Signature           string `json:"signature"`
}

// PolicyReceiptChain links policy receipts in order for multi-step regulated
// workflows. The chain hash gives a compact verifier-friendly integrity check.
type PolicyReceiptChain struct {
	ID        string                 `json:"id"`
	Receipts  []*SignedPolicyReceipt `json:"receipts"`
	ChainHash string                 `json:"chain_hash"`
	CreatedAt time.Time              `json:"created_at"`
}

// CreateSignedPolicyReceipt builds and signs a policy receipt for a completed
// policy evaluation.
func CreateSignedPolicyReceipt(_ context.Context, signerKey *ecdsa.PrivateKey, signer string, req *EvaluationRequest, result *EvaluationResult, previousReceiptHash string) (*SignedPolicyReceipt, error) {
	if signerKey == nil {
		return nil, fmt.Errorf("CreateSignedPolicyReceipt: %w: signer key is required", ErrInvalidInput)
	}
	if signer == "" {
		return nil, fmt.Errorf("CreateSignedPolicyReceipt: %w: signer is required", ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("CreateSignedPolicyReceipt: %w: evaluation request cannot be nil", ErrInvalidInput)
	}
	if result == nil {
		return nil, fmt.Errorf("CreateSignedPolicyReceipt: %w: evaluation result cannot be nil", ErrInvalidInput)
	}

	receipt := &SignedPolicyReceipt{
		ID:                  uuid.New().String(),
		RequestID:           result.RequestID,
		Actor:               req.Actor,
		Action:              req.Action,
		Resource:            req.Resource,
		Context:             cloneStringMap(req.Context),
		Metadata:            cloneStringMap(req.Metadata),
		Decision:            result.Decision.String(),
		MatchedRules:        cloneStringSlice(result.MatchedRules),
		RequiredApprovals:   makeReceiptApprovals(result.RequiredApprovals),
		Conditions:          cloneStringSlice(result.Conditions),
		AuditTrail:          result.AuditTrail,
		EvaluatedAt:         result.EvaluatedAt.UTC(),
		Signer:              signer,
		PreviousReceiptHash: previousReceiptHash,
	}

	receipt.ContentHash = computeSignedPolicyReceiptHash(receipt)

	hashBytes, err := hex.DecodeString(receipt.ContentHash)
	if err != nil {
		return nil, fmt.Errorf("CreateSignedPolicyReceipt: invalid content hash: %w", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, signerKey, hashBytes)
	if err != nil {
		return nil, fmt.Errorf("CreateSignedPolicyReceipt: signing receipt: %w", err)
	}

	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	receipt.Signature = hex.EncodeToString(sigBytes)

	return receipt, nil
}

// VerifySignedPolicyReceipt verifies both the content integrity and the ECDSA
// signature of a signed policy receipt.
func VerifySignedPolicyReceipt(receipt *SignedPolicyReceipt, signerPubKey *ecdsa.PublicKey) error {
	if receipt == nil {
		return fmt.Errorf("VerifySignedPolicyReceipt: %w: receipt cannot be nil", ErrInvalidInput)
	}
	if signerPubKey == nil {
		return fmt.Errorf("VerifySignedPolicyReceipt: %w: signer public key is required", ErrInvalidInput)
	}

	expectedHash := computeSignedPolicyReceiptHash(receipt)
	if receipt.ContentHash != expectedHash {
		return fmt.Errorf("VerifySignedPolicyReceipt: receipt content hash mismatch")
	}

	hashBytes, err := hex.DecodeString(receipt.ContentHash)
	if err != nil {
		return fmt.Errorf("VerifySignedPolicyReceipt: invalid content hash: %w", err)
	}

	sigBytes, err := hex.DecodeString(receipt.Signature)
	if err != nil {
		return fmt.Errorf("VerifySignedPolicyReceipt: invalid signature encoding: %w", err)
	}
	if len(sigBytes) != 64 {
		return fmt.Errorf("VerifySignedPolicyReceipt: invalid signature length: expected 64, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	if !ecdsa.Verify(signerPubKey, hashBytes, r, s) {
		return fmt.Errorf("VerifySignedPolicyReceipt: signature verification failed")
	}

	return nil
}

// EvaluateAndSign evaluates a request and immediately materializes the decision
// as a signed policy receipt that can be verified outside the engine process.
func (e *PolicyEngine) EvaluateAndSign(ctx context.Context, req *EvaluationRequest, signerKey *ecdsa.PrivateKey, signer string, previousReceiptHash string) (*EvaluationResult, *SignedPolicyReceipt, error) {
	result, err := e.Evaluate(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	receipt, err := CreateSignedPolicyReceipt(ctx, signerKey, signer, req, result, previousReceiptHash)
	if err != nil {
		return nil, nil, err
	}

	return result, receipt, nil
}

// BuildPolicyReceiptChain creates a chain hash over ordered policy receipts.
func BuildPolicyReceiptChain(_ context.Context, receipts []*SignedPolicyReceipt) (*PolicyReceiptChain, error) {
	if len(receipts) == 0 {
		return nil, fmt.Errorf("BuildPolicyReceiptChain: %w: at least one receipt is required", ErrInvalidInput)
	}

	h := sha256.New()
	for i, receipt := range receipts {
		if receipt == nil {
			return nil, fmt.Errorf("BuildPolicyReceiptChain: %w: receipt %d is nil", ErrInvalidInput, i)
		}
		if receipt.ContentHash != computeSignedPolicyReceiptHash(receipt) {
			return nil, fmt.Errorf("BuildPolicyReceiptChain: receipt %q has invalid content hash", receipt.ID)
		}
		h.Write([]byte(receipt.ContentHash))
	}

	return &PolicyReceiptChain{
		ID:        uuid.New().String(),
		Receipts:  receipts,
		ChainHash: hex.EncodeToString(h.Sum(nil)),
		CreatedAt: time.Now().UTC(),
	}, nil
}

// VerifyPolicyReceiptChain verifies integrity across all receipts in a chain.
func VerifyPolicyReceiptChain(chain *PolicyReceiptChain) error {
	if chain == nil {
		return fmt.Errorf("VerifyPolicyReceiptChain: %w: chain cannot be nil", ErrInvalidInput)
	}
	if len(chain.Receipts) == 0 {
		return fmt.Errorf("VerifyPolicyReceiptChain: %w: chain has no receipts", ErrInvalidInput)
	}

	h := sha256.New()
	for _, receipt := range chain.Receipts {
		if receipt == nil {
			return fmt.Errorf("VerifyPolicyReceiptChain: %w: receipt cannot be nil", ErrInvalidInput)
		}
		expectedHash := computeSignedPolicyReceiptHash(receipt)
		if receipt.ContentHash != expectedHash {
			return fmt.Errorf("VerifyPolicyReceiptChain: receipt %q has invalid content hash", receipt.ID)
		}
		h.Write([]byte(receipt.ContentHash))
	}

	expectedChainHash := hex.EncodeToString(h.Sum(nil))
	if chain.ChainHash != expectedChainHash {
		return fmt.Errorf("VerifyPolicyReceiptChain: chain hash mismatch")
	}

	return nil
}

func computeSignedPolicyReceiptHash(receipt *SignedPolicyReceipt) string {
	data, _ := json.Marshal(struct {
		ID                  string                             `json:"id"`
		RequestID           string                             `json:"request_id"`
		Actor               string                             `json:"actor"`
		Action              string                             `json:"action"`
		Resource            string                             `json:"resource"`
		Context             map[string]string                  `json:"context,omitempty"`
		Metadata            map[string]string                  `json:"metadata,omitempty"`
		Decision            string                             `json:"decision"`
		MatchedRules        []string                           `json:"matched_rules,omitempty"`
		RequiredApprovals   []PolicyReceiptApprovalRequirement `json:"required_approvals,omitempty"`
		Conditions          []string                           `json:"conditions,omitempty"`
		AuditTrail          string                             `json:"audit_trail"`
		EvaluatedAt         string                             `json:"evaluated_at"`
		Signer              string                             `json:"signer"`
		PreviousReceiptHash string                             `json:"previous_receipt_hash,omitempty"`
	}{
		ID:                  receipt.ID,
		RequestID:           receipt.RequestID,
		Actor:               receipt.Actor,
		Action:              receipt.Action,
		Resource:            receipt.Resource,
		Context:             receipt.Context,
		Metadata:            receipt.Metadata,
		Decision:            receipt.Decision,
		MatchedRules:        receipt.MatchedRules,
		RequiredApprovals:   receipt.RequiredApprovals,
		Conditions:          receipt.Conditions,
		AuditTrail:          receipt.AuditTrail,
		EvaluatedAt:         receipt.EvaluatedAt.Format(time.RFC3339Nano),
		Signer:              receipt.Signer,
		PreviousReceiptHash: receipt.PreviousReceiptHash,
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func makeReceiptApprovals(requirements []ApprovalRequirement) []PolicyReceiptApprovalRequirement {
	if len(requirements) == 0 {
		return nil
	}

	out := make([]PolicyReceiptApprovalRequirement, 0, len(requirements))
	for _, req := range requirements {
		out = append(out, PolicyReceiptApprovalRequirement{
			Type:     req.Type.String(),
			MinCount: req.MinCount,
			Roles:    cloneStringSlice(req.Roles),
			Deadline: req.Deadline.String(),
			Reason:   req.Reason,
		})
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
