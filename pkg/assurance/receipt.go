package assurance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Execution Receipt
// ---------------------------------------------------------------------------
//
// An execution receipt is a cryptographically-bound document that
// aggregates all trust evidence produced during a computation job.
// Receipts are the primary artifact exchanged with regulators, auditors,
// and counterparties as proof of verified execution.
//
// Design:
//   - Immutable once created (content hash covers all fields)
//   - Self-contained: includes all evidence needed for offline verification
//   - Builder pattern for incremental construction
// ---------------------------------------------------------------------------

// ReceiptAttestation captures TEE attestation data within a receipt.
type ReceiptAttestation struct {
	Platform    string `json:"platform"`
	EnclaveID   string `json:"enclave_id"`
	Measurement string `json:"measurement"`
	Timestamp   string `json:"timestamp"`
}

// ReceiptSeal captures a verification seal within a receipt.
type ReceiptSeal struct {
	SealID         string `json:"seal_id"`
	OutputHash     string `json:"output_hash"`
	ValidatorCount int    `json:"validator_count"`
	BlockHeight    int64  `json:"block_height"`
}

// ReceiptAuditTrail captures audit trail metadata within a receipt.
type ReceiptAuditTrail struct {
	RecordCount int    `json:"record_count"`
	FirstHash   string `json:"first_hash"`
	LastHash    string `json:"last_hash"`
	ChainIntact bool   `json:"chain_intact"`
}

// ReceiptComplianceMetadata captures compliance context within a receipt.
type ReceiptComplianceMetadata struct {
	Frameworks    []string `json:"frameworks"`
	ControlsMet   int      `json:"controls_met"`
	ControlsTotal int      `json:"controls_total"`
}

// ReceiptVerification captures verification status within a receipt.
type ReceiptVerification struct {
	HasTEEAttestation bool   `json:"has_tee_attestation"`
	HasZKProof        bool   `json:"has_zk_proof"`
	VerifiedAt        string `json:"verified_at"`
}

// ExecutionReceipt is a cryptographically-bound aggregate of all trust
// evidence for a computation job.
type ExecutionReceipt struct {
	// Identity
	ID    string `json:"receipt_id"`
	JobID string `json:"job_id"`

	// Evidence components
	Attestation *ReceiptAttestation        `json:"attestation,omitempty"`
	Seal        *ReceiptSeal               `json:"seal,omitempty"`
	AuditTrail  *ReceiptAuditTrail         `json:"audit_trail,omitempty"`
	Compliance  *ReceiptComplianceMetadata `json:"compliance,omitempty"`
	Verification *ReceiptVerification      `json:"verification,omitempty"`

	// Assurance
	AssuranceLevel AssuranceLevel `json:"assurance_level"`

	// Integrity
	Timestamp   string `json:"timestamp"`
	ContentHash string `json:"content_hash"`
	Signature   string `json:"signature,omitempty"`
}

// computeContentHash computes the SHA-256 hash of the receipt's content,
// excluding the content hash and signature fields.
func (r *ExecutionReceipt) computeContentHash() (string, error) {
	type hashable struct {
		ID             string                     `json:"receipt_id"`
		JobID          string                     `json:"job_id"`
		Attestation    *ReceiptAttestation        `json:"attestation"`
		Seal           *ReceiptSeal               `json:"seal"`
		AuditTrail     *ReceiptAuditTrail         `json:"audit_trail"`
		Compliance     *ReceiptComplianceMetadata `json:"compliance"`
		Verification   *ReceiptVerification       `json:"verification"`
		AssuranceLevel AssuranceLevel             `json:"assurance_level"`
		Timestamp      string                     `json:"timestamp"`
	}
	h := hashable{
		ID:             r.ID,
		JobID:          r.JobID,
		Attestation:    r.Attestation,
		Seal:           r.Seal,
		AuditTrail:     r.AuditTrail,
		Compliance:     r.Compliance,
		Verification:   r.Verification,
		AssuranceLevel: r.AssuranceLevel,
		Timestamp:      r.Timestamp,
	}
	data, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("assurance/receipt: failed to marshal for hashing: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Validate checks receipt integrity.
func (r *ExecutionReceipt) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("assurance/receipt: ID is required")
	}
	if r.JobID == "" {
		return fmt.Errorf("assurance/receipt: job ID is required")
	}
	if r.Timestamp == "" {
		return fmt.Errorf("assurance/receipt: timestamp is required")
	}
	if r.ContentHash == "" {
		return fmt.Errorf("assurance/receipt: content hash is required")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Receipt Builder
// ---------------------------------------------------------------------------

// ReceiptBuilder constructs execution receipts incrementally.
type ReceiptBuilder struct {
	receipt ExecutionReceipt
}

// NewReceiptBuilder creates a new builder for the given job ID.
func NewReceiptBuilder(jobID string) *ReceiptBuilder {
	return &ReceiptBuilder{
		receipt: ExecutionReceipt{
			ID:        uuid.New().String(),
			JobID:     jobID,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		},
	}
}

// WithAttestation sets the TEE attestation evidence.
func (rb *ReceiptBuilder) WithAttestation(a *ReceiptAttestation) *ReceiptBuilder {
	rb.receipt.Attestation = a
	return rb
}

// WithSeal sets the verification seal evidence.
func (rb *ReceiptBuilder) WithSeal(s *ReceiptSeal) *ReceiptBuilder {
	rb.receipt.Seal = s
	return rb
}

// WithAuditTrail sets the audit trail metadata.
func (rb *ReceiptBuilder) WithAuditTrail(at *ReceiptAuditTrail) *ReceiptBuilder {
	rb.receipt.AuditTrail = at
	return rb
}

// WithCompliance sets the compliance metadata.
func (rb *ReceiptBuilder) WithCompliance(c *ReceiptComplianceMetadata) *ReceiptBuilder {
	rb.receipt.Compliance = c
	return rb
}

// WithVerification sets the verification status.
func (rb *ReceiptBuilder) WithVerification(v *ReceiptVerification) *ReceiptBuilder {
	rb.receipt.Verification = v
	return rb
}

// WithAssuranceLevel sets the assurance level explicitly.
func (rb *ReceiptBuilder) WithAssuranceLevel(level AssuranceLevel) *ReceiptBuilder {
	rb.receipt.AssuranceLevel = level
	return rb
}

// Build finalizes the receipt, computing its content hash.
func (rb *ReceiptBuilder) Build() (*ExecutionReceipt, error) {
	if rb.receipt.JobID == "" {
		return nil, fmt.Errorf("assurance/receipt: job ID is required")
	}

	hash, err := rb.receipt.computeContentHash()
	if err != nil {
		return nil, err
	}
	rb.receipt.ContentHash = hash

	result := rb.receipt
	return &result, nil
}

// ---------------------------------------------------------------------------
// Receipt creation from fabric
// ---------------------------------------------------------------------------

// CreateReceipt creates a complete execution receipt by collecting evidence
// through the fabric and packaging it into a receipt.
func (af *AssuranceFabric) CreateReceipt(ctx context.Context, jobID string) (*ExecutionReceipt, error) {
	evidence, err := af.CollectEvidence(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("assurance/receipt: failed to collect evidence: %w", err)
	}

	builder := NewReceiptBuilder(jobID).
		WithAssuranceLevel(evidence.AssuranceLevel)

	// Map audit evidence.
	if evidence.Audit != nil {
		builder.WithAuditTrail(&ReceiptAuditTrail{
			RecordCount: evidence.Audit.RecordCount,
			ChainIntact: evidence.Audit.ChainIntact,
		})
	}

	// Map seal evidence (use first seal if available).
	if len(evidence.Seals) > 0 {
		s := evidence.Seals[0]
		builder.WithSeal(&ReceiptSeal{
			SealID:         s.SealID,
			OutputHash:     s.OutputHash,
			ValidatorCount: s.ValidatorCount,
			BlockHeight:    s.BlockHeight,
		})
	}

	// Map verification evidence.
	if evidence.Verification != nil {
		builder.WithVerification(&ReceiptVerification{
			HasTEEAttestation: evidence.Verification.HasTEEAttestation,
			HasZKProof:        evidence.Verification.HasZKProof,
			VerifiedAt:        evidence.Verification.VerifiedAt.UTC().Format(time.RFC3339),
		})

		if evidence.Verification.HasTEEAttestation {
			builder.WithAttestation(&ReceiptAttestation{
				Platform:  evidence.Verification.AttestationType,
				Timestamp: evidence.Verification.VerifiedAt.UTC().Format(time.RFC3339),
			})
		}
	}

	// Map compliance evidence.
	if evidence.Compliance != nil {
		builder.WithCompliance(&ReceiptComplianceMetadata{
			Frameworks:    evidence.Compliance.Frameworks,
			ControlsMet:   evidence.Compliance.ControlsMet,
			ControlsTotal: evidence.Compliance.ControlsTotal,
		})
	}

	return builder.Build()
}

// VerifyReceipt verifies the integrity of an execution receipt by
// recomputing its content hash and comparing.
func VerifyReceipt(receipt *ExecutionReceipt) error {
	if receipt == nil {
		return fmt.Errorf("assurance/receipt: nil receipt")
	}

	if err := receipt.Validate(); err != nil {
		return err
	}

	computed, err := receipt.computeContentHash()
	if err != nil {
		return fmt.Errorf("assurance/receipt: failed to recompute content hash: %w", err)
	}

	if computed != receipt.ContentHash {
		return fmt.Errorf("assurance/receipt: content hash mismatch: expected %s, computed %s",
			receipt.ContentHash, computed)
	}

	return nil
}
