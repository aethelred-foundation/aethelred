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

type ReceiptAttestation struct {
	Platform    string `json:"platform"`
	EnclaveID   string `json:"enclave_id"`
	Measurement string `json:"measurement"`
	Timestamp   string `json:"timestamp"`
}

type ReceiptSeal struct {
	SealID         string `json:"seal_id"`
	OutputHash     string `json:"output_hash"`
	ValidatorCount int    `json:"validator_count"`
	BlockHeight    int64  `json:"block_height"`
}

type ReceiptAuditTrail struct {
	RecordCount int    `json:"record_count"`
	FirstHash   string `json:"first_hash"`
	LastHash    string `json:"last_hash"`
	ChainIntact bool   `json:"chain_intact"`
}

type ReceiptComplianceMetadata struct {
	Frameworks    []string `json:"frameworks"`
	ControlsMet   int      `json:"controls_met"`
	ControlsTotal int      `json:"controls_total"`
}

type ReceiptVerification struct {
	HasTEEAttestation bool   `json:"has_tee_attestation"`
	HasZKProof        bool   `json:"has_zk_proof"`
	VerifiedAt        string `json:"verified_at"`
}

// ExecutionReceipt is a compact, self-verifying evidence summary for a job.
type ExecutionReceipt struct {
	ID             string                     `json:"receipt_id"`
	JobID          string                     `json:"job_id"`
	Attestation    *ReceiptAttestation        `json:"attestation,omitempty"`
	Seal           *ReceiptSeal               `json:"seal,omitempty"`
	AuditTrail     *ReceiptAuditTrail         `json:"audit_trail,omitempty"`
	Compliance     *ReceiptComplianceMetadata `json:"compliance,omitempty"`
	Verification   *ReceiptVerification       `json:"verification,omitempty"`
	AssuranceLevel AssuranceLevel             `json:"assurance_level"`
	Timestamp      string                     `json:"timestamp"`
	ContentHash    string                     `json:"content_hash"`
	Signature      string                     `json:"signature,omitempty"`
}

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

	data, err := json.Marshal(hashable{
		ID:             r.ID,
		JobID:          r.JobID,
		Attestation:    r.Attestation,
		Seal:           r.Seal,
		AuditTrail:     r.AuditTrail,
		Compliance:     r.Compliance,
		Verification:   r.Verification,
		AssuranceLevel: r.AssuranceLevel,
		Timestamp:      r.Timestamp,
	})
	if err != nil {
		return "", fmt.Errorf("assurance/receipt: failed to marshal for hashing: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (r *ExecutionReceipt) Validate() error {
	if r == nil {
		return fmt.Errorf("assurance/receipt: %w: receipt is required", ErrInvalidInput)
	}
	if r.ID == "" {
		return fmt.Errorf("assurance/receipt: %w: ID is required", ErrInvalidInput)
	}
	if r.JobID == "" {
		return fmt.Errorf("assurance/receipt: %w: job ID is required", ErrInvalidInput)
	}
	if r.Timestamp == "" {
		return fmt.Errorf("assurance/receipt: %w: timestamp is required", ErrInvalidInput)
	}
	if r.ContentHash == "" {
		return fmt.Errorf("assurance/receipt: %w: content hash is required", ErrInvalidInput)
	}
	return nil
}

type ReceiptBuilder struct {
	receipt ExecutionReceipt
}

func NewReceiptBuilder(jobID string) *ReceiptBuilder {
	return &ReceiptBuilder{
		receipt: ExecutionReceipt{
			ID:        uuid.New().String(),
			JobID:     jobID,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		},
	}
}

func (rb *ReceiptBuilder) WithAttestation(attestation *ReceiptAttestation) *ReceiptBuilder {
	rb.receipt.Attestation = attestation
	return rb
}

func (rb *ReceiptBuilder) WithSeal(seal *ReceiptSeal) *ReceiptBuilder {
	rb.receipt.Seal = seal
	return rb
}

func (rb *ReceiptBuilder) WithAuditTrail(auditTrail *ReceiptAuditTrail) *ReceiptBuilder {
	rb.receipt.AuditTrail = auditTrail
	return rb
}

func (rb *ReceiptBuilder) WithCompliance(compliance *ReceiptComplianceMetadata) *ReceiptBuilder {
	rb.receipt.Compliance = compliance
	return rb
}

func (rb *ReceiptBuilder) WithVerification(verification *ReceiptVerification) *ReceiptBuilder {
	rb.receipt.Verification = verification
	return rb
}

func (rb *ReceiptBuilder) WithAssuranceLevel(level AssuranceLevel) *ReceiptBuilder {
	rb.receipt.AssuranceLevel = level
	return rb
}

func (rb *ReceiptBuilder) Build() (*ExecutionReceipt, error) {
	if rb == nil || rb.receipt.JobID == "" {
		return nil, fmt.Errorf("assurance/receipt: %w: job ID is required", ErrInvalidInput)
	}
	hash, err := rb.receipt.computeContentHash()
	if err != nil {
		return nil, err
	}
	rb.receipt.ContentHash = hash
	result := rb.receipt
	return &result, nil
}

func (af *AssuranceFabric) CreateReceipt(ctx context.Context, jobID string) (*ExecutionReceipt, error) {
	evidence, err := af.CollectEvidence(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("assurance/receipt: failed to collect evidence: %w", err)
	}

	builder := NewReceiptBuilder(jobID).WithAssuranceLevel(evidence.AssuranceLevel)
	if evidence.Audit != nil {
		builder.WithAuditTrail(&ReceiptAuditTrail{
			RecordCount: evidence.Audit.RecordCount,
			ChainIntact: evidence.Audit.ChainIntact,
		})
	}
	if len(evidence.Seals) > 0 {
		seal := evidence.Seals[0]
		builder.WithSeal(&ReceiptSeal{
			SealID:         seal.SealID,
			OutputHash:     seal.OutputHash,
			ValidatorCount: seal.ValidatorCount,
			BlockHeight:    seal.BlockHeight,
		})
	}
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
	if evidence.Compliance != nil {
		builder.WithCompliance(&ReceiptComplianceMetadata{
			Frameworks:    evidence.Compliance.Frameworks,
			ControlsMet:   evidence.Compliance.ControlsMet,
			ControlsTotal: evidence.Compliance.ControlsTotal,
		})
	}
	return builder.Build()
}

func VerifyReceipt(receipt *ExecutionReceipt) error {
	if err := receipt.Validate(); err != nil {
		return err
	}
	computed, err := receipt.computeContentHash()
	if err != nil {
		return fmt.Errorf("assurance/receipt: failed to recompute content hash: %w", err)
	}
	if computed != receipt.ContentHash {
		return fmt.Errorf("assurance/receipt: %w: expected %s, computed %s", ErrVerificationFailed, receipt.ContentHash, computed)
	}
	return nil
}
