// Package assurance provides an assurance fabric that aggregates audit,
// seal, verification, and compliance evidence into one execution-trust view.
package assurance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AssuranceLevel quantifies the degree of trust assurance for one job.
type AssuranceLevel int

const (
	AssuranceLevelNone AssuranceLevel = iota
	AssuranceLevelBasic
	AssuranceLevelStandard
	AssuranceLevelHigh
	AssuranceLevelCritical
)

func (a AssuranceLevel) String() string {
	switch a {
	case AssuranceLevelNone:
		return "None"
	case AssuranceLevelBasic:
		return "Basic"
	case AssuranceLevelStandard:
		return "Standard"
	case AssuranceLevelHigh:
		return "High"
	case AssuranceLevelCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

func (a AssuranceLevel) Score() int {
	switch a {
	case AssuranceLevelNone:
		return 0
	case AssuranceLevelBasic:
		return 25
	case AssuranceLevelStandard:
		return 50
	case AssuranceLevelHigh:
		return 75
	case AssuranceLevelCritical:
		return 100
	default:
		return 0
	}
}

// SealEvidence represents verifiable seal evidence collected for a job.
type SealEvidence struct {
	SealID         string    `json:"seal_id"`
	JobID          string    `json:"job_id"`
	OutputHash     string    `json:"output_hash"`
	ValidatorCount int       `json:"validator_count"`
	BlockHeight    int64     `json:"block_height"`
	Timestamp      time.Time `json:"timestamp"`
	Status         string    `json:"status"`
}

// AuditEvidence summarizes audit-chain coverage for a job.
type AuditEvidence struct {
	RecordCount  int       `json:"record_count"`
	ChainIntact  bool      `json:"chain_intact"`
	FirstRecord  time.Time `json:"first_record"`
	LastRecord   time.Time `json:"last_record"`
	CoverageGaps []string  `json:"coverage_gaps,omitempty"`
}

// VerificationEvidence captures verification posture for a job.
type VerificationEvidence struct {
	HasTEEAttestation bool      `json:"has_tee_attestation"`
	HasZKProof        bool      `json:"has_zk_proof"`
	AttestationType   string    `json:"attestation_type,omitempty"`
	ProofSystem       string    `json:"proof_system,omitempty"`
	VerifiedAt        time.Time `json:"verified_at"`
}

// ComplianceEvidence captures control coverage posture for a job.
type ComplianceEvidence struct {
	Frameworks    []string `json:"frameworks"`
	ControlsMet   int      `json:"controls_met"`
	ControlsTotal int      `json:"controls_total"`
	CoverageScore float64  `json:"coverage_score"`
}

type SealProvider interface {
	GetSealEvidence(ctx context.Context, jobID string) ([]SealEvidence, error)
}

type AuditProvider interface {
	GetAuditEvidence(ctx context.Context, jobID string) (*AuditEvidence, error)
}

type VerificationProvider interface {
	GetVerificationEvidence(ctx context.Context, jobID string) (*VerificationEvidence, error)
}

type ComplianceProvider interface {
	GetComplianceEvidence(ctx context.Context, jobID string) (*ComplianceEvidence, error)
}

// FabricConfig wires the evidence providers used by the fabric.
type FabricConfig struct {
	SealProvider         SealProvider
	AuditProvider        AuditProvider
	VerificationProvider VerificationProvider
	ComplianceProvider   ComplianceProvider
}

func (c *FabricConfig) Validate() error {
	if c == nil || c.AuditProvider == nil {
		return fmt.Errorf("FabricConfig.Validate: %w: audit provider is required", ErrInvalidInput)
	}
	return nil
}

// TrustEvidence is the aggregate evidence package for one job.
type TrustEvidence struct {
	JobID          string                `json:"job_id"`
	CollectedAt    time.Time             `json:"collected_at"`
	Seals          []SealEvidence        `json:"seals,omitempty"`
	Audit          *AuditEvidence        `json:"audit,omitempty"`
	Verification   *VerificationEvidence `json:"verification,omitempty"`
	Compliance     *ComplianceEvidence   `json:"compliance,omitempty"`
	AssuranceLevel AssuranceLevel        `json:"assurance_level"`
	ContentHash    string                `json:"content_hash"`
}

func (te *TrustEvidence) computeHash() error {
	type hashable struct {
		JobID        string                `json:"job_id"`
		CollectedAt  string                `json:"collected_at"`
		Seals        []SealEvidence        `json:"seals"`
		Audit        *AuditEvidence        `json:"audit"`
		Verification *VerificationEvidence `json:"verification"`
		Compliance   *ComplianceEvidence   `json:"compliance"`
	}

	data, err := json.Marshal(hashable{
		JobID:        te.JobID,
		CollectedAt:  te.CollectedAt.UTC().Format(time.RFC3339Nano),
		Seals:        te.Seals,
		Audit:        te.Audit,
		Verification: te.Verification,
		Compliance:   te.Compliance,
	})
	if err != nil {
		return fmt.Errorf("assurance: failed to marshal evidence for hashing: %w", err)
	}
	sum := sha256.Sum256(data)
	te.ContentHash = hex.EncodeToString(sum[:])
	return nil
}

// AssuranceFabric orchestrates trust evidence collection and caching.
type AssuranceFabric struct {
	config FabricConfig
	mu     sync.RWMutex
	cache  map[string]*TrustEvidence
}

func NewAssuranceFabric(config FabricConfig) (*AssuranceFabric, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &AssuranceFabric{
		config: config,
		cache:  make(map[string]*TrustEvidence),
	}, nil
}

func (af *AssuranceFabric) CollectEvidence(ctx context.Context, jobID string) (*TrustEvidence, error) {
	if af == nil {
		return nil, fmt.Errorf("AssuranceFabric.CollectEvidence: %w: fabric is required", ErrInvalidInput)
	}
	if jobID == "" {
		return nil, fmt.Errorf("AssuranceFabric.CollectEvidence: %w: job ID is required", ErrInvalidInput)
	}

	evidence := &TrustEvidence{
		JobID:       jobID,
		CollectedAt: time.Now().UTC(),
	}

	auditEvidence, err := af.config.AuditProvider.GetAuditEvidence(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("AssuranceFabric.CollectEvidence: %w: audit evidence: %v", ErrProviderUnavailable, err)
	}
	evidence.Audit = auditEvidence

	if af.config.SealProvider != nil {
		if seals, err := af.config.SealProvider.GetSealEvidence(ctx, jobID); err == nil {
			evidence.Seals = seals
		}
	}
	if af.config.VerificationProvider != nil {
		if verification, err := af.config.VerificationProvider.GetVerificationEvidence(ctx, jobID); err == nil {
			evidence.Verification = verification
		}
	}
	if af.config.ComplianceProvider != nil {
		if compliance, err := af.config.ComplianceProvider.GetComplianceEvidence(ctx, jobID); err == nil {
			evidence.Compliance = compliance
		}
	}

	evidence.AssuranceLevel = computeAssuranceLevel(evidence)
	if err := evidence.computeHash(); err != nil {
		return nil, err
	}

	af.mu.Lock()
	af.cache[jobID] = evidence
	af.mu.Unlock()
	return evidence, nil
}

func (af *AssuranceFabric) GetAssuranceLevel(ctx context.Context, jobID string) (AssuranceLevel, error) {
	if af == nil {
		return AssuranceLevelNone, fmt.Errorf("AssuranceFabric.GetAssuranceLevel: %w: fabric is required", ErrInvalidInput)
	}

	af.mu.RLock()
	cached, ok := af.cache[jobID]
	af.mu.RUnlock()
	if ok {
		return cached.AssuranceLevel, nil
	}

	evidence, err := af.CollectEvidence(ctx, jobID)
	if err != nil {
		return AssuranceLevelNone, err
	}
	return evidence.AssuranceLevel, nil
}

func (af *AssuranceFabric) GetCachedEvidence(jobID string) (*TrustEvidence, bool) {
	if af == nil {
		return nil, false
	}
	af.mu.RLock()
	defer af.mu.RUnlock()
	evidence, ok := af.cache[jobID]
	return evidence, ok
}

func (af *AssuranceFabric) InvalidateCache(jobID string) {
	if af == nil {
		return
	}
	af.mu.Lock()
	delete(af.cache, jobID)
	af.mu.Unlock()
}

func computeAssuranceLevel(evidence *TrustEvidence) AssuranceLevel {
	if evidence == nil || evidence.Audit == nil || evidence.Audit.RecordCount == 0 || !evidence.Audit.ChainIntact {
		return AssuranceLevelNone
	}

	level := AssuranceLevelBasic
	if len(evidence.Seals) > 0 {
		level = AssuranceLevelStandard
	}
	if evidence.Verification != nil && (evidence.Verification.HasTEEAttestation || evidence.Verification.HasZKProof) && level >= AssuranceLevelStandard {
		level = AssuranceLevelHigh
	}
	if evidence.Compliance != nil && evidence.Compliance.ControlsMet > 0 && level >= AssuranceLevelHigh {
		level = AssuranceLevelCritical
	}
	return level
}
