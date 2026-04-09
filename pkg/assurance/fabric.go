// Package assurance provides the Enterprise Assurance Fabric, which
// orchestrates trust evidence collection across seal, audit, verification,
// and compliance modules. It computes overall assurance levels for
// computation jobs and exposes evidence for regulatory and audit workflows.
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

// ---------------------------------------------------------------------------
// Assurance levels
// ---------------------------------------------------------------------------

// AssuranceLevel quantifies the degree of trust assurance for a given
// computation job. Each level has progressively stricter requirements.
type AssuranceLevel int

const (
	// AssuranceLevelNone indicates no verifiable trust evidence exists.
	AssuranceLevelNone AssuranceLevel = iota

	// AssuranceLevelBasic indicates minimal evidence (e.g., audit records only).
	AssuranceLevelBasic

	// AssuranceLevelStandard indicates audit records plus at least one
	// verification seal.
	AssuranceLevelStandard

	// AssuranceLevelHigh indicates audit records, seals, and at least one
	// TEE attestation or ZK proof.
	AssuranceLevelHigh

	// AssuranceLevelCritical indicates full evidence: audit trail,
	// verification seal, TEE attestation, ZK proof, and compliance mapping.
	AssuranceLevelCritical
)

// String returns the human-readable name of the assurance level.
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

// Score returns a numeric score (0-100) for the assurance level.
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

// ---------------------------------------------------------------------------
// Provider interfaces
// ---------------------------------------------------------------------------

// SealEvidence represents trust evidence from the seal module.
type SealEvidence struct {
	SealID         string    `json:"seal_id"`
	JobID          string    `json:"job_id"`
	OutputHash     string    `json:"output_hash"`
	ValidatorCount int       `json:"validator_count"`
	BlockHeight    int64     `json:"block_height"`
	Timestamp      time.Time `json:"timestamp"`
	Status         string    `json:"status"`
}

// AuditEvidence represents trust evidence from the audit module.
type AuditEvidence struct {
	RecordCount    int       `json:"record_count"`
	ChainIntact    bool      `json:"chain_intact"`
	FirstRecord    time.Time `json:"first_record"`
	LastRecord     time.Time `json:"last_record"`
	CoverageGaps   []string  `json:"coverage_gaps,omitempty"`
}

// VerificationEvidence represents trust evidence from the verification module.
type VerificationEvidence struct {
	HasTEEAttestation bool   `json:"has_tee_attestation"`
	HasZKProof        bool   `json:"has_zk_proof"`
	AttestationType   string `json:"attestation_type,omitempty"`
	ProofSystem       string `json:"proof_system,omitempty"`
	VerifiedAt        time.Time `json:"verified_at"`
}

// ComplianceEvidence represents trust evidence from the compliance module.
type ComplianceEvidence struct {
	Frameworks     []string `json:"frameworks"`
	ControlsMet    int      `json:"controls_met"`
	ControlsTotal  int      `json:"controls_total"`
	CoverageScore  float64  `json:"coverage_score"`
}

// SealProvider retrieves seal evidence for a computation job.
type SealProvider interface {
	GetSealEvidence(ctx context.Context, jobID string) ([]SealEvidence, error)
}

// AuditProvider retrieves audit evidence for a computation job.
type AuditProvider interface {
	GetAuditEvidence(ctx context.Context, jobID string) (*AuditEvidence, error)
}

// VerificationProvider retrieves verification evidence for a computation job.
type VerificationProvider interface {
	GetVerificationEvidence(ctx context.Context, jobID string) (*VerificationEvidence, error)
}

// ComplianceProvider retrieves compliance evidence for a computation job.
type ComplianceProvider interface {
	GetComplianceEvidence(ctx context.Context, jobID string) (*ComplianceEvidence, error)
}

// ---------------------------------------------------------------------------
// Fabric configuration
// ---------------------------------------------------------------------------

// FabricConfig configures the AssuranceFabric with provider implementations.
type FabricConfig struct {
	SealProvider         SealProvider
	AuditProvider        AuditProvider
	VerificationProvider VerificationProvider
	ComplianceProvider   ComplianceProvider
}

// Validate ensures the configuration has at minimum an audit provider.
func (c *FabricConfig) Validate() error {
	if c.AuditProvider == nil {
		return fmt.Errorf("FabricConfig.Validate: %w: audit provider is required", ErrInvalidInput)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Trust evidence aggregate
// ---------------------------------------------------------------------------

// TrustEvidence aggregates all trust evidence collected for a computation job.
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

// computeHash computes a SHA-256 content hash of the evidence aggregate.
func (te *TrustEvidence) computeHash() error {
	type hashable struct {
		JobID        string                `json:"job_id"`
		CollectedAt  string                `json:"collected_at"`
		Seals        []SealEvidence        `json:"seals"`
		Audit        *AuditEvidence        `json:"audit"`
		Verification *VerificationEvidence `json:"verification"`
		Compliance   *ComplianceEvidence   `json:"compliance"`
	}
	h := hashable{
		JobID:        te.JobID,
		CollectedAt:  te.CollectedAt.UTC().Format(time.RFC3339Nano),
		Seals:        te.Seals,
		Audit:        te.Audit,
		Verification: te.Verification,
		Compliance:   te.Compliance,
	}
	data, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("assurance: failed to marshal evidence for hashing: %w", err)
	}
	sum := sha256.Sum256(data)
	te.ContentHash = hex.EncodeToString(sum[:])
	return nil
}

// ---------------------------------------------------------------------------
// Assurance Fabric
// ---------------------------------------------------------------------------

// AssuranceFabric orchestrates trust evidence collection across multiple
// platform subsystems and computes aggregate assurance levels.
type AssuranceFabric struct {
	config FabricConfig
	mu     sync.RWMutex
	cache  map[string]*TrustEvidence
}

// NewAssuranceFabric creates a new fabric coordinator with the given config.
func NewAssuranceFabric(config FabricConfig) (*AssuranceFabric, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &AssuranceFabric{
		config: config,
		cache:  make(map[string]*TrustEvidence),
	}, nil
}

// CollectEvidence gathers all available trust evidence for a computation job.
func (af *AssuranceFabric) CollectEvidence(ctx context.Context, jobID string) (*TrustEvidence, error) {
	if jobID == "" {
		return nil, fmt.Errorf("AssuranceFabric.CollectEvidence: %w: job ID is required", ErrInvalidInput)
	}

	evidence := &TrustEvidence{
		JobID:       jobID,
		CollectedAt: time.Now().UTC(),
	}

	// Collect audit evidence (required).
	auditEv, err := af.config.AuditProvider.GetAuditEvidence(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("AssuranceFabric.CollectEvidence: %w: audit evidence: %v", ErrProviderUnavailable, err)
	}
	evidence.Audit = auditEv

	// Collect seal evidence (optional).
	if af.config.SealProvider != nil {
		seals, err := af.config.SealProvider.GetSealEvidence(ctx, jobID)
		if err == nil {
			evidence.Seals = seals
		}
	}

	// Collect verification evidence (optional).
	if af.config.VerificationProvider != nil {
		verif, err := af.config.VerificationProvider.GetVerificationEvidence(ctx, jobID)
		if err == nil {
			evidence.Verification = verif
		}
	}

	// Collect compliance evidence (optional).
	if af.config.ComplianceProvider != nil {
		comp, err := af.config.ComplianceProvider.GetComplianceEvidence(ctx, jobID)
		if err == nil {
			evidence.Compliance = comp
		}
	}

	// Compute assurance level.
	evidence.AssuranceLevel = computeAssuranceLevel(evidence)

	// Compute content hash.
	if err := evidence.computeHash(); err != nil {
		return nil, err
	}

	// Cache the result.
	af.mu.Lock()
	af.cache[jobID] = evidence
	af.mu.Unlock()

	return evidence, nil
}

// GetAssuranceLevel computes the overall assurance level for a job.
// If evidence has been previously collected and is cached, it uses the
// cached value; otherwise it collects fresh evidence.
func (af *AssuranceFabric) GetAssuranceLevel(ctx context.Context, jobID string) (AssuranceLevel, error) {
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

// GetCachedEvidence returns previously collected evidence without re-collection.
func (af *AssuranceFabric) GetCachedEvidence(jobID string) (*TrustEvidence, bool) {
	af.mu.RLock()
	defer af.mu.RUnlock()
	ev, ok := af.cache[jobID]
	return ev, ok
}

// InvalidateCache removes cached evidence for a job.
func (af *AssuranceFabric) InvalidateCache(jobID string) {
	af.mu.Lock()
	delete(af.cache, jobID)
	af.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Assurance level computation
// ---------------------------------------------------------------------------

// computeAssuranceLevel determines the assurance level from collected evidence.
//
// Scoring criteria:
//   - None:     No audit records
//   - Basic:    Audit records present and chain intact
//   - Standard: Basic + at least one verification seal
//   - High:     Standard + TEE attestation or ZK proof
//   - Critical: High + compliance controls mapped
func computeAssuranceLevel(evidence *TrustEvidence) AssuranceLevel {
	// No audit evidence means no assurance.
	if evidence.Audit == nil || evidence.Audit.RecordCount == 0 {
		return AssuranceLevelNone
	}

	// Audit trail must be intact for any assurance.
	if !evidence.Audit.ChainIntact {
		return AssuranceLevelNone
	}

	level := AssuranceLevelBasic

	// Check for verification seals.
	if len(evidence.Seals) > 0 {
		level = AssuranceLevelStandard
	}

	// Check for TEE attestation or ZK proof.
	if evidence.Verification != nil {
		if evidence.Verification.HasTEEAttestation || evidence.Verification.HasZKProof {
			if level >= AssuranceLevelStandard {
				level = AssuranceLevelHigh
			}
		}
	}

	// Check for compliance mapping.
	if evidence.Compliance != nil && evidence.Compliance.ControlsMet > 0 {
		if level >= AssuranceLevelHigh {
			level = AssuranceLevelCritical
		}
	}

	return level
}
