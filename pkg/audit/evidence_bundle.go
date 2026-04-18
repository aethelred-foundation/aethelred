package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// Evidence Bundle Packager
// ---------------------------------------------------------------------------
//
// Evidence bundles are self-contained, cryptographically-bound packages of
// audit evidence. They combine audit records, verification seals,
// attestations, and compliance control mappings into a single exportable
// artifact.
//
// Bundles follow the schema defined in docs/api/evidence-bundle-schema-v1.md
// and are the primary unit of compliance evidence exchange.
//
// Design:
//   - Builder pattern for incremental construction
//   - Cryptographic integrity via SHA-256 content hash
//   - Control mapping links evidence to specific compliance controls
//   - Framework-aware (NIST, SOC2, ISO 27001, HIPAA, etc.)
// ---------------------------------------------------------------------------

// ComplianceFramework identifies the compliance standard a bundle targets.
type ComplianceFramework string

const (
	FrameworkNIST80053 ComplianceFramework = "NIST-800-53"
	FrameworkNISTCSF   ComplianceFramework = "NIST-CSF"
	FrameworkSOC2      ComplianceFramework = "SOC2"
	FrameworkISO27001  ComplianceFramework = "ISO-27001"
	FrameworkHIPAA     ComplianceFramework = "HIPAA"
	FrameworkGDPR      ComplianceFramework = "GDPR"
	FrameworkFedRAMP   ComplianceFramework = "FedRAMP"
	FrameworkEUAIAct   ComplianceFramework = "EU-AI-Act"
	FrameworkCustom    ComplianceFramework = "custom"
)

// ControlMapping associates a compliance control ID with evidence.
type ControlMapping struct {
	// ControlID is the identifier from the compliance framework
	// (e.g., "AC-2" for NIST 800-53, "CC6.1" for SOC2).
	ControlID string `json:"control_id"`

	// ControlName is the human-readable name of the control.
	ControlName string `json:"control_name"`

	// Description explains how the evidence satisfies the control.
	Description string `json:"description"`

	// EvidenceRefs lists the sequence numbers of audit records that
	// serve as evidence for this control.
	EvidenceRefs []uint64 `json:"evidence_refs"`

	// Status indicates the assessment result.
	Status ControlStatus `json:"status"`

	// Findings contains any observations or gaps.
	Findings []string `json:"findings,omitempty"`
}

// ControlStatus represents the assessment outcome for a control.
type ControlStatus string

const (
	ControlSatisfied     ControlStatus = "satisfied"
	ControlPartial       ControlStatus = "partially_satisfied"
	ControlNotSatisfied  ControlStatus = "not_satisfied"
	ControlNotApplicable ControlStatus = "not_applicable"
	ControlNotAssessed   ControlStatus = "not_assessed"
)

// Seal represents a cryptographic verification seal from the consensus
// process.
type Seal struct {
	SealID         string `json:"seal_id"`
	JobID          string `json:"job_id"`
	OutputHash     string `json:"output_hash"`
	ValidatorCount int    `json:"validator_count"`
	BlockHeight    int64  `json:"block_height"`
	Timestamp      string `json:"timestamp"`
}

// Attestation represents a TEE or validator attestation.
type Attestation struct {
	AttestationID string            `json:"attestation_id"`
	Type          string            `json:"type"` // "tee", "validator", "zkml"
	Platform      string            `json:"platform,omitempty"`
	EnclaveID     string            `json:"enclave_id,omitempty"`
	Measurement   string            `json:"measurement,omitempty"`
	Timestamp     string            `json:"timestamp"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// Proof represents a cryptographic proof (zkML, replay, etc.).
type Proof struct {
	ProofID          string `json:"proof_id"`
	Type             string `json:"type"`                    // "groth16", "plonk", "ezkl", "halo2", "stark", "replay"
	ProofData        string `json:"proof_data,omitempty"`    // base64-encoded
	PublicInputs     string `json:"public_inputs,omitempty"` // base64-encoded
	OutputCommitment string `json:"output_commitment,omitempty"`
	Timestamp        string `json:"timestamp"`
}

// Bundle is the top-level evidence bundle structure.
type Bundle struct {
	// Identity
	ID            string `json:"bundle_id"`
	SchemaVersion string `json:"schema_version"`
	CreatedAt     string `json:"created_at"`

	// Framework and controls
	Framework ComplianceFramework `json:"framework"`
	Controls  []ControlMapping    `json:"controls"`

	// Evidence components
	Records      []keeper.AuditRecord `json:"records"`
	Seals        []Seal               `json:"seals,omitempty"`
	Attestations []Attestation        `json:"attestations,omitempty"`
	Proofs       []Proof              `json:"proofs,omitempty"`

	// Integrity
	ContentHash string `json:"content_hash"`
	Signature   string `json:"signature,omitempty"`

	// Metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ---------------------------------------------------------------------------
// Bundle Builder
// ---------------------------------------------------------------------------

// BundleBuilder constructs evidence bundles incrementally.
type BundleBuilder struct {
	bundle Bundle
}

// NewBundleBuilder creates a new builder targeting the given compliance
// framework.
func NewBundleBuilder(framework ComplianceFramework) *BundleBuilder {
	return &BundleBuilder{
		bundle: Bundle{
			SchemaVersion: "1.0.0",
			Framework:     framework,
			CreatedAt:     time.Now().UTC().Format(time.RFC3339),
			Controls:      make([]ControlMapping, 0),
			Records:       make([]keeper.AuditRecord, 0),
			Metadata:      make(map[string]string),
		},
	}
}

// WithID sets the bundle identifier.
func (b *BundleBuilder) WithID(id string) *BundleBuilder {
	b.bundle.ID = id
	return b
}

// AddRecords appends audit records to the bundle.
func (b *BundleBuilder) AddRecords(records []keeper.AuditRecord) *BundleBuilder {
	b.bundle.Records = append(b.bundle.Records, records...)
	return b
}

// AddSeals appends verification seals to the bundle.
func (b *BundleBuilder) AddSeals(seals []Seal) *BundleBuilder {
	b.bundle.Seals = append(b.bundle.Seals, seals...)
	return b
}

// AddAttestations appends attestations to the bundle.
func (b *BundleBuilder) AddAttestations(attestations []Attestation) *BundleBuilder {
	b.bundle.Attestations = append(b.bundle.Attestations, attestations...)
	return b
}

// AddProofs appends cryptographic proofs to the bundle.
func (b *BundleBuilder) AddProofs(proofs []Proof) *BundleBuilder {
	b.bundle.Proofs = append(b.bundle.Proofs, proofs...)
	return b
}

// AddControlMapping maps evidence to a specific compliance control.
func (b *BundleBuilder) AddControlMapping(controlID string, evidence ControlMapping) *BundleBuilder {
	evidence.ControlID = controlID
	b.bundle.Controls = append(b.bundle.Controls, evidence)
	return b
}

// WithMetadata adds a metadata key-value pair.
func (b *BundleBuilder) WithMetadata(key, value string) *BundleBuilder {
	b.bundle.Metadata[key] = value
	return b
}

// Build finalizes the bundle, computing its content hash. Returns an error
// if the bundle is invalid.
func (b *BundleBuilder) Build() (*Bundle, error) {
	if b.bundle.ID == "" {
		return nil, fmt.Errorf("audit/bundle: bundle ID is required")
	}
	if len(b.bundle.Records) == 0 {
		return nil, fmt.Errorf("audit/bundle: at least one audit record is required")
	}

	// Compute the content hash over the canonical representation.
	hash, err := computeBundleHash(&b.bundle)
	if err != nil {
		return nil, fmt.Errorf("audit/bundle: failed to compute content hash: %w", err)
	}
	b.bundle.ContentHash = hash

	result := b.bundle
	return &result, nil
}

// ---------------------------------------------------------------------------
// Bundle verification
// ---------------------------------------------------------------------------

// VerifyBundle verifies the integrity of an evidence bundle by recomputing
// its content hash and validating the internal consistency of its records.
func VerifyBundle(bundle *Bundle) error {
	if bundle == nil {
		return fmt.Errorf("audit/bundle: nil bundle")
	}

	// Verify content hash.
	computed, err := computeBundleHash(bundle)
	if err != nil {
		return fmt.Errorf("audit/bundle: failed to recompute content hash: %w", err)
	}
	if computed != bundle.ContentHash {
		return fmt.Errorf("audit/bundle: content hash mismatch: expected %s, computed %s",
			bundle.ContentHash, computed)
	}

	// Verify the audit record chain within the bundle.
	if len(bundle.Records) > 0 {
		if err := VerifyChain(bundle.Records); err != nil {
			return fmt.Errorf("audit/bundle: record chain verification failed: %w", err)
		}
	}

	// Verify control mappings reference valid record sequences.
	seqSet := make(map[uint64]bool, len(bundle.Records))
	for _, r := range bundle.Records {
		seqSet[r.Sequence] = true
	}
	for _, ctrl := range bundle.Controls {
		for _, ref := range ctrl.EvidenceRefs {
			if !seqSet[ref] {
				return fmt.Errorf("audit/bundle: control %s references missing record sequence %d",
					ctrl.ControlID, ref)
			}
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Content hashing
// ---------------------------------------------------------------------------

// computeBundleHash computes the SHA-256 hash of the bundle's content in a
// deterministic, canonical format. The hash covers records, seals,
// attestations, proofs, and control mappings but excludes the content hash
// and signature fields.
func computeBundleHash(bundle *Bundle) (string, error) {
	// Build a canonical struct for hashing (exclude hash and signature).
	type hashableBundle struct {
		ID            string               `json:"bundle_id"`
		SchemaVersion string               `json:"schema_version"`
		CreatedAt     string               `json:"created_at"`
		Framework     ComplianceFramework  `json:"framework"`
		Controls      []ControlMapping     `json:"controls"`
		Records       []keeper.AuditRecord `json:"records"`
		Seals         []Seal               `json:"seals"`
		Attestations  []Attestation        `json:"attestations"`
		Proofs        []Proof              `json:"proofs"`
		Metadata      map[string]string    `json:"metadata"`
	}

	h := hashableBundle{
		ID:            bundle.ID,
		SchemaVersion: bundle.SchemaVersion,
		CreatedAt:     bundle.CreatedAt,
		Framework:     bundle.Framework,
		Controls:      bundle.Controls,
		Records:       bundle.Records,
		Seals:         bundle.Seals,
		Attestations:  bundle.Attestations,
		Proofs:        bundle.Proofs,
		Metadata:      bundle.Metadata,
	}

	// Use JSON canonical encoding for determinism.
	data, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("failed to marshal bundle for hashing: %w", err)
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ---------------------------------------------------------------------------
// Pre-built control mappings
// ---------------------------------------------------------------------------

// NIST80053ControlMappings returns standard control mappings for NIST 800-53
// controls commonly satisfied by the Aethelred audit system.
func NIST80053ControlMappings() []ControlMapping {
	return []ControlMapping{
		{
			ControlID:   "AU-2",
			ControlName: "Event Logging",
			Description: "The system generates audit records for defined events including job execution, consensus, evidence detection, and slashing.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "AU-3",
			ControlName: "Content of Audit Records",
			Description: "Audit records contain type, timestamp, source, outcome, and identity of subjects/objects associated with each event.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "AU-6",
			ControlName: "Audit Record Review, Analysis, and Reporting",
			Description: "The Audit Studio provides query, filtering, timeline, and statistical analysis of audit records.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "AU-9",
			ControlName: "Protection of Audit Information",
			Description: "Audit records are protected via cryptographic hash chains. Tampering is detectable through chain verification.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "AU-10",
			ControlName: "Non-repudiation",
			Description: "Hash-chained audit records with actor attribution provide non-repudiation for all recorded actions.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "AU-11",
			ControlName: "Audit Record Retention",
			Description: "Retention policies ensure records are maintained for the required duration per applicable regulation.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "AU-12",
			ControlName: "Audit Record Generation",
			Description: "The pouw module generates audit records at each security-relevant processing checkpoint.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "SA-10",
			ControlName: "Developer Configuration Management",
			Description: "Model and circuit hashes are recorded at computation time, providing configuration integrity evidence.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "SI-7",
			ControlName: "Software, Firmware, and Information Integrity",
			Description: "TEE attestations and zkML proofs verify computation integrity. Replay engine enables re-verification.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "SC-13",
			ControlName: "Cryptographic Protection",
			Description: "SHA-256 hash chains, TEE attestation quotes, and zero-knowledge proofs provide cryptographic protection.",
			Status:      ControlNotAssessed,
		},
	}
}

// SOC2ControlMappings returns standard control mappings for SOC2 Trust
// Services Criteria commonly satisfied by the Aethelred audit system.
func SOC2ControlMappings() []ControlMapping {
	return []ControlMapping{
		{
			ControlID:   "CC6.1",
			ControlName: "Logical and Physical Access Controls",
			Description: "Validator registration and authentication events are recorded with actor attribution.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "CC7.2",
			ControlName: "System Monitoring",
			Description: "Continuous audit logging with severity classification provides real-time system monitoring.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "CC7.3",
			ControlName: "Detection of Changes",
			Description: "Hash chain verification detects any unauthorized modification to the audit trail.",
			Status:      ControlNotAssessed,
		},
		{
			ControlID:   "CC8.1",
			ControlName: "Change Management",
			Description: "Governance parameter changes are recorded with before/after values and authority attribution.",
			Status:      ControlNotAssessed,
		},
	}
}
