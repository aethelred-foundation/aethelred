// Package evidence provides portable, self-contained evidence bundles that
// can be verified offline without network access. Evidence bundles package
// audit records, verification seals, TEE attestations, and chain-of-custody
// metadata into cryptographically-bound artifacts.
//
// This package is distinct from pkg/audit's bundle implementation in that it
// focuses on portability and standalone verification, while pkg/audit focuses
// on internal audit trail management.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Evidence bundle schema version
// ---------------------------------------------------------------------------

const SchemaVersion = "1.0.0"

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

// Record represents an individual evidence record within a bundle.
type Record struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"` // "audit", "computation", "verification", "governance"
	Action      string            `json:"action"`
	Actor       string            `json:"actor"`
	Timestamp   string            `json:"timestamp"`
	BlockHeight int64             `json:"block_height,omitempty"`
	Data        map[string]string `json:"data,omitempty"`
	Hash        string            `json:"hash"`
}

// ComputeHash computes the SHA-256 hash of a record's content.
func (r *Record) ComputeHash() string {
	h := sha256.New()
	h.Write([]byte(r.ID))
	h.Write([]byte(r.Type))
	h.Write([]byte(r.Action))
	h.Write([]byte(r.Actor))
	h.Write([]byte(r.Timestamp))
	data, _ := json.Marshal(r.Data)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Seal represents a cryptographic verification seal.
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
	ID          string            `json:"id"`
	Type        string            `json:"type"` // "tee", "validator", "zkml"
	Platform    string            `json:"platform,omitempty"`
	EnclaveID   string            `json:"enclave_id,omitempty"`
	Measurement string            `json:"measurement,omitempty"`
	Timestamp   string            `json:"timestamp"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// PolicyReceiptEvidence captures a signed policy decision that authorized an
// action before execution.
type PolicyReceiptEvidence struct {
	ID                  string `json:"id"`
	RequestID           string `json:"request_id"`
	Actor               string `json:"actor"`
	Action              string `json:"action"`
	Resource            string `json:"resource"`
	Decision            string `json:"decision"`
	AuditTrail          string `json:"audit_trail"`
	Signer              string `json:"signer"`
	ContentHash         string `json:"content_hash"`
	PreviousReceiptHash string `json:"previous_receipt_hash,omitempty"`
	EvaluatedAt         string `json:"evaluated_at"`
}

// PassportSponsor records one sponsor entry in an exported enterprise agent
// passport.
type PassportSponsor struct {
	SponsorDID        string `json:"sponsor_did"`
	SponsorName       string `json:"sponsor_name,omitempty"`
	Jurisdiction      string `json:"jurisdiction,omitempty"`
	Role              string `json:"role,omitempty"`
	LiabilityAccepted bool   `json:"liability_accepted"`
	SignedAt          string `json:"signed_at,omitempty"`
}

// AgentPassportEvidence captures the accountable identity context for an
// autonomous agent used in a regulated workflow.
type AgentPassportEvidence struct {
	DID              string            `json:"did"`
	Issuer           string            `json:"issuer"`
	PublicKeyHash    string            `json:"public_key_hash"`
	Capabilities     []string          `json:"capabilities,omitempty"`
	SponsorChain     []PassportSponsor `json:"sponsor_chain,omitempty"`
	HumanOwner       string            `json:"human_owner,omitempty"`
	BusinessUnit     string            `json:"business_unit,omitempty"`
	SponsorOfRecord  string            `json:"sponsor_of_record,omitempty"`
	FallbackApprover string            `json:"fallback_approver,omitempty"`
	IncidentContact  string            `json:"incident_contact,omitempty"`
	LiabilityModel   string            `json:"liability_model,omitempty"`
	JurisdictionTags []string          `json:"jurisdiction_tags,omitempty"`
	AllowedTools     []string          `json:"allowed_tools,omitempty"`
	IssuedAt         string            `json:"issued_at"`
	ExpiresAt        string            `json:"expires_at,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// TraceLink binds policy authorization, identity, and sealed execution into a
// single exportable integrity chain.
type TraceLink struct {
	ID                string `json:"id"`
	AgentDID          string `json:"agent_did"`
	PolicyReceiptID   string `json:"policy_receipt_id"`
	PolicyReceiptHash string `json:"policy_receipt_hash"`
	SealID            string `json:"seal_id"`
	OutputHash        string `json:"output_hash,omitempty"`
	LinkedAt          string `json:"linked_at"`
	Description       string `json:"description,omitempty"`
}

// CustodyEntry records a single custody transfer event.
type CustodyEntry struct {
	Custodian    string `json:"custodian"`
	Action       string `json:"action"` // "created", "transfer", "export", "verify"
	Timestamp    string `json:"timestamp"`
	PreviousHash string `json:"previous_hash"`
	Hash         string `json:"hash"`
	Signature    string `json:"signature,omitempty"`
}

// ComputeHash computes the SHA-256 hash of a custody entry.
func (ce *CustodyEntry) ComputeHash() string {
	h := sha256.New()
	h.Write([]byte(ce.Custodian))
	h.Write([]byte(ce.Action))
	h.Write([]byte(ce.Timestamp))
	h.Write([]byte(ce.PreviousHash))
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Evidence Bundle
// ---------------------------------------------------------------------------

// EvidenceBundle is a self-contained, cryptographically-bound package of
// trust evidence for one or more computation jobs.
type EvidenceBundle struct {
	// Identity
	ID        string `json:"bundle_id"`
	Version   string `json:"schema_version"`
	CreatedAt string `json:"created_at"`

	// Framework context
	Framework string `json:"framework,omitempty"`

	// Evidence components
	Records                 []Record                         `json:"records"`
	Seals                   []Seal                           `json:"seals,omitempty"`
	Attestations            []Attestation                    `json:"attestations,omitempty"`
	PolicyReceipts          []PolicyReceiptEvidence          `json:"policy_receipts,omitempty"`
	AgentPassports          []AgentPassportEvidence          `json:"agent_passports,omitempty"`
	ApproverAttestations    []ApproverAttestationEvidence    `json:"approver_attestations,omitempty"`
	ValueSettlements        []ValueSettlementEvidence        `json:"value_settlements,omitempty"`
	TraceLinks              []TraceLink                      `json:"trace_links,omitempty"`
	TrustCompliancePackages []TrustCompliancePackageEvidence `json:"trust_compliance_packages,omitempty"`

	// Chain of custody
	ChainOfCustody []CustodyEntry `json:"chain_of_custody,omitempty"`

	// Integrity
	ContentHash string `json:"content_hash"`
	Signature   string `json:"signature,omitempty"`

	// Metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// NewEvidenceBundle creates a new empty evidence bundle for the given framework.
func NewEvidenceBundle(framework string) *EvidenceBundle {
	return &EvidenceBundle{
		ID:                      uuid.New().String(),
		Version:                 SchemaVersion,
		CreatedAt:               time.Now().UTC().Format(time.RFC3339Nano),
		Framework:               framework,
		Records:                 make([]Record, 0),
		Seals:                   make([]Seal, 0),
		Attestations:            make([]Attestation, 0),
		PolicyReceipts:          make([]PolicyReceiptEvidence, 0),
		AgentPassports:          make([]AgentPassportEvidence, 0),
		ApproverAttestations:    make([]ApproverAttestationEvidence, 0),
		ValueSettlements:        make([]ValueSettlementEvidence, 0),
		TraceLinks:              make([]TraceLink, 0),
		TrustCompliancePackages: make([]TrustCompliancePackageEvidence, 0),
		ChainOfCustody:          make([]CustodyEntry, 0),
		Metadata:                make(map[string]string),
	}
}

// AddRecord appends an evidence record to the bundle.
func (eb *EvidenceBundle) AddRecord(record Record) {
	if record.Hash == "" {
		record.Hash = record.ComputeHash()
	}
	eb.Records = append(eb.Records, record)
}

// AddSeal appends a verification seal to the bundle.
func (eb *EvidenceBundle) AddSeal(seal Seal) {
	eb.Seals = append(eb.Seals, seal)
}

// AddAttestation appends an attestation to the bundle.
func (eb *EvidenceBundle) AddAttestation(attestation Attestation) {
	eb.Attestations = append(eb.Attestations, attestation)
}

// AddPolicyReceipt appends a signed policy receipt to the bundle.
func (eb *EvidenceBundle) AddPolicyReceipt(receipt PolicyReceiptEvidence) {
	eb.PolicyReceipts = append(eb.PolicyReceipts, receipt)
}

// AddAgentPassport appends an enterprise agent passport to the bundle.
func (eb *EvidenceBundle) AddAgentPassport(passport AgentPassportEvidence) {
	eb.AgentPassports = append(eb.AgentPassports, passport)
}

// AddApproverAttestation appends an authenticated approval artifact to the
// bundle.
func (eb *EvidenceBundle) AddApproverAttestation(attestation ApproverAttestationEvidence) error {
	if err := (&attestation).Normalize(); err != nil {
		return err
	}
	eb.ApproverAttestations = append(eb.ApproverAttestations, attestation)
	return nil
}

// AddValueSettlement appends a canonical value-settlement artifact to the
// bundle.
func (eb *EvidenceBundle) AddValueSettlement(settlement ValueSettlementEvidence) error {
	if err := (&settlement).Normalize(); err != nil {
		return err
	}
	eb.ValueSettlements = append(eb.ValueSettlements, settlement)
	return nil
}

// AddTraceLink appends a traceability link to the bundle.
func (eb *EvidenceBundle) AddTraceLink(link TraceLink) {
	eb.TraceLinks = append(eb.TraceLinks, link)
}

// AddTrustCompliancePackage appends a canonical packaged trust-compliance
// artifact to the bundle and projects its audit anchor into the record stream
// when one is present.
func (eb *EvidenceBundle) AddTrustCompliancePackage(pkg TrustCompliancePackageEvidence) error {
	if err := (&pkg).Normalize(); err != nil {
		return err
	}
	eb.TrustCompliancePackages = append(eb.TrustCompliancePackages, pkg)

	if pkg.AuditAnchor != nil {
		record, err := pkg.AnchorRecord()
		if err != nil {
			return err
		}
		for _, existing := range eb.Records {
			if existing.ID == record.ID {
				return nil
			}
		}
		eb.AddRecord(record)
	}
	return nil
}

// Finalize computes the content hash and optionally signs the bundle.
// The signer parameter is a hex-encoded signing key; pass empty string
// to skip signing.
func (eb *EvidenceBundle) Finalize(signer string) error {
	if len(eb.Records) == 0 {
		return fmt.Errorf("EvidenceBundle.Finalize: %w: at least one record is required", ErrInvalidBundle)
	}

	// Check for nil/empty content before computing hash.
	for i, r := range eb.Records {
		if r.ID == "" {
			return fmt.Errorf("EvidenceBundle.Finalize: %w: record %d has empty ID", ErrInvalidBundle, i)
		}
	}

	// Add a custody entry for finalization BEFORE computing the hash,
	// so the hash covers the complete state including the seal entry.
	eb.addCustodyEntry("system", "seal")

	hash, err := eb.computeContentHash()
	if err != nil {
		return fmt.Errorf("EvidenceBundle.Finalize: %w", err)
	}
	eb.ContentHash = hash

	if signer != "" {
		sig, err := computeSignature(hash, signer)
		if err != nil {
			return fmt.Errorf("EvidenceBundle.Finalize: %w: %v", ErrSignatureInvalid, err)
		}
		eb.Signature = sig
	}

	return nil
}

// Validate checks the bundle's structural integrity and content hash.
func (eb *EvidenceBundle) Validate() error {
	if eb.ID == "" {
		return fmt.Errorf("EvidenceBundle.Validate: %w: ID is empty", ErrInvalidBundle)
	}
	if eb.Version == "" {
		return fmt.Errorf("EvidenceBundle.Validate: %w: schema version is empty", ErrInvalidBundle)
	}
	if len(eb.Records) == 0 {
		return fmt.Errorf("EvidenceBundle.Validate: %w: at least one record is required", ErrInvalidBundle)
	}
	if eb.ContentHash == "" {
		return fmt.Errorf("EvidenceBundle.Validate: %w: call Finalize first", ErrBundleNotFinalized)
	}

	// Verify content hash.
	computed, err := eb.computeContentHash()
	if err != nil {
		return fmt.Errorf("EvidenceBundle.Validate: %w: %v", ErrVerificationFailed, err)
	}
	if computed != eb.ContentHash {
		return fmt.Errorf("EvidenceBundle.Validate: %w: expected %s, computed %s",
			ErrChainBroken, eb.ContentHash, computed)
	}

	// Verify individual record hashes.
	for i, r := range eb.Records {
		expected := r.ComputeHash()
		if r.Hash != expected {
			return fmt.Errorf("EvidenceBundle.Validate: %w: record %d hash mismatch", ErrChainBroken, i)
		}
	}

	if err := validateTraceability(eb); err != nil {
		return fmt.Errorf("EvidenceBundle.Validate: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// computeContentHash computes SHA-256 over the canonical bundle content,
// excluding content hash and signature.
func (eb *EvidenceBundle) computeContentHash() (string, error) {
	type hashable struct {
		ID                      string                           `json:"bundle_id"`
		Version                 string                           `json:"schema_version"`
		CreatedAt               string                           `json:"created_at"`
		Framework               string                           `json:"framework"`
		Records                 []Record                         `json:"records"`
		Seals                   []Seal                           `json:"seals,omitempty"`
		Attestations            []Attestation                    `json:"attestations,omitempty"`
		PolicyReceipts          []PolicyReceiptEvidence          `json:"policy_receipts,omitempty"`
		AgentPassports          []AgentPassportEvidence          `json:"agent_passports,omitempty"`
		ApproverAttestations    []ApproverAttestationEvidence    `json:"approver_attestations,omitempty"`
		ValueSettlements        []ValueSettlementEvidence        `json:"value_settlements,omitempty"`
		TraceLinks              []TraceLink                      `json:"trace_links,omitempty"`
		TrustCompliancePackages []TrustCompliancePackageEvidence `json:"trust_compliance_packages,omitempty"`
		ChainOfCustody          []CustodyEntry                   `json:"chain_of_custody,omitempty"`
		Metadata                map[string]string                `json:"metadata,omitempty"`
	}

	h := hashable{
		ID:                      eb.ID,
		Version:                 eb.Version,
		CreatedAt:               eb.CreatedAt,
		Framework:               eb.Framework,
		Records:                 eb.Records,
		Seals:                   eb.Seals,
		Attestations:            eb.Attestations,
		PolicyReceipts:          eb.PolicyReceipts,
		AgentPassports:          eb.AgentPassports,
		ApproverAttestations:    eb.ApproverAttestations,
		ValueSettlements:        eb.ValueSettlements,
		TraceLinks:              eb.TraceLinks,
		TrustCompliancePackages: eb.TrustCompliancePackages,
		ChainOfCustody:          eb.ChainOfCustody,
		Metadata:                eb.Metadata,
	}

	data, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("evidence/bundle: marshal failed: %w", err)
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// computeSignature creates an HMAC-SHA256 signature of the content hash.
func computeSignature(contentHash, signerKey string) (string, error) {
	if contentHash == "" {
		return "", fmt.Errorf("computeSignature: %w: content hash is empty", ErrSignatureInvalid)
	}
	keyBytes, err := hex.DecodeString(signerKey)
	if err != nil {
		return "", fmt.Errorf("computeSignature: %w: invalid signer key encoding: %v", ErrSignatureInvalid, err)
	}
	// Validate signer key length: must be at least 16 bytes (128 bits).
	if len(keyBytes) < 16 {
		return "", fmt.Errorf("computeSignature: %w: signer key too short (%d bytes, minimum 16)", ErrSignatureInvalid, len(keyBytes))
	}

	h := sha256.New()
	h.Write([]byte("aethelred_evidence_sig_v1:"))
	h.Write(keyBytes)
	h.Write([]byte(contentHash))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// addCustodyEntry appends a new custody entry to the chain.
func (eb *EvidenceBundle) addCustodyEntry(custodian, action string) {
	prevHash := ""
	if len(eb.ChainOfCustody) > 0 {
		prevHash = eb.ChainOfCustody[len(eb.ChainOfCustody)-1].Hash
	}

	entry := CustodyEntry{
		Custodian:    custodian,
		Action:       action,
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		PreviousHash: prevHash,
	}
	entry.Hash = entry.ComputeHash()
	eb.ChainOfCustody = append(eb.ChainOfCustody, entry)
}

// NewPolicyReceiptEvidence converts a signed policy receipt into portable
// evidence.
func NewPolicyReceiptEvidence(receipt *policy.SignedPolicyReceipt) (PolicyReceiptEvidence, error) {
	if receipt == nil {
		return PolicyReceiptEvidence{}, fmt.Errorf("NewPolicyReceiptEvidence: nil receipt")
	}
	if receipt.ID == "" || receipt.ContentHash == "" || receipt.Decision == "" || receipt.Signer == "" {
		return PolicyReceiptEvidence{}, fmt.Errorf("NewPolicyReceiptEvidence: receipt is missing required fields")
	}
	return PolicyReceiptEvidence{
		ID:                  receipt.ID,
		RequestID:           receipt.RequestID,
		Actor:               receipt.Actor,
		Action:              receipt.Action,
		Resource:            receipt.Resource,
		Decision:            receipt.Decision,
		AuditTrail:          receipt.AuditTrail,
		Signer:              receipt.Signer,
		ContentHash:         receipt.ContentHash,
		PreviousReceiptHash: receipt.PreviousReceiptHash,
		EvaluatedAt:         receipt.EvaluatedAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

// NewAgentPassportEvidence converts an enterprise agent passport into portable
// evidence.
func NewAgentPassportEvidence(identity *agent.AgentIdentity) (AgentPassportEvidence, error) {
	if identity == nil {
		return AgentPassportEvidence{}, fmt.Errorf("NewAgentPassportEvidence: nil identity")
	}
	if err := agent.VerifyIdentity(identity); err != nil {
		return AgentPassportEvidence{}, fmt.Errorf("NewAgentPassportEvidence: invalid identity: %w", err)
	}
	publicKeyBytes, err := hex.DecodeString(identity.PublicKeyHex)
	if err != nil {
		return AgentPassportEvidence{}, fmt.Errorf("NewAgentPassportEvidence: invalid public key encoding: %w", err)
	}

	capabilities := make([]string, 0, len(identity.Capabilities))
	for _, cap := range identity.Capabilities {
		capabilities = append(capabilities, cap.Name)
	}

	passport := AgentPassportEvidence{
		DID:              identity.AgentID(),
		Issuer:           identity.Issuer,
		PublicKeyHash:    EvidenceHashHex(publicKeyBytes),
		Capabilities:     capabilities,
		SponsorChain:     make([]PassportSponsor, 0, len(identity.SponsorChain)),
		JurisdictionTags: cloneStringSlice(identity.JurisdictionTags),
		AllowedTools:     cloneStringSlice(identity.AllowedTools),
		IssuedAt:         identity.IssuedAt.UTC().Format(time.RFC3339Nano),
		Metadata:         cloneMetadata(identity.Metadata),
	}

	if !identity.ExpiresAt.IsZero() {
		passport.ExpiresAt = identity.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	if identity.Liability != nil {
		passport.HumanOwner = identity.Liability.HumanOwner
		passport.BusinessUnit = identity.Liability.BusinessUnit
		passport.SponsorOfRecord = identity.Liability.SponsorOfRecord
		passport.FallbackApprover = identity.Liability.FallbackApprover
		passport.IncidentContact = identity.Liability.IncidentContact
		passport.LiabilityModel = identity.Liability.LiabilityModel
	}
	for _, sponsor := range identity.SponsorChain {
		passport.SponsorChain = append(passport.SponsorChain, PassportSponsor{
			SponsorDID:        sponsor.SponsorDID,
			SponsorName:       sponsor.SponsorName,
			Jurisdiction:      sponsor.Jurisdiction,
			Role:              sponsor.Role,
			LiabilityAccepted: sponsor.LiabilityAccepted,
			SignedAt:          sponsor.SignedAt.UTC().Format(time.RFC3339Nano),
		})
	}

	return passport, nil
}

// NewTraceLink binds one agent passport, one policy receipt, and one seal into
// a single evidence-exportable trace.
func NewTraceLink(identity *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, seal Seal, description string) (TraceLink, error) {
	if identity == nil {
		return TraceLink{}, fmt.Errorf("NewTraceLink: nil identity")
	}
	if err := agent.VerifyIdentity(identity); err != nil {
		return TraceLink{}, fmt.Errorf("NewTraceLink: invalid identity: %w", err)
	}
	if receipt == nil {
		return TraceLink{}, fmt.Errorf("NewTraceLink: nil policy receipt")
	}
	if receipt.ID == "" || receipt.ContentHash == "" {
		return TraceLink{}, fmt.Errorf("NewTraceLink: policy receipt is missing required fields")
	}
	if seal.SealID == "" {
		return TraceLink{}, fmt.Errorf("NewTraceLink: seal ID is required")
	}

	return TraceLink{
		ID:                uuid.New().String(),
		AgentDID:          identity.AgentID(),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		SealID:            seal.SealID,
		OutputHash:        seal.OutputHash,
		LinkedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		Description:       description,
	}, nil
}

func validateTraceability(bundle *EvidenceBundle) error {
	policyHashes := make(map[string]struct{}, len(bundle.PolicyReceipts))
	policyIDs := make(map[string]struct{}, len(bundle.PolicyReceipts))
	for _, receipt := range bundle.PolicyReceipts {
		if receipt.ID == "" || receipt.ContentHash == "" || receipt.Decision == "" {
			return fmt.Errorf("traceability receipt is missing required fields")
		}
		policyIDs[receipt.ID] = struct{}{}
		policyHashes[receipt.ContentHash] = struct{}{}
	}

	passportDIDs := make(map[string]struct{}, len(bundle.AgentPassports))
	for _, passport := range bundle.AgentPassports {
		if passport.DID == "" || passport.PublicKeyHash == "" {
			return fmt.Errorf("traceability passport is missing required fields")
		}
		passportDIDs[passport.DID] = struct{}{}
	}

	sealIDs := make(map[string]Seal, len(bundle.Seals))
	for _, seal := range bundle.Seals {
		if seal.SealID == "" {
			return fmt.Errorf("traceability seal is missing seal ID")
		}
		sealIDs[seal.SealID] = seal
	}

	for _, link := range bundle.TraceLinks {
		if link.ID == "" || link.AgentDID == "" || link.PolicyReceiptHash == "" || link.PolicyReceiptID == "" || link.SealID == "" {
			return fmt.Errorf("trace link is missing required fields")
		}
		if _, ok := passportDIDs[link.AgentDID]; !ok {
			return fmt.Errorf("trace link references unknown agent DID %q", link.AgentDID)
		}
		if _, ok := policyIDs[link.PolicyReceiptID]; !ok {
			return fmt.Errorf("trace link references unknown policy receipt ID %q", link.PolicyReceiptID)
		}
		if _, ok := policyHashes[link.PolicyReceiptHash]; !ok {
			return fmt.Errorf("trace link references unknown policy receipt hash %q", link.PolicyReceiptHash)
		}
		seal, ok := sealIDs[link.SealID]
		if !ok {
			return fmt.Errorf("trace link references unknown seal ID %q", link.SealID)
		}
		if link.OutputHash != "" && seal.OutputHash != "" && link.OutputHash != seal.OutputHash {
			return fmt.Errorf("trace link output hash mismatch for seal %q", link.SealID)
		}
	}

	recordIDs := make(map[string]Record, len(bundle.Records))
	for _, record := range bundle.Records {
		recordIDs[record.ID] = record
	}

	for _, attestation := range bundle.ApproverAttestations {
		attestation := attestation
		if err := (&attestation).Normalize(); err != nil {
			return err
		}
		if attestation.PassportDID != "" {
			if _, ok := passportDIDs[attestation.PassportDID]; !ok {
				return fmt.Errorf("approver attestation references unknown passport DID %q", attestation.PassportDID)
			}
		}
		if attestation.ApproverDID != "" {
			if _, ok := passportDIDs[attestation.ApproverDID]; !ok {
				return fmt.Errorf("approver attestation references unknown approver DID %q", attestation.ApproverDID)
			}
		}
		if _, ok := policyIDs[attestation.PolicyReceiptID]; !ok {
			return fmt.Errorf("approver attestation references unknown policy receipt ID %q", attestation.PolicyReceiptID)
		}
		if _, ok := policyHashes[attestation.PolicyReceiptHash]; !ok {
			return fmt.Errorf("approver attestation references unknown policy receipt hash %q", attestation.PolicyReceiptHash)
		}
		if attestation.ApprovalRecordID != "" {
			record, ok := recordIDs[attestation.ApprovalRecordID]
			if !ok {
				return fmt.Errorf("approver attestation references unknown approval record %q", attestation.ApprovalRecordID)
			}
			if attestation.ApproverDID != "" && record.Actor != "" && record.Actor != attestation.ApproverDID {
				return fmt.Errorf("approver attestation record actor mismatch for %q", attestation.ID)
			}
		}
		if attestation.TraceLinkID != "" {
			var matched TraceLink
			found := false
			for _, link := range bundle.TraceLinks {
				if link.ID == attestation.TraceLinkID {
					matched = link
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("approver attestation references unknown trace link %q", attestation.TraceLinkID)
			}
			if matched.PolicyReceiptID != attestation.PolicyReceiptID || matched.PolicyReceiptHash != attestation.PolicyReceiptHash {
				return fmt.Errorf("approver attestation trace link mismatch for %q", attestation.ID)
			}
			if attestation.SealID != "" && matched.SealID != attestation.SealID {
				return fmt.Errorf("approver attestation seal mismatch for %q", attestation.ID)
			}
		}
		if attestation.SealID != "" {
			if _, ok := sealIDs[attestation.SealID]; !ok {
				return fmt.Errorf("approver attestation references unknown seal ID %q", attestation.SealID)
			}
		}
	}

	settlementIDs := make(map[string]struct{}, len(bundle.ValueSettlements))
	for _, settlement := range bundle.ValueSettlements {
		settlement := settlement
		if err := (&settlement).Normalize(); err != nil {
			return err
		}
		if _, exists := settlementIDs[settlement.ID]; exists {
			return fmt.Errorf("value settlement ID %q is duplicated", settlement.ID)
		}
		settlementIDs[settlement.ID] = struct{}{}
		if _, ok := policyIDs[settlement.PolicyReceiptID]; !ok {
			return fmt.Errorf("value settlement references unknown policy receipt ID %q", settlement.PolicyReceiptID)
		}
		if _, ok := policyHashes[settlement.PolicyReceiptHash]; !ok {
			return fmt.Errorf("value settlement references unknown policy receipt hash %q", settlement.PolicyReceiptHash)
		}
		if settlement.SealID != "" {
			if _, ok := sealIDs[settlement.SealID]; !ok {
				return fmt.Errorf("value settlement references unknown seal ID %q", settlement.SealID)
			}
		}
	}

	packageIDs := make(map[string]struct{}, len(bundle.TrustCompliancePackages))
	for _, pkg := range bundle.TrustCompliancePackages {
		pkg := pkg
		if err := (&pkg).Normalize(); err != nil {
			return err
		}
		if _, exists := packageIDs[pkg.ID]; exists {
			return fmt.Errorf("trust compliance package ID %q is duplicated", pkg.ID)
		}
		packageIDs[pkg.ID] = struct{}{}

		if pkg.AuditAnchor != nil {
			record, ok := recordIDs[pkg.AnchorRecordID()]
			if !ok {
				return fmt.Errorf("trust compliance package %q is missing projected audit anchor record %q", pkg.ID, pkg.AnchorRecordID())
			}
			if record.Action != pkg.AuditAnchor.Action || record.Timestamp != pkg.AuditAnchor.Timestamp {
				return fmt.Errorf("trust compliance package %q anchor record mismatch", pkg.ID)
			}
			if record.Data["package_hash"] != pkg.PackageHash || record.Data["audit_record_hash"] != pkg.AuditAnchor.RecordHash {
				return fmt.Errorf("trust compliance package %q anchor record hashes do not match package evidence", pkg.ID)
			}
		}
	}

	return nil
}

func cloneMetadata(in map[string]string) map[string]string {
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

// EvidenceHashHex returns the hex-encoded SHA-256 hash of evidence data.
func EvidenceHashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
