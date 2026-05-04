package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
	"github.com/aethelred/aethelred/x/seal/types"
	"github.com/google/uuid"
)

// EvidenceType enumerates the kinds of evidence that can be attached to a seal.
type EvidenceType string

const (
	EvidenceTypeTEEAttestation         EvidenceType = "tee_attestation"
	EvidenceTypeZKMLProof              EvidenceType = "zkml_proof"
	EvidenceTypeAuditLog               EvidenceType = "audit_log"
	EvidenceTypeModelCard              EvidenceType = "model_card"
	EvidenceTypeDataSheet              EvidenceType = "data_sheet"
	EvidenceTypeComplianceDoc          EvidenceType = "compliance_doc"
	EvidenceTypeTrustCompliancePackage EvidenceType = "trust_compliance_package"
	EvidenceTypePolicyReceipt          EvidenceType = "policy_receipt"
	EvidenceTypeAgentPassport          EvidenceType = "agent_passport"
	EvidenceTypeTraceLink              EvidenceType = "trace_link"
	EvidenceTypeCustom                 EvidenceType = "custom"
)

// EvidenceAttachment represents a piece of evidence linked to a seal.
type EvidenceAttachment struct {
	// Type is the category of evidence.
	Type EvidenceType

	// Data is the raw evidence payload.
	Data []byte

	// Hash is the SHA-256 hash of Data.
	Hash []byte

	// Timestamp is when the evidence was created.
	Timestamp time.Time

	// Signer is the address of the entity that produced this evidence.
	Signer string

	// Description is a human-readable summary.
	Description string

	// MimeType describes the data format (e.g., "application/json").
	MimeType string
}

// EvidenceBundle is a collection of evidence attachments for export or archival.
type EvidenceBundle struct {
	// SealID is the seal this bundle pertains to.
	SealID string

	// SealHash is the integrity hash of the seal at the time of bundling.
	SealHash []byte

	// Attachments contains all evidence items.
	Attachments []EvidenceAttachment

	// CreatedAt is when the bundle was assembled.
	CreatedAt time.Time

	// BundleHash is the hash of the complete bundle contents.
	BundleHash []byte

	// Metadata holds optional key-value annotations.
	Metadata map[string]string
}

// Seal is a portable representation of a seal suitable for trace-linking and
// evidence export.
type Seal struct {
	SealID     string `json:"seal_id"`
	JobID      string `json:"job_id,omitempty"`
	OutputHash string `json:"output_hash,omitempty"`
}

// PolicyReceiptEvidence is a portable representation of a signed policy
// decision that can be serialized into an evidence attachment.
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

// PassportSponsor records one sponsor entry in an enterprise agent passport.
type PassportSponsor struct {
	SponsorDID        string `json:"sponsor_did"`
	SponsorName       string `json:"sponsor_name,omitempty"`
	Jurisdiction      string `json:"jurisdiction,omitempty"`
	Role              string `json:"role,omitempty"`
	LiabilityAccepted bool   `json:"liability_accepted"`
	SignedAt          string `json:"signed_at,omitempty"`
}

// AgentPassportEvidence captures the accountable identity context for a
// regulated autonomous agent.
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

// TraceLink binds one agent passport, one policy receipt, and one seal into a
// single evidence-exportable integrity record.
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

// EvidenceStore provides storage operations for evidence attachments.
// In production this would be backed by on-chain or off-chain storage.
type EvidenceStore interface {
	StoreEvidence(sealID string, attachment EvidenceAttachment) error
	GetEvidence(sealID string) ([]EvidenceAttachment, error)
}

// InMemoryEvidenceStore is a simple in-memory implementation for testing.
type InMemoryEvidenceStore struct {
	evidence map[string][]EvidenceAttachment
}

// NewInMemoryEvidenceStore creates a new in-memory evidence store.
func NewInMemoryEvidenceStore() *InMemoryEvidenceStore {
	return &InMemoryEvidenceStore{
		evidence: make(map[string][]EvidenceAttachment),
	}
}

// StoreEvidence stores an evidence attachment for a seal.
func (s *InMemoryEvidenceStore) StoreEvidence(sealID string, attachment EvidenceAttachment) error {
	s.evidence[sealID] = append(s.evidence[sealID], attachment)
	return nil
}

// GetEvidence retrieves all evidence for a seal.
func (s *InMemoryEvidenceStore) GetEvidence(sealID string) ([]EvidenceAttachment, error) {
	ev, ok := s.evidence[sealID]
	if !ok {
		return nil, nil
	}
	return ev, nil
}

// NewEvidenceAttachment creates a new evidence attachment with computed hash.
func NewEvidenceAttachment(evidenceType EvidenceType, data []byte, signer, description, mimeType string) EvidenceAttachment {
	h := sha256.Sum256(data)
	return EvidenceAttachment{
		Type:        evidenceType,
		Data:        data,
		Hash:        h[:],
		Timestamp:   time.Now().UTC(),
		Signer:      signer,
		Description: description,
		MimeType:    mimeType,
	}
}

// AttachEvidence attaches a piece of evidence to an existing seal.
func AttachEvidence(store EvidenceStore, sealID string, evidence EvidenceAttachment) error {
	if sealID == "" {
		return fmt.Errorf("seal ID is required")
	}
	if len(evidence.Data) == 0 {
		return fmt.Errorf("evidence data cannot be empty")
	}

	// Recompute hash to ensure integrity
	h := sha256.Sum256(evidence.Data)
	if len(evidence.Hash) > 0 && !bytesEqual(evidence.Hash, h[:]) {
		return fmt.Errorf("evidence hash mismatch: data has been tampered with")
	}
	evidence.Hash = h[:]

	if evidence.Timestamp.IsZero() {
		evidence.Timestamp = time.Now().UTC()
	}

	return store.StoreEvidence(sealID, evidence)
}

// GetEvidence retrieves all evidence attachments for a seal.
func GetEvidence(store EvidenceStore, sealID string) ([]EvidenceAttachment, error) {
	if sealID == "" {
		return nil, fmt.Errorf("seal ID is required")
	}
	return store.GetEvidence(sealID)
}

// CreateBundle assembles an exportable evidence bundle for a seal.
func CreateBundle(store EvidenceStore, seal *types.DigitalSeal) (*EvidenceBundle, error) {
	if seal == nil {
		return nil, fmt.Errorf("seal is required")
	}

	attachments, err := store.GetEvidence(seal.GetId())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve evidence: %w", err)
	}

	// Build bundle
	bundle := &EvidenceBundle{
		SealID:      seal.GetId(),
		Attachments: attachments,
		CreatedAt:   time.Now().UTC(),
		Metadata: map[string]string{
			"purpose":      seal.GetPurpose(),
			"requested_by": seal.GetRequestedBy(),
			"status":       seal.GetStatus().String(),
		},
	}

	// Include protocol-level evidence as attachments
	for _, att := range seal.GetTeeAttestations() {
		bundle.Attachments = append(bundle.Attachments, attestationToEvidence(att))
	}
	if seal.GetZkProof() != nil {
		bundle.Attachments = append(bundle.Attachments, proofToEvidence(seal.GetZkProof()))
	}

	// Compute seal hash at bundle time
	bundle.SealHash = computeSealHashForBundle(seal)

	// Compute bundle hash
	bundle.BundleHash = computeBundleHash(bundle)

	return bundle, nil
}

// VerifyBundle validates the integrity of an evidence bundle.
func VerifyBundle(bundle *EvidenceBundle) error {
	if bundle == nil {
		return fmt.Errorf("bundle is nil")
	}
	if bundle.SealID == "" {
		return fmt.Errorf("bundle has no seal ID")
	}

	// Verify each attachment hash
	for i, att := range bundle.Attachments {
		if len(att.Data) > 0 && len(att.Hash) > 0 {
			h := sha256.Sum256(att.Data)
			if !bytesEqual(h[:], att.Hash) {
				return fmt.Errorf("attachment[%d] hash mismatch: evidence may be corrupted", i)
			}
		}
	}

	// Verify bundle hash
	expectedHash := computeBundleHash(bundle)
	if len(bundle.BundleHash) > 0 && !bytesEqual(bundle.BundleHash, expectedHash) {
		return fmt.Errorf("bundle hash mismatch: bundle may be corrupted")
	}

	return nil
}

// NewPolicyReceiptEvidence converts a signed policy receipt into portable
// evidence suitable for JSON export and downstream attachment.
func NewPolicyReceiptEvidence(receipt *policy.SignedPolicyReceipt) (PolicyReceiptEvidence, error) {
	if receipt == nil {
		return PolicyReceiptEvidence{}, fmt.Errorf("NewPolicyReceiptEvidence: nil receipt")
	}
	if receipt.ID == "" || receipt.RequestID == "" || receipt.Signer == "" || receipt.ContentHash == "" || receipt.Decision == "" {
		return PolicyReceiptEvidence{}, fmt.Errorf("NewPolicyReceiptEvidence: receipt is missing required fields")
	}
	if receipt.EvaluatedAt.IsZero() {
		return PolicyReceiptEvidence{}, fmt.Errorf("NewPolicyReceiptEvidence: evaluated_at is required")
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

// NewAgentPassportEvidence converts an enterprise agent identity into portable
// evidence suitable for JSON export and downstream attachment.
func NewAgentPassportEvidence(identity *agent.AgentIdentity) (AgentPassportEvidence, error) {
	if identity == nil {
		return AgentPassportEvidence{}, fmt.Errorf("NewAgentPassportEvidence: nil identity")
	}
	if err := agent.VerifyIdentity(identity); err != nil {
		return AgentPassportEvidence{}, fmt.Errorf("NewAgentPassportEvidence: invalid identity: %w", err)
	}

	pubBytes, err := hex.DecodeString(identity.PublicKeyHex)
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
		PublicKeyHash:    EvidenceHashHex(pubBytes),
		Capabilities:     capabilities,
		SponsorChain:     make([]PassportSponsor, 0, len(identity.SponsorChain)),
		HumanOwner:       "",
		BusinessUnit:     "",
		SponsorOfRecord:  "",
		FallbackApprover: "",
		IncidentContact:  "",
		LiabilityModel:   "",
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
// a single evidence-exportable integrity record.
func NewTraceLink(identity *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, seal Seal, description string) (TraceLink, error) {
	if identity == nil {
		return TraceLink{}, fmt.Errorf("NewTraceLink: nil identity")
	}
	if receipt == nil {
		return TraceLink{}, fmt.Errorf("NewTraceLink: nil policy receipt")
	}
	if identity.AgentID() == "" {
		return TraceLink{}, fmt.Errorf("NewTraceLink: agent DID is required")
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

// NewPolicyReceiptAttachment converts a signed policy receipt into a JSON
// evidence attachment with a stable policy receipt evidence type.
func NewPolicyReceiptAttachment(receipt *policy.SignedPolicyReceipt) (EvidenceAttachment, error) {
	evidence, err := NewPolicyReceiptEvidence(receipt)
	if err != nil {
		return EvidenceAttachment{}, err
	}
	data, err := json.Marshal(evidence)
	if err != nil {
		return EvidenceAttachment{}, fmt.Errorf("NewPolicyReceiptAttachment: marshal evidence: %w", err)
	}
	return NewEvidenceAttachment(EvidenceTypePolicyReceipt, data, evidence.Signer, "Signed policy receipt", "application/json"), nil
}

// NewAgentPassportAttachment converts an enterprise agent identity into a JSON
// evidence attachment with a stable passport evidence type.
func NewAgentPassportAttachment(identity *agent.AgentIdentity) (EvidenceAttachment, error) {
	evidence, err := NewAgentPassportEvidence(identity)
	if err != nil {
		return EvidenceAttachment{}, err
	}
	data, err := json.Marshal(evidence)
	if err != nil {
		return EvidenceAttachment{}, fmt.Errorf("NewAgentPassportAttachment: marshal evidence: %w", err)
	}
	return NewEvidenceAttachment(EvidenceTypeAgentPassport, data, evidence.DID, "Enterprise agent passport", "application/json"), nil
}

// NewTraceLinkAttachment converts a trace link into a JSON evidence attachment
// suitable for storing alongside other seal evidence.
func NewTraceLinkAttachment(link TraceLink) (EvidenceAttachment, error) {
	if link.ID == "" || link.AgentDID == "" || link.PolicyReceiptID == "" || link.PolicyReceiptHash == "" || link.SealID == "" || link.LinkedAt == "" {
		return EvidenceAttachment{}, fmt.Errorf("NewTraceLinkAttachment: trace link is missing required fields")
	}
	data, err := json.Marshal(link)
	if err != nil {
		return EvidenceAttachment{}, fmt.Errorf("NewTraceLinkAttachment: marshal evidence: %w", err)
	}
	return NewEvidenceAttachment(EvidenceTypeTraceLink, data, link.AgentDID, "Trace link between policy receipt, passport, and seal", "application/json"), nil
}

// --- internal helpers ---

func attestationToEvidence(att *types.TEEAttestation) EvidenceAttachment {
	// Build a deterministic representation of the attestation
	data := make([]byte, 0, 256)
	data = append(data, []byte(att.GetValidatorAddress())...)
	data = append(data, []byte(att.GetPlatform())...)
	data = append(data, []byte(att.GetEnclaveId())...)
	data = append(data, att.GetMeasurement()...)
	data = append(data, att.GetQuote()...)
	data = append(data, att.GetSignature()...)

	h := sha256.Sum256(data)

	var ts time.Time
	if att.GetTimestamp() != nil {
		ts = att.GetTimestamp().AsTime()
	} else {
		ts = time.Now().UTC()
	}

	return EvidenceAttachment{
		Type:        EvidenceTypeTEEAttestation,
		Data:        data,
		Hash:        h[:],
		Timestamp:   ts,
		Signer:      att.GetValidatorAddress(),
		Description: fmt.Sprintf("TEE attestation from %s on %s", att.GetValidatorAddress(), att.GetPlatform()),
		MimeType:    "application/octet-stream",
	}
}

func proofToEvidence(proof *types.ZKMLProof) EvidenceAttachment {
	data := make([]byte, 0, len(proof.GetProofBytes())+128)
	data = append(data, []byte(proof.GetProofSystem())...)
	data = append(data, proof.GetProofBytes()...)
	data = append(data, proof.GetPublicInputs()...)
	data = append(data, proof.GetVerifyingKeyHash()...)
	data = append(data, proof.GetCircuitHash()...)

	h := sha256.Sum256(data)

	return EvidenceAttachment{
		Type:        EvidenceTypeZKMLProof,
		Data:        data,
		Hash:        h[:],
		Timestamp:   time.Now().UTC(),
		Description: fmt.Sprintf("zkML proof using %s", proof.GetProofSystem()),
		MimeType:    "application/octet-stream",
	}
}

func computeSealHashForBundle(seal *types.DigitalSeal) []byte {
	h := sha256.New()
	h.Write([]byte(seal.GetId()))
	h.Write(seal.GetModelCommitment())
	h.Write(seal.GetInputCommitment())
	h.Write(seal.GetOutputCommitment())
	h.Write([]byte(seal.GetRequestedBy()))
	h.Write([]byte(seal.GetPurpose()))
	return h.Sum(nil)
}

func computeBundleHash(bundle *EvidenceBundle) []byte {
	h := sha256.New()
	h.Write([]byte(bundle.SealID))
	h.Write(bundle.SealHash)
	for _, att := range bundle.Attachments {
		h.Write(att.Hash)
	}
	h.Write([]byte(bundle.CreatedAt.Format(time.RFC3339Nano)))
	return h.Sum(nil)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// EvidenceHashHex returns the hex-encoded SHA-256 hash of evidence data.
func EvidenceHashHex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
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
