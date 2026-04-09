package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/x/seal/types"
)

// EvidenceType enumerates the kinds of evidence that can be attached to a seal.
type EvidenceType string

const (
	EvidenceTypeTEEAttestation EvidenceType = "tee_attestation"
	EvidenceTypeZKMLProof      EvidenceType = "zkml_proof"
	EvidenceTypeAuditLog       EvidenceType = "audit_log"
	EvidenceTypeModelCard      EvidenceType = "model_card"
	EvidenceTypeDataSheet      EvidenceType = "data_sheet"
	EvidenceTypeComplianceDoc  EvidenceType = "compliance_doc"
	EvidenceTypeCustom         EvidenceType = "custom"
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
