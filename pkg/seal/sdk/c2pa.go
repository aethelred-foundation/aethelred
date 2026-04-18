package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/x/seal/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// C2PA Content Credentials bridge.
//
// The Coalition for Content Provenance and Authenticity (C2PA) defines an open
// standard for certifying the provenance of digital content. This bridge converts
// Aethelred Digital Seals to and from C2PA manifests, enabling interoperability
// with the broader content authenticity ecosystem.

// C2PAManifest represents a C2PA content credentials manifest.
type C2PAManifest struct {
	// ClaimGenerator identifies the software that generated the manifest.
	ClaimGenerator string `json:"claim_generator"`

	// ClaimGeneratorVersion is the version of the generator.
	ClaimGeneratorVersion string `json:"claim_generator_version"`

	// Title is a human-readable title for the content.
	Title string `json:"title"`

	// Format describes the content MIME type.
	Format string `json:"format"`

	// InstanceID is a unique identifier for this manifest instance.
	InstanceID string `json:"instance_id"`

	// Assertions contain the provenance claims.
	Assertions []C2PAAssertion `json:"assertions"`

	// Signature is the cryptographic signature over the manifest.
	Signature C2PASignature `json:"signature"`

	// CreatedAt is when the manifest was generated.
	CreatedAt time.Time `json:"created_at"`

	// Ingredients lists parent content (for derived content).
	Ingredients []C2PAIngredient `json:"ingredients,omitempty"`
}

// C2PAAssertion is a single claim within a C2PA manifest.
type C2PAAssertion struct {
	// Label identifies the assertion type (e.g., "c2pa.hash.data",
	// "aethelred.seal.verification").
	Label string `json:"label"`

	// Data is the assertion payload.
	Data map[string]interface{} `json:"data"`

	// Hash is the SHA-256 hash of the assertion data.
	Hash string `json:"hash"`

	// Algorithm is the hashing algorithm used.
	Algorithm string `json:"algorithm"`
}

// C2PASignature holds the manifest signature.
type C2PASignature struct {
	// Algorithm is the signing algorithm (e.g., "ecdsa-sha256").
	Algorithm string `json:"algorithm"`

	// CertificateChain is the PEM-encoded certificate chain.
	CertificateChain string `json:"certificate_chain,omitempty"`

	// SignatureBytes is the hex-encoded signature.
	SignatureBytes string `json:"signature_bytes"`

	// Timestamp is when the signature was created.
	Timestamp time.Time `json:"timestamp"`
}

// C2PAIngredient describes a parent content item.
type C2PAIngredient struct {
	// Title of the ingredient.
	Title string `json:"title"`

	// Format MIME type.
	Format string `json:"format,omitempty"`

	// InstanceID of the ingredient's manifest.
	InstanceID string `json:"instance_id,omitempty"`

	// Hash of the ingredient content.
	Hash string `json:"hash"`

	// Relationship to the current content (e.g., "parentOf", "componentOf").
	Relationship string `json:"relationship"`
}

// C2PABridge converts between Aethelred Digital Seals and C2PA manifests.
type C2PABridge struct {
	// generatorName identifies this bridge in C2PA manifests.
	generatorName string

	// generatorVersion is the version string.
	generatorVersion string
}

// NewC2PABridge creates a new C2PA bridge instance.
func NewC2PABridge() *C2PABridge {
	return &C2PABridge{
		generatorName:    "Aethelred Digital Seal SDK",
		generatorVersion: "1.0.0",
	}
}

// ToC2PAManifest converts a Digital Seal into a C2PA manifest.
// The seal's commitments, attestations, and proof become C2PA assertions.
func (b *C2PABridge) ToC2PAManifest(seal *types.DigitalSeal) (*C2PAManifest, error) {
	if seal == nil {
		return nil, fmt.Errorf("seal is nil")
	}

	manifest := &C2PAManifest{
		ClaimGenerator:        b.generatorName,
		ClaimGeneratorVersion: b.generatorVersion,
		Title:                 fmt.Sprintf("AI Computation Seal: %s", seal.GetPurpose()),
		Format:                "application/aethelred.seal+json",
		InstanceID:            seal.GetId(),
		CreatedAt:             time.Now().UTC(),
	}

	// Add commitment assertions
	manifest.Assertions = append(manifest.Assertions, b.buildCommitmentAssertion(seal))

	// Add verification type assertion
	manifest.Assertions = append(manifest.Assertions, b.buildVerificationAssertion(seal))

	// Add attestation assertions
	for _, att := range seal.GetTeeAttestations() {
		manifest.Assertions = append(manifest.Assertions, b.buildAttestationAssertion(att))
	}

	// Add proof assertion if present
	if seal.GetZkProof() != nil {
		manifest.Assertions = append(manifest.Assertions, b.buildProofAssertion(seal.GetZkProof()))
	}

	// Add regulatory info assertion if present
	if seal.GetRegulatoryInfo() != nil {
		manifest.Assertions = append(manifest.Assertions, b.buildRegulatoryAssertion(seal.GetRegulatoryInfo()))
	}

	// Add provenance assertion
	manifest.Assertions = append(manifest.Assertions, b.buildProvenanceAssertion(seal))

	// Build signature placeholder (actual signing depends on key management)
	manifest.Signature = C2PASignature{
		Algorithm: "ecdsa-sha256",
		Timestamp: time.Now().UTC(),
	}

	return manifest, nil
}

// FromC2PAManifest creates a Digital Seal from a C2PA manifest.
// This extracts commitment hashes, attestations, and proofs from the
// manifest's assertions to reconstruct the seal.
func (b *C2PABridge) FromC2PAManifest(manifest *C2PAManifest) (*types.DigitalSeal, error) {
	if manifest == nil {
		return nil, fmt.Errorf("manifest is nil")
	}

	seal := &types.DigitalSeal{
		Id:              manifest.InstanceID,
		Timestamp:       timestamppb.New(manifest.CreatedAt),
		TeeAttestations: make([]*types.TEEAttestation, 0),
		ValidatorSet:    make([]string, 0),
		Status:          types.SealStatusPending,
	}

	// Extract data from assertions
	for _, assertion := range manifest.Assertions {
		switch assertion.Label {
		case "aethelred.seal.commitments":
			if err := b.extractCommitments(assertion.Data, seal); err != nil {
				return nil, fmt.Errorf("failed to extract commitments: %w", err)
			}

		case "aethelred.seal.tee_attestation":
			att, err := b.extractAttestation(assertion.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to extract attestation: %w", err)
			}
			seal.TeeAttestations = append(seal.TeeAttestations, att)
			seal.ValidatorSet = append(seal.ValidatorSet, att.GetValidatorAddress())

		case "aethelred.seal.zkml_proof":
			proof, err := b.extractProof(assertion.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to extract proof: %w", err)
			}
			seal.ZkProof = proof

		case "aethelred.seal.provenance":
			b.extractProvenance(assertion.Data, seal)

		case "aethelred.seal.regulatory":
			seal.RegulatoryInfo = b.extractRegulatory(assertion.Data)
		}
	}

	// Activate if verification evidence is present
	if seal.IsVerified() {
		seal.Status = types.SealStatusActive
	}

	return seal, nil
}

// --- assertion builders ---

func (b *C2PABridge) buildCommitmentAssertion(seal *types.DigitalSeal) C2PAAssertion {
	data := map[string]interface{}{
		"model_commitment":  hex.EncodeToString(seal.GetModelCommitment()),
		"input_commitment":  hex.EncodeToString(seal.GetInputCommitment()),
		"output_commitment": hex.EncodeToString(seal.GetOutputCommitment()),
	}
	return C2PAAssertion{
		Label:     "aethelred.seal.commitments",
		Data:      data,
		Hash:      hashAssertionData(data),
		Algorithm: "sha256",
	}
}

func (b *C2PABridge) buildVerificationAssertion(seal *types.DigitalSeal) C2PAAssertion {
	data := map[string]interface{}{
		"verification_type": seal.GetVerificationType(),
		"status":            seal.GetStatus().String(),
		"attestation_count": len(seal.GetTeeAttestations()),
		"has_proof":         seal.GetZkProof() != nil,
	}
	return C2PAAssertion{
		Label:     "aethelred.seal.verification",
		Data:      data,
		Hash:      hashAssertionData(data),
		Algorithm: "sha256",
	}
}

func (b *C2PABridge) buildAttestationAssertion(att *types.TEEAttestation) C2PAAssertion {
	data := map[string]interface{}{
		"validator_address": att.GetValidatorAddress(),
		"platform":          att.GetPlatform(),
		"enclave_id":        att.GetEnclaveId(),
		"measurement":       hex.EncodeToString(att.GetMeasurement()),
	}
	return C2PAAssertion{
		Label:     "aethelred.seal.tee_attestation",
		Data:      data,
		Hash:      hashAssertionData(data),
		Algorithm: "sha256",
	}
}

func (b *C2PABridge) buildProofAssertion(proof *types.ZKMLProof) C2PAAssertion {
	data := map[string]interface{}{
		"proof_system":       proof.GetProofSystem(),
		"proof_bytes":        hex.EncodeToString(proof.GetProofBytes()),
		"public_inputs":      hex.EncodeToString(proof.GetPublicInputs()),
		"verifying_key_hash": hex.EncodeToString(proof.GetVerifyingKeyHash()),
		"circuit_hash":       hex.EncodeToString(proof.GetCircuitHash()),
	}
	return C2PAAssertion{
		Label:     "aethelred.seal.zkml_proof",
		Data:      data,
		Hash:      hashAssertionData(data),
		Algorithm: "sha256",
	}
}

func (b *C2PABridge) buildRegulatoryAssertion(ri *types.RegulatoryInfo) C2PAAssertion {
	data := map[string]interface{}{
		"data_classification":       ri.GetDataClassification(),
		"compliance_frameworks":     ri.GetComplianceFrameworks(),
		"jurisdiction_restrictions": ri.GetJurisdictionRestrictions(),
		"audit_required":            ri.GetAuditRequired(),
	}
	if ri.GetRetentionPeriod() != nil {
		data["retention_period_days"] = int64(ri.GetRetentionPeriod().AsDuration().Hours() / 24)
	}
	return C2PAAssertion{
		Label:     "aethelred.seal.regulatory",
		Data:      data,
		Hash:      hashAssertionData(data),
		Algorithm: "sha256",
	}
}

func (b *C2PABridge) buildProvenanceAssertion(seal *types.DigitalSeal) C2PAAssertion {
	data := map[string]interface{}{
		"requested_by": seal.GetRequestedBy(),
		"purpose":      seal.GetPurpose(),
		"block_height": seal.GetBlockHeight(),
	}
	if seal.GetTimestamp() != nil {
		data["timestamp"] = seal.GetTimestamp().AsTime().Format(time.RFC3339Nano)
	}
	return C2PAAssertion{
		Label:     "aethelred.seal.provenance",
		Data:      data,
		Hash:      hashAssertionData(data),
		Algorithm: "sha256",
	}
}

// --- assertion extractors ---

func (b *C2PABridge) extractCommitments(data map[string]interface{}, seal *types.DigitalSeal) error {
	modelHex, _ := data["model_commitment"].(string)
	inputHex, _ := data["input_commitment"].(string)
	outputHex, _ := data["output_commitment"].(string)

	var err error
	seal.ModelCommitment, err = hex.DecodeString(modelHex)
	if err != nil {
		return fmt.Errorf("invalid model_commitment: %w", err)
	}
	seal.InputCommitment, err = hex.DecodeString(inputHex)
	if err != nil {
		return fmt.Errorf("invalid input_commitment: %w", err)
	}
	seal.OutputCommitment, err = hex.DecodeString(outputHex)
	if err != nil {
		return fmt.Errorf("invalid output_commitment: %w", err)
	}
	return nil
}

func (b *C2PABridge) extractAttestation(data map[string]interface{}) (*types.TEEAttestation, error) {
	att := &types.TEEAttestation{}
	att.ValidatorAddress, _ = data["validator_address"].(string)
	att.Platform, _ = data["platform"].(string)
	att.EnclaveId, _ = data["enclave_id"].(string)

	if measHex, ok := data["measurement"].(string); ok {
		var err error
		att.Measurement, err = hex.DecodeString(measHex)
		if err != nil {
			return nil, fmt.Errorf("invalid measurement: %w", err)
		}
	}

	return att, nil
}

func (b *C2PABridge) extractProof(data map[string]interface{}) (*types.ZKMLProof, error) {
	proof := &types.ZKMLProof{}
	proof.ProofSystem, _ = data["proof_system"].(string)

	var err error
	if v, ok := data["proof_bytes"].(string); ok {
		proof.ProofBytes, err = hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid proof_bytes: %w", err)
		}
	}
	if v, ok := data["public_inputs"].(string); ok {
		proof.PublicInputs, err = hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid public_inputs: %w", err)
		}
	}
	if v, ok := data["verifying_key_hash"].(string); ok {
		proof.VerifyingKeyHash, err = hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid verifying_key_hash: %w", err)
		}
	}
	if v, ok := data["circuit_hash"].(string); ok {
		proof.CircuitHash, err = hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid circuit_hash: %w", err)
		}
	}

	return proof, nil
}

func (b *C2PABridge) extractProvenance(data map[string]interface{}, seal *types.DigitalSeal) {
	seal.RequestedBy, _ = data["requested_by"].(string)
	seal.Purpose, _ = data["purpose"].(string)
	if bh, ok := data["block_height"].(float64); ok {
		seal.BlockHeight = int64(bh)
	}
}

func (b *C2PABridge) extractRegulatory(data map[string]interface{}) *types.RegulatoryInfo {
	ri := &types.RegulatoryInfo{}
	ri.DataClassification, _ = data["data_classification"].(string)

	if frameworks, ok := data["compliance_frameworks"].([]interface{}); ok {
		for _, fw := range frameworks {
			if s, ok := fw.(string); ok {
				ri.ComplianceFrameworks = append(ri.ComplianceFrameworks, s)
			}
		}
	}
	if jurisdictions, ok := data["jurisdiction_restrictions"].([]interface{}); ok {
		for _, j := range jurisdictions {
			if s, ok := j.(string); ok {
				ri.JurisdictionRestrictions = append(ri.JurisdictionRestrictions, s)
			}
		}
	}
	if ar, ok := data["audit_required"].(bool); ok {
		ri.AuditRequired = ar
	}

	return ri
}

// hashAssertionData computes a SHA-256 hash over the assertion data for integrity.
func hashAssertionData(data map[string]interface{}) string {
	h := sha256.New()
	for k, v := range data {
		h.Write([]byte(k))
		h.Write([]byte(fmt.Sprintf("%v", v)))
	}
	return hex.EncodeToString(h.Sum(nil))
}
