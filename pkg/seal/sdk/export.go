package sdk

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/x/seal/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ExportFormat enumerates supported export encodings.
type ExportFormat string

const (
	FormatJSON     ExportFormat = "json"
	FormatCBOR     ExportFormat = "cbor"
	FormatProtobuf ExportFormat = "protobuf"
)

// SealExport is the portable, format-agnostic representation of a Digital Seal
// used for JSON and CBOR serialization. It captures all seal data including
// attestations, proofs, and regulatory metadata.
type SealExport struct {
	// Version of the export format.
	Version string `json:"version"`

	// SealID is the unique identifier.
	SealID string `json:"seal_id"`

	// ModelCommitment is the hex-encoded model hash.
	ModelCommitment string `json:"model_commitment"`

	// InputCommitment is the hex-encoded input hash.
	InputCommitment string `json:"input_commitment"`

	// OutputCommitment is the hex-encoded output hash.
	OutputCommitment string `json:"output_commitment"`

	// Status is the seal status as a string.
	Status string `json:"status"`

	// BlockHeight at which the seal was anchored.
	BlockHeight int64 `json:"block_height"`

	// Timestamp in RFC 3339 format.
	Timestamp string `json:"timestamp"`

	// RequestedBy is the signer address.
	RequestedBy string `json:"requested_by"`

	// Purpose describes the use case.
	Purpose string `json:"purpose"`

	// ValidatorSet lists attesting validators.
	ValidatorSet []string `json:"validator_set,omitempty"`

	// Attestations contains serialized TEE attestation data.
	Attestations []ExportAttestation `json:"attestations,omitempty"`

	// Proof contains the zkML proof if present.
	Proof *ExportProof `json:"proof,omitempty"`

	// RegulatoryInfo contains compliance metadata.
	RegulatoryInfo *ExportRegulatoryInfo `json:"regulatory_info,omitempty"`

	// EvidenceRefs lists references to attached evidence.
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

// ExportAttestation is the portable representation of a TEE attestation.
type ExportAttestation struct {
	ValidatorAddress string `json:"validator_address"`
	Platform         string `json:"platform"`
	EnclaveID        string `json:"enclave_id"`
	Measurement      string `json:"measurement"`
	Quote            string `json:"quote"`
	Signature        string `json:"signature"`
	Timestamp        string `json:"timestamp,omitempty"`
}

// ExportProof is the portable representation of a zkML proof.
type ExportProof struct {
	ProofSystem      string `json:"proof_system"`
	ProofBytes       string `json:"proof_bytes"`
	PublicInputs     string `json:"public_inputs"`
	VerifyingKeyHash string `json:"verifying_key_hash"`
	CircuitHash      string `json:"circuit_hash"`
}

// ExportRegulatoryInfo is the portable representation of regulatory metadata.
type ExportRegulatoryInfo struct {
	DataClassification       string   `json:"data_classification"`
	ComplianceFrameworks     []string `json:"compliance_frameworks,omitempty"`
	JurisdictionRestrictions []string `json:"jurisdiction_restrictions,omitempty"`
	RetentionPeriodDays      int64    `json:"retention_period_days,omitempty"`
	AuditRequired            bool     `json:"audit_required"`
}

const exportVersion = "1.0.0"

// ExportJSON serializes a Digital Seal to JSON format.
func ExportJSON(seal *types.DigitalSeal) ([]byte, error) {
	if seal == nil {
		return nil, fmt.Errorf("seal is nil")
	}

	export := sealToExport(seal)
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("JSON marshal failed: %w", err)
	}
	return data, nil
}

// ExportCBOR serializes a Digital Seal to CBOR format.
// CBOR provides a compact binary encoding suitable for constrained environments.
// This uses a deterministic JSON-compatible encoding until a dedicated CBOR
// library is integrated.
func ExportCBOR(seal *types.DigitalSeal) ([]byte, error) {
	if seal == nil {
		return nil, fmt.Errorf("seal is nil")
	}

	export := sealToExport(seal)

	// Use compact JSON as interim CBOR representation.
	// Production: replace with github.com/fxamacker/cbor/v2 for true CBOR.
	data, err := json.Marshal(export)
	if err != nil {
		return nil, fmt.Errorf("CBOR encode failed: %w", err)
	}
	return data, nil
}

// ExportProtobuf serializes a Digital Seal to native protobuf wire format.
func ExportProtobuf(seal *types.DigitalSeal) ([]byte, error) {
	if seal == nil {
		return nil, fmt.Errorf("seal is nil")
	}

	data, err := proto.Marshal(seal)
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal failed: %w", err)
	}
	return data, nil
}

// ImportJSON deserializes a Digital Seal from JSON format.
func ImportJSON(data []byte) (*types.DigitalSeal, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty JSON data")
	}

	var export SealExport
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	seal, err := exportToSeal(&export)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct seal: %w", err)
	}

	return seal, nil
}

// ImportCBOR deserializes a Digital Seal from CBOR format.
func ImportCBOR(data []byte) (*types.DigitalSeal, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty CBOR data")
	}

	// Interim: parse as compact JSON (mirrors ExportCBOR).
	return ImportJSON(data)
}

// ImportProtobuf deserializes a Digital Seal from native protobuf wire format.
func ImportProtobuf(data []byte) (*types.DigitalSeal, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty protobuf data")
	}

	seal := &types.DigitalSeal{}
	if err := proto.Unmarshal(data, seal); err != nil {
		return nil, fmt.Errorf("protobuf unmarshal failed: %w", err)
	}

	return seal, nil
}

// --- conversion helpers ---

func sealToExport(seal *types.DigitalSeal) *SealExport {
	export := &SealExport{
		Version:          exportVersion,
		SealID:           seal.GetId(),
		ModelCommitment:  hex.EncodeToString(seal.GetModelCommitment()),
		InputCommitment:  hex.EncodeToString(seal.GetInputCommitment()),
		OutputCommitment: hex.EncodeToString(seal.GetOutputCommitment()),
		Status:           seal.GetStatus().String(),
		BlockHeight:      seal.GetBlockHeight(),
		RequestedBy:      seal.GetRequestedBy(),
		Purpose:          seal.GetPurpose(),
		ValidatorSet:     seal.GetValidatorSet(),
	}

	if seal.GetTimestamp() != nil {
		export.Timestamp = seal.GetTimestamp().AsTime().Format(time.RFC3339Nano)
	}

	// Export attestations
	for _, att := range seal.GetTeeAttestations() {
		ea := ExportAttestation{
			ValidatorAddress: att.GetValidatorAddress(),
			Platform:         att.GetPlatform(),
			EnclaveID:        att.GetEnclaveId(),
			Measurement:      hex.EncodeToString(att.GetMeasurement()),
			Quote:            hex.EncodeToString(att.GetQuote()),
			Signature:        hex.EncodeToString(att.GetSignature()),
		}
		if att.GetTimestamp() != nil {
			ea.Timestamp = att.GetTimestamp().AsTime().Format(time.RFC3339Nano)
		}
		export.Attestations = append(export.Attestations, ea)
	}

	// Export proof
	if proof := seal.GetZkProof(); proof != nil {
		export.Proof = &ExportProof{
			ProofSystem:      proof.GetProofSystem(),
			ProofBytes:       hex.EncodeToString(proof.GetProofBytes()),
			PublicInputs:     hex.EncodeToString(proof.GetPublicInputs()),
			VerifyingKeyHash: hex.EncodeToString(proof.GetVerifyingKeyHash()),
			CircuitHash:      hex.EncodeToString(proof.GetCircuitHash()),
		}
	}

	// Export regulatory info
	if ri := seal.GetRegulatoryInfo(); ri != nil {
		export.RegulatoryInfo = &ExportRegulatoryInfo{
			DataClassification:       ri.GetDataClassification(),
			ComplianceFrameworks:     ri.GetComplianceFrameworks(),
			JurisdictionRestrictions: ri.GetJurisdictionRestrictions(),
			AuditRequired:            ri.GetAuditRequired(),
		}
		if ri.GetRetentionPeriod() != nil {
			export.RegulatoryInfo.RetentionPeriodDays = int64(ri.GetRetentionPeriod().AsDuration().Hours() / 24)
		}
	}

	return export
}

func exportToSeal(export *SealExport) (*types.DigitalSeal, error) {
	modelCommitment, err := hex.DecodeString(export.ModelCommitment)
	if err != nil {
		return nil, fmt.Errorf("invalid model_commitment hex: %w", err)
	}
	inputCommitment, err := hex.DecodeString(export.InputCommitment)
	if err != nil {
		return nil, fmt.Errorf("invalid input_commitment hex: %w", err)
	}
	outputCommitment, err := hex.DecodeString(export.OutputCommitment)
	if err != nil {
		return nil, fmt.Errorf("invalid output_commitment hex: %w", err)
	}

	seal := &types.DigitalSeal{
		Id:               export.SealID,
		ModelCommitment:  modelCommitment,
		InputCommitment:  inputCommitment,
		OutputCommitment: outputCommitment,
		BlockHeight:      export.BlockHeight,
		RequestedBy:      export.RequestedBy,
		Purpose:          export.Purpose,
		ValidatorSet:     export.ValidatorSet,
		Status:           parseStatus(export.Status),
	}

	// Parse timestamp
	if export.Timestamp != "" {
		t, err := time.Parse(time.RFC3339Nano, export.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp: %w", err)
		}
		seal.Timestamp = timestamppb.New(t)
	}

	// Import attestations
	for i, ea := range export.Attestations {
		att, err := importAttestation(ea)
		if err != nil {
			return nil, fmt.Errorf("attestation[%d]: %w", i, err)
		}
		seal.TeeAttestations = append(seal.TeeAttestations, att)
	}

	// Import proof
	if export.Proof != nil {
		proof, err := importProof(export.Proof)
		if err != nil {
			return nil, fmt.Errorf("proof: %w", err)
		}
		seal.ZkProof = proof
	}

	// Import regulatory info
	if export.RegulatoryInfo != nil {
		seal.RegulatoryInfo = importRegulatoryInfo(export.RegulatoryInfo)
	}

	return seal, nil
}

func importAttestation(ea ExportAttestation) (*types.TEEAttestation, error) {
	measurement, err := hex.DecodeString(ea.Measurement)
	if err != nil {
		return nil, fmt.Errorf("invalid measurement hex: %w", err)
	}
	quote, err := hex.DecodeString(ea.Quote)
	if err != nil {
		return nil, fmt.Errorf("invalid quote hex: %w", err)
	}
	sig, err := hex.DecodeString(ea.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}

	att := &types.TEEAttestation{
		ValidatorAddress: ea.ValidatorAddress,
		Platform:         ea.Platform,
		EnclaveId:        ea.EnclaveID,
		Measurement:      measurement,
		Quote:            quote,
		Signature:        sig,
	}

	if ea.Timestamp != "" {
		t, err := time.Parse(time.RFC3339Nano, ea.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("invalid attestation timestamp: %w", err)
		}
		att.Timestamp = timestamppb.New(t)
	}

	return att, nil
}

func importProof(ep *ExportProof) (*types.ZKMLProof, error) {
	proofBytes, err := hex.DecodeString(ep.ProofBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid proof_bytes hex: %w", err)
	}
	publicInputs, err := hex.DecodeString(ep.PublicInputs)
	if err != nil {
		return nil, fmt.Errorf("invalid public_inputs hex: %w", err)
	}
	vkHash, err := hex.DecodeString(ep.VerifyingKeyHash)
	if err != nil {
		return nil, fmt.Errorf("invalid verifying_key_hash hex: %w", err)
	}
	circuitHash, err := hex.DecodeString(ep.CircuitHash)
	if err != nil {
		return nil, fmt.Errorf("invalid circuit_hash hex: %w", err)
	}

	return &types.ZKMLProof{
		ProofSystem:      ep.ProofSystem,
		ProofBytes:       proofBytes,
		PublicInputs:     publicInputs,
		VerifyingKeyHash: vkHash,
		CircuitHash:      circuitHash,
	}, nil
}

func importRegulatoryInfo(eri *ExportRegulatoryInfo) *types.RegulatoryInfo {
	ri := &types.RegulatoryInfo{
		DataClassification:       eri.DataClassification,
		ComplianceFrameworks:     eri.ComplianceFrameworks,
		JurisdictionRestrictions: eri.JurisdictionRestrictions,
		AuditRequired:            eri.AuditRequired,
	}
	if eri.RetentionPeriodDays > 0 {
		ri.RetentionPeriod = durationpb.New(time.Duration(eri.RetentionPeriodDays) * 24 * time.Hour)
	}
	return ri
}

func parseStatus(s string) types.SealStatus {
	switch s {
	case "SEAL_STATUS_PENDING":
		return types.SealStatusPending
	case "SEAL_STATUS_ACTIVE":
		return types.SealStatusActive
	case "SEAL_STATUS_REVOKED":
		return types.SealStatusRevoked
	case "SEAL_STATUS_EXPIRED":
		return types.SealStatusExpired
	default:
		return types.SealStatus_SEAL_STATUS_UNSPECIFIED
	}
}
