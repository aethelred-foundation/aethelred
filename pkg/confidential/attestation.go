package confidential

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/evidence"
	sealsdk "github.com/aethelred/aethelred/pkg/seal/sdk"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// Attestor produces TEE attestations bound to a concrete workflow execution.
type Attestor interface {
	Attest(ctx context.Context, req AttestationRequest) ([]*sealtypes.TEEAttestation, error)
}

// AttestationRequest captures the exact execution boundary that must be bound
// into a confidential-execution quote.
type AttestationRequest struct {
	JobID             string            `json:"job_id"`
	Workflow          string            `json:"workflow"`
	Stage             string            `json:"stage"`
	Purpose           string            `json:"purpose,omitempty"`
	Resource          string            `json:"resource,omitempty"`
	Jurisdiction      string            `json:"jurisdiction,omitempty"`
	InputHash         []byte            `json:"input_hash,omitempty"`
	OutputHash        []byte            `json:"output_hash,omitempty"`
	PolicyReceiptID   string            `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string            `json:"policy_receipt_hash,omitempty"`
	ReceiptChainHash  string            `json:"receipt_chain_hash,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// BindingHash returns the canonical hash of the execution boundary.
func (r AttestationRequest) BindingHash() string {
	canonical := struct {
		JobID             string            `json:"job_id"`
		Workflow          string            `json:"workflow"`
		Stage             string            `json:"stage"`
		Purpose           string            `json:"purpose,omitempty"`
		Resource          string            `json:"resource,omitempty"`
		Jurisdiction      string            `json:"jurisdiction,omitempty"`
		InputHash         string            `json:"input_hash,omitempty"`
		OutputHash        string            `json:"output_hash,omitempty"`
		PolicyReceiptID   string            `json:"policy_receipt_id,omitempty"`
		PolicyReceiptHash string            `json:"policy_receipt_hash,omitempty"`
		ReceiptChainHash  string            `json:"receipt_chain_hash,omitempty"`
		Metadata          map[string]string `json:"metadata,omitempty"`
	}{
		JobID:             strings.TrimSpace(r.JobID),
		Workflow:          strings.TrimSpace(r.Workflow),
		Stage:             strings.TrimSpace(r.Stage),
		Purpose:           strings.TrimSpace(r.Purpose),
		Resource:          strings.TrimSpace(r.Resource),
		Jurisdiction:      strings.TrimSpace(r.Jurisdiction),
		InputHash:         hex.EncodeToString(r.InputHash),
		OutputHash:        hex.EncodeToString(r.OutputHash),
		PolicyReceiptID:   strings.TrimSpace(r.PolicyReceiptID),
		PolicyReceiptHash: strings.TrimSpace(r.PolicyReceiptHash),
		ReceiptChainHash:  strings.TrimSpace(r.ReceiptChainHash),
		Metadata:          cloneStringMap(r.Metadata),
	}
	payload, _ := json.Marshal(canonical)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// QuoteEnvelope is the portable, verifier-readable quote wrapper used for
// workflow-bound confidential execution.
type QuoteEnvelope struct {
	Version           string            `json:"version"`
	Workflow          string            `json:"workflow"`
	Stage             string            `json:"stage"`
	JobID             string            `json:"job_id"`
	Purpose           string            `json:"purpose,omitempty"`
	Resource          string            `json:"resource,omitempty"`
	Jurisdiction      string            `json:"jurisdiction,omitempty"`
	InputHash         string            `json:"input_hash,omitempty"`
	OutputHash        string            `json:"output_hash,omitempty"`
	PolicyReceiptID   string            `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string            `json:"policy_receipt_hash,omitempty"`
	ReceiptChainHash  string            `json:"receipt_chain_hash,omitempty"`
	BindingHash       string            `json:"binding_hash"`
	ValidatorAddress  string            `json:"validator_address,omitempty"`
	Platform          string            `json:"platform,omitempty"`
	EnclaveID         string            `json:"enclave_id,omitempty"`
	Measurement       string            `json:"measurement,omitempty"`
	PlatformQuote     []byte            `json:"platform_quote,omitempty"`
	UserDataHash      string            `json:"user_data_hash,omitempty"`
	NonceHash         string            `json:"nonce_hash,omitempty"`
	GeneratedAt       string            `json:"generated_at,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// BuildQuoteEnvelope constructs a canonical bound-quote envelope for one
// confidential execution event.
func BuildQuoteEnvelope(req AttestationRequest, att *sealtypes.TEEAttestation, platformQuote []byte, userData []byte, nonce []byte, generatedAt time.Time) QuoteEnvelope {
	envelope := QuoteEnvelope{
		Version:           "1.0.0",
		Workflow:          strings.TrimSpace(req.Workflow),
		Stage:             strings.TrimSpace(req.Stage),
		JobID:             strings.TrimSpace(req.JobID),
		Purpose:           strings.TrimSpace(req.Purpose),
		Resource:          strings.TrimSpace(req.Resource),
		Jurisdiction:      strings.TrimSpace(req.Jurisdiction),
		InputHash:         hex.EncodeToString(req.InputHash),
		OutputHash:        hex.EncodeToString(req.OutputHash),
		PolicyReceiptID:   strings.TrimSpace(req.PolicyReceiptID),
		PolicyReceiptHash: strings.TrimSpace(req.PolicyReceiptHash),
		ReceiptChainHash:  strings.TrimSpace(req.ReceiptChainHash),
		BindingHash:       req.BindingHash(),
		Metadata:          cloneStringMap(req.Metadata),
		PlatformQuote:     append([]byte(nil), platformQuote...),
	}
	if att != nil {
		envelope.ValidatorAddress = strings.TrimSpace(att.GetValidatorAddress())
		envelope.Platform = strings.TrimSpace(att.GetPlatform())
		envelope.EnclaveID = strings.TrimSpace(att.GetEnclaveId())
		envelope.Measurement = hex.EncodeToString(att.GetMeasurement())
	}
	if len(userData) > 0 {
		sum := sha256.Sum256(userData)
		envelope.UserDataHash = hex.EncodeToString(sum[:])
	}
	if len(nonce) > 0 {
		sum := sha256.Sum256(nonce)
		envelope.NonceHash = hex.EncodeToString(sum[:])
	}
	if !generatedAt.IsZero() {
		envelope.GeneratedAt = generatedAt.UTC().Format(time.RFC3339Nano)
	}
	return envelope
}

// EncodeQuoteEnvelope serializes the bound quote wrapper.
func EncodeQuoteEnvelope(envelope QuoteEnvelope) ([]byte, error) {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("confidential/attestation: marshal quote envelope: %w", err)
	}
	return payload, nil
}

// DecodeQuoteEnvelope parses a bound quote wrapper.
func DecodeQuoteEnvelope(quote []byte) (*QuoteEnvelope, error) {
	if len(quote) == 0 {
		return nil, fmt.Errorf("confidential/attestation: quote envelope is empty")
	}
	var envelope QuoteEnvelope
	if err := json.Unmarshal(quote, &envelope); err != nil {
		return nil, fmt.Errorf("confidential/attestation: decode quote envelope: %w", err)
	}
	return &envelope, nil
}

// Policy defines workflow-grade attestation verification requirements.
type Policy struct {
	Required                 bool
	MinimumValidAttestations int
	TrustedPlatforms         []string
	MaxAttestationAge        time.Duration
	AllowedEnclaveIDs        []string
	AllowedMeasurements      []string
	RequireQuoteBinding      bool
	TrustedValidatorKeys     map[string]*ecdsa.PublicKey
}

// VerificationSummary is the portable operator-facing summary of one
// confidential-execution verification pass.
type VerificationSummary struct {
	Required            bool      `json:"required"`
	Verified            bool      `json:"verified"`
	Present             int       `json:"present"`
	Checked             int       `json:"checked"`
	Valid               int       `json:"valid"`
	Invalid             int       `json:"invalid"`
	MinimumRequired     int       `json:"minimum_required"`
	Platforms           []string  `json:"platforms,omitempty"`
	Validators          []string  `json:"validators,omitempty"`
	EnclaveIDs          []string  `json:"enclave_ids,omitempty"`
	AllowedMeasurements []string  `json:"allowed_measurements,omitempty"`
	BindingHash         string    `json:"binding_hash,omitempty"`
	BoundOutputHash     string    `json:"bound_output_hash,omitempty"`
	VerifiedAt          time.Time `json:"verified_at"`
	Failures            []string  `json:"failures,omitempty"`
}

// VerifyAttestations performs strict workflow-bound attestation validation.
func VerifyAttestations(attestations []*sealtypes.TEEAttestation, req AttestationRequest, policy Policy) (VerificationSummary, error) {
	policy = normalizePolicy(policy)
	summary := VerificationSummary{
		Required:            policy.Required,
		Present:             len(attestations),
		MinimumRequired:     minimumRequired(policy, len(attestations)),
		AllowedMeasurements: append([]string(nil), policy.AllowedMeasurements...),
		BindingHash:         req.BindingHash(),
		BoundOutputHash:     hex.EncodeToString(req.OutputHash),
		VerifiedAt:          time.Now().UTC(),
	}

	if len(attestations) == 0 {
		if summary.MinimumRequired > 0 {
			summary.Failures = append(summary.Failures, "no TEE attestations were provided")
			return summary, fmt.Errorf("confidential/attestation: %s", summary.Failures[0])
		}
		return summary, nil
	}

	verifier := sealsdk.NewVerifier(policy.TrustedValidatorKeys,
		sealsdk.WithTrustedPlatforms(policy.TrustedPlatforms),
		sealsdk.WithMaxAttestationAge(policy.MaxAttestationAge),
	)

	for idx, att := range attestations {
		if att == nil {
			summary.Invalid++
			summary.Failures = append(summary.Failures, fmt.Sprintf("attestation %d is nil", idx))
			continue
		}
		summary.Checked++
		if err := verifier.ValidateAttestation(att); err != nil {
			summary.Invalid++
			summary.Failures = append(summary.Failures, fmt.Sprintf("attestation %d failed baseline verification: %v", idx, err))
			continue
		}
		if len(policy.AllowedEnclaveIDs) > 0 && !containsString(policy.AllowedEnclaveIDs, att.GetEnclaveId()) {
			summary.Invalid++
			summary.Failures = append(summary.Failures, fmt.Sprintf("attestation %d enclave %q is not allowlisted", idx, att.GetEnclaveId()))
			continue
		}
		measurementHex := hex.EncodeToString(att.GetMeasurement())
		if len(policy.AllowedMeasurements) > 0 && !containsString(policy.AllowedMeasurements, measurementHex) {
			summary.Invalid++
			summary.Failures = append(summary.Failures, fmt.Sprintf("attestation %d measurement %q is not allowlisted", idx, measurementHex))
			continue
		}
		if policy.RequireQuoteBinding {
			envelope, err := DecodeQuoteEnvelope(att.GetQuote())
			if err != nil {
				summary.Invalid++
				summary.Failures = append(summary.Failures, fmt.Sprintf("attestation %d quote binding is invalid: %v", idx, err))
				continue
			}
			if err := validateQuoteEnvelope(envelope, att, req); err != nil {
				summary.Invalid++
				summary.Failures = append(summary.Failures, fmt.Sprintf("attestation %d quote binding failed: %v", idx, err))
				continue
			}
		}
		summary.Valid++
		summary.Platforms = append(summary.Platforms, att.GetPlatform())
		summary.Validators = append(summary.Validators, att.GetValidatorAddress())
		summary.EnclaveIDs = append(summary.EnclaveIDs, att.GetEnclaveId())
	}

	summary.Platforms = sortedUniqueStrings(summary.Platforms)
	summary.Validators = sortedUniqueStrings(summary.Validators)
	summary.EnclaveIDs = sortedUniqueStrings(summary.EnclaveIDs)
	summary.Verified = summary.Valid >= summary.MinimumRequired
	if !summary.Verified {
		return summary, fmt.Errorf("confidential/attestation: only %d/%d valid attestations", summary.Valid, summary.MinimumRequired)
	}
	return summary, nil
}

// BuildEvidenceAttestations converts validated seal attestations into canonical
// evidence artifacts that can travel through the control-ledger export path.
func BuildEvidenceAttestations(attestations []*sealtypes.TEEAttestation, req AttestationRequest, summary VerificationSummary, trustedKeys map[string]*ecdsa.PublicKey) []evidence.Attestation {
	items := make([]evidence.Attestation, 0, len(attestations))
	bindingHash := req.BindingHash()
	for idx, att := range attestations {
		if att == nil {
			continue
		}
		metadata := map[string]string{
			"workflow":            strings.TrimSpace(req.Workflow),
			"stage":               strings.TrimSpace(req.Stage),
			"job_id":              strings.TrimSpace(req.JobID),
			"purpose":             strings.TrimSpace(req.Purpose),
			"resource":            strings.TrimSpace(req.Resource),
			"jurisdiction":        strings.TrimSpace(req.Jurisdiction),
			"validator_address":   strings.TrimSpace(att.GetValidatorAddress()),
			"binding_hash":        bindingHash,
			"output_hash":         hex.EncodeToString(req.OutputHash),
			"policy_receipt_id":   strings.TrimSpace(req.PolicyReceiptID),
			"policy_receipt_hash": strings.TrimSpace(req.PolicyReceiptHash),
			"receipt_chain_hash":  strings.TrimSpace(req.ReceiptChainHash),
			"verified":            fmt.Sprintf("%t", summary.Verified),
		}
		if att.GetQuote() != nil {
			quoteSum := sha256.Sum256(att.GetQuote())
			metadata["quote_hash"] = hex.EncodeToString(quoteSum[:])
		}
		if key := trustedKeys[strings.TrimSpace(att.GetValidatorAddress())]; key != nil {
			if encoded, err := x509.MarshalPKIXPublicKey(key); err == nil {
				metadata["validator_public_key"] = hex.EncodeToString(encoded)
			}
		}
		if envelope, err := DecodeQuoteEnvelope(att.GetQuote()); err == nil {
			if envelope.GeneratedAt != "" {
				metadata["generated_at"] = envelope.GeneratedAt
			}
			if envelope.UserDataHash != "" {
				metadata["tee_user_data_hash"] = envelope.UserDataHash
			}
			if envelope.NonceHash != "" {
				metadata["tee_nonce_hash"] = envelope.NonceHash
			}
		}
		items = append(items, evidence.Attestation{
			ID:          fmt.Sprintf("tee-attestation:%s:%s:%02d", sanitizeIDComponent(req.JobID), sanitizeIDComponent(req.Stage), idx+1),
			Type:        "tee",
			Platform:    att.GetPlatform(),
			EnclaveID:   att.GetEnclaveId(),
			Measurement: hex.EncodeToString(att.GetMeasurement()),
			Timestamp:   att.GetTimestamp().AsTime().UTC().Format(time.RFC3339Nano),
			Metadata:    metadata,
		})
	}
	return items
}

func normalizePolicy(policy Policy) Policy {
	if policy.MinimumValidAttestations <= 0 {
		policy.MinimumValidAttestations = 1
	}
	if len(policy.TrustedPlatforms) == 0 {
		policy.TrustedPlatforms = sealsdk.DefaultTrustedPlatforms()
	}
	if policy.MaxAttestationAge <= 0 {
		policy.MaxAttestationAge = 24 * time.Hour
	}
	if !policy.RequireQuoteBinding {
		policy.RequireQuoteBinding = true
	}
	if policy.TrustedValidatorKeys == nil {
		policy.TrustedValidatorKeys = make(map[string]*ecdsa.PublicKey)
	}
	policy.AllowedEnclaveIDs = sortedUniqueStrings(policy.AllowedEnclaveIDs)
	policy.AllowedMeasurements = sortedUniqueStrings(policy.AllowedMeasurements)
	return policy
}

func minimumRequired(policy Policy, present int) int {
	if policy.Required {
		return policy.MinimumValidAttestations
	}
	if present > 0 {
		return 1
	}
	return 0
}

func validateQuoteEnvelope(envelope *QuoteEnvelope, att *sealtypes.TEEAttestation, req AttestationRequest) error {
	if envelope == nil {
		return fmt.Errorf("missing quote envelope")
	}
	if strings.TrimSpace(envelope.Version) == "" {
		return fmt.Errorf("quote envelope version is required")
	}
	if envelope.BindingHash != req.BindingHash() {
		return fmt.Errorf("binding hash mismatch")
	}
	if envelope.Workflow != strings.TrimSpace(req.Workflow) {
		return fmt.Errorf("workflow mismatch: got %q want %q", envelope.Workflow, req.Workflow)
	}
	if envelope.Stage != strings.TrimSpace(req.Stage) {
		return fmt.Errorf("stage mismatch: got %q want %q", envelope.Stage, req.Stage)
	}
	if envelope.JobID != strings.TrimSpace(req.JobID) {
		return fmt.Errorf("job ID mismatch: got %q want %q", envelope.JobID, req.JobID)
	}
	if envelope.OutputHash != hex.EncodeToString(req.OutputHash) {
		return fmt.Errorf("output hash mismatch")
	}
	if envelope.InputHash != hex.EncodeToString(req.InputHash) {
		return fmt.Errorf("input hash mismatch")
	}
	if envelope.PolicyReceiptID != strings.TrimSpace(req.PolicyReceiptID) {
		return fmt.Errorf("policy receipt ID mismatch")
	}
	if envelope.PolicyReceiptHash != strings.TrimSpace(req.PolicyReceiptHash) {
		return fmt.Errorf("policy receipt hash mismatch")
	}
	if envelope.ReceiptChainHash != strings.TrimSpace(req.ReceiptChainHash) {
		return fmt.Errorf("receipt chain hash mismatch")
	}
	if envelope.Platform != att.GetPlatform() {
		return fmt.Errorf("platform mismatch")
	}
	if envelope.EnclaveID != att.GetEnclaveId() {
		return fmt.Errorf("enclave ID mismatch")
	}
	if envelope.ValidatorAddress != att.GetValidatorAddress() {
		return fmt.Errorf("validator address mismatch")
	}
	if envelope.Measurement != hex.EncodeToString(att.GetMeasurement()) {
		return fmt.Errorf("measurement mismatch")
	}
	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func containsString(items []string, value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	for _, item := range items {
		if strings.TrimSpace(strings.ToLower(item)) == value {
			return true
		}
	}
	return false
}

func sortedUniqueStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		set[item] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func sanitizeIDComponent(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(":", "-", "/", "-", " ", "-", "_", "-")
	value = replacer.Replace(value)
	return value
}
