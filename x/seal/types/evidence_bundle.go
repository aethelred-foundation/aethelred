package types

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SchemaVersionV1 is the canonical schema version for enterprise evidence bundles.
const SchemaVersionV1 = "1.0.0"

// EvidenceBundle is the top-level structure for enterprise hybrid job evidence bundles.
// It conforms to docs/api/evidence-bundle-v1.schema.json.
type EvidenceBundle struct {
	SchemaVersion   string          `json:"schema_version"`
	BundleID        string          `json:"bundle_id"`
	JobID           string          `json:"job_id"`
	Timestamp       string          `json:"timestamp"`
	ModelHash       string          `json:"model_hash"`
	CircuitHash     string          `json:"circuit_hash"`
	VerifyingKeyHash string         `json:"verifying_key_hash"`
	TEEEvidence     TEEEvidenceV1   `json:"tee_evidence"`
	ZKMLEvidence    ZKMLEvidenceV1  `json:"zkml_evidence"`
	Region          string          `json:"region"`
	Operator        string          `json:"operator"`
	PolicyDecision  PolicyDecision  `json:"policy_decision"`
	Metadata        map[string]any  `json:"metadata,omitempty"`
}

// TEEEvidenceV1 contains TEE attestation evidence matching the v1 schema.
type TEEEvidenceV1 struct {
	Platform    string `json:"platform"`
	EnclaveID   string `json:"enclave_id"`
	Measurement string `json:"measurement"`
	Quote       string `json:"quote"`
	Nonce       string `json:"nonce"`
}

// ZKMLEvidenceV1 contains zkML proof evidence matching the v1 schema.
type ZKMLEvidenceV1 struct {
	ProofSystem      string `json:"proof_system"`
	ProofBytes       string `json:"proof_bytes"`
	PublicInputs     string `json:"public_inputs"`
	OutputCommitment string `json:"output_commitment"`
}

// PolicyDecision records the policy engine output for enterprise bundles.
type PolicyDecision struct {
	Mode            string `json:"mode"`
	RequireBoth     bool   `json:"require_both"`
	FallbackAllowed bool   `json:"fallback_allowed"`
	PolicyVersion   string `json:"policy_version,omitempty"`
}

// Valid TEE platform values per schema v1.
var validTEEPlatforms = map[string]bool{
	"sgx":     true,
	"nitro":   true,
	"sev-snp": true,
}

// Valid proof system values per schema v1.
var validProofSystems = map[string]bool{
	"groth16": true,
	"plonk":   true,
	"ezkl":    true,
	"halo2":   true,
	"stark":   true,
}

// hexSHA256Re matches exactly 64 lowercase hex characters.
var hexSHA256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// zeroHash is the 64-character all-zero hash, which is explicitly forbidden.
const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// uuidV4Re matches a UUID v4 string.
var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// operatorRe matches bech32 addresses with the aethel prefix.
var operatorRe = regexp.MustCompile(`^aethel1[a-z0-9]{38,58}$`)

// base64Re matches standard base64-encoded strings (RFC 4648 Section 4).
var base64Re = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)

// jobIDRe matches 64-character hex strings (uppercase or lowercase).
var jobIDRe = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)

// Validate checks all required fields and format constraints defined by the v1 schema.
func (b *EvidenceBundle) Validate() error {
	// Schema version
	if b.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("schema_version must be %q, got %q", SchemaVersionV1, b.SchemaVersion)
	}

	// Bundle ID (UUID v4)
	if !uuidV4Re.MatchString(b.BundleID) {
		return fmt.Errorf("bundle_id must be a valid UUID v4, got %q", b.BundleID)
	}

	// Job ID (64-char hex)
	if !jobIDRe.MatchString(b.JobID) {
		return fmt.Errorf("job_id must be a 64-character hex string, got %q", b.JobID)
	}

	// Timestamp (ISO 8601 with Z suffix)
	if err := validateTimestamp(b.Timestamp); err != nil {
		return fmt.Errorf("timestamp: %w", err)
	}

	// SHA-256 hex fields
	if err := validateSHA256Hex("model_hash", b.ModelHash); err != nil {
		return err
	}
	if err := validateSHA256Hex("circuit_hash", b.CircuitHash); err != nil {
		return err
	}
	if err := validateSHA256Hex("verifying_key_hash", b.VerifyingKeyHash); err != nil {
		return err
	}

	// TEE evidence
	if err := b.TEEEvidence.Validate(); err != nil {
		return fmt.Errorf("tee_evidence: %w", err)
	}

	// ZKML evidence
	if err := b.ZKMLEvidence.Validate(); err != nil {
		return fmt.Errorf("zkml_evidence: %w", err)
	}

	// Region
	if strings.TrimSpace(b.Region) == "" {
		return fmt.Errorf("region is required")
	}

	// Operator (bech32 with aethel prefix)
	if !operatorRe.MatchString(b.Operator) {
		return fmt.Errorf("operator must be a valid bech32 address with 'aethel' prefix, got %q", b.Operator)
	}

	// Policy decision
	if err := b.PolicyDecision.Validate(); err != nil {
		return fmt.Errorf("policy_decision: %w", err)
	}

	return nil
}

// Validate checks TEE evidence required fields and format.
func (t *TEEEvidenceV1) Validate() error {
	if !validTEEPlatforms[t.Platform] {
		return fmt.Errorf("platform must be one of sgx, nitro, sev-snp; got %q", t.Platform)
	}
	if strings.TrimSpace(t.EnclaveID) == "" {
		return fmt.Errorf("enclave_id is required")
	}
	if t.Measurement == "" || !isLowercaseHex(t.Measurement) {
		return fmt.Errorf("measurement must be a non-empty lowercase hex string")
	}
	if err := validateBase64("quote", t.Quote); err != nil {
		return err
	}
	if err := validateSHA256Hex("nonce", t.Nonce); err != nil {
		return err
	}
	return nil
}

// Validate checks ZKML evidence required fields and format.
func (z *ZKMLEvidenceV1) Validate() error {
	if !validProofSystems[z.ProofSystem] {
		return fmt.Errorf("proof_system must be one of groth16, plonk, ezkl, halo2, stark; got %q", z.ProofSystem)
	}
	if err := validateBase64("proof_bytes", z.ProofBytes); err != nil {
		return err
	}
	if err := validateBase64("public_inputs", z.PublicInputs); err != nil {
		return err
	}
	if err := validateSHA256Hex("output_commitment", z.OutputCommitment); err != nil {
		return err
	}
	return nil
}

// Validate checks that enterprise policy constraints hold.
func (p *PolicyDecision) Validate() error {
	if p.Mode != "hybrid" {
		return fmt.Errorf("mode must be \"hybrid\" for enterprise bundles, got %q", p.Mode)
	}
	if !p.RequireBoth {
		return fmt.Errorf("require_both must be true for enterprise bundles")
	}
	if p.FallbackAllowed {
		return fmt.Errorf("fallback_allowed must be false for enterprise bundles")
	}
	return nil
}

// NewEnterprisePolicyDecision returns the canonical enterprise policy.
func NewEnterprisePolicyDecision(policyVersion string) PolicyDecision {
	return PolicyDecision{
		Mode:            "hybrid",
		RequireBoth:     true,
		FallbackAllowed: false,
		PolicyVersion:   policyVersion,
	}
}

// --- helpers ---

func validateSHA256Hex(field, value string) error {
	if !hexSHA256Re.MatchString(value) {
		return fmt.Errorf("%s must be a 64-character lowercase hex string, got %q", field, value)
	}
	if value == zeroHash {
		return fmt.Errorf("%s must not be the zero hash", field)
	}
	return nil
}

func validateTimestamp(ts string) error {
	if ts == "" {
		return fmt.Errorf("timestamp is required")
	}
	if !strings.HasSuffix(ts, "Z") {
		return fmt.Errorf("timestamp must end with 'Z' (UTC), got %q", ts)
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		if _, err2 := time.Parse("2006-01-02T15:04:05.000Z", ts); err2 != nil {
			return fmt.Errorf("timestamp must be valid ISO 8601: %w", err)
		}
	}
	return nil
}

func validateBase64(field, value string) error {
	if len(value) < 4 {
		return fmt.Errorf("%s must be a non-empty base64 string (minimum 4 chars)", field)
	}
	if !base64Re.MatchString(value) {
		return fmt.Errorf("%s must be valid base64 (RFC 4648), got invalid characters", field)
	}
	return nil
}

func isLowercaseHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

// HexEncodeBytes is a convenience helper for converting []byte to lowercase hex.
func HexEncodeBytes(b []byte) string {
	return hex.EncodeToString(b)
}
