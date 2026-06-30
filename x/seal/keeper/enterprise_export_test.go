package keeper

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"cosmossdk.io/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/seal/types"
)

// enterpriseSDKContext returns a wrapped SDK context for enterprise export tests.
func enterpriseSDKContext() context.Context {
	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  200,
	}
	sdkCtx := sdk.NewContext(nil, header, false, log.NewNopLogger())
	return sdkCtx
}

// newHybridSealForTest creates a seal with both TEE attestation and zkML proof
// (the minimum required for enterprise hybrid bundles).
func newHybridSealForTest() *types.DigitalSeal {
	ensureBech32()
	seal := types.NewDigitalSeal(
		bytes.Repeat([]byte{0xAA}, 32), // model commitment
		bytes.Repeat([]byte{0xBB}, 32), // input commitment
		bytes.Repeat([]byte{0xCC}, 32), // output commitment
		200,
		testAccAddress(1),
		"enterprise_inference",
	)
	seal.JobId = string(bytes.Repeat([]byte{'a'}, 64))
	seal.Status = types.SealStatusActive

	// TEE attestation with realistic data.
	seal.TeeAttestations = []*types.TEEAttestation{
		{
			ValidatorAddress: testAccAddress(2),
			Platform:         "nitro",
			EnclaveId:        "i-0abc123def456789a:enc-0def456789abc1230",
			Measurement:      bytes.Repeat([]byte{0xDD}, 48), // 48 bytes for Nitro PCR
			Quote:            bytes.Repeat([]byte{0xEE}, 64), // sample attestation quote
			Signature:        bytes.Repeat([]byte{0xAB}, 64),
		},
	}
	seal.ValidatorSet = []string{testAccAddress(2)}

	// zkML proof with realistic data.
	seal.ZkProof = &types.ZKMLProof{
		ProofSystem:      "groth16",
		ProofBytes:       bytes.Repeat([]byte{0x11}, 128),
		PublicInputs:     bytes.Repeat([]byte{0x22}, 64),
		VerifyingKeyHash: bytes.Repeat([]byte{0x33}, 32),
		CircuitHash:      bytes.Repeat([]byte{0x44}, 32),
	}

	return seal
}

// TestEnterprise_ExportHybridBundle verifies that ExportEnterpriseEvidenceBundle
// produces a complete, schema-compliant bundle for a hybrid job.
func TestEnterprise_ExportHybridBundle(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := enterpriseSDKContext()

	seal := newHybridSealForTest()
	if err := k.SetSeal(context.Background(), seal); err != nil {
		t.Fatalf("SetSeal failed: %v", err)
	}

	bundle, err := ExportEnterpriseEvidenceBundle(ctx, &k, seal.JobId)
	if err != nil {
		t.Fatalf("ExportEnterpriseEvidenceBundle failed: %v", err)
	}

	// --- Verify all top-level required fields are populated ---
	if bundle.SchemaVersion != types.SchemaVersionV1 {
		t.Errorf("schema_version = %q, want %q", bundle.SchemaVersion, types.SchemaVersionV1)
	}
	if bundle.BundleID == "" {
		t.Error("bundle_id must not be empty")
	}
	if bundle.JobID != seal.JobId {
		t.Errorf("job_id = %q, want %q", bundle.JobID, seal.JobId)
	}
	if bundle.ChainID == "" {
		t.Error("chain_id must not be empty")
	}
	if bundle.SealID != seal.Id {
		t.Errorf("seal_id = %q, want %q", bundle.SealID, seal.Id)
	}
	if bundle.Timestamp == "" {
		t.Error("timestamp must not be empty")
	}
	if bundle.ModelHash == "" {
		t.Error("model_hash must not be empty")
	}
	if bundle.CircuitHash == "" {
		t.Error("circuit_hash must not be empty")
	}
	if bundle.VerifyingKeyHash == "" {
		t.Error("verifying_key_hash must not be empty")
	}
	if bundle.ValidatorSignature == "" {
		t.Error("validator_signature must not be empty")
	}
	if bundle.ConfidenceScore == nil || *bundle.ConfidenceScore <= 0 || *bundle.ConfidenceScore > 1 {
		t.Errorf("confidence_score = %v, want within (0, 1]", bundle.ConfidenceScore)
	}
	if bundle.Region == "" {
		t.Error("region must not be empty")
	}
	if bundle.Operator == "" {
		t.Error("operator must not be empty")
	}

	// --- Verify TEE evidence ---
	if bundle.TEEEvidence.Platform == "" {
		t.Error("tee_evidence.platform must not be empty")
	}
	if bundle.TEEEvidence.EnclaveID == "" {
		t.Error("tee_evidence.enclave_id must not be empty")
	}
	if bundle.TEEEvidence.Measurement == "" {
		t.Error("tee_evidence.measurement must not be empty")
	}
	if bundle.TEEEvidence.Quote == "" {
		t.Error("tee_evidence.quote must not be empty")
	}
	if bundle.TEEEvidence.Nonce == "" {
		t.Error("tee_evidence.nonce must not be empty")
	}

	// --- Verify ZKML evidence ---
	if bundle.ZKMLEvidence.ProofSystem == "" {
		t.Error("zkml_evidence.proof_system must not be empty")
	}
	if bundle.ZKMLEvidence.ProofBytes == "" {
		t.Error("zkml_evidence.proof_bytes must not be empty")
	}
	if bundle.ZKMLEvidence.PublicInputs == "" {
		t.Error("zkml_evidence.public_inputs must not be empty")
	}
	if bundle.ZKMLEvidence.OutputCommitment == "" {
		t.Error("zkml_evidence.output_commitment must not be empty")
	}

	// --- Verify policy decision (enterprise constraints) ---
	if bundle.PolicyDecision.Mode != "hybrid" {
		t.Errorf("policy_decision.mode = %q, want %q", bundle.PolicyDecision.Mode, "hybrid")
	}
	if !bundle.PolicyDecision.RequireBoth {
		t.Error("policy_decision.require_both must be true")
	}
	if bundle.PolicyDecision.FallbackAllowed == nil || *bundle.PolicyDecision.FallbackAllowed {
		t.Error("policy_decision.fallback_allowed must be false")
	}
	if bundle.ArchivePointer.DocumentID != seal.JobId {
		t.Errorf("archive_pointer.document_id = %q, want %q", bundle.ArchivePointer.DocumentID, seal.JobId)
	}
	if !bundle.Verification.SchemaVerified || !bundle.Verification.PolicyVerified {
		t.Error("verification must mark schema and policy as verified")
	}

	// --- Bundle must pass its own validation ---
	if err := bundle.Validate(); err != nil {
		t.Errorf("bundle.Validate() failed: %v", err)
	}
}

func TestEnterprise_ExportM42Region(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	header := tmproto.Header{
		ChainID: "aethelred-m42-pilot-1",
		Height:  200,
	}
	ctx := sdk.NewContext(nil, header, false, log.NewNopLogger())

	seal := newHybridSealForTest()
	if err := k.SetSeal(context.Background(), seal); err != nil {
		t.Fatalf("SetSeal failed: %v", err)
	}

	bundle, err := ExportEnterpriseEvidenceBundle(ctx, &k, seal.JobId)
	if err != nil {
		t.Fatalf("ExportEnterpriseEvidenceBundle failed: %v", err)
	}
	if bundle.Region != "me-central-1" {
		t.Fatalf("region = %q, want me-central-1", bundle.Region)
	}
}

func TestEnterprise_ExportRejectsMissingChainID(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	header := tmproto.Header{Height: 200}
	ctx := sdk.NewContext(nil, header, false, log.NewNopLogger())

	seal := newHybridSealForTest()
	if err := k.SetSeal(context.Background(), seal); err != nil {
		t.Fatalf("SetSeal failed: %v", err)
	}

	if _, err := ExportEnterpriseEvidenceBundle(ctx, &k, seal.JobId); err == nil || !contains(err.Error(), "chain ID") {
		t.Fatalf("expected missing chain ID error, got %v", err)
	}
}

func TestEnterprise_ExportRejectsMissingValidatorSignature(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := enterpriseSDKContext()

	seal := newHybridSealForTest()
	seal.TeeAttestations[0].Signature = nil
	if err := k.SetSeal(context.Background(), seal); err != nil {
		t.Fatalf("SetSeal failed: %v", err)
	}

	if _, err := ExportEnterpriseEvidenceBundle(ctx, &k, seal.JobId); err == nil || !contains(err.Error(), "validator signature") {
		t.Fatalf("expected missing validator signature error, got %v", err)
	}
}

func TestQueryEnterpriseEvidenceBundle(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := enterpriseSDKContext()

	seal := newHybridSealForTest()
	if err := k.SetSeal(context.Background(), seal); err != nil {
		t.Fatalf("SetSeal failed: %v", err)
	}

	queryServer := NewQueryServerImpl(k)
	if _, err := queryServer.EnterpriseEvidenceBundle(ctx, &types.QueryEnterpriseEvidenceBundleRequest{}); err == nil {
		t.Fatal("expected missing job_id error")
	}

	resp, err := queryServer.EnterpriseEvidenceBundle(ctx, &types.QueryEnterpriseEvidenceBundleRequest{
		JobId: seal.JobId,
	})
	if err != nil {
		t.Fatalf("EnterpriseEvidenceBundle query failed: %v", err)
	}
	if resp.EvidenceBundle == nil {
		t.Fatal("expected evidence bundle")
	}
	if got := resp.EvidenceBundle.Fields["schema_version"].GetStringValue(); got != types.SchemaVersionV1 {
		t.Fatalf("schema_version = %q, want %q", got, types.SchemaVersionV1)
	}
	if got := resp.EvidenceBundle.Fields["job_id"].GetStringValue(); got != seal.JobId {
		t.Fatalf("job_id = %q, want %q", got, seal.JobId)
	}
	for _, field := range []string{
		"chain_id",
		"seal_id",
		"validator_signature",
		"confidence_score",
		"archive_pointer",
		"verification",
	} {
		if _, ok := resp.EvidenceBundle.Fields[field]; !ok {
			t.Fatalf("expected %s field", field)
		}
	}
	if resp.EvidenceBundle.Fields["tee_evidence"].GetStructValue() == nil {
		t.Fatal("expected tee_evidence object")
	}
	if resp.EvidenceBundle.Fields["zkml_evidence"].GetStructValue() == nil {
		t.Fatal("expected zkml_evidence object")
	}
}

// TestEnterprise_BundleValidation ensures that bundles with missing or invalid
// fields are rejected by Validate().
func TestEnterprise_BundleValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(b *types.EvidenceBundle)
		wantErr string
	}{
		{
			name:    "empty schema version",
			mutate:  func(b *types.EvidenceBundle) { b.SchemaVersion = "" },
			wantErr: "schema_version",
		},
		{
			name:    "invalid bundle_id",
			mutate:  func(b *types.EvidenceBundle) { b.BundleID = "not-a-uuid" },
			wantErr: "bundle_id",
		},
		{
			name:    "empty job_id",
			mutate:  func(b *types.EvidenceBundle) { b.JobID = "" },
			wantErr: "job_id",
		},
		{
			name:    "empty chain_id",
			mutate:  func(b *types.EvidenceBundle) { b.ChainID = "" },
			wantErr: "chain_id",
		},
		{
			name:    "empty seal_id",
			mutate:  func(b *types.EvidenceBundle) { b.SealID = "" },
			wantErr: "seal_id",
		},
		{
			name:    "invalid timestamp",
			mutate:  func(b *types.EvidenceBundle) { b.Timestamp = "2026-03-28" },
			wantErr: "timestamp",
		},
		{
			name:    "zero model_hash",
			mutate:  func(b *types.EvidenceBundle) { b.ModelHash = types.HexEncodeBytes(bytes.Repeat([]byte{0x00}, 32)) },
			wantErr: "model_hash",
		},
		{
			name:    "empty circuit_hash",
			mutate:  func(b *types.EvidenceBundle) { b.CircuitHash = "" },
			wantErr: "circuit_hash",
		},
		{
			name:    "empty validator_signature",
			mutate:  func(b *types.EvidenceBundle) { b.ValidatorSignature = "" },
			wantErr: "validator_signature",
		},
		{
			name:    "missing confidence_score",
			mutate:  func(b *types.EvidenceBundle) { b.ConfidenceScore = nil },
			wantErr: "confidence_score",
		},
		{
			name:    "invalid confidence_score",
			mutate:  func(b *types.EvidenceBundle) { b.ConfidenceScore = types.Float64Ptr(1.5) },
			wantErr: "confidence_score",
		},
		{
			name:    "empty region",
			mutate:  func(b *types.EvidenceBundle) { b.Region = "" },
			wantErr: "region",
		},
		{
			name:    "invalid operator",
			mutate:  func(b *types.EvidenceBundle) { b.Operator = "cosmos1abc" },
			wantErr: "operator",
		},
		{
			name:    "invalid TEE platform",
			mutate:  func(b *types.EvidenceBundle) { b.TEEEvidence.Platform = "unknown" },
			wantErr: "platform",
		},
		{
			name:    "invalid proof system",
			mutate:  func(b *types.EvidenceBundle) { b.ZKMLEvidence.ProofSystem = "snark42" },
			wantErr: "proof_system",
		},
		{
			name:    "policy mode not hybrid",
			mutate:  func(b *types.EvidenceBundle) { b.PolicyDecision.Mode = "tee-only" },
			wantErr: "mode",
		},
		{
			name:    "require_both false",
			mutate:  func(b *types.EvidenceBundle) { b.PolicyDecision.RequireBoth = false },
			wantErr: "require_both",
		},
		{
			name:    "fallback_allowed true",
			mutate:  func(b *types.EvidenceBundle) { b.PolicyDecision.FallbackAllowed = types.BoolPtr(true) },
			wantErr: "fallback_allowed",
		},
		{
			name:    "fallback_allowed missing",
			mutate:  func(b *types.EvidenceBundle) { b.PolicyDecision.FallbackAllowed = nil },
			wantErr: "fallback_allowed",
		},
		{
			name:    "empty archive pointer",
			mutate:  func(b *types.EvidenceBundle) { b.ArchivePointer = types.ArchivePointer{} },
			wantErr: "archive_pointer",
		},
		{
			name:    "empty verification",
			mutate:  func(b *types.EvidenceBundle) { b.Verification = types.Verification{} },
			wantErr: "verification",
		},
		{
			name:    "missing tee verification flag",
			mutate:  func(b *types.EvidenceBundle) { b.Verification.TEEAttestationVerified = nil },
			wantErr: "tee_attestation_verified",
		},
		{
			name:    "missing zkml verification flag",
			mutate:  func(b *types.EvidenceBundle) { b.Verification.ZKMLProofVerified = nil },
			wantErr: "zkml_proof_verified",
		},
		{
			name:    "missing digital seal verification flag",
			mutate:  func(b *types.EvidenceBundle) { b.Verification.DigitalSealVerified = nil },
			wantErr: "digital_seal_verified",
		},
		{
			name:    "missing live verification flag",
			mutate:  func(b *types.EvidenceBundle) { b.Verification.LiveVerificationRequired = nil },
			wantErr: "live_verification_required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := validTestBundle()
			tc.mutate(bundle)
			err := bundle.Validate()
			if err == nil {
				t.Fatalf("expected validation error containing %q, got nil", tc.wantErr)
			}
			if !contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// TestEnterprise_BundleMatchesSchemaV1 verifies that the JSON field names
// produced by marshalling EvidenceBundle match the canonical schema v1.
func TestEnterprise_BundleMatchesSchemaV1(t *testing.T) {
	bundle := validTestBundle()

	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Top-level required fields from the schema.
	requiredTopLevel := []string{
		"schema_version",
		"bundle_id",
		"job_id",
		"chain_id",
		"seal_id",
		"timestamp",
		"model_hash",
		"circuit_hash",
		"verifying_key_hash",
		"validator_signature",
		"confidence_score",
		"tee_evidence",
		"zkml_evidence",
		"region",
		"operator",
		"policy_decision",
		"archive_pointer",
		"verification",
	}
	for _, field := range requiredTopLevel {
		if _, ok := raw[field]; !ok {
			t.Errorf("top-level JSON field %q missing from marshalled bundle", field)
		}
	}

	// TEE evidence required fields.
	teeEv, ok := raw["tee_evidence"].(map[string]interface{})
	if !ok {
		t.Fatal("tee_evidence is not an object")
	}
	for _, field := range []string{"platform", "enclave_id", "measurement", "quote", "nonce"} {
		if _, ok := teeEv[field]; !ok {
			t.Errorf("tee_evidence JSON field %q missing", field)
		}
	}

	// ZKML evidence required fields.
	zkmlEv, ok := raw["zkml_evidence"].(map[string]interface{})
	if !ok {
		t.Fatal("zkml_evidence is not an object")
	}
	for _, field := range []string{"proof_system", "proof_bytes", "public_inputs", "output_commitment"} {
		if _, ok := zkmlEv[field]; !ok {
			t.Errorf("zkml_evidence JSON field %q missing", field)
		}
	}

	// Policy decision required fields.
	pd, ok := raw["policy_decision"].(map[string]interface{})
	if !ok {
		t.Fatal("policy_decision is not an object")
	}
	for _, field := range []string{"mode", "require_both", "fallback_allowed"} {
		if _, ok := pd[field]; !ok {
			t.Errorf("policy_decision JSON field %q missing", field)
		}
	}

	// Verify enterprise policy values.
	if pd["mode"] != "hybrid" {
		t.Errorf("policy_decision.mode = %v, want \"hybrid\"", pd["mode"])
	}
	if pd["require_both"] != true {
		t.Errorf("policy_decision.require_both = %v, want true", pd["require_both"])
	}
	if pd["fallback_allowed"] != false {
		t.Errorf("policy_decision.fallback_allowed = %v, want false", pd["fallback_allowed"])
	}
}

// --- helpers ---

// validTestBundle builds a fully populated, schema-compliant EvidenceBundle for
// testing. Mutate individual fields to create invalid bundles.
func validTestBundle() *types.EvidenceBundle {
	return &types.EvidenceBundle{
		SchemaVersion:      types.SchemaVersionV1,
		BundleID:           "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		JobID:              "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		ChainID:            "aethelred-test-1",
		SealID:             "seal-test-1",
		Timestamp:          "2026-03-28T14:30:00Z",
		ModelHash:          "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		CircuitHash:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		VerifyingKeyHash:   "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		ValidatorSignature: "dmFsaWRhdG9yLXNpZ25hdHVyZQ==",
		ConfidenceScore:    types.Float64Ptr(1.0),
		TEEEvidence: types.TEEEvidenceV1{
			Platform:    "nitro",
			EnclaveID:   "i-0abc123def456789a:enc-0def456789abc1230",
			Measurement: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
			Quote:       "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBzYW1wbGUgYXR0ZXN0YXRpb24gcXVvdGU=",
			Nonce:       "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b",
		},
		ZKMLEvidence: types.ZKMLEvidenceV1{
			ProofSystem:      "groth16",
			ProofBytes:       "eyJwaSI6eyJhIjpbIjB4MDEiLCIweDIiXX19",
			PublicInputs:     "W1siMHgwMSIsIjB4MDIiXV0=",
			OutputCommitment: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		Region:   "us-east-1",
		Operator: "aethel1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu",
		PolicyDecision: types.PolicyDecision{
			Mode:            "hybrid",
			RequireBoth:     true,
			FallbackAllowed: types.BoolPtr(false),
			PolicyVersion:   "1.0.0",
		},
		ArchivePointer: types.ArchivePointer{
			ArchiveType:   "opensearch",
			Index:         "aethelred-enterprise-evidence",
			DocumentID:    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			URI:           "opensearch://aethelred-enterprise-evidence/_doc/a1b2",
			RetentionDays: 30,
			WriteStatus:   "pending_archive_write",
		},
		Verification: types.Verification{
			SchemaVerified:           true,
			PolicyVerified:           true,
			TEEAttestationVerified:   types.BoolPtr(true),
			ZKMLProofVerified:        types.BoolPtr(true),
			DigitalSealVerified:      types.BoolPtr(true),
			LiveVerificationRequired: types.BoolPtr(false),
			VerifierVersion:          "test",
		},
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
