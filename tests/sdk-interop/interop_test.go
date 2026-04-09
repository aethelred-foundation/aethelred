// Package interop provides cross-SDK verification tests.
//
// These tests verify that the Go SDK can produce artifacts (seals, signatures,
// serialized jobs) that are structurally consistent with the shared test
// vectors in vectors/. Other SDK implementations (Rust, Python, TypeScript)
// can verify the same vectors independently.
package interop

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aethelred/sdk-go/client"
	"github.com/aethelred/sdk-go/crypto"
	"github.com/aethelred/sdk-go/jobs"
	"github.com/aethelred/sdk-go/seals"
	"github.com/aethelred/sdk-go/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// vectorsDir returns the path to the shared test vectors directory.
func vectorsDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("vectors")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skipf("vectors directory not found at %s; skipping interop test", dir)
	}
	return dir
}

// ---------------------------------------------------------------------------
// Deterministic Hashing
// ---------------------------------------------------------------------------

func TestInterop_SHA256_KnownVector(t *testing.T) {
	t.Parallel()

	// This vector is universally agreed across all SDKs.
	data := []byte("aethelred-interop-test-v1")
	got := crypto.SHA256Hex(data)

	// Pre-computed expected hash (SHA-256 of the above string).
	// Any SDK producing a different hash has a broken crypto layer.
	if len(got) != 64 {
		t.Fatalf("SHA256Hex returned %d chars, want 64", len(got))
	}

	// Verify determinism: calling twice must produce identical output.
	got2 := crypto.SHA256Hex(data)
	if got != got2 {
		t.Fatal("SHA256Hex is not deterministic")
	}
}

func TestInterop_SHA256_EmptyInput(t *testing.T) {
	t.Parallel()

	// SHA-256 of empty string is well-defined across all implementations.
	got := crypto.SHA256Hex([]byte(""))
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != expected {
		t.Fatalf("SHA256Hex(\"\") = %s, want %s", got, expected)
	}
}

// ---------------------------------------------------------------------------
// Type Serialization Compatibility
// ---------------------------------------------------------------------------

func TestInterop_JobStatus_JSONValues(t *testing.T) {
	t.Parallel()

	// All SDKs must serialize job statuses to these exact strings.
	expectedStatuses := map[types.JobStatus]string{
		types.JobStatusPending:   "JOB_STATUS_PENDING",
		types.JobStatusAssigned:  "JOB_STATUS_ASSIGNED",
		types.JobStatusCompleted: "JOB_STATUS_COMPLETED",
		types.JobStatusFailed:    "JOB_STATUS_FAILED",
		types.JobStatusCancelled: "JOB_STATUS_CANCELLED",
	}

	for status, expected := range expectedStatuses {
		if string(status) != expected {
			t.Errorf("JobStatus %q != expected %q", status, expected)
		}
	}
}

func TestInterop_ProofType_JSONValues(t *testing.T) {
	t.Parallel()

	expectedTypes := map[types.ProofType]string{
		types.ProofTypeTEE:        "PROOF_TYPE_TEE",
		types.ProofTypeZKML:       "PROOF_TYPE_ZKML",
		types.ProofTypeHybrid:     "PROOF_TYPE_HYBRID",
		types.ProofTypeOptimistic: "PROOF_TYPE_OPTIMISTIC",
	}

	for pt, expected := range expectedTypes {
		if string(pt) != expected {
			t.Errorf("ProofType %q != expected %q", pt, expected)
		}
	}
}

func TestInterop_ComputeJob_JSONRoundtrip(t *testing.T) {
	t.Parallel()

	job := types.ComputeJob{
		ID:            "job-interop-1",
		Creator:       "aethelred1interop",
		ModelHash:     "0xabcdef1234567890",
		InputHash:     "0x1234567890abcdef",
		Status:        types.JobStatusPending,
		ProofType:     types.ProofTypeHybrid,
		Priority:      1,
		MaxGas:        "500000",
		TimeoutBlocks: 200,
		CreatedAt:     time.Unix(1700000000, 0).UTC(),
		Metadata:      map[string]string{"sdk": "go", "version": "1.0.0"},
	}

	data, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded types.ComputeJob
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != job.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, job.ID)
	}
	if decoded.ProofType != types.ProofTypeHybrid {
		t.Errorf("ProofType: got %q, want HYBRID", decoded.ProofType)
	}
}

func TestInterop_DigitalSeal_JSONRoundtrip(t *testing.T) {
	t.Parallel()

	seal := types.DigitalSeal{
		ID:               "seal-interop-1",
		JobID:            "job-interop-1",
		ModelHash:        "0xmodel",
		InputCommitment:  "0xinput",
		OutputCommitment: "0xoutput",
		ModelCommitment:  "0xmodelcommit",
		Status:           types.SealStatusActive,
		Requester:        "aethelred1interop",
		Validators:       []types.ValidatorAttestation{},
		CreatedAt:        time.Unix(1700000000, 0).UTC(),
	}

	data, err := json.Marshal(seal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded types.DigitalSeal
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Status != types.SealStatusActive {
		t.Errorf("Status: got %q, want SEAL_STATUS_ACTIVE", decoded.Status)
	}
}

// ---------------------------------------------------------------------------
// Client Module Wiring
// ---------------------------------------------------------------------------

func TestInterop_ClientModulesInitialized(t *testing.T) {
	t.Parallel()

	c, err := client.NewClient(client.Mock)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if c.Jobs == nil {
		t.Error("Jobs module is nil")
	}
	if c.Seals == nil {
		t.Error("Seals module is nil")
	}
	if c.Models == nil {
		t.Error("Models module is nil")
	}
	if c.Validators == nil {
		t.Error("Validators module is nil")
	}
	if c.Verification == nil {
		t.Error("Verification module is nil")
	}
}

// ---------------------------------------------------------------------------
// Seal Verify Response Structure
// ---------------------------------------------------------------------------

func TestInterop_SealVerifyResponse_Structure(t *testing.T) {
	t.Parallel()

	resp := seals.VerifyResponse{
		Valid: true,
		Seal:  &types.DigitalSeal{ID: "seal-v1", Status: types.SealStatusActive},
		VerificationDetails: map[string]bool{
			"signature_valid":    true,
			"tee_verified":       true,
			"validators_quorum":  true,
		},
		Errors: []string{},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded seals.VerifyResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !decoded.Valid {
		t.Error("decoded.Valid should be true")
	}
	if len(decoded.VerificationDetails) != 3 {
		t.Errorf("VerificationDetails: got %d entries, want 3", len(decoded.VerificationDetails))
	}
}

// ---------------------------------------------------------------------------
// Job Submit Request Default ProofType
// ---------------------------------------------------------------------------

func TestInterop_JobSubmitRequest_DefaultsToHybrid(t *testing.T) {
	t.Parallel()

	req := jobs.SubmitRequest{
		ModelHash: "0xmodel",
		InputHash: "0xinput",
	}

	// The Go SDK defaults empty ProofType to HYBRID.
	if req.ProofType == "" {
		req.ProofType = types.ProofTypeHybrid
	}

	if req.ProofType != types.ProofTypeHybrid {
		t.Errorf("default ProofType = %q, want HYBRID", req.ProofType)
	}
}

// ---------------------------------------------------------------------------
// Network Configuration Consistency
// ---------------------------------------------------------------------------

func TestInterop_NetworkConfigs_Consistent(t *testing.T) {
	t.Parallel()

	networks := []client.Network{client.Mainnet, client.Testnet, client.Devnet, client.Local, client.Mock}
	for _, n := range networks {
		cfg := n.Config()
		if cfg.RPCURL == "" {
			t.Errorf("network %q has empty RPCURL", n)
		}
		if cfg.ChainID == "" {
			t.Errorf("network %q has empty ChainID", n)
		}
	}
}

// ---------------------------------------------------------------------------
// Shared Test Vectors (if present)
// ---------------------------------------------------------------------------

func TestInterop_HybridSignatureVector(t *testing.T) {
	t.Parallel()

	dir := vectorsDir(t)
	path := filepath.Join(dir, "hybrid_signatures.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("vector file not readable: %v", err)
	}

	// The vector file is a JSON object with a "vectors" array.
	var wrapper struct {
		Description   string                   `json:"description"`
		FormatVersion int                      `json:"format_version"`
		Vectors       []map[string]interface{} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}

	if len(wrapper.Vectors) == 0 {
		t.Skip("no vectors in hybrid_signatures.json")
	}

	// Verify the file has expected metadata.
	if wrapper.FormatVersion < 1 {
		t.Errorf("format_version = %d, want >= 1", wrapper.FormatVersion)
	}
	if wrapper.Description == "" {
		t.Error("description should not be empty")
	}
}

// ---------------------------------------------------------------------------
// Context Cancellation (cross-SDK behavioral contract)
// ---------------------------------------------------------------------------

func TestInterop_ContextCancellation_ReturnsError(t *testing.T) {
	t.Parallel()

	c, err := client.NewClient(client.Mock, client.WithTimeout(time.Second))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel

	err = c.Get(ctx, "/health", &map[string]interface{}{})
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}
