package app

import (
	"encoding/json"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	"github.com/aethelred/aethelred/x/verify"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

// ---------------------------------------------------------------------------
// mapProofType (from verifier_bridge.go perspective)
// ---------------------------------------------------------------------------

func TestVerifierBridge_MapProofType_AllCases(t *testing.T) {
	cases := []struct {
		input    pouwtypes.ProofType
		expected verifytypes.VerificationType
		wantErr  bool
	}{
		{pouwtypes.ProofTypeTEE, verifytypes.VerificationTypeTEE, false},
		{pouwtypes.ProofTypeZKML, verifytypes.VerificationTypeZKML, false},
		{pouwtypes.ProofTypeHybrid, verifytypes.VerificationTypeHybrid, false},
		{pouwtypes.ProofType(99), verifytypes.VerificationTypeUnspecified, true},
		{pouwtypes.ProofType_PROOF_TYPE_UNSPECIFIED, verifytypes.VerificationTypeUnspecified, true},
	}

	for _, tc := range cases {
		vt, err := mapProofType(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("expected error for input %v", tc.input)
			}
			continue
		}
		if err != nil {
			t.Fatalf("unexpected error for input %v: %v", tc.input, err)
		}
		if vt != tc.expected {
			t.Fatalf("for input %v: expected %v, got %v", tc.input, tc.expected, vt)
		}
	}
}

// ---------------------------------------------------------------------------
// mapResponse
// ---------------------------------------------------------------------------

func TestMapResponse_Success_TEE(t *testing.T) {
	resp := &verify.VerificationResponse{
		Success:          true,
		OutputHash:       []byte("output-hash"),
		TotalTimeMs:      150,
		Timestamp:        time.Now().UTC(),
		VerificationType: verifytypes.VerificationTypeTEE,
		TEEResult: &verify.TEEVerificationResult{
			Platform:  "aws-nitro",
			EnclaveID: "enc-1",
		},
	}

	result := mapResponse(resp, "validator1")
	if !result.Success {
		t.Fatal("expected success")
	}
	if result.ValidatorAddress != "validator1" {
		t.Fatal("wrong validator address")
	}
	if result.AttestationType != "tee" {
		t.Fatalf("expected tee, got %s", result.AttestationType)
	}
	if result.TeePlatform != "aws-nitro" {
		t.Fatalf("expected aws-nitro, got %s", result.TeePlatform)
	}
}

func TestMapResponse_Success_ZKML(t *testing.T) {
	resp := &verify.VerificationResponse{
		Success:          true,
		OutputHash:       []byte("output"),
		TotalTimeMs:      200,
		Timestamp:        time.Now().UTC(),
		VerificationType: verifytypes.VerificationTypeZKML,
		ZKMLResult: &verify.ZKMLVerificationResult{
			ProofSystem: "ezkl",
		},
	}

	result := mapResponse(resp, "validator2")
	if result.AttestationType != "zkml" {
		t.Fatalf("expected zkml, got %s", result.AttestationType)
	}
}

func TestMapResponse_Success_Hybrid(t *testing.T) {
	resp := &verify.VerificationResponse{
		Success:          true,
		OutputHash:       []byte("output"),
		TotalTimeMs:      300,
		Timestamp:        time.Now().UTC(),
		VerificationType: verifytypes.VerificationTypeHybrid,
		TEEResult: &verify.TEEVerificationResult{
			Platform: "aws-nitro",
		},
		ZKMLResult: &verify.ZKMLVerificationResult{
			ProofSystem: "ezkl",
		},
	}

	result := mapResponse(resp, "validator3")
	if result.AttestationType != "hybrid" {
		t.Fatalf("expected hybrid, got %s", result.AttestationType)
	}
	if result.TeePlatform != "aws-nitro" {
		t.Fatalf("expected aws-nitro platform, got %s", result.TeePlatform)
	}
}

func TestMapResponse_Failure(t *testing.T) {
	resp := &verify.VerificationResponse{
		Success:          false,
		Error:            "verification failed",
		Timestamp:        time.Now().UTC(),
		VerificationType: verifytypes.VerificationTypeTEE,
	}

	result := mapResponse(resp, "validator4")
	if result.Success {
		t.Fatal("expected failure")
	}
	if result.ErrorMessage != "verification failed" {
		t.Fatal("error message mismatch")
	}
}

func TestMapResponse_UnknownType(t *testing.T) {
	resp := &verify.VerificationResponse{
		Success:          true,
		Timestamp:        time.Now().UTC(),
		VerificationType: verifytypes.VerificationTypeUnspecified,
	}

	result := mapResponse(resp, "validator5")
	if result.AttestationType != "unknown" {
		t.Fatalf("expected unknown, got %s", result.AttestationType)
	}
}

// ---------------------------------------------------------------------------
// marshalAttestationData
// ---------------------------------------------------------------------------

func TestMarshalAttestationData_BothNil(t *testing.T) {
	result := marshalAttestationData(nil, nil)
	if result != nil {
		t.Fatal("expected nil when both inputs are nil")
	}
}

func TestMarshalAttestationData_TEEOnly(t *testing.T) {
	teeResult := &verify.TEEVerificationResult{
		Platform:  "aws-nitro",
		EnclaveID: "enc-1",
	}
	result := marshalAttestationData(teeResult, nil)
	if result == nil {
		t.Fatal("expected non-nil for TEE-only")
	}

	var parsed bridgeAttestationData
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed.TEE == nil {
		t.Fatal("expected TEE data")
	}
	if parsed.ZKML != nil {
		t.Fatal("expected nil ZKML data")
	}
}

func TestMarshalAttestationData_ZKMLOnly(t *testing.T) {
	zkmlResult := &verify.ZKMLVerificationResult{
		ProofSystem: "ezkl",
	}
	result := marshalAttestationData(nil, zkmlResult)
	if result == nil {
		t.Fatal("expected non-nil for ZKML-only")
	}

	var parsed bridgeAttestationData
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed.ZKML == nil {
		t.Fatal("expected ZKML data")
	}
}

func TestMarshalAttestationData_Both(t *testing.T) {
	teeResult := &verify.TEEVerificationResult{Platform: "aws-nitro"}
	zkmlResult := &verify.ZKMLVerificationResult{ProofSystem: "ezkl"}
	result := marshalAttestationData(teeResult, zkmlResult)
	if result == nil {
		t.Fatal("expected non-nil for both")
	}

	var parsed bridgeAttestationData
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed.TEE == nil || parsed.ZKML == nil {
		t.Fatal("expected both TEE and ZKML data")
	}
}

// ---------------------------------------------------------------------------
// OrchestratorBridge constructor
// ---------------------------------------------------------------------------

func TestNewOrchestratorBridge_NilOrchestrator(t *testing.T) {
	bridge := NewOrchestratorBridge(nil)
	if bridge == nil {
		t.Fatal("expected non-nil bridge even with nil orchestrator")
	}
}

// ---------------------------------------------------------------------------
// OrchestratorBridge.VerifyJob nil checks
// ---------------------------------------------------------------------------

func TestOrchestratorBridge_VerifyJob_NilJob(t *testing.T) {
	bridge := NewOrchestratorBridge(nil)
	ctx := sdk.Context{}
	_, err := bridge.VerifyJob(ctx, nil, nil, "validator")
	if err == nil {
		t.Fatal("expected error for nil job")
	}
}

func TestOrchestratorBridge_VerifyJob_NilModel(t *testing.T) {
	bridge := NewOrchestratorBridge(nil)
	ctx := sdk.Context{}
	job := &pouwtypes.ComputeJob{Id: "job-1"}
	_, err := bridge.VerifyJob(ctx, job, nil, "validator")
	if err == nil {
		t.Fatal("expected error for nil model")
	}
}
