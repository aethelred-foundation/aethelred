package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aethelred/aethelred/x/verify/tee"
)

func TestHandleExecuteFailClosedWhenSimulationDisabled(t *testing.T) {
	s := &server{cfg: config{AllowSimulated: false}}
	reqBody, _ := json.Marshal(appExecutionRequest{
		JobID:     "job-1",
		ModelHash: []byte("model"),
		InputHash: []byte("input"),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	s.handleExecute(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
}

func TestSimulatedEnclaveExecuteAndVerify(t *testing.T) {
	s := &server{
		cfg: config{
			AllowSimulated:    true,
			Platform:          "aws-nitro",
			EnclaveID:         "enclave-1",
			MaxAttestationAge: 5 * time.Minute,
		},
	}
	reqBody, _ := json.Marshal(tee.EnclaveExecutionRequest{
		RequestID:           "req-1",
		ModelHash:           []byte("model"),
		InputHash:           []byte("input"),
		InputData:           []byte("payload"),
		GenerateAttestation: true,
		Nonce:               []byte("nonce"),
	})

	execRec := httptest.NewRecorder()
	execReq := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	s.handleExecute(execRec, execReq)
	if execRec.Code != http.StatusOK {
		t.Fatalf("expected execute status %d, got %d", http.StatusOK, execRec.Code)
	}

	var execResp tee.EnclaveExecutionResult
	if err := json.Unmarshal(execRec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("failed to decode execute response: %v", err)
	}
	if !execResp.Success {
		t.Fatalf("expected success response")
	}
	if execResp.AttestationDocument == nil {
		t.Fatalf("expected attestation document")
	}

	verifyBody, _ := json.Marshal(execResp.AttestationDocument)
	verifyRec := httptest.NewRecorder()
	verifyReq := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(verifyBody))
	s.handleVerify(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected verify status %d, got %d", http.StatusOK, verifyRec.Code)
	}

	var verifyResp map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("failed to decode verify response: %v", err)
	}
	if verified, ok := verifyResp["verified"].(bool); !ok || !verified {
		t.Fatalf("expected verified=true, got %v", verifyResp["verified"])
	}
}

func TestSimulatedAppExecute(t *testing.T) {
	s := &server{
		cfg: config{
			AllowSimulated:     true,
			Platform:           "aws-nitro",
			EnclaveID:          "enclave-app",
			SupportsZKProofGen: true,
		},
	}
	reqBody, _ := json.Marshal(appExecutionRequest{
		JobID:          "job-1",
		ModelHash:      []byte("model"),
		InputHash:      []byte("input"),
		InputData:      []byte("payload"),
		RequireZKProof: true,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	s.handleExecute(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected execute status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp appExecutionResult
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected success=true")
	}
	if resp.JobID != "job-1" {
		t.Fatalf("expected job-1, got %q", resp.JobID)
	}
	if resp.ZKProof == nil {
		t.Fatalf("expected ZKProof in response")
	}
}

func TestHandleExecuteRateLimit(t *testing.T) {
	s := &server{
		cfg: config{
			AllowSimulated:     true,
			Platform:           "aws-nitro",
			EnclaveID:          "enclave-rate",
			MinRequestInterval: 5 * time.Second,
		},
	}
	reqBody, _ := json.Marshal(appExecutionRequest{
		JobID:     "job-rate",
		ModelHash: []byte("model"),
		InputHash: []byte("input"),
		InputData: []byte("payload"),
	})

	req1 := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	req1.RemoteAddr = "127.0.0.1:9999"
	rec1 := httptest.NewRecorder()
	s.handleExecute(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request expected %d, got %d", http.StatusOK, rec1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	req2.RemoteAddr = "127.0.0.1:9999"
	rec2 := httptest.NewRecorder()
	s.handleExecute(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request expected %d, got %d", http.StatusTooManyRequests, rec2.Code)
	}
}
