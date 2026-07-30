package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aethelred/aethelred/x/verify/tee"
)

func newLoopbackRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.RemoteAddr = "127.0.0.1:1234"
	return req
}

func TestHandleExecuteFailClosedWhenSimulationDisabled(t *testing.T) {
	s := &server{cfg: config{AllowSimulated: false}}
	reqBody, _ := json.Marshal(appExecutionRequest{
		JobID:     "job-1",
		ModelHash: []byte("model"),
		InputHash: []byte("input"),
	})

	rec := httptest.NewRecorder()
	req := newLoopbackRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	s.handleExecute(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
}

func TestValidateConfigRequiresRealBackendOutsideSimulation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{
			name:    "missing production backend",
			cfg:     config{ListenAddr: defaultListenAddr},
			wantErr: "AETHELRED_TEE_BACKEND_URL",
		},
		{
			name: "unsafe backend",
			cfg: config{
				ListenAddr: defaultListenAddr,
				BackendURL: "http://203.0.113.10:8545",
			},
			wantErr: "invalid tee worker backend URL",
		},
		{
			name: "real backend requires outbound token",
			cfg: config{
				ListenAddr: defaultListenAddr,
				BackendURL: "http://127.0.0.1:18545",
			},
			wantErr: backendAPITokenEnv,
		},
		{
			name: "simulated local development",
			cfg: config{
				ListenAddr:     defaultListenAddr,
				AllowSimulated: true,
			},
		},
		{
			name: "validated local backend",
			cfg: config{
				ListenAddr:      defaultListenAddr,
				BackendURL:      "http://127.0.0.1:18545",
				BackendAPIToken: "backend-secret",
			},
		},
		{
			name: "production cannot simulate",
			cfg: config{
				ListenAddr:     defaultListenAddr,
				AllowSimulated: true,
				ProductionMode: true,
			},
			wantErr: "not allowed in production",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid config, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestLoadConfigSeparatesBackendTokenAndRejectsProductionSimulation(t *testing.T) {
	t.Setenv("TEE_MODE", "production")
	t.Setenv("AETHELRED_ALLOW_SIMULATED", "true")
	t.Setenv(apiTokenEnv, "  inbound-secret  ")
	t.Setenv(backendAPITokenEnv, "  backend-secret  ")

	cfg := loadConfig()

	if !cfg.ProductionMode {
		t.Fatal("expected TEE_MODE=production to enable production mode")
	}
	if cfg.APIToken != "inbound-secret" {
		t.Fatalf("expected trimmed inbound API token, got %q", cfg.APIToken)
	}
	if cfg.BackendAPIToken != "backend-secret" {
		t.Fatalf("expected trimmed backend API token, got %q", cfg.BackendAPIToken)
	}
	if err := validateConfig(cfg); err == nil ||
		!strings.Contains(err.Error(), "not allowed in production") {
		t.Fatalf("expected production simulation to be rejected, got %v", err)
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
	execReq := newLoopbackRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
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
	verifyReq := newLoopbackRequest(http.MethodPost, "/verify", bytes.NewReader(verifyBody))
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

func TestSimulatedVerifyRejectsTamperedAttestation(t *testing.T) {
	s := &server{
		cfg: config{
			AllowSimulated:    true,
			Platform:          "aws-nitro",
			EnclaveID:         "enclave-1",
			MaxAttestationAge: 5 * time.Minute,
		},
	}
	reqBody, _ := json.Marshal(tee.EnclaveExecutionRequest{
		RequestID:           "req-2",
		ModelHash:           []byte("model"),
		InputHash:           []byte("input"),
		InputData:           []byte("payload"),
		GenerateAttestation: true,
		Nonce:               []byte("nonce"),
	})

	execRec := httptest.NewRecorder()
	execReq := newLoopbackRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	s.handleExecute(execRec, execReq)
	if execRec.Code != http.StatusOK {
		t.Fatalf("expected execute status %d, got %d", http.StatusOK, execRec.Code)
	}

	var execResp tee.EnclaveExecutionResult
	if err := json.Unmarshal(execRec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("failed to decode execute response: %v", err)
	}
	if execResp.AttestationDocument == nil {
		t.Fatalf("expected attestation document")
	}
	execResp.AttestationDocument.UserData = []byte("tampered")

	verifyBody, _ := json.Marshal(execResp.AttestationDocument)
	verifyRec := httptest.NewRecorder()
	verifyReq := newLoopbackRequest(http.MethodPost, "/verify", bytes.NewReader(verifyBody))
	s.handleVerify(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected verify status %d, got %d", http.StatusOK, verifyRec.Code)
	}

	var verifyResp map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("failed to decode verify response: %v", err)
	}
	if verified, ok := verifyResp["verified"].(bool); !ok || verified {
		t.Fatalf("expected verified=false, got %v", verifyResp["verified"])
	}
	if verifyResp["error"] == nil {
		t.Fatalf("expected verification error for tampered attestation")
	}
}

func TestSimulatedVerifyRejectsUnsignedAttestation(t *testing.T) {
	s := &server{
		cfg: config{
			AllowSimulated:    true,
			Platform:          "aws-nitro",
			EnclaveID:         "enclave-1",
			MaxAttestationAge: 5 * time.Minute,
		},
	}
	doc := tee.NitroAttestationDocument{
		ModuleID:  "enclave-1",
		Timestamp: time.Now().UTC(),
		Digest:    "SHA256",
		PCRs: map[int][]byte{
			0: []byte("pcr0"),
		},
		UserData: []byte("user-data"),
		Nonce:    []byte("nonce"),
	}

	verifyBody, _ := json.Marshal(doc)
	verifyRec := httptest.NewRecorder()
	verifyReq := newLoopbackRequest(http.MethodPost, "/verify", bytes.NewReader(verifyBody))
	s.handleVerify(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected verify status %d, got %d", http.StatusOK, verifyRec.Code)
	}

	var verifyResp map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("failed to decode verify response: %v", err)
	}
	if verified, ok := verifyResp["verified"].(bool); !ok || verified {
		t.Fatalf("expected verified=false, got %v", verifyResp["verified"])
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
	req := newLoopbackRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
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

func TestSimulatedOutputIsCanonicalAcrossValidatorsAndRequests(t *testing.T) {
	modelHash := sha256.Sum256([]byte("model-v1"))
	inputHash := sha256.Sum256([]byte("canonical-input"))
	validatorA := &server{cfg: config{EnclaveID: "validator-a", Platform: "aws-nitro"}}
	validatorB := &server{cfg: config{EnclaveID: "validator-b", Platform: "aws-nitro"}}

	enclaveA := validatorA.simulateEnclaveExecution(&tee.EnclaveExecutionRequest{
		RequestID:   "request-a",
		ModelHash:   modelHash[:],
		InputHash:   inputHash[:],
		InputData:   []byte("local-copy-a"),
		Nonce:       []byte("nonce-a"),
		BlockHeight: 100,
		ChainID:     "chain-a",
	})
	enclaveB := validatorB.simulateEnclaveExecution(&tee.EnclaveExecutionRequest{
		RequestID:   "request-b",
		ModelHash:   modelHash[:],
		InputHash:   inputHash[:],
		InputData:   []byte("local-copy-b"),
		Nonce:       []byte("nonce-b"),
		BlockHeight: 101,
		ChainID:     "chain-b",
	})

	if !bytes.Equal(enclaveA.OutputData, enclaveB.OutputData) {
		t.Fatal("canonical enclave output changed with request or validator metadata")
	}
	if !bytes.Equal(enclaveA.OutputHash, enclaveB.OutputHash) {
		t.Fatal("canonical enclave output hash changed with request or validator metadata")
	}
	expectedHash := sha256.Sum256(enclaveA.OutputData)
	if !bytes.Equal(enclaveA.OutputHash, expectedHash[:]) {
		t.Fatal("enclave OutputHash is not SHA-256(OutputData)")
	}

	appA := validatorA.simulateAppExecution(&appExecutionRequest{
		JobID:       "job-a",
		ModelHash:   modelHash[:],
		InputHash:   inputHash[:],
		InputData:   []byte("local-copy-a"),
		Nonce:       []byte("nonce-a"),
		BlockHeight: 100,
		ChainID:     "chain-a",
	})
	appB := validatorB.simulateAppExecution(&appExecutionRequest{
		JobID:       "job-b",
		ModelHash:   modelHash[:],
		InputHash:   inputHash[:],
		InputData:   []byte("local-copy-b"),
		Nonce:       []byte("nonce-b"),
		BlockHeight: 101,
		ChainID:     "chain-b",
	})
	if !bytes.Equal(appA.Output, appB.Output) ||
		!bytes.Equal(appA.OutputHash, appB.OutputHash) {
		t.Fatal("canonical app output changed with request or validator metadata")
	}
	if !bytes.Equal(enclaveA.OutputHash, appA.OutputHash) {
		t.Fatal("enclave and app request shapes produced different output commitments")
	}

	otherModelHash := sha256.Sum256([]byte("model-v2"))
	_, otherModelOutputHash := simulateCanonicalModelExecution(otherModelHash[:], inputHash[:])
	if bytes.Equal(enclaveA.OutputHash, otherModelOutputHash) {
		t.Fatal("changing the canonical model hash did not change OutputHash")
	}
	otherInputHash := sha256.Sum256([]byte("other-input"))
	_, otherInputOutputHash := simulateCanonicalModelExecution(modelHash[:], otherInputHash[:])
	if bytes.Equal(enclaveA.OutputHash, otherInputOutputHash) {
		t.Fatal("changing the canonical input hash did not change OutputHash")
	}
}

func TestBackendReadinessAndProxyUseOnlyBackendAuthorization(t *testing.T) {
	healthAuthorization := make(chan string, 1)
	executeAuthorization := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			healthAuthorization <- r.Header.Get("Authorization")
			w.WriteHeader(http.StatusNoContent)
		case "/execute":
			executeAuthorization <- r.Header.Get("Authorization")
			writeJSON(w, http.StatusOK, map[string]any{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	s := &server{
		cfg: config{
			BackendURL:      upstream.URL,
			APIToken:        "inbound-secret",
			BackendAPIToken: "backend-secret",
			Timeout:         time.Second,
		},
		client: upstream.Client(),
	}

	healthRec := httptest.NewRecorder()
	healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthReq.RemoteAddr = "203.0.113.10:4321"
	healthReq.Header.Set("Authorization", "Bearer inbound-secret")
	s.handleHealth(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("expected ready status %d, got %d", http.StatusOK, healthRec.Code)
	}
	if got := <-healthAuthorization; got != "Bearer backend-secret" {
		t.Fatalf("backend health received unexpected authorization %q", got)
	}

	executeRec := httptest.NewRecorder()
	executeReq := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{}`))
	executeReq.RemoteAddr = "203.0.113.10:4321"
	executeReq.Header.Set("Authorization", "Bearer inbound-secret")
	s.handleExecute(executeRec, executeReq)
	if executeRec.Code != http.StatusOK {
		t.Fatalf("expected proxied status %d, got %d", http.StatusOK, executeRec.Code)
	}
	if got := <-executeAuthorization; got != "Bearer backend-secret" {
		t.Fatalf("backend execute received unexpected authorization %q", got)
	}
}

func TestBackendReadinessFailsClosed(t *testing.T) {
	t.Run("non-2xx response", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, strings.Repeat("not ready", 1024), http.StatusServiceUnavailable)
		}))
		defer upstream.Close()

		s := &server{
			cfg: config{
				BackendURL:      upstream.URL,
				APIToken:        "inbound-secret",
				BackendAPIToken: "backend-secret",
				Timeout:         time.Second,
			},
			client: upstream.Client(),
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "203.0.113.10:4321"
		req.Header.Set("Authorization", "Bearer inbound-secret")
		s.handleHealth(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected unavailable status %d, got %d", http.StatusServiceUnavailable, rec.Code)
		}
	})

	t.Run("unreachable backend", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		backendURL := upstream.URL
		client := upstream.Client()
		upstream.Close()

		s := &server{
			cfg: config{
				BackendURL:      backendURL,
				APIToken:        "inbound-secret",
				BackendAPIToken: "backend-secret",
				Timeout:         100 * time.Millisecond,
			},
			client: client,
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "203.0.113.10:4321"
		req.Header.Set("Authorization", "Bearer inbound-secret")
		s.handleHealth(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected unavailable status %d, got %d", http.StatusServiceUnavailable, rec.Code)
		}
	})
}

func TestSimulatedNoBackendHealthRemainsReady(t *testing.T) {
	s := &server{cfg: config{AllowSimulated: true}}
	rec := httptest.NewRecorder()
	s.handleHealth(rec, newLoopbackRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected simulated development health %d, got %d", http.StatusOK, rec.Code)
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

	req1 := newLoopbackRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	req1.RemoteAddr = "127.0.0.1:9999"
	rec1 := httptest.NewRecorder()
	s.handleExecute(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request expected %d, got %d", http.StatusOK, rec1.Code)
	}

	req2 := newLoopbackRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	req2.RemoteAddr = "127.0.0.1:9999"
	rec2 := httptest.NewRecorder()
	s.handleExecute(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request expected %d, got %d", http.StatusTooManyRequests, rec2.Code)
	}
	if got := rec2.Header().Get("Retry-After"); got != "5" {
		t.Fatalf("expected integer Retry-After of 5 seconds, got %q", got)
	}
}

func TestExecuteRateLimitCannotBeBypassedWithForwardedHeadersOrSourcePorts(t *testing.T) {
	s := &server{
		cfg: config{
			AllowSimulated:     true,
			APIToken:           "secret-token",
			MinRequestInterval: 5 * time.Second,
		},
	}
	body, err := json.Marshal(appExecutionRequest{
		JobID:     "job-rate",
		ModelHash: []byte("model"),
		InputHash: []byte("input"),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	first := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(body))
	first.RemoteAddr = "203.0.113.10:41001"
	first.Header.Set("Authorization", "Bearer secret-token")
	first.Header.Set("X-Forwarded-For", "198.51.100.1")
	firstRec := httptest.NewRecorder()
	s.handleExecute(firstRec, first)
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first request expected %d, got %d", http.StatusOK, firstRec.Code)
	}

	second := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(body))
	second.RemoteAddr = "203.0.113.10:51002"
	second.Header.Set("Authorization", "Bearer secret-token")
	second.Header.Set("X-Forwarded-For", "198.51.100.200")
	second.Header.Set("Forwarded", "for=192.0.2.44")
	secondRec := httptest.NewRecorder()
	s.handleExecute(secondRec, second)
	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed forwarding headers/source port bypassed limiter: got %d", secondRec.Code)
	}

	otherPeer := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(body))
	otherPeer.RemoteAddr = "203.0.113.11:41001"
	otherPeer.Header.Set("Authorization", "Bearer secret-token")
	otherPeer.Header.Set("X-Forwarded-For", "198.51.100.200")
	otherPeerRec := httptest.NewRecorder()
	s.handleExecute(otherPeerRec, otherPeer)
	if otherPeerRec.Code != http.StatusOK {
		t.Fatalf("distinct actual peer should have an independent limit, got %d", otherPeerRec.Code)
	}
}

func TestRateLimiterSerializesConcurrentRequestsForSamePrincipalAndPeer(t *testing.T) {
	s := &server{cfg: config{MinRequestInterval: time.Second}}
	var allowed atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/execute", nil)
			req.RemoteAddr = "203.0.113.10:41001"
			req.Header.Set("Authorization", "Bearer secret-token")
			req.Header.Set("X-Forwarded-For", "198.51.100.200")
			if ok, _ := s.allowRequest(req, "/execute"); ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got != 1 {
		t.Fatalf("expected exactly one concurrent request to pass, got %d", got)
	}
}

func TestNewHTTPServerSetsBoundedRequestProtections(t *testing.T) {
	cfg := config{
		ListenAddr: "127.0.0.1:8545",
		Timeout:    12 * time.Second,
	}
	handler := http.NewServeMux()
	srv := newHTTPServer(cfg, handler)

	if srv.ReadHeaderTimeout != serverReadHeaderTimeout {
		t.Fatalf("unexpected ReadHeaderTimeout: %s", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != serverReadTimeout || srv.ReadTimeout <= 0 {
		t.Fatalf("ReadTimeout must be bounded, got %s", srv.ReadTimeout)
	}
	wantWriteTimeout := serverReadTimeout + cfg.Timeout + serverWriteTimeoutGrace
	if srv.WriteTimeout != wantWriteTimeout {
		t.Fatalf("WriteTimeout must cover request read, backend timeout, and grace, got %s", srv.WriteTimeout)
	}
	if srv.IdleTimeout != serverIdleTimeout || srv.IdleTimeout <= 0 {
		t.Fatalf("IdleTimeout must be bounded, got %s", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes != serverMaxHeaderBytes || srv.MaxHeaderBytes <= 0 {
		t.Fatalf("MaxHeaderBytes must be bounded, got %d", srv.MaxHeaderBytes)
	}
	if srv.Handler != handler {
		t.Fatal("HTTP server did not retain configured handler")
	}
}

func TestReadBoundedRequestBodyRejectsOversizedPayload(t *testing.T) {
	rec := httptest.NewRecorder()
	req := newLoopbackRequest(
		http.MethodPost,
		"/execute",
		bytes.NewBufferString("12345"),
	)

	body, err := readBoundedRequestBody(rec, req, 4)
	if err == nil {
		t.Fatal("expected oversized request body to fail")
	}
	if body != nil {
		t.Fatalf("expected no body on failure, got %q", body)
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusRequestEntityTooLarge,
			rec.Code,
		)
	}
}

func TestHandleExecuteRejectsInvalidBackendEndpoint(t *testing.T) {
	s := &server{
		cfg: config{
			BackendURL: "https://169.254.169.254",
		},
		client: &http.Client{Timeout: time.Second},
	}
	reqBody, _ := json.Marshal(appExecutionRequest{
		JobID:     "job-invalid-backend",
		ModelHash: []byte("model"),
		InputHash: []byte("input"),
	})

	rec := httptest.NewRecorder()
	req := newLoopbackRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	s.handleExecute(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, rec.Code)
	}
}

func TestHandleVerifyRejectsInvalidBackendEndpoint(t *testing.T) {
	s := &server{
		cfg: config{
			BackendURL: "https://169.254.169.254",
		},
		client: &http.Client{Timeout: time.Second},
	}
	verifyBody, _ := json.Marshal(tee.NitroAttestationDocument{
		ModuleID:  "enclave-1",
		Timestamp: time.Now().UTC(),
		Digest:    "SHA256",
		PCRs: map[int][]byte{
			0: []byte("pcr0"),
		},
		UserData: []byte("user-data"),
		Nonce:    []byte("nonce"),
	})

	rec := httptest.NewRecorder()
	req := newLoopbackRequest(http.MethodPost, "/verify", bytes.NewReader(verifyBody))
	s.handleVerify(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, rec.Code)
	}
}

func TestHandleExecuteRejectsRemoteRequestWithoutBearerToken(t *testing.T) {
	s := &server{
		cfg: config{
			AllowSimulated: true,
			Platform:       "aws-nitro",
			EnclaveID:      "enclave-auth",
		},
	}
	reqBody, _ := json.Marshal(appExecutionRequest{
		JobID:     "job-auth",
		ModelHash: []byte("model"),
		InputHash: []byte("input"),
		InputData: []byte("payload"),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	req.RemoteAddr = "203.0.113.10:4321"
	s.handleExecute(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestHandleExecuteAcceptsRemoteBearerToken(t *testing.T) {
	s := &server{
		cfg: config{
			AllowSimulated: true,
			Platform:       "aws-nitro",
			EnclaveID:      "enclave-auth",
			APIToken:       "secret-token",
		},
	}
	reqBody, _ := json.Marshal(appExecutionRequest{
		JobID:     "job-auth-ok",
		ModelHash: []byte("model"),
		InputHash: []byte("input"),
		InputData: []byte("payload"),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(reqBody))
	req.RemoteAddr = "203.0.113.10:4321"
	req.Header.Set("Authorization", "Bearer secret-token")
	s.handleExecute(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}
