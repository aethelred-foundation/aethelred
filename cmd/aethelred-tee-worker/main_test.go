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

func TestLoadConfigDefaultsToLoopbackAndLoadsAPIToken(t *testing.T) {
	t.Setenv("AETHELRED_TEE_LISTEN_ADDR", "")
	t.Setenv(apiTokenEnv, "  worker-secret  ")
	t.Setenv(backendAPITokenEnv, "  backend-secret  ")
	t.Setenv("AETHELRED_TEE_MIN_REQUEST_INTERVAL", "")

	cfg := loadConfig()

	if cfg.ListenAddr != defaultListenAddr {
		t.Fatalf("expected default listen address %q, got %q", defaultListenAddr, cfg.ListenAddr)
	}
	if cfg.APIToken != "worker-secret" {
		t.Fatalf("expected trimmed API token, got %q", cfg.APIToken)
	}
	if cfg.BackendAPIToken != "backend-secret" {
		t.Fatalf("expected trimmed backend API token, got %q", cfg.BackendAPIToken)
	}
	if cfg.MinRequestInterval != defaultMinRequestInterval {
		t.Fatalf("expected default request interval %s, got %s", defaultMinRequestInterval, cfg.MinRequestInterval)
	}
}

func TestBackendReadinessAndProxyUseOnlyBackendAuthorization(t *testing.T) {
	var (
		healthAuthorization  string
		executeAuthorization string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			healthAuthorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		case "/execute":
			executeAuthorization = r.Header.Get("Authorization")
			writeJSON(w, http.StatusOK, map[string]any{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	s := &server{
		cfg: config{
			BackendURL:      upstream.URL,
			BackendAPIToken: "backend-secret",
			Timeout:         time.Second,
		},
		client: upstream.Client(),
	}

	healthRec := httptest.NewRecorder()
	s.handleHealth(healthRec, newLoopbackRequest(http.MethodGet, "/health", nil))
	if healthRec.Code != http.StatusOK {
		t.Fatalf("expected ready status %d, got %d", http.StatusOK, healthRec.Code)
	}
	if healthAuthorization != "Bearer backend-secret" {
		t.Fatalf("backend health received unexpected authorization %q", healthAuthorization)
	}

	executeRec := httptest.NewRecorder()
	executeReq := newLoopbackRequest(http.MethodPost, "/execute", strings.NewReader(`{}`))
	executeReq.Header.Set("Authorization", "Bearer inbound-secret")
	s.handleExecute(executeRec, executeReq)
	if executeRec.Code != http.StatusOK {
		t.Fatalf("expected proxied status %d, got %d", http.StatusOK, executeRec.Code)
	}
	if executeAuthorization != "Bearer backend-secret" {
		t.Fatalf("backend execute received unexpected authorization %q", executeAuthorization)
	}
}

func TestBackendReadinessFailsClosed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer upstream.Close()

	s := &server{
		cfg: config{
			BackendURL:      upstream.URL,
			BackendAPIToken: "backend-secret",
			Timeout:         time.Second,
		},
		client: upstream.Client(),
	}
	rec := httptest.NewRecorder()
	s.handleHealth(rec, newLoopbackRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unavailable status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
}

func TestValidateListenAddrSecurity(t *testing.T) {
	tests := []struct {
		name       string
		listenAddr string
		apiToken   string
		wantErr    bool
	}{
		{name: "IPv4 loopback", listenAddr: "127.0.0.1:8545"},
		{name: "IPv6 loopback", listenAddr: "[::1]:8545"},
		{name: "localhost", listenAddr: "localhost:8545"},
		{name: "empty address", listenAddr: "", wantErr: true},
		{name: "implicit wildcard", listenAddr: ":8545", wantErr: true},
		{name: "IPv4 wildcard", listenAddr: "0.0.0.0:8545", wantErr: true},
		{name: "IPv6 wildcard", listenAddr: "[::]:8545", wantErr: true},
		{name: "public IP", listenAddr: "203.0.113.10:8545", wantErr: true},
		{name: "non-loopback hostname", listenAddr: "tee-worker.internal:8545", wantErr: true},
		{name: "wildcard with token", listenAddr: "0.0.0.0:8545", apiToken: "secret"},
		{name: "hostname with token", listenAddr: "tee-worker.internal:8545", apiToken: "secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateListenAddrSecurity(tt.listenAddr, tt.apiToken)
			if tt.wantErr && err == nil {
				t.Fatalf("expected %q to be rejected without a token", tt.listenAddr)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected %q to be accepted: %v", tt.listenAddr, err)
			}
			if err != nil && !strings.Contains(err.Error(), apiTokenEnv) {
				t.Fatalf("expected error to name %s, got %q", apiTokenEnv, err)
			}
		})
	}
}

func TestRemoteRoutesRequireBearerToken(t *testing.T) {
	s := &server{cfg: config{AllowSimulated: true}}
	tests := []struct {
		name    string
		method  string
		target  string
		handler http.HandlerFunc
	}{
		{name: "health", method: http.MethodGet, target: "/health", handler: s.handleHealth},
		{name: "capabilities", method: http.MethodGet, target: "/capabilities", handler: s.handleCapabilities},
		{name: "execute", method: http.MethodPost, target: "/execute", handler: s.handleExecute},
		{name: "verify", method: http.MethodPost, target: "/verify", handler: s.handleVerify},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.target, strings.NewReader(`{}`))
			req.RemoteAddr = "203.0.113.10:4321"

			tt.handler(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
			}
		})
	}
}

func TestRemoteRoutesAcceptConfiguredBearerToken(t *testing.T) {
	s := &server{
		cfg: config{
			AllowSimulated:    true,
			APIToken:          "secret-token",
			MaxAttestationAge: 5 * time.Minute,
		},
	}
	tests := []struct {
		name    string
		method  string
		target  string
		body    string
		handler http.HandlerFunc
	}{
		{name: "health", method: http.MethodGet, target: "/health", handler: s.handleHealth},
		{name: "capabilities", method: http.MethodGet, target: "/capabilities", handler: s.handleCapabilities},
		{name: "execute", method: http.MethodPost, target: "/execute", body: `{"JobID":"job-auth"}`, handler: s.handleExecute},
		{name: "verify", method: http.MethodPost, target: "/verify", body: `{}`, handler: s.handleVerify},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body))
			req.RemoteAddr = "203.0.113.10:4321"
			req.Header.Set("Authorization", "Bearer secret-token")

			tt.handler(rec, req)

			if rec.Code == http.StatusUnauthorized {
				t.Fatalf("configured bearer token was rejected")
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
			}
		})
	}
}

func TestRemoteBearerTokenAuthorization(t *testing.T) {
	s := &server{cfg: config{AllowSimulated: true, APIToken: "secret-token"}}

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{name: "missing", wantStatus: http.StatusUnauthorized},
		{name: "wrong scheme", authHeader: "Basic secret-token", wantStatus: http.StatusUnauthorized},
		{name: "empty bearer", authHeader: "Bearer ", wantStatus: http.StatusUnauthorized},
		{name: "wrong token", authHeader: "Bearer wrong-token", wantStatus: http.StatusUnauthorized},
		{name: "valid token", authHeader: "Bearer secret-token", wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			req.RemoteAddr = "203.0.113.10:4321"
			req.Header.Set("Authorization", tt.authHeader)

			s.handleHealth(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestDirectLoopbackRequestDoesNotRequireToken(t *testing.T) {
	s := &server{cfg: config{AllowSimulated: true}}
	rec := httptest.NewRecorder()
	req := newLoopbackRequest(http.MethodGet, "/health", nil)

	s.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestForwardedLoopbackRequestRequiresToken(t *testing.T) {
	for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP"} {
		t.Run(header, func(t *testing.T) {
			s := &server{cfg: config{AllowSimulated: true, APIToken: "secret-token"}}
			rec := httptest.NewRecorder()
			req := newLoopbackRequest(http.MethodGet, "/health", nil)
			req.Header.Set(header, "for=203.0.113.10")

			s.handleHealth(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
			}

			rec = httptest.NewRecorder()
			req = newLoopbackRequest(http.MethodGet, "/health", nil)
			req.Header.Set(header, "for=203.0.113.10")
			req.Header.Set("Authorization", "Bearer secret-token")
			s.handleHealth(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected authenticated status %d, got %d", http.StatusOK, rec.Code)
			}
		})
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
	body := `{"JobID":"job-rate","ModelHash":"bW9kZWw=","InputHash":"aW5wdXQ="}`

	first := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(body))
	first.RemoteAddr = "203.0.113.10:41001"
	first.Header.Set("Authorization", "Bearer secret-token")
	first.Header.Set("X-Forwarded-For", "198.51.100.1")
	firstRec := httptest.NewRecorder()
	s.handleExecute(firstRec, first)
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first request expected %d, got %d", http.StatusOK, firstRec.Code)
	}

	second := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(body))
	second.RemoteAddr = "203.0.113.10:51002"
	second.Header.Set("Authorization", "Bearer secret-token")
	second.Header.Set("X-Forwarded-For", "198.51.100.200")
	second.Header.Set("Forwarded", "for=192.0.2.44")
	secondRec := httptest.NewRecorder()
	s.handleExecute(secondRec, second)
	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed forwarding headers/source port bypassed limiter: got %d", secondRec.Code)
	}
	if got := secondRec.Header().Get("Retry-After"); got != "5" {
		t.Fatalf("expected integer Retry-After of 5 seconds, got %q", got)
	}

	otherPeer := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(body))
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
		strings.NewReader("12345"),
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
