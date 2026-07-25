package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aethelred/aethelred/x/verify/ezkl"
)

func newLoopbackRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.RemoteAddr = "127.0.0.1:1234"
	return req
}

func TestHandleProveFailClosedWhenSimulationDisabled(t *testing.T) {
	s := &server{cfg: config{AllowSimulated: false}}
	reqBody, _ := json.Marshal(ezkl.ProofRequest{
		ModelHash:   []byte("model"),
		InputHash:   []byte("input"),
		OutputHash:  []byte("output"),
		CircuitHash: []byte("circuit"),
	})

	rec := httptest.NewRecorder()
	req := newLoopbackRequest(http.MethodPost, "/prove", bytes.NewReader(reqBody))
	s.handleProve(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
}

func TestSimulatedProveAndVerify(t *testing.T) {
	s := &server{cfg: config{AllowSimulated: true}}
	verifyingKey := []byte("verifying-key")
	reqBody, _ := json.Marshal(ezkl.ProofRequest{
		RequestID:        "req-1",
		ModelHash:        []byte("model"),
		InputHash:        []byte("input"),
		OutputHash:       []byte("output"),
		CircuitHash:      []byte("circuit"),
		VerifyingKeyHash: hashBytes(verifyingKey),
	})

	proveRec := httptest.NewRecorder()
	proveReq := newLoopbackRequest(http.MethodPost, "/prove", bytes.NewReader(reqBody))
	s.handleProve(proveRec, proveReq)
	if proveRec.Code != http.StatusOK {
		t.Fatalf("expected prove status %d, got %d", http.StatusOK, proveRec.Code)
	}

	var proveResp ezkl.ProofResult
	if err := json.Unmarshal(proveRec.Body.Bytes(), &proveResp); err != nil {
		t.Fatalf("failed to decode prove response: %v", err)
	}
	if !proveResp.Success {
		t.Fatalf("expected proof success")
	}
	if len(proveResp.Proof) == 0 {
		t.Fatalf("expected non-empty proof bytes")
	}

	verifyBody, _ := json.Marshal(verifyRequest{
		Proof:        proveResp.Proof,
		PublicInputs: proveResp.PublicInputs,
		VerifyingKey: verifyingKey,
	})
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

func TestLoadConfigUsesSecureDefaultsAndAuthToken(t *testing.T) {
	t.Setenv("AETHELRED_ZKML_LISTEN_ADDR", "")
	t.Setenv("AETHELRED_ZKML_BACKEND_URL", "")
	t.Setenv("AETHELRED_ZKML_MIN_REQUEST_INTERVAL", "")
	t.Setenv("AETHELRED_ALLOW_SIMULATED", "true")
	t.Setenv("PROVER_MODE", "development")
	t.Setenv(apiTokenEnv, "  prover-secret  ")
	t.Setenv(backendAPITokenEnv, "  backend-secret  ")

	cfg := loadConfig()

	if cfg.ListenAddr != defaultListenAddr {
		t.Fatalf("expected default listen address %q, got %q", defaultListenAddr, cfg.ListenAddr)
	}
	if cfg.APIToken != "prover-secret" {
		t.Fatalf("expected trimmed API token, got %q", cfg.APIToken)
	}
	if cfg.BackendAPIToken != "backend-secret" {
		t.Fatalf("expected trimmed backend API token, got %q", cfg.BackendAPIToken)
	}
	if cfg.MinRequestInterval != defaultMinRequestInterval {
		t.Fatalf("expected default request interval %s, got %s", defaultMinRequestInterval, cfg.MinRequestInterval)
	}
	if cfg.ProductionMode {
		t.Fatal("development mode was classified as production")
	}
}

func TestValidateConfigRequiresBackendOutsideSimulation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{
			name: "simulation disabled",
			cfg: config{
				ListenAddr:     defaultListenAddr,
				AllowSimulated: false,
			},
			wantErr: "AETHELRED_ZKML_BACKEND_URL",
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
		{
			name: "production requires backend",
			cfg: config{
				ListenAddr:     defaultListenAddr,
				ProductionMode: true,
			},
			wantErr: "AETHELRED_ZKML_BACKEND_URL",
		},
		{
			name: "unsafe remote backend",
			cfg: config{
				ListenAddr: defaultListenAddr,
				BackendURL: "http://203.0.113.10:8546",
			},
			wantErr: "invalid zkML prover backend URL",
		},
		{
			name: "real backend requires outbound token",
			cfg: config{
				ListenAddr: defaultListenAddr,
				BackendURL: "http://127.0.0.1:18546",
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
				BackendURL:      "http://127.0.0.1:18546",
				BackendAPIToken: "backend-secret",
			},
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

func TestBackendReadinessAndProxyUseOnlyBackendAuthorization(t *testing.T) {
	var (
		healthAuthorization string
		proveAuthorization  string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			healthAuthorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		case "/prove":
			proveAuthorization = r.Header.Get("Authorization")
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

	proveRec := httptest.NewRecorder()
	proveReq := newLoopbackRequest(http.MethodPost, "/prove", strings.NewReader(`{}`))
	proveReq.Header.Set("Authorization", "Bearer inbound-secret")
	s.handleProve(proveRec, proveReq)
	if proveRec.Code != http.StatusOK {
		t.Fatalf("expected proxied status %d, got %d", http.StatusOK, proveRec.Code)
	}
	if proveAuthorization != "Bearer backend-secret" {
		t.Fatalf("backend prove received unexpected authorization %q", proveAuthorization)
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
		{name: "IPv4 loopback", listenAddr: "127.0.0.1:8546"},
		{name: "IPv6 loopback", listenAddr: "[::1]:8546"},
		{name: "localhost", listenAddr: "localhost:8546"},
		{name: "implicit wildcard", listenAddr: ":8546", wantErr: true},
		{name: "IPv4 wildcard", listenAddr: "0.0.0.0:8546", wantErr: true},
		{name: "IPv6 wildcard", listenAddr: "[::]:8546", wantErr: true},
		{name: "public address", listenAddr: "203.0.113.10:8546", wantErr: true},
		{name: "wildcard with token", listenAddr: "0.0.0.0:8546", apiToken: "secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateListenAddrSecurity(tt.listenAddr, tt.apiToken)
			if tt.wantErr && err == nil {
				t.Fatalf("expected %q to require a token", tt.listenAddr)
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

func TestRemoteRoutesRequireConfiguredBearerToken(t *testing.T) {
	s := &server{
		cfg: config{
			AllowSimulated: true,
			APIToken:       "secret-token",
		},
	}
	tests := []struct {
		name    string
		method  string
		target  string
		handler http.HandlerFunc
	}{
		{name: "health", method: http.MethodGet, target: "/health", handler: s.handleHealth},
		{name: "prove", method: http.MethodPost, target: "/prove", handler: s.handleProve},
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

			rec = httptest.NewRecorder()
			req = httptest.NewRequest(tt.method, tt.target, strings.NewReader(`{}`))
			req.RemoteAddr = "203.0.113.10:4321"
			req.Header.Set("Authorization", "Bearer secret-token")
			tt.handler(rec, req)
			if rec.Code == http.StatusUnauthorized {
				t.Fatal("configured bearer token was rejected")
			}
		})
	}
}

func TestForwardedLoopbackRequestCannotBypassAuthentication(t *testing.T) {
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

func TestExpensiveRoutesRateLimitByPrincipalAndActualPeer(t *testing.T) {
	s := &server{
		cfg: config{
			AllowSimulated:     true,
			APIToken:           "secret-token",
			MinRequestInterval: 5 * time.Second,
		},
	}

	tests := []struct {
		name    string
		target  string
		handler http.HandlerFunc
	}{
		{name: "prove", target: "/prove", handler: s.handleProve},
		{name: "verify", target: "/verify", handler: s.handleVerify},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader(`{}`))
			first.RemoteAddr = "203.0.113.10:41001"
			first.Header.Set("Authorization", "Bearer secret-token")
			first.Header.Set("X-Forwarded-For", "198.51.100.1")
			firstRec := httptest.NewRecorder()
			tt.handler(firstRec, first)
			if firstRec.Code == http.StatusTooManyRequests || firstRec.Code == http.StatusUnauthorized {
				t.Fatalf("first request unexpectedly rejected with %d", firstRec.Code)
			}

			second := httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader(`{}`))
			second.RemoteAddr = "203.0.113.10:51002"
			second.Header.Set("Authorization", "Bearer secret-token")
			second.Header.Set("X-Forwarded-For", "198.51.100.200")
			second.Header.Set("Forwarded", "for=192.0.2.44")
			secondRec := httptest.NewRecorder()
			tt.handler(secondRec, second)
			if secondRec.Code != http.StatusTooManyRequests {
				t.Fatalf("spoofed forwarding headers/source port bypassed limiter: got %d", secondRec.Code)
			}
			if got := secondRec.Header().Get("Retry-After"); got != "5" {
				t.Fatalf("expected integer Retry-After of 5 seconds, got %q", got)
			}

			otherPeer := httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader(`{}`))
			otherPeer.RemoteAddr = "203.0.113.11:41001"
			otherPeer.Header.Set("Authorization", "Bearer secret-token")
			otherPeer.Header.Set("X-Forwarded-For", "198.51.100.200")
			otherPeerRec := httptest.NewRecorder()
			tt.handler(otherPeerRec, otherPeer)
			if otherPeerRec.Code == http.StatusTooManyRequests || otherPeerRec.Code == http.StatusUnauthorized {
				t.Fatalf("distinct actual peer should have an independent limit, got %d", otherPeerRec.Code)
			}
		})
	}
}

func TestRateLimiterSerializesConcurrentRequests(t *testing.T) {
	s := &server{cfg: config{MinRequestInterval: time.Second}}
	var allowed atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/prove", nil)
			req.RemoteAddr = "203.0.113.10:41001"
			req.Header.Set("Authorization", "Bearer secret-token")
			req.Header.Set("X-Forwarded-For", "198.51.100.200")
			if ok, _ := s.allowRequest(req, "/prove"); ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got != 1 {
		t.Fatalf("expected exactly one concurrent request to pass, got %d", got)
	}
}

func TestRequestBodiesRejectOversizeInsteadOfTruncating(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		handler func(*server, http.ResponseWriter, *http.Request)
	}{
		{name: "prove", target: "/prove", handler: (*server).handleProve},
		{name: "verify", target: "/verify", handler: (*server).handleVerify},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server{cfg: config{AllowSimulated: true}}
			body := bytes.Repeat([]byte("x"), int(maxRequestBodyBytes)+1)
			rec := httptest.NewRecorder()
			req := newLoopbackRequest(http.MethodPost, tt.target, bytes.NewReader(body))

			tt.handler(s, rec, req)

			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "request body too large") {
				t.Fatalf("unexpected oversized-body response: %s", rec.Body.String())
			}
		})
	}
}

func TestNewHTTPServerSetsBoundedRequestProtections(t *testing.T) {
	cfg := config{
		ListenAddr: defaultListenAddr,
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
