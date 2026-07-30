package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aethelred/aethelred/x/verify/ezkl"
	"github.com/aethelred/aethelred/x/verify/httputil"
)

const (
	defaultListenAddr               = "127.0.0.1:8546"
	apiTokenEnv                     = "AETHELRED_ZKML_API_TOKEN"
	backendAPITokenEnv              = "AETHELRED_ZKML_BACKEND_API_TOKEN"
	defaultMinRequestInterval       = 200 * time.Millisecond
	maxRequestBodyBytes       int64 = 8 << 20
	backendHealthProbeTimeout       = 3 * time.Second
	serverReadHeaderTimeout         = 5 * time.Second
	serverReadTimeout               = 30 * time.Second
	serverWriteTimeoutGrace         = 5 * time.Second
	serverIdleTimeout               = 60 * time.Second
	serverMaxHeaderBytes            = 64 << 10
	rateLimitEntryRetention         = 10 * time.Minute
	rateLimitCleanupInterval        = time.Minute
)

type config struct {
	ListenAddr         string
	BackendURL         string
	AllowSimulated     bool
	ProductionMode     bool
	APIToken           string
	BackendAPIToken    string
	MinRequestInterval time.Duration
	Timeout            time.Duration
}

type server struct {
	cfg    config
	client *http.Client

	rateMu          sync.Mutex
	lastRequestByK  map[string]time.Time
	lastRateCleanup time.Time
}

type simulatedProof struct {
	Version           string `json:"version"`
	RequestDigestHex  string `json:"request_digest_hex"`
	ModelCommitment   []byte `json:"model_commitment"`
	InputCommitment   []byte `json:"input_commitment"`
	OutputCommitment  []byte `json:"output_commitment"`
	VerifyingKeyHash  []byte `json:"verifying_key_hash"`
	GeneratedUnixNano int64  `json:"generated_unix_nano"`
}

type verifyRequest struct {
	Proof        []byte             `json:"proof"`
	PublicInputs *ezkl.PublicInputs `json:"public_inputs"`
	VerifyingKey []byte             `json:"verifying_key"`
}

func main() {
	cfg := loadConfig()
	if err := validateConfig(cfg); err != nil {
		log.Fatalf("invalid zkML prover configuration: %v", err)
	}
	client, err := httputil.NewSecureClient(&http.Client{Timeout: cfg.Timeout})
	if err != nil {
		log.Fatalf("failed to create secure backend HTTP client: %v", err)
	}
	srv := &server{
		cfg:    cfg,
		client: client,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/prove", srv.handleProve)
	mux.HandleFunc("/verify", srv.handleVerify)

	httpServer := newHTTPServer(cfg, mux)

	log.Printf("starting zkML prover service on %s (simulated=%t backend=%q)", cfg.ListenAddr, cfg.AllowSimulated, cfg.BackendURL)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("zkML prover server failed: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("zkML prover shutdown error: %v", err)
	}
}

func loadConfig() config {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("PROVER_MODE")))
	allowSimulated := envBool("AETHELRED_ALLOW_SIMULATED")
	if !allowSimulated {
		if mode == "development" || mode == "dev" || mode == "simulated" {
			allowSimulated = true
		}
	}
	timeout := 15 * time.Second
	if v := strings.TrimSpace(os.Getenv("AETHELRED_ZKML_TIMEOUT")); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			timeout = parsed
		}
	}

	return config{
		ListenAddr:         envOrDefault("AETHELRED_ZKML_LISTEN_ADDR", defaultListenAddr),
		BackendURL:         strings.TrimRight(strings.TrimSpace(os.Getenv("AETHELRED_ZKML_BACKEND_URL")), "/"),
		AllowSimulated:     allowSimulated,
		ProductionMode:     mode == "production" || mode == "prod",
		APIToken:           strings.TrimSpace(os.Getenv(apiTokenEnv)),
		BackendAPIToken:    strings.TrimSpace(os.Getenv(backendAPITokenEnv)),
		MinRequestInterval: envDurationOrDefault("AETHELRED_ZKML_MIN_REQUEST_INTERVAL", defaultMinRequestInterval),
		Timeout:            timeout,
	}
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func envDurationOrDefault(key string, fallback time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed >= 0 {
			return parsed
		}
	}
	return fallback
}

func validateConfig(cfg config) error {
	if cfg.ProductionMode && cfg.AllowSimulated {
		return errors.New("simulated proofs are not allowed in production mode")
	}
	if (cfg.ProductionMode || !cfg.AllowSimulated) && cfg.BackendURL == "" {
		return errors.New("AETHELRED_ZKML_BACKEND_URL is required when simulation is disabled or production mode is enabled")
	}
	if cfg.BackendURL != "" {
		if err := httputil.ValidateEndpointURL(cfg.BackendURL); err != nil {
			return fmt.Errorf("invalid zkML prover backend URL: %w", err)
		}
		if !cfg.AllowSimulated && strings.TrimSpace(cfg.BackendAPIToken) == "" {
			return fmt.Errorf("%s is required for a real zkML backend", backendAPITokenEnv)
		}
	}
	if err := validateListenAddrSecurity(cfg.ListenAddr, cfg.APIToken); err != nil {
		return err
	}
	return nil
}

func newHTTPServer(cfg config, handler http.Handler) *http.Server {
	backendTimeout := cfg.Timeout
	if backendTimeout <= 0 {
		backendTimeout = 15 * time.Second
	}
	writeTimeout := addDurationSaturating(serverReadTimeout, backendTimeout)
	writeTimeout = addDurationSaturating(writeTimeout, serverWriteTimeoutGrace)

	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       serverIdleTimeout,
		MaxHeaderBytes:    serverMaxHeaderBytes,
	}
}

func addDurationSaturating(base, delta time.Duration) time.Duration {
	const maxDuration = time.Duration(1<<63 - 1)
	if delta > 0 && base > maxDuration-delta {
		return maxDuration
	}
	return base + delta
}

func validateListenAddrSecurity(listenAddr, apiToken string) error {
	if isLoopbackListenAddr(listenAddr) {
		return nil
	}
	if strings.TrimSpace(apiToken) == "" {
		return fmt.Errorf("%s is required when the zkML prover listens beyond explicit loopback addresses", apiTokenEnv)
	}
	return nil
}

func isLoopbackListenAddr(listenAddr string) bool {
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" || strings.HasPrefix(listenAddr, ":") {
		return false
	}

	host := listenAddr
	if parsedHost, _, err := net.SplitHostPort(listenAddr); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

func (s *server) authorizeRequest(r *http.Request) error {
	if isDirectLoopbackRequest(r) {
		return nil
	}

	expectedToken := strings.TrimSpace(s.cfg.APIToken)
	if expectedToken == "" {
		return errors.New("authorization required")
	}

	providedToken, ok := parseBearerToken(r.Header.Get("Authorization"))
	if !ok || subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) != 1 {
		return errors.New("authorization required")
	}
	return nil
}

func isDirectLoopbackRequest(r *http.Request) bool {
	if r == nil || !isLoopbackRemoteAddr(r.RemoteAddr) {
		return false
	}
	return !hasForwardingHeaders(r.Header)
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return false
	}

	host := remoteAddr
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

func hasForwardingHeaders(header http.Header) bool {
	if header == nil {
		return false
	}
	for _, key := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP"} {
		if strings.TrimSpace(header.Get(key)) != "" {
			return true
		}
	}
	return false
}

func parseBearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", false
	}
	return token, true
}

func (s *server) rateLimitKey(r *http.Request, endpoint string) string {
	principal := "unauthenticated"
	if isDirectLoopbackRequest(r) {
		principal = "local-loopback"
	} else if r != nil {
		if token, ok := parseBearerToken(r.Header.Get("Authorization")); ok {
			digest := sha256.Sum256([]byte(token))
			principal = fmt.Sprintf("bearer:%x", digest[:])
		}
	}

	remoteHost := "unknown"
	if r != nil {
		remoteHost = normalizedRemoteHost(r.RemoteAddr)
	}
	return endpoint + "|" + principal + "|" + remoteHost
}

func normalizedRemoteHost(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return "unknown"
	}

	host := remoteAddr
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	if host == "" {
		return "unknown"
	}
	return strings.ToLower(host)
}

func (s *server) allowRequest(r *http.Request, endpoint string) (bool, time.Duration) {
	if s == nil || s.cfg.MinRequestInterval <= 0 {
		return true, 0
	}

	now := time.Now()
	key := s.rateLimitKey(r, endpoint)

	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	if s.lastRequestByK == nil {
		s.lastRequestByK = make(map[string]time.Time)
	}
	if s.lastRateCleanup.IsZero() || now.Sub(s.lastRateCleanup) >= rateLimitCleanupInterval {
		retention := rateLimitEntryRetention
		if s.cfg.MinRequestInterval > retention {
			retention = s.cfg.MinRequestInterval
		}
		for existingKey, lastSeen := range s.lastRequestByK {
			if now.Sub(lastSeen) >= retention {
				delete(s.lastRequestByK, existingKey)
			}
		}
		s.lastRateCleanup = now
	}

	if last, ok := s.lastRequestByK[key]; ok {
		elapsed := now.Sub(last)
		if elapsed < s.cfg.MinRequestInterval {
			return false, s.cfg.MinRequestInterval - elapsed
		}
	}
	s.lastRequestByK[key] = now
	return true, 0
}

func writeRateLimitError(w http.ResponseWriter, retryAfter time.Duration) {
	if retryAfter > 0 {
		retryAfterSeconds := retryAfter / time.Second
		if retryAfter%time.Second != 0 {
			retryAfterSeconds++
		}
		if retryAfterSeconds < 1 {
			retryAfterSeconds = 1
		}
		w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfterSeconds), 10))
	}
	writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
}

func readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	return io.ReadAll(r.Body)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.authorizeRequest(r); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.checkBackendHealth(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"service":       "aethelred-zkml-prover",
			"status":        "unavailable",
			"backend_ready": false,
		})
		return
	}

	status := map[string]any{
		"service":         "aethelred-zkml-prover",
		"status":          "ok",
		"allow_simulated": s.cfg.AllowSimulated,
		"backend_url":     s.cfg.BackendURL != "",
		"backend_ready":   true,
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *server) checkBackendHealth(parent context.Context) error {
	if s == nil {
		return errors.New("zkML prover is not initialized")
	}
	if s.cfg.BackendURL == "" {
		if s.cfg.AllowSimulated {
			return nil
		}
		return errors.New("zkML backend is not configured")
	}
	if s.client == nil {
		return errors.New("zkML backend client is not configured")
	}

	target := s.cfg.BackendURL + "/health"
	if err := httputil.ValidateEndpointURL(target); err != nil {
		return fmt.Errorf("zkML backend health endpoint is not allowed: %w", err)
	}

	timeout := backendHealthProbeTimeout
	if s.cfg.Timeout > 0 && s.cfg.Timeout < timeout {
		timeout = s.cfg.Timeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("build zkML backend health request: %w", err)
	}
	setBackendAuthorization(req, s.cfg.BackendAPIToken)

	// #nosec G704 -- the URL is validated above and production uses the SSRF-safe client.
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("probe zkML backend health: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, httputil.MaxErrorBodySize))

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("zkML backend health returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *server) handleProve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.authorizeRequest(r); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if allowed, retryAfter := s.allowRequest(r, "/prove"); !allowed {
		writeRateLimitError(w, retryAfter)
		return
	}

	body, err := readRequestBody(w, r)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	if s.cfg.BackendURL != "" {
		s.proxy(w, r, "/prove", body)
		return
	}
	if !s.cfg.AllowSimulated {
		writeError(w, http.StatusServiceUnavailable, "zkML prover backend not configured and simulation disabled")
		return
	}

	var req ezkl.ProofRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid proof request")
		return
	}

	if len(req.ModelHash) == 0 || len(req.InputHash) == 0 || len(req.OutputHash) == 0 || len(req.CircuitHash) == 0 {
		writeError(w, http.StatusBadRequest, "proof request missing required hashes")
		return
	}

	start := time.Now()
	result, err := simulateProof(&req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	result.GenerationTimeMs = time.Since(start).Milliseconds()
	writeJSON(w, http.StatusOK, result)
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.authorizeRequest(r); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if allowed, retryAfter := s.allowRequest(r, "/verify"); !allowed {
		writeRateLimitError(w, retryAfter)
		return
	}

	body, err := readRequestBody(w, r)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	if s.cfg.BackendURL != "" {
		s.proxy(w, r, "/verify", body)
		return
	}
	if !s.cfg.AllowSimulated {
		writeError(w, http.StatusServiceUnavailable, "zkML verifier backend not configured and simulation disabled")
		return
	}

	var req verifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid verification request")
		return
	}

	verified, verifyErr := verifyProof(req.Proof, req.PublicInputs, req.VerifyingKey)
	resp := map[string]any{
		"verified": verified,
	}
	if verifyErr != "" {
		resp["error"] = verifyErr
	}
	writeJSON(w, http.StatusOK, resp)
}

func simulateProof(req *ezkl.ProofRequest) (*ezkl.ProofResult, error) {
	publicInputs := &ezkl.PublicInputs{
		ModelCommitment:  hashBytes(req.ModelHash),
		InputCommitment:  hashBytes(req.InputHash),
		OutputCommitment: hashBytes(req.OutputHash),
		Instances: [][]byte{
			req.InputHash,
			req.OutputHash,
		},
	}
	metadata := simulatedProof{
		Version:           "aethelred-zkml-sim-v1",
		RequestDigestHex:  fmt.Sprintf("%x", hashMany(req.ModelHash, req.InputHash, req.OutputHash, req.CircuitHash, req.VerifyingKeyHash)),
		ModelCommitment:   publicInputs.ModelCommitment,
		InputCommitment:   publicInputs.InputCommitment,
		OutputCommitment:  publicInputs.OutputCommitment,
		VerifyingKeyHash:  req.VerifyingKeyHash,
		GeneratedUnixNano: time.Now().UTC().UnixNano(),
	}
	proofBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal simulated proof: %w", err)
	}

	return &ezkl.ProofResult{
		Success:          true,
		Proof:            proofBytes,
		PublicInputs:     publicInputs,
		VerifyingKeyHash: req.VerifyingKeyHash,
		CircuitHash:      req.CircuitHash,
		ProofSize:        int64(len(proofBytes)),
		Timestamp:        time.Now().UTC(),
		RequestID:        req.RequestID,
	}, nil
}

func verifyProof(proof []byte, publicInputs *ezkl.PublicInputs, verifyingKey []byte) (bool, string) {
	if len(proof) == 0 {
		return false, "empty proof"
	}
	if publicInputs == nil {
		return false, "missing public_inputs"
	}

	var parsed simulatedProof
	if err := json.Unmarshal(proof, &parsed); err != nil {
		return false, "invalid proof encoding"
	}
	if parsed.Version != "aethelred-zkml-sim-v1" {
		return false, "unsupported proof version"
	}
	if !bytes.Equal(publicInputs.ModelCommitment, parsed.ModelCommitment) {
		return false, "model commitment mismatch"
	}
	if !bytes.Equal(publicInputs.InputCommitment, parsed.InputCommitment) {
		return false, "input commitment mismatch"
	}
	if !bytes.Equal(publicInputs.OutputCommitment, parsed.OutputCommitment) {
		return false, "output commitment mismatch"
	}
	if len(parsed.VerifyingKeyHash) > 0 {
		if !bytes.Equal(hashBytes(verifyingKey), parsed.VerifyingKeyHash) {
			return false, "verifying key mismatch"
		}
	}
	return true, ""
}

func (s *server) proxy(w http.ResponseWriter, r *http.Request, path string, body []byte) {
	target := s.cfg.BackendURL + path
	if err := httputil.ValidateEndpointURL(target); err != nil {
		writeError(w, http.StatusBadGateway, "backend endpoint not allowed")
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to build backend request")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	setBackendAuthorization(req, s.cfg.BackendAPIToken)

	// #nosec G704 -- the URL is validated above and the secure transport pins a validated public IP before dialing.
	resp, err := s.client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "backend request failed")
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func setBackendAuthorization(req *http.Request, token string) {
	if req == nil {
		return
	}
	if token = strings.TrimSpace(token); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func hashBytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func hashMany(chunks ...[]byte) []byte {
	h := sha256.New()
	for _, c := range chunks {
		if len(c) > 0 {
			_, _ = h.Write(c)
		}
	}
	return h.Sum(nil)
}
