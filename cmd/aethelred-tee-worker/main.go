package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
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

	"github.com/aethelred/aethelred/x/verify/httputil"
	"github.com/aethelred/aethelred/x/verify/tee"
)

const (
	defaultListenAddr         = "127.0.0.1:8545"
	apiTokenEnv               = "AETHELRED_TEE_API_TOKEN"
	backendAPITokenEnv        = "AETHELRED_TEE_BACKEND_API_TOKEN"
	defaultMinRequestInterval = 200 * time.Millisecond
	backendHealthProbeTimeout = 3 * time.Second
	serverReadHeaderTimeout   = 5 * time.Second
	serverReadTimeout         = 30 * time.Second
	serverWriteTimeoutGrace   = 5 * time.Second
	serverIdleTimeout         = 60 * time.Second
	serverMaxHeaderBytes      = 64 << 10
	rateLimitEntryRetention   = 10 * time.Minute
	rateLimitCleanupInterval  = time.Minute
	maxExecuteRequestBytes    = 8 << 20
	maxVerifyRequestBytes     = 4 << 20
)

type config struct {
	ListenAddr         string
	BackendURL         string
	AllowSimulated     bool
	ProductionMode     bool
	APIToken           string
	BackendAPIToken    string
	Platform           string
	EnclaveID          string
	MaxAttestationAge  time.Duration
	MinRequestInterval time.Duration
	Timeout            time.Duration
	SupportsZKProofGen bool
}

type server struct {
	cfg    config
	client *http.Client

	rateMu          sync.Mutex
	lastRequestByK  map[string]time.Time
	lastRateCleanup time.Time
}

type appExecutionRequest struct {
	JobID          string            `json:"JobID"`
	ModelHash      []byte            `json:"ModelHash"`
	ModelURI       string            `json:"ModelURI"`
	InputHash      []byte            `json:"InputHash"`
	InputData      []byte            `json:"InputData"`
	InputURI       string            `json:"InputURI"`
	Nonce          []byte            `json:"Nonce"`
	RequireZKProof bool              `json:"RequireZKProof"`
	Metadata       map[string]string `json:"Metadata"`

	// BlockHeight anchors the attestation to a specific consensus height.
	// The verifier rejects attestations whose height doesn't match the
	// current vote extension height, preventing cross-block replay.
	BlockHeight int64 `json:"BlockHeight,omitempty"`

	// ChainID binds the attestation to a specific chain, preventing
	// cross-chain replay of attestation documents.
	ChainID string `json:"ChainID,omitempty"`
}

type appExecutionResult struct {
	JobID           string             `json:"JobID"`
	Success         bool               `json:"Success"`
	OutputHash      []byte             `json:"OutputHash"`
	Output          []byte             `json:"Output"`
	Attestation     *appTEEAttestation `json:"Attestation,omitempty"`
	ZKProof         *appZKProof        `json:"ZKProof,omitempty"`
	ExecutionTimeMs int64              `json:"ExecutionTimeMs"`
	ErrorCode       string             `json:"ErrorCode,omitempty"`
	ErrorMessage    string             `json:"ErrorMessage,omitempty"`
	GasUsed         int64              `json:"GasUsed"`
}

type appTEEAttestation struct {
	Platform         string    `json:"platform"`
	EnclaveID        string    `json:"enclave_id"`
	Measurement      []byte    `json:"measurement"`
	Quote            []byte    `json:"quote"`
	UserData         []byte    `json:"user_data"`
	CertificateChain [][]byte  `json:"certificate_chain,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
	Nonce            []byte    `json:"nonce"`

	// BlockHeight at which this attestation was generated. Bound into
	// UserData via SHA-256(outputHash || blockHeight || chainID) to
	// prevent cross-block and cross-chain attestation replay.
	BlockHeight int64  `json:"block_height,omitempty"`
	ChainID     string `json:"chain_id,omitempty"`
}

type appZKProof struct {
	ProofSystem      string `json:"proof_system"`
	Proof            []byte `json:"proof"`
	PublicInputs     []byte `json:"public_inputs"`
	VerifyingKeyHash []byte `json:"verifying_key_hash"`
	CircuitHash      []byte `json:"circuit_hash"`
	ProofSize        int64  `json:"proof_size"`
}

type appCapabilities struct {
	Platform              string   `json:"Platform"`
	SupportedModels       []string `json:"SupportedModels"`
	MaxModelSize          int64    `json:"MaxModelSize"`
	MaxInputSize          int64    `json:"MaxInputSize"`
	SupportsZKML          bool     `json:"SupportsZKML"`
	SupportedProofSystems []string `json:"SupportedProofSystems"`
	MemoryAvailable       int64    `json:"MemoryAvailable"`
	GPUAvailable          bool     `json:"GPUAvailable"`
}

func main() {
	cfg := loadConfig()
	if err := validateConfig(cfg); err != nil {
		log.Fatalf("invalid tee worker configuration: %v", err)
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
	mux.HandleFunc("/capabilities", srv.handleCapabilities)
	mux.HandleFunc("/execute", srv.handleExecute)
	mux.HandleFunc("/verify", srv.handleVerify)

	httpServer := newHTTPServer(cfg, mux)

	log.Printf("starting tee worker on %s (simulated=%t backend=%q)", cfg.ListenAddr, cfg.AllowSimulated, cfg.BackendURL)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("tee worker server failed: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("tee worker shutdown error: %v", err)
	}
}

func loadConfig() config {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("TEE_MODE")))
	allowSimulated := envBool("AETHELRED_ALLOW_SIMULATED")
	if !allowSimulated {
		switch mode {
		case "mock", "simulated", "nitro-simulated":
			allowSimulated = true
		}
	}

	timeout := 15 * time.Second
	if v := strings.TrimSpace(os.Getenv("AETHELRED_TEE_TIMEOUT")); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			timeout = parsed
		}
	}

	maxAge := 5 * time.Minute
	if v := strings.TrimSpace(os.Getenv("AETHELRED_TEE_MAX_ATTESTATION_AGE")); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			maxAge = parsed
		}
	}

	return config{
		ListenAddr:         envOrDefault("AETHELRED_TEE_LISTEN_ADDR", defaultListenAddr),
		BackendURL:         strings.TrimRight(strings.TrimSpace(os.Getenv("AETHELRED_TEE_BACKEND_URL")), "/"),
		AllowSimulated:     allowSimulated,
		ProductionMode:     mode == "production" || mode == "prod",
		APIToken:           strings.TrimSpace(os.Getenv(apiTokenEnv)),
		BackendAPIToken:    strings.TrimSpace(os.Getenv(backendAPITokenEnv)),
		Platform:           envOrDefault("AETHELRED_TEE_PLATFORM", "aws-nitro"),
		EnclaveID:          envOrDefault("AETHELRED_TEE_ENCLAVE_ID", "aethelred-tee-worker"),
		MaxAttestationAge:  maxAge,
		MinRequestInterval: envDurationOrDefault("AETHELRED_TEE_MIN_REQUEST_INTERVAL", defaultMinRequestInterval),
		Timeout:            timeout,
		SupportsZKProofGen: envBool("AETHELRED_TEE_SUPPORTS_ZKML"),
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

func validateConfig(cfg config) error {
	if cfg.ProductionMode && cfg.AllowSimulated {
		return errors.New("simulated TEE execution is not allowed in production mode")
	}
	if !cfg.AllowSimulated && cfg.BackendURL == "" {
		return errors.New("AETHELRED_TEE_BACKEND_URL is required when simulation is disabled")
	}
	if cfg.BackendURL != "" {
		if err := httputil.ValidateEndpointURL(cfg.BackendURL); err != nil {
			return fmt.Errorf("invalid tee worker backend URL: %w", err)
		}
		if !cfg.AllowSimulated && strings.TrimSpace(cfg.BackendAPIToken) == "" {
			return fmt.Errorf("%s is required for a real TEE backend", backendAPITokenEnv)
		}
	}
	if err := validateListenAddrSecurity(cfg.ListenAddr, cfg.APIToken); err != nil {
		return err
	}
	return nil
}

func validateListenAddrSecurity(listenAddr, apiToken string) error {
	if isLoopbackListenAddr(listenAddr) {
		return nil
	}
	if strings.TrimSpace(apiToken) == "" {
		return fmt.Errorf("%s is required when the tee worker listens beyond explicit loopback addresses", apiTokenEnv)
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
	if !ok {
		return errors.New("authorization required")
	}
	if subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) != 1 {
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
			"service":       "aethelred-tee-worker",
			"status":        "unavailable",
			"backend_ready": false,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service":         "aethelred-tee-worker",
		"status":          "ok",
		"platform":        s.cfg.Platform,
		"allow_simulated": s.cfg.AllowSimulated,
		"backend_url":     s.cfg.BackendURL != "",
		"backend_ready":   true,
	})
}

func (s *server) checkBackendHealth(parent context.Context) error {
	if s == nil {
		return errors.New("TEE worker is not initialized")
	}
	if s.cfg.BackendURL == "" {
		if s.cfg.AllowSimulated {
			return nil
		}
		return errors.New("TEE backend is not configured")
	}
	if s.client == nil {
		return errors.New("TEE backend client is not configured")
	}

	target := s.cfg.BackendURL + "/health"
	if err := httputil.ValidateEndpointURL(target); err != nil {
		return fmt.Errorf("TEE backend health endpoint is not allowed: %w", err)
	}

	timeout := backendHealthProbeTimeout
	if s.cfg.Timeout > 0 && s.cfg.Timeout < timeout {
		timeout = s.cfg.Timeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("build TEE backend health request: %w", err)
	}
	setBackendAuthorization(req, s.cfg.BackendAPIToken)

	// #nosec G704 -- the URL is validated above and production uses the SSRF-safe client.
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("probe TEE backend health: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, httputil.MaxErrorBodySize))

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("TEE backend health returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.authorizeRequest(r); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	caps := appCapabilities{
		Platform:              s.cfg.Platform,
		SupportedModels:       []string{"onnx", "torchscript"},
		MaxModelSize:          2 << 30,
		MaxInputSize:          8 << 20,
		SupportsZKML:          s.cfg.SupportsZKProofGen,
		SupportedProofSystems: []string{"ezkl"},
		MemoryAvailable:       8 << 30,
		GPUAvailable:          false,
	}
	writeJSON(w, http.StatusOK, caps)
}

func (s *server) handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.authorizeRequest(r); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if allowed, retryAfter := s.allowRequest(r, "/execute"); !allowed {
		writeRateLimitError(w, retryAfter)
		return
	}

	body, err := readBoundedRequestBody(w, r, maxExecuteRequestBytes)
	if err != nil {
		return
	}

	if s.cfg.BackendURL != "" {
		s.proxy(w, r, "/execute", body)
		return
	}
	if !s.cfg.AllowSimulated {
		writeError(w, http.StatusServiceUnavailable, "TEE backend not configured and simulation disabled")
		return
	}

	isEnclaveReq, err := looksLikeEnclaveRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if isEnclaveReq {
		var req tee.EnclaveExecutionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid enclave execution request")
			return
		}
		result := s.simulateEnclaveExecution(&req)
		writeJSON(w, http.StatusOK, result)
		return
	}

	var req appExecutionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid TEE execution request")
		return
	}
	result := s.simulateAppExecution(&req)
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

	body, err := readBoundedRequestBody(w, r, maxVerifyRequestBytes)
	if err != nil {
		return
	}

	if s.cfg.BackendURL != "" {
		s.proxy(w, r, "/verify", body)
		return
	}
	if !s.cfg.AllowSimulated {
		writeError(w, http.StatusServiceUnavailable, "attestation verifier backend not configured and simulation disabled")
		return
	}

	var doc tee.NitroAttestationDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid attestation document")
		return
	}

	verified, verifyErr := s.verifyAttestation(&doc)
	resp := map[string]any{
		"verified": verified,
	}
	if verifyErr != "" {
		resp["error"] = verifyErr
	}
	writeJSON(w, http.StatusOK, resp)
}

func looksLikeEnclaveRequest(body []byte) (bool, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, err
	}
	if _, ok := payload["request_id"]; ok {
		return true, nil
	}
	if _, ok := payload["RequestID"]; ok {
		return true, nil
	}
	if _, ok := payload["JobID"]; ok {
		return false, nil
	}
	return false, nil
}

func (s *server) simulateEnclaveExecution(req *tee.EnclaveExecutionRequest) *tee.EnclaveExecutionResult {
	start := time.Now()
	requestID := req.RequestID
	if requestID == "" {
		requestID = fmt.Sprintf("auto-%d", start.UnixNano())
	}

	outputData, outputHash := simulateCanonicalModelExecution(req.ModelHash, req.InputHash)
	pcr0 := hashMany([]byte(s.cfg.EnclaveID), []byte("pcr0"))
	pcr1 := hashMany([]byte(s.cfg.EnclaveID), []byte("pcr1"))
	pcr2 := hashMany([]byte(s.cfg.EnclaveID), []byte("pcr2"))

	result := &tee.EnclaveExecutionResult{
		RequestID:       requestID,
		Success:         true,
		OutputData:      outputData,
		OutputHash:      outputHash,
		ExecutionTimeMs: time.Since(start).Milliseconds(),
		AttestationDocument: &tee.NitroAttestationDocument{
			ModuleID:  s.cfg.EnclaveID,
			Timestamp: time.Now().UTC(),
			Digest:    "SHA256",
			PCRs: map[int][]byte{
				0: pcr0,
				1: pcr1,
				2: pcr2,
			},
			UserData:    tee.ComputeAttestationUserData(outputHash, req.BlockHeight, req.ChainID),
			Nonce:       req.Nonce,
			BlockHeight: req.BlockHeight,
			ChainID:     req.ChainID,
		},
	}
	if !req.GenerateAttestation {
		result.AttestationDocument = nil
	}
	return result
}

func (s *server) simulateAppExecution(req *appExecutionRequest) *appExecutionResult {
	start := time.Now()
	output, outputHash := simulateCanonicalModelExecution(req.ModelHash, req.InputHash)

	// ── Attestation Timestamp Binding ──
	// Bind the block height and chain ID into UserData so that attestation
	// documents are anchored to a specific consensus moment. This prevents:
	//   1. Cross-block replay: an old attestation reused in a later block
	//   2. Cross-chain replay: an attestation from chain A accepted on chain B
	// UserData = SHA-256(outputHash || LE64(blockHeight) || chainID)
	userData := tee.ComputeAttestationUserData(outputHash, req.BlockHeight, req.ChainID)

	attestation := &appTEEAttestation{
		Platform:    s.cfg.Platform,
		EnclaveID:   s.cfg.EnclaveID,
		Measurement: hashMany([]byte(s.cfg.EnclaveID), []byte("measurement")),
		Quote:       hashMany([]byte("quote"), userData),
		UserData:    userData,
		Timestamp:   time.Now().UTC(),
		Nonce:       req.Nonce,
		BlockHeight: req.BlockHeight,
		ChainID:     req.ChainID,
	}

	result := &appExecutionResult{
		JobID:           req.JobID,
		Success:         true,
		OutputHash:      outputHash,
		Output:          output,
		Attestation:     attestation,
		ExecutionTimeMs: time.Since(start).Milliseconds(),
		GasUsed:         1000,
	}
	if req.RequireZKProof && s.cfg.SupportsZKProofGen {
		proof := hashMany(outputHash, []byte("zk-proof"))
		result.ZKProof = &appZKProof{
			ProofSystem:      "ezkl",
			Proof:            proof,
			PublicInputs:     outputHash,
			VerifyingKeyHash: hashMany([]byte("vk"), req.ModelHash),
			CircuitHash:      hashMany([]byte("circuit"), req.ModelHash),
			ProofSize:        int64(len(proof)),
		}
	}
	return result
}

// simulateCanonicalModelExecution returns a deterministic stand-in for model
// execution. ModelHash and InputHash are the canonical on-chain computation
// commitments; request IDs, validator identity, worker configuration, nonce,
// and other attestation-domain fields must never influence the model output.
//
// The returned OutputHash follows EnclaveExecutionResult's contract and is the
// SHA-256 digest of the returned output bytes.
func simulateCanonicalModelExecution(modelHash, inputHash []byte) ([]byte, []byte) {
	computation := sha256.New()
	_, _ = computation.Write([]byte("aethelred/tee/simulated-model-output/v1"))
	writeCanonicalField := func(field []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = computation.Write(length[:])
		_, _ = computation.Write(field)
	}
	writeCanonicalField(modelHash)
	writeCanonicalField(inputHash)

	output := computation.Sum(nil)
	outputDigest := sha256.Sum256(output)
	return output, outputDigest[:]
}

func (s *server) verifyAttestation(doc *tee.NitroAttestationDocument) (bool, string) {
	if doc.ModuleID == "" {
		return false, "module_id is required"
	}
	if doc.Timestamp.IsZero() {
		return false, "timestamp is required"
	}
	if len(doc.UserData) == 0 {
		return false, "user_data is required"
	}
	age := time.Since(doc.Timestamp)
	if age < 0 {
		age = -age
	}
	if age > s.cfg.MaxAttestationAge {
		return false, "attestation outside allowed age window"
	}

	// ── Attestation Timestamp Binding Verification ──
	// UserData must be at least 32 bytes (SHA-256 hash). If the attestation
	// was generated with block height binding, UserData will include height
	// and chain ID commitments that the consensus layer can verify.
	if len(doc.UserData) < 32 {
		return false, "user_data too short: must be at least 32 bytes (SHA-256 commitment)"
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

func readBoundedRequestBody(
	w http.ResponseWriter,
	r *http.Request,
	maxBytes int64,
) ([]byte, error) {
	if r == nil || r.Body == nil {
		err := errors.New("request body is required")
		writeError(w, http.StatusBadRequest, err.Error())
		return nil, err
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	body, err := io.ReadAll(r.Body)
	if err == nil {
		return body, nil
	}

	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, err
	}
	writeError(w, http.StatusBadRequest, "failed to read request body")
	return nil, err
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
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
