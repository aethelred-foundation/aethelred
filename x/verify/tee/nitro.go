package tee

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
	"github.com/aethelred/aethelred/internal/httpclient"
	"github.com/aethelred/aethelred/x/verify/httputil"
)

// NitroEnclaveService provides AWS Nitro Enclave attestation and execution
type NitroEnclaveService struct {
	logger log.Logger
	config NitroConfig

	// Connection to the enclave
	vsockConn net.Conn

	// Enclave state
	enclaveMutex sync.RWMutex
	enclaveReady bool
	enclaveID    string

	// Metrics
	metrics *NitroMetrics

	// Circuit breakers for external endpoints
	executorBreaker    *circuitbreaker.Breaker
	attestationBreaker *circuitbreaker.Breaker

	// HTTP client for remote executor/verifier calls
	remoteClient    *http.Client
	remoteClientErr error
}

// NitroConfig contains configuration for Nitro Enclave
type NitroConfig struct {
	// EnclavePort is the vsock port for enclave communication
	EnclavePort uint32

	// EnclaveCID is the vsock context ID
	EnclaveCID uint32

	// ExecutorEndpoint is the HTTP endpoint for remote enclave execution
	ExecutorEndpoint string

	// AttestationDocumentMaxAge is the max age of attestation documents
	AttestationDocumentMaxAge time.Duration

	// ExpectedPCR0 is the expected PCR0 value for the enclave
	ExpectedPCR0 []byte

	// ExpectedPCR1 is the expected PCR1 value
	ExpectedPCR1 []byte

	// ExpectedPCR2 is the expected PCR2 value
	ExpectedPCR2 []byte

	// MaxConcurrentRequests limits parallel enclave requests
	MaxConcurrentRequests int

	// RequestTimeout for enclave operations
	RequestTimeout time.Duration

	// AttestationVerifierEndpoint is the HTTP endpoint for attestation verification
	AttestationVerifierEndpoint string

	// AllowSimulated enables simulated execution/attestation (dev/test only)
	AllowSimulated bool

	// APIToken authenticates remote HTTP calls to a protected TEE worker.
	APIToken string

	// SimulatedAttestationKey signs simulated attestation documents so they
	// remain cryptographically bound in dev/test mode instead of being accepted
	// on structure alone.
	SimulatedAttestationKey []byte
}

// DefaultNitroConfig returns default Nitro configuration
func DefaultNitroConfig() NitroConfig {
	return NitroConfig{
		EnclavePort:                 5000,
		EnclaveCID:                  16, // Default CID for Nitro Enclaves
		AttestationDocumentMaxAge:   5 * time.Minute,
		MaxConcurrentRequests:       10,
		RequestTimeout:              60 * time.Second,
		ExecutorEndpoint:            "",
		AttestationVerifierEndpoint: "",
		AllowSimulated:              false,
		APIToken:                    strings.TrimSpace(os.Getenv("AETHELRED_TEE_API_TOKEN")),
	}
}

// NitroMetrics tracks Nitro Enclave metrics
type NitroMetrics struct {
	TotalAttestations      int64
	TotalExecutions        int64
	FailedAttestations     int64
	FailedExecutions       int64
	AverageExecutionTimeMs int64
	mutex                  *sync.Mutex
}

// NitroAttestationDocument represents an AWS Nitro attestation document
type NitroAttestationDocument struct {
	// ModuleID is the enclave image file ID
	ModuleID string `json:"module_id"`

	// Timestamp when the document was created
	Timestamp time.Time `json:"timestamp"`

	// Digest is the hash algorithm used
	Digest string `json:"digest"`

	// PCRs are the Platform Configuration Register values
	PCRs map[int][]byte `json:"pcrs"`

	// Certificate is the signing certificate chain
	Certificate []byte `json:"certificate"`

	// CABundle is the CA certificate bundle
	CABundle []byte `json:"cabundle"`

	// PublicKey is the enclave's public key
	PublicKey []byte `json:"public_key,omitempty"`

	// UserData is custom data bound to the attestation
	UserData []byte `json:"user_data,omitempty"`

	// Nonce to prevent replay attacks
	Nonce []byte `json:"nonce,omitempty"`

	// BlockHeight and ChainID are included in the signed document and in the
	// UserData output-binding digest.
	BlockHeight int64  `json:"block_height,omitempty"`
	ChainID     string `json:"chain_id,omitempty"`

	// Signature authenticates simulated attestation documents in dev/test mode.
	Signature []byte `json:"signature,omitempty"`
}

// EnclaveExecutionRequest represents a request to execute in the enclave
type EnclaveExecutionRequest struct {
	// RequestID for tracking
	RequestID string `json:"request_id"`

	// ModelHash identifies the model to execute
	ModelHash []byte `json:"model_hash"`

	// InputData is the model input (encrypted)
	InputData []byte `json:"input_data"`

	// InputHash is the hash of the unencrypted input
	InputHash []byte `json:"input_hash"`

	// EncryptionKey for decrypting input (encrypted to enclave's key)
	EncryptionKey []byte `json:"encryption_key,omitempty"`

	// GenerateAttestation requests an attestation with the result
	GenerateAttestation bool `json:"generate_attestation"`

	// Nonce for the attestation
	Nonce []byte `json:"nonce,omitempty"`

	// BlockHeight and ChainID domain-separate the signed output commitment.
	BlockHeight int64  `json:"block_height,omitempty"`
	ChainID     string `json:"chain_id,omitempty"`
}

// EnclaveExecutionResult represents the result from enclave execution
type EnclaveExecutionResult struct {
	// RequestID for correlation
	RequestID string `json:"request_id"`

	// Success indicates if execution succeeded
	Success bool `json:"success"`

	// OutputData is the model output (may be encrypted)
	OutputData []byte `json:"output_data,omitempty"`

	// OutputHash is the SHA-256 hash of the output
	OutputHash []byte `json:"output_hash"`

	// AttestationDocument for verification
	AttestationDocument *NitroAttestationDocument `json:"attestation_document,omitempty"`

	// ExecutionTimeMs is how long execution took
	ExecutionTimeMs int64 `json:"execution_time_ms"`

	// Error message if failed
	Error string `json:"error,omitempty"`
}

// NewNitroEnclaveService creates a new Nitro Enclave service
func NewNitroEnclaveService(logger log.Logger, config NitroConfig) *NitroEnclaveService {
	if strings.TrimSpace(config.APIToken) == "" {
		config.APIToken = strings.TrimSpace(os.Getenv("AETHELRED_TEE_API_TOKEN"))
	}
	baseClient := httpclient.NewPooledClient(httpclient.PoolConfig{
		Timeout:             config.RequestTimeout,
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     90 * time.Second,
	})
	secureClient, secureClientErr := httputil.NewSecureClient(baseClient)

	return &NitroEnclaveService{
		logger:             logger,
		config:             config,
		metrics:            &NitroMetrics{mutex: &sync.Mutex{}},
		executorBreaker:    circuitbreaker.NewDefault("nitro_executor"),
		attestationBreaker: circuitbreaker.NewDefault("nitro_attestation_verifier"),
		remoteClient:       secureClient,
		remoteClientErr:    secureClientErr,
	}
}

func (nes *NitroEnclaveService) applyAuth(req *http.Request) {
	if nes == nil || req == nil || strings.TrimSpace(nes.config.APIToken) == "" {
		return
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(nes.config.APIToken))
}

// Initialize initializes the connection to the Nitro Enclave
func (nes *NitroEnclaveService) Initialize(ctx context.Context) error {
	nes.enclaveMutex.Lock()
	defer nes.enclaveMutex.Unlock()

	// Require a remote executor unless simulation is explicitly enabled.
	if nes.config.ExecutorEndpoint == "" && !nes.config.AllowSimulated {
		return fmt.Errorf("nitro executor endpoint not configured")
	}

	if nes.config.ExecutorEndpoint != "" {
		nes.enclaveID = "nitro-remote"
	} else {
		if err := nes.ensureSimulatedAttestationKey(); err != nil {
			return err
		}
		nes.enclaveID = "nitro-simulated"
	}
	nes.enclaveReady = true

	nes.logger.Info("Nitro Enclave service initialized",
		"enclave_id", nes.enclaveID,
	)

	return nil
}

// Execute runs a model in the Nitro Enclave
func (nes *NitroEnclaveService) Execute(ctx context.Context, req *EnclaveExecutionRequest) (*EnclaveExecutionResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("enclave execution context cannot be nil")
	}
	if err := validateEnclaveExecutionRequest(req); err != nil {
		return nil, err
	}

	startTime := time.Now()

	nes.enclaveMutex.RLock()
	if !nes.enclaveReady {
		nes.enclaveMutex.RUnlock()
		return nil, fmt.Errorf("enclave not ready")
	}
	nes.enclaveMutex.RUnlock()

	result := &EnclaveExecutionResult{
		RequestID: req.RequestID,
	}

	// Prefer remote executor when configured.
	if nes.config.ExecutorEndpoint != "" {
		remoteResult, err := nes.callRemoteExecutor(ctx, req)
		if err != nil {
			nes.metrics.mutex.Lock()
			nes.metrics.FailedExecutions++
			nes.metrics.mutex.Unlock()
			return nil, err
		}
		nes.metrics.mutex.Lock()
		nes.metrics.TotalExecutions++
		if !remoteResult.Success {
			nes.metrics.FailedExecutions++
		} else {
			nes.metrics.AverageExecutionTimeMs = (nes.metrics.AverageExecutionTimeMs*nes.metrics.TotalExecutions + remoteResult.ExecutionTimeMs) / (nes.metrics.TotalExecutions + 1)
		}
		nes.metrics.mutex.Unlock()
		return remoteResult, nil
	}

	if !nes.config.AllowSimulated {
		return nil, fmt.Errorf("nitro executor endpoint not configured and simulation disabled")
	}

	// Simulated execution (dev/test only)
	output, outputHash, err := nes.simulateEnclaveExecution(req)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.ExecutionTimeMs = time.Since(startTime).Milliseconds()

		nes.metrics.mutex.Lock()
		nes.metrics.FailedExecutions++
		nes.metrics.mutex.Unlock()

		return result, nil
	}

	result.Success = true
	result.OutputData = output
	result.OutputHash = outputHash
	result.ExecutionTimeMs = time.Since(startTime).Milliseconds()

	// Generate attestation if requested
	if req.GenerateAttestation {
		attestation, err := nes.generateAttestation(
			outputHash,
			req.Nonce,
			req.BlockHeight,
			req.ChainID,
		)
		if err != nil {
			nes.logger.Warn("Failed to generate attestation", "error", err)
		} else {
			result.AttestationDocument = attestation
		}
	}

	// Update metrics
	nes.metrics.mutex.Lock()
	nes.metrics.TotalExecutions++
	nes.metrics.AverageExecutionTimeMs = (nes.metrics.AverageExecutionTimeMs*nes.metrics.TotalExecutions + result.ExecutionTimeMs) / (nes.metrics.TotalExecutions + 1)
	nes.metrics.mutex.Unlock()

	nes.logger.Info("Enclave execution completed",
		"request_id", req.RequestID,
		"execution_time_ms", result.ExecutionTimeMs,
	)

	return result, nil
}

// simulateEnclaveExecution simulates model execution in the enclave
func (nes *NitroEnclaveService) simulateEnclaveExecution(req *EnclaveExecutionRequest) ([]byte, []byte, error) {
	// Create deterministic output based on model and input
	combined := append(req.ModelHash, req.InputHash...)
	combined = append(combined, []byte("nitro_enclave_v1")...)

	outputHash := sha256.Sum256(combined)

	// Simulate output data
	output := map[string]interface{}{
		"probability": 0.85,
		"confidence":  0.92,
		"model_hash":  shortHashHex(req.ModelHash),
	}
	outputData, _ := json.Marshal(output)

	return outputData, outputHash[:], nil
}

func validateEnclaveExecutionRequest(req *EnclaveExecutionRequest) error {
	if req == nil {
		return fmt.Errorf("enclave execution request cannot be nil")
	}
	if len(req.ModelHash) != sha256.Size {
		return fmt.Errorf("model hash must be exactly %d bytes, got %d", sha256.Size, len(req.ModelHash))
	}
	if len(req.InputHash) != sha256.Size {
		return fmt.Errorf("input hash must be exactly %d bytes, got %d", sha256.Size, len(req.InputHash))
	}
	if len(req.InputData) == 0 {
		return fmt.Errorf("input data cannot be empty")
	}
	return nil
}

func shortHashHex(hash []byte) string {
	const logPrefixBytes = 8
	if len(hash) > logPrefixBytes {
		hash = hash[:logPrefixBytes]
	}
	return fmt.Sprintf("%x", hash)
}

// generateAttestation generates a Nitro attestation document
func (nes *NitroEnclaveService) generateAttestation(
	outputHash, nonce []byte,
	blockHeight int64,
	chainID string,
) (*NitroAttestationDocument, error) {
	// In production: call nsm_get_attestation_doc()
	// For MVP: simulate attestation document

	doc := &NitroAttestationDocument{
		ModuleID:  nes.enclaveID,
		Timestamp: time.Now().UTC(),
		Digest:    "SHA384",
		PCRs: map[int][]byte{
			0: nes.config.ExpectedPCR0,
			1: nes.config.ExpectedPCR1,
			2: nes.config.ExpectedPCR2,
		},
		UserData:    ComputeAttestationUserData(outputHash, blockHeight, chainID),
		Nonce:       nonce,
		BlockHeight: blockHeight,
		ChainID:     chainID,
	}

	// Simulate PCRs if not set
	if len(doc.PCRs[0]) == 0 {
		doc.PCRs[0] = sha256Hash([]byte("aethelred_pcr0"))
		doc.PCRs[1] = sha256Hash([]byte("aethelred_pcr1"))
		doc.PCRs[2] = sha256Hash([]byte("aethelred_pcr2"))
	}

	if err := nes.ensureSimulatedAttestationKey(); err != nil {
		return nil, err
	}
	doc.Signature = SignSimulatedNitroAttestation(doc, nes.config.SimulatedAttestationKey)

	nes.metrics.mutex.Lock()
	nes.metrics.TotalAttestations++
	nes.metrics.mutex.Unlock()

	return doc, nil
}

// VerifyAttestation verifies a Nitro attestation document
func (nes *NitroEnclaveService) VerifyAttestation(ctx context.Context, doc *NitroAttestationDocument) (*AttestationVerificationResult, error) {
	result := &AttestationVerificationResult{
		Valid:     true,
		Timestamp: doc.Timestamp,
	}

	// Check document age
	if time.Since(doc.Timestamp) > nes.config.AttestationDocumentMaxAge {
		result.Valid = false
		result.Errors = append(result.Errors, "attestation document too old")
	}

	// Verify PCR values
	if len(nes.config.ExpectedPCR0) > 0 && !bytes.Equal(doc.PCRs[0], nes.config.ExpectedPCR0) {
		result.Valid = false
		result.Errors = append(result.Errors, "PCR0 mismatch")
	}

	if len(nes.config.ExpectedPCR1) > 0 && !bytes.Equal(doc.PCRs[1], nes.config.ExpectedPCR1) {
		result.Valid = false
		result.Errors = append(result.Errors, "PCR1 mismatch")
	}

	if len(nes.config.ExpectedPCR2) > 0 && !bytes.Equal(doc.PCRs[2], nes.config.ExpectedPCR2) {
		result.Valid = false
		result.Errors = append(result.Errors, "PCR2 mismatch")
	}

	// Verify certificate chain / attestation signature using remote verifier if configured.
	if nes.config.AttestationVerifierEndpoint != "" {
		verified, err := nes.callRemoteAttestationVerifier(ctx, doc)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err.Error())
		} else if !verified {
			result.Valid = false
			result.Errors = append(result.Errors, "attestation verification failed")
		}
		result.CertificateChainValid = verified
	} else {
		if !nes.config.AllowSimulated {
			return nil, fmt.Errorf("attestation verifier endpoint not configured and simulation disabled")
		}
		if err := nes.ensureSimulatedAttestationKey(); err != nil {
			return nil, err
		}
		if err := VerifySimulatedNitroAttestation(doc, nes.config.SimulatedAttestationKey); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err.Error())
			result.CertificateChainValid = false
		} else {
			result.CertificateChainValid = true
		}
	}

	result.PCRsVerified = true
	result.EnclaveID = doc.ModuleID

	nes.logger.Debug("Attestation verified",
		"enclave_id", doc.ModuleID,
		"valid", result.Valid,
	)

	return result, nil
}

func (nes *NitroEnclaveService) ensureSimulatedAttestationKey() error {
	if !nes.config.AllowSimulated || len(nes.config.SimulatedAttestationKey) > 0 {
		return nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to initialize simulated attestation key: %w", err)
	}
	nes.config.SimulatedAttestationKey = key
	return nil
}

// SignSimulatedNitroAttestation computes a simulation-only MAC for a Nitro
// attestation document so local verification remains cryptographically bound.
func SignSimulatedNitroAttestation(doc *NitroAttestationDocument, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(simulatedNitroAttestationPayload(doc))
	return mac.Sum(nil)
}

// VerifySimulatedNitroAttestation rejects unsigned or tampered simulated Nitro
// attestation documents.
func VerifySimulatedNitroAttestation(doc *NitroAttestationDocument, key []byte) error {
	if len(doc.Signature) == 0 {
		return fmt.Errorf("simulated attestation signature is required")
	}
	expected := SignSimulatedNitroAttestation(doc, key)
	if !hmac.Equal(doc.Signature, expected) {
		return fmt.Errorf("simulated attestation signature mismatch")
	}
	return nil
}

func simulatedNitroAttestationPayload(doc *NitroAttestationDocument) []byte {
	var buf bytes.Buffer
	writeString := func(v string) {
		// #nosec G115 -- simulated documents are locally generated and request-size bounded.
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(v)))
		buf.WriteString(v)
	}
	writeBytes := func(v []byte) {
		// #nosec G115 -- simulated documents are locally generated and request-size bounded.
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(v)))
		buf.Write(v)
	}

	writeString(doc.ModuleID)
	_ = binary.Write(&buf, binary.BigEndian, doc.Timestamp.UTC().UnixNano())
	writeString(doc.Digest)

	pcrIndexes := make([]int, 0, len(doc.PCRs))
	for idx := range doc.PCRs {
		pcrIndexes = append(pcrIndexes, idx)
	}
	sort.Ints(pcrIndexes)
	// #nosec G115 -- Nitro exposes a fixed, protocol-bounded PCR register set.
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(pcrIndexes)))
	for _, idx := range pcrIndexes {
		// #nosec G115 -- Nitro PCR indices are canonical small non-negative register numbers.
		_ = binary.Write(&buf, binary.BigEndian, int32(idx))
		writeBytes(doc.PCRs[idx])
	}

	writeBytes(doc.Certificate)
	writeBytes(doc.CABundle)
	writeBytes(doc.PublicKey)
	writeBytes(doc.UserData)
	writeBytes(doc.Nonce)
	_ = binary.Write(&buf, binary.BigEndian, doc.BlockHeight)
	writeString(doc.ChainID)

	return buf.Bytes()
}

// callRemoteExecutor invokes a remote enclave worker for execution.
func (nes *NitroEnclaveService) callRemoteExecutor(ctx context.Context, req *EnclaveExecutionRequest) (*EnclaveExecutionResult, error) {
	if nes.executorBreaker != nil && !nes.executorBreaker.Allow() {
		return nil, fmt.Errorf("nitro executor circuit open")
	}
	if nes.remoteClientErr != nil {
		return nil, fmt.Errorf("secure Nitro executor HTTP client unavailable: %w", nes.remoteClientErr)
	}

	endpoint := strings.TrimRight(nes.config.ExecutorEndpoint, "/") + "/execute"

	// SECURITY FIX M-01: Validate endpoint URL to prevent SSRF attacks.
	if err := httputil.ValidateEndpointURL(endpoint); err != nil {
		if nes.executorBreaker != nil {
			nes.executorBreaker.RecordFailure()
		}
		return nil, fmt.Errorf("invalid executor endpoint: %w", err)
	}

	body, err := json.Marshal(req)
	if err != nil {
		if nes.executorBreaker != nil {
			nes.executorBreaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to marshal executor request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		if nes.executorBreaker != nil {
			nes.executorBreaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to create executor request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	nes.applyAuth(httpReq)

	resp, err := nes.remoteClient.Do(httpReq)
	if err != nil {
		if nes.executorBreaker != nil {
			nes.executorBreaker.RecordFailure()
		}
		return nil, fmt.Errorf("executor request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		// SECURITY FIX M-02: Bound error body read to prevent memory-pressure DoS.
		payload, _ := io.ReadAll(httputil.LimitedReader(resp.Body, httputil.MaxErrorBodySize))
		if nes.executorBreaker != nil {
			nes.executorBreaker.RecordFailure()
		}
		return nil, fmt.Errorf("executor returned status %d: %s", resp.StatusCode, string(payload))
	}

	var result EnclaveExecutionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		if nes.executorBreaker != nil {
			nes.executorBreaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to decode executor response: %w", err)
	}

	if nes.executorBreaker != nil {
		nes.executorBreaker.RecordSuccess()
	}
	return &result, nil
}

// callRemoteAttestationVerifier invokes a remote attestation verifier.
func (nes *NitroEnclaveService) callRemoteAttestationVerifier(ctx context.Context, doc *NitroAttestationDocument) (bool, error) {
	if nes.attestationBreaker != nil && !nes.attestationBreaker.Allow() {
		return false, fmt.Errorf("nitro attestation verifier circuit open")
	}
	if nes.remoteClientErr != nil {
		return false, fmt.Errorf("secure Nitro attestation HTTP client unavailable: %w", nes.remoteClientErr)
	}

	endpoint := strings.TrimRight(nes.config.AttestationVerifierEndpoint, "/") + "/verify"

	// SECURITY FIX M-01: Validate endpoint URL to prevent SSRF attacks.
	if err := httputil.ValidateEndpointURL(endpoint); err != nil {
		if nes.attestationBreaker != nil {
			nes.attestationBreaker.RecordFailure()
		}
		return false, fmt.Errorf("invalid attestation verifier endpoint: %w", err)
	}

	body, err := json.Marshal(doc)
	if err != nil {
		if nes.attestationBreaker != nil {
			nes.attestationBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to marshal attestation: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		if nes.attestationBreaker != nil {
			nes.attestationBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to create verifier request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	nes.applyAuth(httpReq)

	resp, err := nes.remoteClient.Do(httpReq)
	if err != nil {
		if nes.attestationBreaker != nil {
			nes.attestationBreaker.RecordFailure()
		}
		return false, fmt.Errorf("verifier request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		// SECURITY FIX M-02: Bound error body read to prevent memory-pressure DoS.
		payload, _ := io.ReadAll(httputil.LimitedReader(resp.Body, httputil.MaxErrorBodySize))
		if nes.attestationBreaker != nil {
			nes.attestationBreaker.RecordFailure()
		}
		return false, fmt.Errorf("verifier returned status %d: %s", resp.StatusCode, string(payload))
	}

	var result struct {
		Verified bool   `json:"verified"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		if nes.attestationBreaker != nil {
			nes.attestationBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to decode verifier response: %w", err)
	}
	if result.Error != "" && !result.Verified {
		if nes.attestationBreaker != nil {
			nes.attestationBreaker.RecordFailure()
		}
		return false, fmt.Errorf("verification failed: %s", result.Error)
	}

	if nes.attestationBreaker != nil {
		nes.attestationBreaker.RecordSuccess()
	}
	return result.Verified, nil
}

// AttestationVerificationResult contains the result of attestation verification
type AttestationVerificationResult struct {
	Valid                 bool      `json:"valid"`
	Timestamp             time.Time `json:"timestamp"`
	EnclaveID             string    `json:"enclave_id"`
	PCRsVerified          bool      `json:"pcrs_verified"`
	CertificateChainValid bool      `json:"certificate_chain_valid"`
	Errors                []string  `json:"errors,omitempty"`
}

// GetEnclaveInfo returns information about the connected enclave
func (nes *NitroEnclaveService) GetEnclaveInfo() *EnclaveInfo {
	nes.enclaveMutex.RLock()
	defer nes.enclaveMutex.RUnlock()

	return &EnclaveInfo{
		EnclaveID: nes.enclaveID,
		Ready:     nes.enclaveReady,
		PCRs: map[int]string{
			0: fmt.Sprintf("%x", nes.config.ExpectedPCR0),
			1: fmt.Sprintf("%x", nes.config.ExpectedPCR1),
			2: fmt.Sprintf("%x", nes.config.ExpectedPCR2),
		},
	}
}

// EnclaveInfo contains enclave information
type EnclaveInfo struct {
	EnclaveID string         `json:"enclave_id"`
	Ready     bool           `json:"ready"`
	PCRs      map[int]string `json:"pcrs"`
}

// GetMetrics returns Nitro Enclave metrics
func (nes *NitroEnclaveService) GetMetrics() NitroMetrics {
	nes.metrics.mutex.Lock()
	defer nes.metrics.mutex.Unlock()
	return *nes.metrics
}

// Shutdown gracefully shuts down the Nitro Enclave service
func (nes *NitroEnclaveService) Shutdown() error {
	nes.enclaveMutex.Lock()
	defer nes.enclaveMutex.Unlock()

	if nes.vsockConn != nil {
		if err := nes.vsockConn.Close(); err != nil {
			nes.logger.Error("failed to close vsock connection", "error", err)
		}
	}

	nes.enclaveReady = false

	nes.logger.Info("Nitro Enclave service shut down",
		"total_executions", nes.metrics.TotalExecutions,
	)

	return nil
}

// ExecutorBreaker exposes the executor circuit breaker.
func (nes *NitroEnclaveService) ExecutorBreaker() *circuitbreaker.Breaker {
	return nes.executorBreaker
}

// AttestationBreaker exposes the attestation verifier circuit breaker.
func (nes *NitroEnclaveService) AttestationBreaker() *circuitbreaker.Breaker {
	return nes.attestationBreaker
}

// EncryptForEnclave encrypts data for the enclave's public key
func (nes *NitroEnclaveService) EncryptForEnclave(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	if nes.enclaveID == "nitro-simulated" || (nes.config.AllowSimulated && nes.config.ExecutorEndpoint == "") {
		key, err := nes.simulatedNitroEncryptionKey()
		if err != nil {
			return nil, err
		}
		return encryptSimulatedNitroPayload(key, plaintext)
	}

	return nil, fmt.Errorf("remote nitro encryption requires an attested enclave public key")
}

// sha256Hash computes SHA-256 hash
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (nes *NitroEnclaveService) simulatedNitroEncryptionKey() ([]byte, error) {
	if err := nes.ensureSimulatedAttestationKey(); err != nil {
		return nil, err
	}
	seed := append([]byte("aethelred_nitro_encrypt_v1:"), nes.config.SimulatedAttestationKey...)
	key := sha256.Sum256(seed)
	return key[:], nil
}

func encryptSimulatedNitroPayload(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize simulated nitro cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize simulated nitro AEAD: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate simulated nitro nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, []byte("aethelred:nitro:simulated:v1")), nil
}
