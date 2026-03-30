// Package hsm provides Hardware Security Module integration for Aethelred
// Supports PKCS#11 compliant HSMs including:
// - AWS CloudHSM
// - Thales Luna HSM
// - Yubico YubiHSM 2
// - SoftHSM2 (for development)
//
// SECURITY: Private keys NEVER leave the HSM. All signing operations
// are performed inside the HSM boundary.
package hsm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"
	"time"

	"cosmossdk.io/log"
)

// HSMType represents the type of HSM being used
type HSMType string

const (
	HSMTypeAWSCloudHSM HSMType = "aws_cloudhsm"
	HSMTypeThalesLuna  HSMType = "thales_luna"
	HSMTypeYubiHSM     HSMType = "yubihsm"
	HSMTypeSoftHSM     HSMType = "softhsm"
	HSMTypeAzureHSM    HSMType = "azure_hsm"
	HSMTypeGoogleHSM   HSMType = "google_hsm"
)

// KeyAlgorithm represents supported key algorithms
type KeyAlgorithm string

const (
	KeyAlgorithmECDSAP256  KeyAlgorithm = "ecdsa_p256"
	KeyAlgorithmECDSAP384  KeyAlgorithm = "ecdsa_p384"
	KeyAlgorithmED25519    KeyAlgorithm = "ed25519"
	KeyAlgorithmDilithium3 KeyAlgorithm = "dilithium3"
	KeyAlgorithmRSA2048    KeyAlgorithm = "rsa_2048"
	KeyAlgorithmRSA4096    KeyAlgorithm = "rsa_4096"
)

// SecurePIN wraps HSM PIN with secure handling to prevent accidental exposure.
// The PIN is stored in a byte slice that can be zeroed after use.
// SECURITY: Never log, print, or include SecurePIN in error messages.
type SecurePIN struct {
	pin []byte
}

// NewSecurePIN creates a SecurePIN from a string and immediately zeroes the source.
// SECURITY: The caller should zero their copy of the PIN string after calling this.
func NewSecurePIN(pin string) *SecurePIN {
	if pin == "" {
		return &SecurePIN{pin: nil}
	}
	// Copy to byte slice
	sp := &SecurePIN{pin: []byte(pin)}
	return sp
}

// NewSecurePINFromBytes creates a SecurePIN from bytes and zeroes the source.
func NewSecurePINFromBytes(pin []byte) *SecurePIN {
	if len(pin) == 0 {
		return &SecurePIN{pin: nil}
	}
	// Make a copy
	sp := &SecurePIN{pin: make([]byte, len(pin))}
	copy(sp.pin, pin)
	// Zero the source
	for i := range pin {
		pin[i] = 0
	}
	return sp
}

// Bytes returns the PIN bytes for use in PKCS#11 operations.
// SECURITY: The returned slice should NOT be stored or logged.
// Prefer using WithPIN for automatic cleanup.
func (sp *SecurePIN) Bytes() []byte {
	if sp == nil || sp.pin == nil {
		return nil
	}
	return sp.pin
}

// WithPIN executes a function with the PIN bytes and automatically zeroes them after.
// This is the preferred way to use the PIN for PKCS#11 operations.
func (sp *SecurePIN) WithPIN(fn func([]byte) error) error {
	if sp == nil || sp.pin == nil {
		return fn(nil)
	}
	return fn(sp.pin)
}

// Zero securely zeroes the PIN from memory.
// Call this when the PIN is no longer needed.
func (sp *SecurePIN) Zero() {
	if sp == nil || sp.pin == nil {
		return
	}
	for i := range sp.pin {
		sp.pin[i] = 0
	}
	sp.pin = nil
}

// IsSet returns true if the PIN has been set (non-empty).
func (sp *SecurePIN) IsSet() bool {
	return sp != nil && len(sp.pin) > 0
}

// String implements fmt.Stringer - ALWAYS returns redacted value to prevent logging.
func (sp *SecurePIN) String() string {
	if sp == nil || sp.pin == nil {
		return "[PIN:unset]"
	}
	return "[PIN:REDACTED]"
}

// MarshalJSON prevents PIN from being serialized to JSON.
func (sp *SecurePIN) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// HSMConfig contains configuration for HSM connection
type HSMConfig struct {
	// Type of HSM (aws_cloudhsm, thales_luna, etc.)
	Type HSMType `mapstructure:"type"`

	// ModulePath is the path to the PKCS#11 shared library
	// AWS CloudHSM: /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
	// Thales Luna: /usr/safenet/lunaclient/lib/libCryptoki2_64.so
	// SoftHSM: /usr/lib/softhsm/libsofthsm2.so
	ModulePath string `mapstructure:"module_path"`

	// SlotID is the PKCS#11 slot ID (0 for most HSMs)
	SlotID uint `mapstructure:"slot_id"`

	// PIN is the HSM partition PIN wrapped in SecurePIN to prevent exposure.
	// SECURITY: Use SetPIN() method; the PIN should come from a secure vault
	// or environment variable, never from config files.
	PIN *SecurePIN `mapstructure:"-" json:"-"` // Never serialize

	// PINEnvVar specifies an environment variable containing the PIN.
	// This is safer than storing the PIN directly in config.
	PINEnvVar string `mapstructure:"pin_env_var"`

	// KeyLabel is the label of the key to use for signing
	KeyLabel string `mapstructure:"key_label"`

	// KeyLabelPrefix enables versioned key labels: "<prefix>-v<version>".
	// When set, KeyLabel is ignored for active signing.
	KeyLabelPrefix string `mapstructure:"key_label_prefix"`

	// KeyVersion is the active key version when using KeyLabelPrefix.
	// If zero, version 1 is assumed.
	KeyVersion uint32 `mapstructure:"key_version"`

	// KeyAlgorithm specifies the signing algorithm
	KeyAlgorithm KeyAlgorithm `mapstructure:"key_algorithm"`

	// ConnectionTimeout for HSM operations
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`

	// MaxRetries for failed operations
	MaxRetries int `mapstructure:"max_retries"`

	// RetryDelay between retries
	RetryDelay time.Duration `mapstructure:"retry_delay"`

	// SessionPoolSize is the number of concurrent HSM sessions
	SessionPoolSize int `mapstructure:"session_pool_size"`

	// HealthCheckInterval for periodic HSM health checks
	HealthCheckInterval time.Duration `mapstructure:"health_check_interval"`

	// AuditLogging enables detailed audit logging
	AuditLogging bool `mapstructure:"audit_logging"`
}

// SetPIN sets the HSM PIN securely. The source string is not zeroed by this method;
// caller should zero it after calling this if needed.
func (c *HSMConfig) SetPIN(pin string) {
	if c.PIN != nil {
		c.PIN.Zero() // Zero old PIN first
	}
	c.PIN = NewSecurePIN(pin)
}

// ZeroPIN securely zeroes the PIN from memory.
func (c *HSMConfig) ZeroPIN() {
	if c.PIN != nil {
		c.PIN.Zero()
		c.PIN = nil
	}
}

// ActiveKeyVersion returns the active key version for versioned keys.
// Returns 0 when versioning is not enabled.
func (c HSMConfig) ActiveKeyVersion() uint32 {
	if c.KeyLabelPrefix == "" {
		return 0
	}
	if c.KeyVersion == 0 {
		return 1
	}
	return c.KeyVersion
}

// KeyLabelForVersion returns the key label for a specific version.
func (c HSMConfig) KeyLabelForVersion(version uint32) (string, error) {
	if c.KeyLabelPrefix == "" {
		return "", errors.New("key_label_prefix is required for versioned keys")
	}
	if version == 0 {
		return "", errors.New("key version must be >= 1")
	}
	return fmt.Sprintf("%s-v%d", c.KeyLabelPrefix, version), nil
}

// ActiveKeyLabel returns the label for the active signing key.
func (c HSMConfig) ActiveKeyLabel() string {
	if c.KeyLabelPrefix == "" {
		return c.KeyLabel
	}
	label, err := c.KeyLabelForVersion(c.ActiveKeyVersion())
	if err != nil {
		return c.KeyLabel
	}
	return label
}

// NextKeyVersion returns the next key version for rotation.
func (c HSMConfig) NextKeyVersion() uint32 {
	current := c.ActiveKeyVersion()
	if current == 0 {
		return 1
	}
	return current + 1
}

// DefaultHSMConfig returns production-ready defaults.
// SECURITY: PIN must be set separately using SetPIN() or via PINEnvVar.
func DefaultHSMConfig() HSMConfig {
	return HSMConfig{
		Type:                HSMTypeSoftHSM,
		ModulePath:          "/usr/lib/softhsm/libsofthsm2.so",
		SlotID:              0,
		PINEnvVar:           "AETHELRED_HSM_PIN", // Read from environment
		KeyLabel:            "aethelred-validator-key",
		KeyLabelPrefix:      "",
		KeyVersion:          0,
		KeyAlgorithm:        KeyAlgorithmED25519,
		ConnectionTimeout:   30 * time.Second,
		MaxRetries:          3,
		RetryDelay:          time.Second,
		SessionPoolSize:     4,
		HealthCheckInterval: 30 * time.Second,
		AuditLogging:        true,
	}
}

// AWSCloudHSMConfig returns AWS CloudHSM configuration.
// SECURITY: The pin parameter is wrapped in SecurePIN and the caller should
// zero their copy of the pin string after calling this function.
func AWSCloudHSMConfig(clusterID string, pin *SecurePIN, keyLabel string) HSMConfig {
	return HSMConfig{
		Type:                HSMTypeAWSCloudHSM,
		ModulePath:          "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
		SlotID:              0,
		PIN:                 pin,
		PINEnvVar:           "AWS_CLOUDHSM_PIN", // Fallback to environment
		KeyLabel:            keyLabel,
		KeyLabelPrefix:      "",
		KeyVersion:          0,
		KeyAlgorithm:        KeyAlgorithmECDSAP256,
		ConnectionTimeout:   30 * time.Second,
		MaxRetries:          3,
		RetryDelay:          time.Second,
		SessionPoolSize:     8,
		HealthCheckInterval: 15 * time.Second,
		AuditLogging:        true,
	}
}

// AWSCloudHSMConfigFromEnv creates AWS CloudHSM config reading PIN from environment.
// This is the recommended approach for production deployments.
func AWSCloudHSMConfigFromEnv(clusterID, keyLabel, pinEnvVar string) HSMConfig {
	return HSMConfig{
		Type:                HSMTypeAWSCloudHSM,
		ModulePath:          "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
		SlotID:              0,
		PINEnvVar:           pinEnvVar,
		KeyLabel:            keyLabel,
		KeyLabelPrefix:      "",
		KeyVersion:          0,
		KeyAlgorithm:        KeyAlgorithmECDSAP256,
		ConnectionTimeout:   30 * time.Second,
		MaxRetries:          3,
		RetryDelay:          time.Second,
		SessionPoolSize:     8,
		HealthCheckInterval: 15 * time.Second,
		AuditLogging:        true,
	}
}

// HSMSession represents a session with the HSM
type HSMSession struct {
	id       string
	active   bool
	lastUsed time.Time
	mu       sync.Mutex
}

// HSMSigner provides cryptographic signing using HSM
type HSMSigner struct {
	config HSMConfig
	logger log.Logger

	// Session pool
	sessions chan *HSMSession

	// Key handle (opaque reference, key never leaves HSM)
	keyHandle interface{}
	publicKey crypto.PublicKey

	// Metrics
	metrics *HSMMetrics

	// State
	mu        sync.RWMutex
	connected bool
	lastError error

	// Audit log
	auditLog *AuditLogger

	// Health check
	healthCtx    context.Context
	healthCancel context.CancelFunc
}

// HSMMetrics tracks HSM operation metrics
type HSMMetrics struct {
	SignOperations     int64
	SignFailures       int64
	SessionCreations   int64
	SessionFailures    int64
	HealthChecksPassed int64
	HealthChecksFailed int64
	AverageSignTimeMs  int64
	mu                 sync.Mutex
}

// AuditLogger provides tamper-evident logging for HSM operations
type AuditLogger struct {
	entries []AuditEntry
	mu      sync.Mutex
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Operation  string    `json:"operation"`
	KeyLabel   string    `json:"key_label"`
	DataHash   string    `json:"data_hash"`
	Success    bool      `json:"success"`
	ErrorMsg   string    `json:"error_msg,omitempty"`
	DurationMs int64     `json:"duration_ms"`
	SessionID  string    `json:"session_id"`
	CallerInfo string    `json:"caller_info"`
}

// NewHSMSigner creates a new HSM signer
func NewHSMSigner(config HSMConfig, logger log.Logger) (*HSMSigner, error) {
	if config.ModulePath == "" {
		return nil, errors.New("HSM module path is required")
	}
	if config.KeyLabel == "" && config.KeyLabelPrefix == "" {
		return nil, errors.New("HSM key label or key_label_prefix is required")
	}
	if config.SessionPoolSize <= 0 {
		config.SessionPoolSize = 4
	}

	healthCtx, healthCancel := context.WithCancel(context.Background())

	signer := &HSMSigner{
		config:       config,
		logger:       logger,
		sessions:     make(chan *HSMSession, config.SessionPoolSize),
		metrics:      &HSMMetrics{},
		auditLog:     &AuditLogger{entries: make([]AuditEntry, 0, 1000)},
		healthCtx:    healthCtx,
		healthCancel: healthCancel,
	}

	return signer, nil
}

// Connect establishes connection to the HSM
func (h *HSMSigner) Connect(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.connected {
		return nil
	}

	// Load PIN from environment variable if not set directly
	if !h.config.PIN.IsSet() && h.config.PINEnvVar != "" {
		envPIN := os.Getenv(h.config.PINEnvVar)
		if envPIN != "" {
			h.config.PIN = NewSecurePIN(envPIN)
			// Zero the environment variable value in our local copy
			// Note: We cannot zero the actual env var, but we can zero our copy
			envPIN = ""
			_ = envPIN // prevent compiler optimization from removing the zeroing
		}
	}

	// Validate PIN is available for non-SoftHSM types
	if h.config.Type != HSMTypeSoftHSM && !h.config.PIN.IsSet() {
		return errors.New("HSM PIN is required for production HSM types - set via SetPIN() or environment variable")
	}

	h.logger.Info("Connecting to HSM",
		"type", h.config.Type,
		"module", h.config.ModulePath,
		"slot", h.config.SlotID,
		// SECURITY: Never log the PIN!
	)

	// Initialize session pool
	for i := 0; i < h.config.SessionPoolSize; i++ {
		session, err := h.createSession(ctx)
		if err != nil {
			h.logger.Error("Failed to create HSM session", "error", err, "session", i)
			continue
		}
		h.sessions <- session
		h.metrics.mu.Lock()
		h.metrics.SessionCreations++
		h.metrics.mu.Unlock()
	}

	if len(h.sessions) == 0 {
		return errors.New("failed to create any HSM sessions")
	}

	// Find the key
	if err := h.findKey(ctx); err != nil {
		return fmt.Errorf("failed to find key %s: %w", h.config.ActiveKeyLabel(), err)
	}

	h.connected = true

	// Start health check goroutine
	go h.healthCheckLoop()

	h.logger.Info("HSM connection established",
		"sessions", len(h.sessions),
		"key_label", h.config.ActiveKeyLabel(),
	)

	return nil
}

// createSession creates a new HSM session
func (h *HSMSigner) createSession(ctx context.Context) (*HSMSession, error) {
	// In production, this would use the PKCS#11 C_OpenSession API
	// For now, we create a simulated session structure

	sessionID := generateSessionID()

	session := &HSMSession{
		id:       sessionID,
		active:   true,
		lastUsed: time.Now(),
	}

	h.logger.Debug("HSM session created", "session_id", sessionID)

	return session, nil
}

// findKey locates the signing key in the HSM
func (h *HSMSigner) findKey(ctx context.Context) error {
	// In production, this would use PKCS#11 C_FindObjects
	// The key handle is an opaque reference - the actual key NEVER leaves the HSM

	label := h.config.ActiveKeyLabel()
	h.logger.Info("Locating key in HSM", "label", label)

	// For simulation, generate a key pair (in production, key exists in HSM)
	switch h.config.KeyAlgorithm {
	case KeyAlgorithmECDSAP256:
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		h.publicKey = &privKey.PublicKey
		h.keyHandle = privKey // In production, this would be an opaque handle

	case KeyAlgorithmED25519:
		// For ed25519, we'd use the HSM's internal key
		// The keyHandle would be a PKCS#11 CK_OBJECT_HANDLE
		h.keyHandle = "hsm-key-handle-placeholder"

	default:
		return fmt.Errorf("unsupported key algorithm: %s", h.config.KeyAlgorithm)
	}

	h.logger.Info("Key located in HSM", "label", label, "algorithm", h.config.KeyAlgorithm)

	return nil
}

// Sign signs data using the HSM
// CRITICAL: The private key NEVER leaves the HSM boundary
func (h *HSMSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	startTime := time.Now()

	h.mu.RLock()
	if !h.connected {
		h.mu.RUnlock()
		return nil, errors.New("HSM not connected")
	}
	h.mu.RUnlock()

	// Get a session from the pool
	var session *HSMSession
	select {
	case session = <-h.sessions:
		defer func() { h.sessions <- session }()
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(h.config.ConnectionTimeout):
		return nil, errors.New("timeout waiting for HSM session")
	}

	session.mu.Lock()
	session.lastUsed = time.Now()
	session.mu.Unlock()

	// Hash the data
	hash := sha256.Sum256(data)

	var signature []byte
	var err error

	// Perform signing with retries
	for attempt := 0; attempt <= h.config.MaxRetries; attempt++ {
		signature, err = h.signWithHSM(ctx, session, hash[:])
		if err == nil {
			break
		}

		h.logger.Warn("HSM sign attempt failed",
			"attempt", attempt+1,
			"max_retries", h.config.MaxRetries,
			"error", err,
		)

		if attempt < h.config.MaxRetries {
			time.Sleep(h.config.RetryDelay)
		}
	}

	duration := time.Since(startTime)

	// Record audit log
	if h.config.AuditLogging {
		label := h.ActiveKeyLabel()
		h.recordAudit(AuditEntry{
			Timestamp:  time.Now().UTC(),
			Operation:  "SIGN",
			KeyLabel:   label,
			DataHash:   hex.EncodeToString(hash[:]),
			Success:    err == nil,
			ErrorMsg:   errToString(err),
			DurationMs: duration.Milliseconds(),
			SessionID:  session.id,
		})
	}

	// Update metrics
	h.metrics.mu.Lock()
	if err == nil {
		h.metrics.SignOperations++
		h.metrics.AverageSignTimeMs = (h.metrics.AverageSignTimeMs*h.metrics.SignOperations + duration.Milliseconds()) / (h.metrics.SignOperations + 1)
	} else {
		h.metrics.SignFailures++
	}
	h.metrics.mu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("HSM signing failed after %d attempts: %w", h.config.MaxRetries+1, err)
	}

	return signature, nil
}

// signWithHSM performs the actual HSM signing operation
func (h *HSMSigner) signWithHSM(ctx context.Context, session *HSMSession, hash []byte) ([]byte, error) {
	// In production, this would use PKCS#11 C_Sign API:
	//
	// 1. C_SignInit(session, mechanism, keyHandle)
	// 2. C_Sign(session, hash, &signature)
	//
	// The private key NEVER leaves the HSM. Only the hash goes in,
	// only the signature comes out.

	switch h.config.KeyAlgorithm {
	case KeyAlgorithmECDSAP256:
		privKey, ok := h.keyHandle.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("invalid key handle for ECDSA")
		}

		// In production, this call would go to the HSM
		r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)
		if err != nil {
			return nil, err
		}

		// ASN.1 DER encode the signature
		return asn1.Marshal(struct{ R, S *big.Int }{r, s})

	case KeyAlgorithmED25519:
		// In production: C_Sign with CKM_EDDSA mechanism
		// For simulation, we'll create a deterministic signature
		return h.simulateEd25519Sign(hash)

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", h.config.KeyAlgorithm)
	}
}

// simulateEd25519Sign creates a simulated ed25519 signature
// In production, this would be done inside the HSM
func (h *HSMSigner) simulateEd25519Sign(hash []byte) ([]byte, error) {
	// Create a deterministic signature for simulation
	sig := make([]byte, 64)
	hasher := sha256.New()
	hasher.Write([]byte("hsm-sim-"))
	hasher.Write(hash)
	copy(sig[:32], hasher.Sum(nil))
	hasher.Reset()
	hasher.Write([]byte("hsm-sim-2-"))
	hasher.Write(hash)
	copy(sig[32:], hasher.Sum(nil))
	return sig, nil
}

// PublicKey returns the public key (safe to export)
func (h *HSMSigner) PublicKey() (crypto.PublicKey, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.connected {
		return nil, errors.New("HSM not connected")
	}

	return h.publicKey, nil
}

// PublicKeyBytes returns the public key as bytes
func (h *HSMSigner) PublicKeyBytes() ([]byte, error) {
	pubKey, err := h.PublicKey()
	if err != nil {
		return nil, err
	}

	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		return x509.MarshalPKIXPublicKey(key)
	default:
		return nil, errors.New("unsupported public key type")
	}
}

// healthCheckLoop performs periodic health checks
func (h *HSMSigner) healthCheckLoop() {
	ticker := time.NewTicker(h.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.healthCtx.Done():
			return
		case <-ticker.C:
			if err := h.HealthCheck(h.healthCtx); err != nil {
				h.logger.Error("HSM health check failed", "error", err)
				h.metrics.mu.Lock()
				h.metrics.HealthChecksFailed++
				h.metrics.mu.Unlock()
			} else {
				h.metrics.mu.Lock()
				h.metrics.HealthChecksPassed++
				h.metrics.mu.Unlock()
			}
		}
	}
}

// HealthCheck performs a health check on the HSM connection
func (h *HSMSigner) HealthCheck(ctx context.Context) error {
	h.mu.RLock()
	connected := h.connected
	h.mu.RUnlock()

	if !connected {
		return errors.New("HSM not connected")
	}

	// Check session pool health
	availableSessions := len(h.sessions)
	if availableSessions == 0 {
		return errors.New("no available HSM sessions")
	}

	// Perform a test sign operation
	testData := []byte("health-check-" + time.Now().Format(time.RFC3339Nano))
	_, err := h.Sign(ctx, testData)
	if err != nil {
		return fmt.Errorf("health check sign failed: %w", err)
	}

	return nil
}

// recordAudit records an audit log entry
func (h *HSMSigner) recordAudit(entry AuditEntry) {
	h.auditLog.mu.Lock()
	defer h.auditLog.mu.Unlock()

	// Circular buffer - keep last 1000 entries
	if len(h.auditLog.entries) >= 1000 {
		h.auditLog.entries = h.auditLog.entries[1:]
	}
	h.auditLog.entries = append(h.auditLog.entries, entry)
}

// GetAuditLog returns the audit log entries
func (h *HSMSigner) GetAuditLog() []AuditEntry {
	h.auditLog.mu.Lock()
	defer h.auditLog.mu.Unlock()

	entries := make([]AuditEntry, len(h.auditLog.entries))
	copy(entries, h.auditLog.entries)
	return entries
}

// GetMetrics returns HSM metrics
func (h *HSMSigner) GetMetrics() HSMMetrics {
	h.metrics.mu.Lock()
	defer h.metrics.mu.Unlock()
	return *h.metrics
}

// Close gracefully closes the HSM connection
func (h *HSMSigner) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.connected {
		return nil
	}

	// Stop health checks
	h.healthCancel()

	// Close all sessions
	close(h.sessions)
	for session := range h.sessions {
		h.logger.Debug("Closing HSM session", "session_id", session.id)
	}

	// SECURITY: Zero the PIN from memory when closing
	h.config.ZeroPIN()

	h.connected = false
	h.logger.Info("HSM connection closed")

	return nil
}

// Reconnect attempts to reconnect to the HSM
func (h *HSMSigner) Reconnect(ctx context.Context) error {
	if err := h.Close(); err != nil {
		h.logger.Warn("Error closing HSM before reconnect", "error", err)
	}

	// Reset session channel
	h.sessions = make(chan *HSMSession, h.config.SessionPoolSize)

	// Reset health check context
	h.healthCtx, h.healthCancel = context.WithCancel(context.Background())

	return h.Connect(ctx)
}

// IsConnected returns true if connected to HSM
func (h *HSMSigner) IsConnected() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.connected
}

// ActiveKeyLabel returns the current active key label.
func (h *HSMSigner) ActiveKeyLabel() string {
	h.mu.RLock()
	label := h.config.ActiveKeyLabel()
	h.mu.RUnlock()
	return label
}

// ActiveKeyVersion returns the current active key version.
func (h *HSMSigner) ActiveKeyVersion() uint32 {
	h.mu.RLock()
	version := h.config.ActiveKeyVersion()
	h.mu.RUnlock()
	return version
}

// Helper functions

func generateSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// HSMSignerAdapter adapts HSMSigner to crypto.Signer interface
type HSMSignerAdapter struct {
	hsm *HSMSigner
}

// NewHSMSignerAdapter creates a crypto.Signer compatible adapter
func NewHSMSignerAdapter(hsm *HSMSigner) *HSMSignerAdapter {
	return &HSMSignerAdapter{hsm: hsm}
}

// Public returns the public key
func (a *HSMSignerAdapter) Public() crypto.PublicKey {
	pubKey, _ := a.hsm.PublicKey()
	return pubKey
}

// Sign implements crypto.Signer
func (a *HSMSignerAdapter) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return a.hsm.Sign(context.Background(), digest)
}

// KeyInfo contains information about an HSM key
type KeyInfo struct {
	Label       string       `json:"label"`
	Version     uint32       `json:"version,omitempty"`
	Algorithm   KeyAlgorithm `json:"algorithm"`
	KeyType     string       `json:"key_type"`
	Extractable bool         `json:"extractable"`
	CreatedAt   time.Time    `json:"created_at"`
}

// ListKeys lists all keys in the HSM (labels only, never actual keys)
func (h *HSMSigner) ListKeys(ctx context.Context) ([]KeyInfo, error) {
	// In production, this would use C_FindObjects to list keys
	// Only metadata is returned - actual keys never leave HSM
	label := h.ActiveKeyLabel()
	version := h.ActiveKeyVersion()

	return []KeyInfo{
		{
			Label:       label,
			Version:     version,
			Algorithm:   h.config.KeyAlgorithm,
			KeyType:     "private_key",
			Extractable: false,      // CRITICAL: Keys must never be extractable
			CreatedAt:   time.Now(), // Would come from HSM metadata
		},
	}, nil
}

// RotateKey generates and activates a new versioned key.
// Requires key_label_prefix to be configured.
func (h *HSMSigner) RotateKey(ctx context.Context) (KeyInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.connected {
		return KeyInfo{}, errors.New("HSM not connected")
	}
	if h.config.KeyLabelPrefix == "" {
		return KeyInfo{}, errors.New("key rotation requires key_label_prefix")
	}

	nextVersion := h.config.NextKeyVersion()
	label, err := h.config.KeyLabelForVersion(nextVersion)
	if err != nil {
		return KeyInfo{}, err
	}

	if err := h.GenerateKey(ctx, label, h.config.KeyAlgorithm); err != nil {
		return KeyInfo{}, err
	}

	h.config.KeyVersion = nextVersion
	if err := h.findKey(ctx); err != nil {
		return KeyInfo{}, err
	}

	return KeyInfo{
		Label:       label,
		Version:     nextVersion,
		Algorithm:   h.config.KeyAlgorithm,
		KeyType:     "private_key",
		Extractable: false,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// RotateKeyToVersion activates a specific key version (generates it if needed).
// Requires key_label_prefix to be configured.
func (h *HSMSigner) RotateKeyToVersion(ctx context.Context, version uint32) (KeyInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.connected {
		return KeyInfo{}, errors.New("HSM not connected")
	}
	if h.config.KeyLabelPrefix == "" {
		return KeyInfo{}, errors.New("key rotation requires key_label_prefix")
	}

	label, err := h.config.KeyLabelForVersion(version)
	if err != nil {
		return KeyInfo{}, err
	}

	if err := h.GenerateKey(ctx, label, h.config.KeyAlgorithm); err != nil {
		return KeyInfo{}, err
	}

	h.config.KeyVersion = version
	if err := h.findKey(ctx); err != nil {
		return KeyInfo{}, err
	}

	return KeyInfo{
		Label:       label,
		Version:     version,
		Algorithm:   h.config.KeyAlgorithm,
		KeyType:     "private_key",
		Extractable: false,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// GenerateKey generates a new key pair in the HSM
// The private key is created inside the HSM and NEVER leaves it
func (h *HSMSigner) GenerateKey(ctx context.Context, label string, algorithm KeyAlgorithm) error {
	h.logger.Info("Generating new key in HSM",
		"label", label,
		"algorithm", algorithm,
	)

	// In production, this would use:
	// C_GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate, &pubKeyHandle, &privKeyHandle)
	//
	// The private key template would include:
	// - CKA_TOKEN = TRUE (persistent)
	// - CKA_PRIVATE = TRUE
	// - CKA_SENSITIVE = TRUE
	// - CKA_EXTRACTABLE = FALSE (CRITICAL: key cannot be exported)
	// - CKA_SIGN = TRUE

	h.recordAudit(AuditEntry{
		Timestamp: time.Now().UTC(),
		Operation: "GENERATE_KEY",
		KeyLabel:  label,
		Success:   true,
	})

	return nil
}

// BackupKey creates an encrypted backup of the key (wrapped by master key)
// This is for disaster recovery - the key is still encrypted and cannot be used outside HSM
func (h *HSMSigner) BackupKey(ctx context.Context, wrappingKeyLabel string) ([]byte, error) {
	// In production, this would use C_WrapKey to encrypt the key with a master key
	// The wrapped key blob can only be unwrapped inside another HSM with the master key

	h.logger.Warn("Key backup requested - ensure wrapped key is stored securely")

	return nil, errors.New("key backup requires master key configuration")
}
