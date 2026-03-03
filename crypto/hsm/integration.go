// Package hsm provides integration layer between HSM and Aethelred node
package hsm

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"cosmossdk.io/log"
)

// ValidatorHSMManager manages HSM for validator operations
type ValidatorHSMManager struct {
	signer *HSMSigner
	logger log.Logger

	// Failover configuration
	primaryHSM *HSMSigner
	backupHSM  *HSMSigner
	activeHSM  *HSMSigner
	failoverMu sync.RWMutex

	// Configuration
	config ValidatorHSMConfig

	// State
	initialized bool
	mu          sync.RWMutex
}

// ValidatorHSMConfig contains configuration for validator HSM management
type ValidatorHSMConfig struct {
	// Primary HSM configuration
	Primary HSMConfig `mapstructure:"primary"`

	// Backup HSM configuration (for failover)
	Backup *HSMConfig `mapstructure:"backup,omitempty"`

	// EnableFailover enables automatic failover to backup HSM
	EnableFailover bool `mapstructure:"enable_failover"`

	// FailoverThreshold is number of consecutive failures before failover
	FailoverThreshold int `mapstructure:"failover_threshold"`

	// AutoRecovery enables automatic recovery to primary after failover
	AutoRecovery bool `mapstructure:"auto_recovery"`

	// RecoveryCheckInterval is how often to check if primary is recovered
	RecoveryCheckInterval time.Duration `mapstructure:"recovery_check_interval"`
}

// NewValidatorHSMManager creates a new validator HSM manager
func NewValidatorHSMManager(config ValidatorHSMConfig, logger log.Logger) (*ValidatorHSMManager, error) {
	if config.FailoverThreshold <= 0 {
		config.FailoverThreshold = 3
	}
	if config.RecoveryCheckInterval <= 0 {
		config.RecoveryCheckInterval = 5 * time.Minute
	}

	manager := &ValidatorHSMManager{
		config: config,
		logger: logger,
	}

	return manager, nil
}

// Initialize initializes the HSM connections
func (m *ValidatorHSMManager) Initialize(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized {
		return nil
	}

	// Initialize primary HSM
	primarySigner, err := NewHSMSigner(m.config.Primary, m.logger)
	if err != nil {
		return fmt.Errorf("failed to create primary HSM signer: %w", err)
	}

	if err := primarySigner.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to primary HSM: %w", err)
	}

	m.primaryHSM = primarySigner
	m.activeHSM = primarySigner

	// Initialize backup HSM if configured
	if m.config.Backup != nil && m.config.EnableFailover {
		backupSigner, err := NewHSMSigner(*m.config.Backup, m.logger)
		if err != nil {
			m.logger.Warn("Failed to create backup HSM signer", "error", err)
		} else if err := backupSigner.Connect(ctx); err != nil {
			m.logger.Warn("Failed to connect to backup HSM", "error", err)
		} else {
			m.backupHSM = backupSigner
			m.logger.Info("Backup HSM initialized for failover")
		}
	}

	m.signer = m.activeHSM
	m.initialized = true

	// Start recovery check if enabled
	if m.config.AutoRecovery && m.backupHSM != nil {
		go m.recoveryCheckLoop(ctx)
	}

	m.logger.Info("Validator HSM Manager initialized",
		"primary_connected", m.primaryHSM.IsConnected(),
		"backup_available", m.backupHSM != nil,
	)

	return nil
}

// Sign signs data using the active HSM
func (m *ValidatorHSMManager) Sign(ctx context.Context, data []byte) ([]byte, error) {
	m.failoverMu.RLock()
	signer := m.activeHSM
	m.failoverMu.RUnlock()

	if signer == nil {
		return nil, fmt.Errorf("no HSM available")
	}

	signature, err := signer.Sign(ctx, data)
	if err != nil && m.config.EnableFailover && m.backupHSM != nil {
		// Attempt failover
		if m.tryFailover(ctx) {
			m.failoverMu.RLock()
			signer = m.activeHSM
			m.failoverMu.RUnlock()
			return signer.Sign(ctx, data)
		}
	}

	return signature, err
}

// tryFailover attempts to failover to backup HSM
func (m *ValidatorHSMManager) tryFailover(ctx context.Context) bool {
	m.failoverMu.Lock()
	defer m.failoverMu.Unlock()

	if m.activeHSM == m.backupHSM {
		return false // Already on backup
	}

	if m.backupHSM == nil || !m.backupHSM.IsConnected() {
		m.logger.Error("Failover failed: backup HSM not available")
		return false
	}

	// Perform health check on backup
	if err := m.backupHSM.HealthCheck(ctx); err != nil {
		m.logger.Error("Failover failed: backup HSM health check failed", "error", err)
		return false
	}

	m.activeHSM = m.backupHSM
	m.signer = m.backupHSM

	m.logger.Warn("HSM FAILOVER: Switched to backup HSM",
		"primary_status", "FAILED",
		"backup_status", "ACTIVE",
	)

	return true
}

// recoveryCheckLoop periodically checks if primary can be recovered
func (m *ValidatorHSMManager) recoveryCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.RecoveryCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkRecovery(ctx)
		}
	}
}

// checkRecovery checks if primary HSM can be recovered
func (m *ValidatorHSMManager) checkRecovery(ctx context.Context) {
	m.failoverMu.RLock()
	onBackup := m.activeHSM == m.backupHSM
	m.failoverMu.RUnlock()

	if !onBackup {
		return // Not in failover state
	}

	// Check if primary is healthy
	if err := m.primaryHSM.HealthCheck(ctx); err != nil {
		return // Primary still unhealthy
	}

	// Recover to primary
	m.failoverMu.Lock()
	m.activeHSM = m.primaryHSM
	m.signer = m.primaryHSM
	m.failoverMu.Unlock()

	m.logger.Info("HSM RECOVERY: Switched back to primary HSM",
		"primary_status", "ACTIVE",
		"backup_status", "STANDBY",
	)
}

// GetPublicKey returns the validator's public key
func (m *ValidatorHSMManager) GetPublicKey() ([]byte, error) {
	m.failoverMu.RLock()
	signer := m.activeHSM
	m.failoverMu.RUnlock()

	if signer == nil {
		return nil, fmt.Errorf("no HSM available")
	}

	return signer.PublicKeyBytes()
}

// KeyRotationResult captures the outcome of a key rotation across HSMs.
type KeyRotationResult struct {
	TargetVersion uint32   `json:"target_version"`
	Primary       KeyInfo  `json:"primary"`
	Backup        *KeyInfo `json:"backup,omitempty"`
}

// RotateActiveKey rotates the key on the active HSM only.
func (m *ValidatorHSMManager) RotateActiveKey(ctx context.Context) (KeyInfo, error) {
	m.failoverMu.RLock()
	signer := m.activeHSM
	m.failoverMu.RUnlock()

	if signer == nil {
		return KeyInfo{}, fmt.Errorf("no HSM available")
	}

	return signer.RotateKey(ctx)
}

// RotateAllKeys rotates keys on both primary and backup HSMs to the same version.
// Backup is rotated first to avoid activating a version that failover can't sign with.
func (m *ValidatorHSMManager) RotateAllKeys(ctx context.Context) (KeyRotationResult, error) {
	m.failoverMu.Lock()
	defer m.failoverMu.Unlock()

	if m.primaryHSM == nil {
		return KeyRotationResult{}, fmt.Errorf("primary HSM not initialized")
	}

	targetVersion := m.primaryHSM.ActiveKeyVersion()
	if targetVersion == 0 {
		return KeyRotationResult{}, fmt.Errorf("primary HSM does not have versioned keys enabled")
	}
	targetVersion++

	var backupInfo *KeyInfo
	if m.backupHSM != nil {
		info, err := m.backupHSM.RotateKeyToVersion(ctx, targetVersion)
		if err != nil {
			return KeyRotationResult{}, fmt.Errorf("backup key rotation failed: %w", err)
		}
		backupInfo = &info
	}

	primaryInfo, err := m.primaryHSM.RotateKeyToVersion(ctx, targetVersion)
	if err != nil {
		return KeyRotationResult{}, fmt.Errorf("primary key rotation failed: %w", err)
	}

	if m.activeHSM == m.primaryHSM {
		m.signer = m.primaryHSM
	}

	return KeyRotationResult{
		TargetVersion: targetVersion,
		Primary:       primaryInfo,
		Backup:        backupInfo,
	}, nil
}

// Status returns the current HSM status
func (m *ValidatorHSMManager) Status() HSMStatus {
	m.failoverMu.RLock()
	defer m.failoverMu.RUnlock()

	status := HSMStatus{
		Initialized: m.initialized,
	}

	if m.primaryHSM != nil {
		status.PrimaryConnected = m.primaryHSM.IsConnected()
		status.PrimaryMetrics = m.primaryHSM.GetMetrics()
	}

	if m.backupHSM != nil {
		status.BackupConnected = m.backupHSM.IsConnected()
		status.BackupMetrics = m.backupHSM.GetMetrics()
	}

	if m.activeHSM == m.primaryHSM {
		status.ActiveHSM = "primary"
	} else if m.activeHSM == m.backupHSM {
		status.ActiveHSM = "backup"
	} else {
		status.ActiveHSM = "none"
	}

	if m.activeHSM != nil {
		status.ActiveKeyLabel = m.activeHSM.ActiveKeyLabel()
		status.ActiveKeyVersion = m.activeHSM.ActiveKeyVersion()
	}

	return status
}

// HSMStatus represents the current status of HSM infrastructure
type HSMStatus struct {
	Initialized      bool       `json:"initialized"`
	ActiveHSM        string     `json:"active_hsm"`
	ActiveKeyLabel   string     `json:"active_key_label,omitempty"`
	ActiveKeyVersion uint32     `json:"active_key_version,omitempty"`
	PrimaryConnected bool       `json:"primary_connected"`
	BackupConnected  bool       `json:"backup_connected"`
	PrimaryMetrics   HSMMetrics `json:"primary_metrics"`
	BackupMetrics    HSMMetrics `json:"backup_metrics"`
}

// Close gracefully closes HSM connections and zeroes sensitive data
func (m *ValidatorHSMManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error

	if m.primaryHSM != nil {
		if err := m.primaryHSM.Close(); err != nil {
			errs = append(errs, fmt.Errorf("primary HSM close: %w", err))
		}
	}

	if m.backupHSM != nil {
		if err := m.backupHSM.Close(); err != nil {
			errs = append(errs, fmt.Errorf("backup HSM close: %w", err))
		}
	}

	// SECURITY: Zero PINs from config memory
	m.config.Primary.ZeroPIN()
	if m.config.Backup != nil {
		m.config.Backup.ZeroPIN()
	}

	m.initialized = false

	if len(errs) > 0 {
		return fmt.Errorf("errors closing HSMs: %v", errs)
	}

	return nil
}

// SignVoteExtension signs a vote extension using HSM
func (m *ValidatorHSMManager) SignVoteExtension(ctx context.Context, extensionData []byte) ([]byte, error) {
	// Add domain separation for vote extensions
	prefix := []byte("aethelred/vote-extension/v1:")
	data := make([]byte, len(prefix)+len(extensionData))
	copy(data, prefix)
	copy(data[len(prefix):], extensionData)

	signature, err := m.Sign(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("HSM vote extension signing failed: %w", err)
	}

	m.logger.Debug("Vote extension signed with HSM",
		"extension_hash", hex.EncodeToString(extensionData[:min(8, len(extensionData))]),
		"signature_len", len(signature),
	)

	return signature, nil
}

// SignBlock signs a block proposal using HSM
func (m *ValidatorHSMManager) SignBlock(ctx context.Context, blockData []byte) ([]byte, error) {
	// Add domain separation for block signing
	prefix := []byte("aethelred/block/v1:")
	data := make([]byte, len(prefix)+len(blockData))
	copy(data, prefix)
	copy(data[len(prefix):], blockData)

	return m.Sign(ctx, data)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
