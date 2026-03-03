// Package hsm — preflight.go provides HSM preflight validation for the G8 gate.
// RunPreflight validates HSM readiness before the validator node starts,
// checking connectivity, key availability, signing capability, and failover.
package hsm

import (
	"context"
	"fmt"
	"time"

	"cosmossdk.io/log"
)

// PreflightResult captures the outcome of every HSM readiness check
// performed during the G8 preflight validation gate.
type PreflightResult struct {
	HSMConnected     bool     `json:"hsm_connected"`
	TestSignOK       bool     `json:"test_sign_ok"`
	KeyLabelValid    bool     `json:"key_label_valid"`
	PKCS11SessionOK  bool     `json:"pkcs11_session_ok"`
	FailoverReady    bool     `json:"failover_ready"`
	Errors           []string `json:"errors,omitempty"`
}

// Pass returns true only when all critical HSM subsystems are healthy
// and no errors were recorded during the preflight run.
func (r PreflightResult) Pass() bool {
	return r.HSMConnected &&
		r.TestSignOK &&
		r.KeyLabelValid &&
		r.PKCS11SessionOK &&
		len(r.Errors) == 0
}

// RunPreflight executes the full HSM preflight validation sequence.
// It creates a ValidatorHSMManager from the supplied config, attempts to
// initialize it, and then exercises key lookup, test signing, and (when
// configured) failover readiness.
func RunPreflight(ctx context.Context, config ValidatorHSMConfig, logger log.Logger) PreflightResult {
	result := PreflightResult{}
	startTime := time.Now()

	logger.Info("HSM preflight validation starting", "time", startTime.Format(time.RFC3339))

	// Step (a): create the manager
	manager, err := NewValidatorHSMManager(config, logger)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to create HSM manager: %v", err))
		logger.Error("HSM preflight: manager creation failed", "error", err)
		return result
	}
	defer func() {
		if closeErr := manager.Close(); closeErr != nil {
			logger.Warn("HSM preflight: error closing manager", "error", closeErr)
		}
	}()

	// Step (b): initialize (connects to primary HSM, opens sessions, finds key)
	if err := manager.Initialize(ctx); err != nil {
		result.HSMConnected = false
		result.Errors = append(result.Errors, fmt.Sprintf("HSM initialization failed: %v", err))
		logger.Error("HSM preflight: initialization failed", "error", err)
		return result
	}
	result.HSMConnected = true
	logger.Info("HSM preflight: connection established")

	// Step (d): verify the key label by retrieving the public key
	if _, err := manager.GetPublicKey(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("key label validation failed: %v", err))
		logger.Error("HSM preflight: GetPublicKey failed", "error", err)
	} else {
		result.KeyLabelValid = true
		logger.Info("HSM preflight: key label valid")
	}

	// Step (e): test signing with domain-separated preflight payload
	testPayload := []byte("aethelred/hsm-preflight/v1")
	if _, err := manager.Sign(ctx, testPayload); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("test sign failed: %v", err))
		logger.Error("HSM preflight: test sign failed", "error", err)
	} else {
		result.TestSignOK = true
		logger.Info("HSM preflight: test sign succeeded")
	}

	// Step (f): a successful sign implies the PKCS#11 session is functional
	if result.TestSignOK {
		result.PKCS11SessionOK = true
		logger.Info("HSM preflight: PKCS#11 session validated")
	}

	// Step (g): check failover readiness when configured
	if config.EnableFailover && config.Backup != nil {
		status := manager.Status()
		if status.BackupConnected {
			result.FailoverReady = true
			logger.Info("HSM preflight: failover ready", "backup_connected", true)
		} else {
			logger.Warn("HSM preflight: failover configured but backup HSM not connected")
		}
	}

	elapsed := time.Since(startTime)
	logger.Info("HSM preflight validation complete",
		"pass", result.Pass(),
		"duration", elapsed.String(),
		"errors", len(result.Errors),
	)

	return result
}
