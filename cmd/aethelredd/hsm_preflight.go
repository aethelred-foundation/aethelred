// hsm_preflight.go - HSM preflight validation for validator nodes.
// This file defines the runHSMPreflight logic that is invoked from the
// main command tree. It reads configuration from environment variables,
// constructs an hsm.ValidatorHSMConfig, and delegates to hsm.RunPreflight.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/crypto/hsm"
)

// envOrDefault returns the value of the environment variable named by key,
// or fallback if the variable is empty or unset.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// runHSMPreflight executes the G8 HSM preflight validation gate.
// It returns 0 on success and 1 on failure so the caller can translate
// the result into a process exit code.
func runHSMPreflight() int {
	logger := log.NewLogger(os.Stderr)

	// ---- read configuration from environment variables ----
	hsmType := envOrDefault("AETHELRED_HSM_TYPE", "softhsm")
	hsmLibrary := envOrDefault("AETHELRED_HSM_LIBRARY", "/usr/lib/softhsm/libsofthsm2.so")
	hsmSlotStr := envOrDefault("AETHELRED_HSM_SLOT", "0")
	hsmPINEnv := envOrDefault("AETHELRED_HSM_PIN_ENV", "AETHELRED_HSM_PIN")
	hsmKeyLabel := envOrDefault("AETHELRED_HSM_KEY_LABEL", "aethelred-validator-key")
	hsmKeyAlgo := envOrDefault("AETHELRED_HSM_KEY_ALGO", "ed25519")

	slotID, err := strconv.ParseUint(hsmSlotStr, 10, 32)
	if err != nil {
		logger.Error("invalid AETHELRED_HSM_SLOT value", "value", hsmSlotStr, "error", err)
		return 1
	}

	// ---- construct the validator HSM config ----
	config := hsm.ValidatorHSMConfig{
		Primary: hsm.HSMConfig{
			Type:                hsm.HSMType(hsmType),
			ModulePath:          hsmLibrary,
			SlotID:              uint(slotID),
			PINEnvVar:           hsmPINEnv,
			KeyLabel:            hsmKeyLabel,
			KeyAlgorithm:        hsm.KeyAlgorithm(hsmKeyAlgo),
			ConnectionTimeout:   30 * time.Second,
			MaxRetries:          3,
			RetryDelay:          time.Second,
			SessionPoolSize:     4,
			HealthCheckInterval: 30 * time.Second,
			AuditLogging:        true,
		},
	}

	// ---- run preflight with a 30-second timeout ----
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := hsm.RunPreflight(ctx, config, logger)

	// ---- output the result as JSON ----
	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		logger.Error("failed to marshal preflight result", "error", err)
		return 1
	}
	fmt.Println(string(out))

	if result.Pass() {
		return 0
	}
	return 1
}
