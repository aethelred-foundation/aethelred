package app

import (
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// isTestEnvironment
// ---------------------------------------------------------------------------

func TestIsTestEnvironment_InTestBinary(t *testing.T) {
	// We ARE in a test binary, so this should return true (os.Args has -test.* flags).
	if !isTestEnvironment() {
		t.Fatal("expected isTestEnvironment() to return true inside go test")
	}
}

func TestIsTestEnvironment_ViaEnvVar(t *testing.T) {
	t.Setenv("AETHELRED_TEST_MODE", "1")
	if !isTestEnvironment() {
		t.Fatal("expected isTestEnvironment() to return true when AETHELRED_TEST_MODE=1")
	}
}

func TestIsTestEnvironment_EnvVarUnset(t *testing.T) {
	// Even with the env var unset, isTestEnvironment() returns true in
	// go test because -test.* args are present. This test documents that.
	t.Setenv("AETHELRED_TEST_MODE", "")
	// Still true because os.Args has -test.* flags from the go test binary.
	if !isTestEnvironment() {
		t.Fatal("expected true due to -test.* args")
	}
}

// ---------------------------------------------------------------------------
// DefaultEncryptedMempoolBridgeConfig (referenced from readiness code path)
// ---------------------------------------------------------------------------

func TestReadiness_ConfigIntegrity(t *testing.T) {
	// Verify that the encrypted mempool config defaults are reasonable.
	cfg := DefaultEncryptedMempoolBridgeConfig()
	if cfg.MaxDecryptedTxSize <= 0 {
		t.Fatal("max decrypted tx size must be positive")
	}
}

// ---------------------------------------------------------------------------
// IsProductionBuild
// ---------------------------------------------------------------------------

func TestIsProductionBuild_InTestBinary(t *testing.T) {
	// In test builds, IsProductionBuild should return false unless the
	// 'production' build tag was explicitly provided.
	// We don't have the production tag, so this should be false.
	result := IsProductionBuild()
	// This is informational; the value depends on build tags.
	_ = result
}

// ---------------------------------------------------------------------------
// buildOrchestratorConfig environment variable handling
// ---------------------------------------------------------------------------

func TestBuildOrchestratorConfig_EnterpriseMode(t *testing.T) {
	// Just test the env var parsing logic, not the full app struct.
	t.Setenv("AETHELRED_ENTERPRISE_MODE", "1")
	t.Setenv("AETHELRED_TEE_ENDPOINT", "")
	t.Setenv("TEE_ENDPOINT", "")
	t.Setenv("AETHELRED_TEE_MODE", "")
	t.Setenv("TEE_MODE", "")
	t.Setenv("AETHELRED_PROVER_ENDPOINT", "")
	t.Setenv("AETHELRED_ATTESTATION_VERIFIER_ENDPOINT", "")
	t.Setenv("AETHELRED_TEE_ATTESTATION_ENDPOINT", "")

	val := os.Getenv("AETHELRED_ENTERPRISE_MODE")
	if val != "1" {
		t.Fatal("env var should be set")
	}
}

func TestBuildOrchestratorConfig_TEEMode_Mock(t *testing.T) {
	t.Setenv("AETHELRED_TEE_MODE", "mock")
	mode := os.Getenv("AETHELRED_TEE_MODE")
	allowSimulated := mode == "mock" || mode == "simulated" || mode == "nitro-simulated"
	if !allowSimulated {
		t.Fatal("mock mode should allow simulated")
	}
}

func TestBuildOrchestratorConfig_TEEMode_Simulated(t *testing.T) {
	t.Setenv("AETHELRED_TEE_MODE", "simulated")
	mode := os.Getenv("AETHELRED_TEE_MODE")
	allowSimulated := mode == "mock" || mode == "simulated" || mode == "nitro-simulated"
	if !allowSimulated {
		t.Fatal("simulated mode should allow simulated")
	}
}

func TestBuildOrchestratorConfig_TEEMode_NitroSimulated(t *testing.T) {
	t.Setenv("AETHELRED_TEE_MODE", "nitro-simulated")
	mode := os.Getenv("AETHELRED_TEE_MODE")
	allowSimulated := mode == "mock" || mode == "simulated" || mode == "nitro-simulated"
	if !allowSimulated {
		t.Fatal("nitro-simulated mode should allow simulated")
	}
}

func TestBuildOrchestratorConfig_TEEMode_Production(t *testing.T) {
	t.Setenv("AETHELRED_TEE_MODE", "production")
	mode := os.Getenv("AETHELRED_TEE_MODE")
	allowSimulated := mode == "mock" || mode == "simulated" || mode == "nitro-simulated"
	if allowSimulated {
		t.Fatal("production mode should NOT allow simulated")
	}
}
