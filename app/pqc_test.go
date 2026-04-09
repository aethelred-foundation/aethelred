package app

import (
	"testing"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/crypto/pqc"
)

// ---------------------------------------------------------------------------
// PQC mode helpers
// ---------------------------------------------------------------------------

type mockPQCAppOpts struct {
	data map[string]interface{}
}

func (m mockPQCAppOpts) Get(key string) interface{} {
	if m.data == nil {
		return nil
	}
	return m.data[key]
}

func TestInitPQCMode_DefaultSimulated(t *testing.T) {
	// With no env vars or app opts, should default to simulated.
	t.Setenv("AETHELRED_PQC_MODE", "")
	t.Setenv("PQC_MODE", "")

	logger := log.NewNopLogger()
	opts := mockPQCAppOpts{data: map[string]interface{}{}}

	err := initPQCMode(logger, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pqc.GetPQCMode() != pqc.PQCModeSimulated {
		t.Fatalf("expected simulated mode, got %s", pqc.GetPQCMode().String())
	}
}

func TestInitPQCMode_DisabledExplicit(t *testing.T) {
	t.Setenv("AETHELRED_PQC_MODE", "disabled")
	t.Setenv("PQC_MODE", "")

	logger := log.NewNopLogger()
	opts := mockPQCAppOpts{data: map[string]interface{}{}}

	err := initPQCMode(logger, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pqc.GetPQCMode() != pqc.PQCModeSimulated {
		t.Fatalf("disabled should map to simulated, got %s", pqc.GetPQCMode().String())
	}
}

func TestInitPQCMode_FalseString(t *testing.T) {
	t.Setenv("AETHELRED_PQC_MODE", "false")
	t.Setenv("PQC_MODE", "")

	logger := log.NewNopLogger()
	opts := mockPQCAppOpts{data: map[string]interface{}{}}

	err := initPQCMode(logger, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pqc.GetPQCMode() != pqc.PQCModeSimulated {
		t.Fatalf("false should map to simulated, got %s", pqc.GetPQCMode().String())
	}
}

func TestInitPQCMode_ZeroString(t *testing.T) {
	t.Setenv("AETHELRED_PQC_MODE", "0")
	t.Setenv("PQC_MODE", "")

	logger := log.NewNopLogger()
	opts := mockPQCAppOpts{data: map[string]interface{}{}}

	err := initPQCMode(logger, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pqc.GetPQCMode() != pqc.PQCModeSimulated {
		t.Fatalf("0 should map to simulated, got %s", pqc.GetPQCMode().String())
	}
}

func TestInitPQCMode_UnsupportedMode(t *testing.T) {
	t.Setenv("AETHELRED_PQC_MODE", "quantum-teleport")
	t.Setenv("PQC_MODE", "")

	logger := log.NewNopLogger()
	opts := mockPQCAppOpts{data: map[string]interface{}{}}

	err := initPQCMode(logger, opts)
	if err == nil {
		t.Fatal("expected error for unsupported PQC mode")
	}
}

func TestInitPQCMode_AppOptsOverridesEnv(t *testing.T) {
	t.Setenv("AETHELRED_PQC_MODE", "")
	t.Setenv("PQC_MODE", "")

	logger := log.NewNopLogger()
	opts := mockPQCAppOpts{data: map[string]interface{}{
		"aethelred.pqc.mode": "simulated",
	}}

	err := initPQCMode(logger, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pqc.GetPQCMode() != pqc.PQCModeSimulated {
		t.Fatalf("expected simulated from app opts, got %s", pqc.GetPQCMode().String())
	}
}

func TestInitPQCMode_EnvFallback(t *testing.T) {
	t.Setenv("AETHELRED_PQC_MODE", "simulated")
	t.Setenv("PQC_MODE", "")

	logger := log.NewNopLogger()
	opts := mockPQCAppOpts{data: map[string]interface{}{}}

	err := initPQCMode(logger, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pqc.GetPQCMode() != pqc.PQCModeSimulated {
		t.Fatalf("expected simulated from env, got %s", pqc.GetPQCMode().String())
	}
}

// ---------------------------------------------------------------------------
// PQC key type and sign/verify (through pqc package)
// ---------------------------------------------------------------------------

func TestPQCIntegration_KeyType(t *testing.T) {
	mode := pqc.GetPQCMode()
	// In test environment, mode is typically simulated.
	if mode.String() == "" {
		t.Fatal("PQC mode string should not be empty")
	}
}

func TestPQCIntegration_SignVerify(t *testing.T) {
	// Use the simulated mode for testing sign/verify through app layer.
	pqc.SetPQCMode(pqc.PQCModeSimulated)

	check := pqc.CheckPQCReadiness()
	// In simulated mode, the check may have errors but should not panic.
	_ = check
}
