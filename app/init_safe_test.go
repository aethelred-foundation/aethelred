package app

import (
	"testing"

	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/testutil/sims"

	"github.com/aethelred/aethelred/crypto/pqc"
)

func TestTeeModeRequiresHealthyVerifier(t *testing.T) {
	t.Parallel()

	nonCriticalModes := []string{"", "disabled", "mock", "simulated", "nitro-simulated"}
	for _, mode := range nonCriticalModes {
		if teeModeRequiresHealthyVerifier(mode) {
			t.Fatalf("expected mode %q to allow degraded init", mode)
		}
	}

	criticalModes := []string{"remote", "http", "nitro", "aws-nitro", "production", "mainnet"}
	for _, mode := range criticalModes {
		if !teeModeRequiresHealthyVerifier(mode) {
			t.Fatalf("expected mode %q to require a healthy verifier", mode)
		}
	}
}

func TestSafeInitTEEClient_FailsClosedForRemoteModes(t *testing.T) {
	t.Parallel()

	modes := []string{"remote", "http", "nitro", "aws-nitro"}
	for _, mode := range modes {
		app := &AethelredApp{}
		opts := sims.AppOptionsMap{
			"aethelred.tee.mode": mode,
		}

		initErr, err := SafeInitTEEClient(app, log.NewNopLogger(), opts)
		if err == nil {
			t.Fatalf("expected init failure for mode %q without endpoint", mode)
		}
		if initErr == nil || !initErr.IsCritical {
			t.Fatalf("expected critical init error for mode %q", mode)
		}
		if app.teeClient != nil {
			t.Fatalf("expected no tee client to be installed for mode %q", mode)
		}
	}
}

func TestSafeInitTEEClient_AllowsExplicitSimulatedMode(t *testing.T) {
	t.Parallel()

	app := &AethelredApp{}
	opts := sims.AppOptionsMap{
		"aethelred.tee.mode": "nitro-simulated",
	}

	initErr, err := SafeInitTEEClient(app, log.NewNopLogger(), opts)
	if err != nil {
		t.Fatalf("expected simulated mode to initialize, got %v", err)
	}
	if initErr != nil {
		t.Fatalf("expected no degraded init warning for simulated mode, got %v", initErr)
	}
	if app.teeClient == nil {
		t.Fatalf("expected tee client to be installed for simulated mode")
	}
}

func TestCheckPQCAvailability_RequiresCirclForProductionModes(t *testing.T) {
	if pqc.IsCirclAvailable() {
		t.Skip("this test expects the non-circl build")
	}

	productionOpts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "production",
	}
	if checkPQCAvailability(productionOpts) {
		t.Fatalf("expected production PQC mode to report unavailable without circl")
	}

	hybridOpts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "hybrid",
	}
	if checkPQCAvailability(hybridOpts) {
		t.Fatalf("expected hybrid PQC mode to report unavailable without circl")
	}

	simulatedOpts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
	}
	if !checkPQCAvailability(simulatedOpts) {
		t.Fatalf("expected simulated PQC mode to remain available")
	}
}

func TestSafeInitPQCMode_FallsBackWhenRequestedBackendUnavailable(t *testing.T) {
	if pqc.IsCirclAvailable() {
		t.Skip("this test expects the non-circl build")
	}

	previousMode := pqc.GetPQCMode()
	defer pqc.SetPQCMode(previousMode)
	pqc.SetPQCMode(pqc.PQCModeSimulated)

	opts := sims.AppOptionsMap{
		"aethelred.pqc.enabled": true,
		"aethelred.pqc.mode":    "production",
	}

	if err := SafeInitPQCMode(log.NewNopLogger(), opts); err != nil {
		t.Fatalf("expected graceful PQC fallback, got %v", err)
	}
	if pqc.GetPQCMode() != pqc.PQCModeSimulated {
		t.Fatalf("expected fallback to preserve simulated PQC mode, got %s", pqc.GetPQCMode().String())
	}
}
