package app

import (
	"testing"

	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/testutil/sims"
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
