//go:build production

package app

import (
	"fmt"
	"strings"
	"testing"

	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/testutil/sims"

	"github.com/aethelred/aethelred/crypto/pqc"
)

func TestResolvePQCModeDefaultsToProductionInProductionBuild(t *testing.T) {
	t.Setenv("AETHELRED_PQC_MODE", "")
	t.Setenv("PQC_MODE", "")

	if got := resolvePQCMode(sims.AppOptionsMap{}); got != "production" {
		t.Fatalf("expected production PQC default %q, got %q", "production", got)
	}
	if !resolvePQCEnabled(sims.AppOptionsMap{}) {
		t.Fatal("expected PQC to default enabled in production builds")
	}
}

func TestSafeInitPQCModeProductionDefault(t *testing.T) {
	t.Setenv("AETHELRED_PQC_MODE", "")
	t.Setenv("PQC_MODE", "")

	previousMode := pqc.GetPQCMode()
	defer pqc.SetPQCMode(previousMode)

	err := SafeInitPQCMode(log.NewNopLogger(), sims.AppOptionsMap{})
	if !pqc.IsCirclAvailable() {
		if err == nil || !strings.Contains(err.Error(), "CIRCL") {
			t.Fatalf("expected a clear CIRCL startup error, got %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("expected tagged production PQC initialization to succeed, got %v", err)
	}
	if got := pqc.GetPQCMode(); got != pqc.PQCModeProduction {
		t.Fatalf("expected production PQC mode, got %s", got.String())
	}
}

func TestSafeInitPQCModeProductionRejectsDowngrade(t *testing.T) {
	tests := []struct {
		name string
		opts sims.AppOptionsMap
	}{
		{
			name: "explicitly disabled",
			opts: sims.AppOptionsMap{"aethelred.pqc.enabled": false},
		},
		{
			name: "simulated mode",
			opts: sims.AppOptionsMap{"aethelred.pqc.mode": "simulated"},
		},
		{
			name: "disabled mode",
			opts: sims.AppOptionsMap{"aethelred.pqc.mode": "disabled"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := SafeInitPQCMode(log.NewNopLogger(), test.opts)
			if err == nil || !strings.Contains(err.Error(), "production builds require") {
				t.Fatalf("expected production downgrade rejection, got %v", err)
			}
		})
	}
}

func TestInitializePQCModeOrPanicFailsClosedWithoutCircl(t *testing.T) {
	if pqc.IsCirclAvailable() {
		t.Skip("the tagged CIRCL backend is available")
	}
	t.Setenv("AETHELRED_PQC_MODE", "")
	t.Setenv("PQC_MODE", "")

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("expected production initialization to panic without CIRCL")
		}
		if !strings.Contains(fmt.Sprint(recovered), "CIRCL") {
			t.Fatalf("expected panic to identify the missing CIRCL backend, got %v", recovered)
		}
	}()

	initializePQCModeOrPanic(log.NewNopLogger(), sims.AppOptionsMap{})
}
