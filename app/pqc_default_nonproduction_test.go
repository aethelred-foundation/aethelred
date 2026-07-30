//go:build !production

package app

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/testutil/sims"
)

func TestResolvePQCModeDefaultsToSimulatedOutsideProduction(t *testing.T) {
	t.Setenv("AETHELRED_PQC_MODE", "")
	t.Setenv("PQC_MODE", "")

	if got := resolvePQCMode(sims.AppOptionsMap{}); got != "simulated" {
		t.Fatalf("expected non-production PQC default %q, got %q", "simulated", got)
	}
	if resolvePQCEnabled(sims.AppOptionsMap{}) {
		t.Fatal("expected PQC to default disabled outside production builds")
	}
}
