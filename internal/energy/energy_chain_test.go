package energy_test

import (
	"testing"

	"github.com/aethelred/aethelred/internal/energy"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

// The worker emits these keys/labels and the x/pouw keeper parses them. If
// either side drifts, measured receipts silently stop being recorded — so pin
// them together here.
func TestMetadataKeysMatchChain(t *testing.T) {
	pairs := []struct{ worker, chain string }{
		{energy.MetaKeyDeviceClass, pouwtypes.MetaEnergyDeviceClass},
		{energy.MetaKeyDeviceMs, pouwtypes.MetaEnergyDeviceMs},
		{energy.MetaKeyAvgPowerMw, pouwtypes.MetaEnergyAvgPowerMw},
		{energy.MetaKeyBasis, pouwtypes.MetaEnergyBasis},
		{energy.BasisMeasured, string(pouwtypes.EnergyBasisMeasured)},
		{energy.BasisDeviceProfile, string(pouwtypes.EnergyBasisDeviceProfile)},
	}
	for _, p := range pairs {
		if p.worker != p.chain {
			t.Fatalf("worker/chain energy constant drift: %q != %q", p.worker, p.chain)
		}
	}
}
