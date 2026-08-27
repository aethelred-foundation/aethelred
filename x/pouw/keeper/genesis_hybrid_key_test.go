package keeper

import (
	"bytes"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/crypto/pqc"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// TestGenesisSeedsHybridKeys proves validator hybrid keys can be seeded at
// genesis (no registration tx needed) and survive an export/import round-trip.
func TestGenesisSeedsHybridKeys(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)

	w1, _ := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	w2, _ := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	addr1 := sdk.AccAddress([]byte("genesis-validator-1")).String()
	addr2 := sdk.AccAddress([]byte("genesis-validator-2")).String()

	gs := types.DefaultGenesis()
	gs.ValidatorHybridKeys = []*types.ValidatorHybridKey{
		{ValidatorAddress: addr1, HybridPublicKey: w1.HybridPublicKey()},
		{ValidatorAddress: addr2, HybridPublicKey: w2.HybridPublicKey()},
	}

	if err := k.InitGenesis(ctx, gs); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}

	// Both keys are now registered and usable for verification.
	got1, err := k.GetValidatorHybridKey(ctx, addr1)
	if err != nil || !bytes.Equal(got1, w1.HybridPublicKey()) {
		t.Fatalf("validator 1 key not seeded: err=%v", err)
	}
	msg := []byte("seeded-key signing")
	sig, _ := w1.SignHybrid(msg)
	if ok, err := pqc.VerifyHybrid(got1, msg, sig); err != nil || !ok {
		t.Fatalf("seeded key failed verification: ok=%v err=%v", ok, err)
	}

	// Export must round-trip both keys.
	exported, err := k.ExportGenesis(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(exported.ValidatorHybridKeys) != 2 {
		t.Fatalf("expected 2 exported hybrid keys, got %d", len(exported.ValidatorHybridKeys))
	}
	seen := map[string][]byte{}
	for _, hk := range exported.ValidatorHybridKeys {
		seen[hk.ValidatorAddress] = hk.HybridPublicKey
	}
	if !bytes.Equal(seen[addr1], w1.HybridPublicKey()) || !bytes.Equal(seen[addr2], w2.HybridPublicKey()) {
		t.Fatal("exported hybrid keys do not match seeded keys")
	}

	// Malformed seeded key is rejected at InitGenesis.
	k2, ctx2 := newRegistryTestKeeper(t)
	bad := types.DefaultGenesis()
	bad.ValidatorHybridKeys = []*types.ValidatorHybridKey{
		{ValidatorAddress: addr1, HybridPublicKey: []byte{0x01, 0x02}},
	}
	if err := k2.InitGenesis(ctx2, bad); err == nil {
		t.Fatal("expected InitGenesis to reject a malformed hybrid key")
	}
}
