package keeper

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/crypto/pqc"
	"github.com/aethelred/aethelred/x/pouw/types"
)

func TestMsgRegisterValidatorHybridKey(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	srv := NewMsgServerImpl(k)
	goCtx := sdk.WrapSDKContext(ctx)

	// A bech32 address valid under the global SDK prefix (whatever it is in tests).
	addr := sdk.AccAddress([]byte("validator-account-1")).String()

	w, err := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	pub := w.HybridPublicKey()

	// Happy path: validator registers its own hybrid key.
	resp, err := srv.RegisterValidatorHybridKey(goCtx, &types.MsgRegisterValidatorHybridKey{
		Creator:          addr,
		ValidatorAddress: addr,
		HybridPublicKey:  pub,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.ValidatorAddress != addr {
		t.Fatalf("unexpected response address %q", resp.ValidatorAddress)
	}

	// The key must be retrievable and usable for verification.
	got, err := k.GetValidatorHybridKey(ctx, addr)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	msg := []byte("seal claim")
	sig, _ := w.SignHybrid(msg)
	if ok, err := pqc.VerifyHybrid(got, msg, sig); err != nil || !ok {
		t.Fatalf("stored key failed verification: ok=%v err=%v", ok, err)
	}

	// Rejection: creator != validator_address.
	other := sdk.AccAddress([]byte("a-different-account")).String()
	if _, err := srv.RegisterValidatorHybridKey(goCtx, &types.MsgRegisterValidatorHybridKey{
		Creator:          other,
		ValidatorAddress: addr,
		HybridPublicKey:  pub,
	}); err == nil {
		t.Fatal("expected error when creator != validator_address")
	}

	// Rejection: malformed hybrid key.
	if _, err := srv.RegisterValidatorHybridKey(goCtx, &types.MsgRegisterValidatorHybridKey{
		Creator:          addr,
		ValidatorAddress: addr,
		HybridPublicKey:  []byte{0x01, 0x02},
	}); err == nil {
		t.Fatal("expected error for malformed hybrid key")
	}
}
