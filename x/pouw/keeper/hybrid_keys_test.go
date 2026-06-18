package keeper

import (
	"bytes"
	"testing"

	"github.com/aethelred/aethelred/crypto/pqc"
)

func TestValidatorHybridKeyRegistration(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)

	w, err := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	pub := w.HybridPublicKey()
	const addr = "aethelvaloper1abc"

	// Register a valid key.
	if err := k.RegisterValidatorHybridKey(ctx, addr, pub); err != nil {
		t.Fatalf("register: %v", err)
	}
	if !k.HasValidatorHybridKey(ctx, addr) {
		t.Fatal("HasValidatorHybridKey = false after registration")
	}

	got, err := k.GetValidatorHybridKey(ctx, addr)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Fatal("retrieved key does not match registered key")
	}

	// Reject malformed keys and empty address.
	if err := k.RegisterValidatorHybridKey(ctx, addr, []byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("expected error registering malformed hybrid key")
	}
	if err := k.RegisterValidatorHybridKey(ctx, "", pub); err == nil {
		t.Fatal("expected error registering with empty address")
	}

	// A second validator, then GetAll returns both.
	w2, _ := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	if err := k.RegisterValidatorHybridKey(ctx, "aethelvaloper1xyz", w2.HybridPublicKey()); err != nil {
		t.Fatal(err)
	}
	all, err := k.GetAllValidatorHybridKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("GetAll returned %d keys, want 2", len(all))
	}

	// The registered key must verify a signature from its wallet over a claim,
	// proving the stored bytes are usable for quorum verification.
	msg := []byte("seal claim bytes")
	sig, err := w.SignHybrid(msg)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := pqc.VerifyHybrid(all[addr], msg, sig)
	if err != nil || !ok {
		t.Fatalf("stored key failed to verify signature: ok=%v err=%v", ok, err)
	}
}
