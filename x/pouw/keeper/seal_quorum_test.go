package keeper

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/aethelred/aethelred/crypto/pqc"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

func TestVerifyJobSealQuorum(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)

	claim := sealtypes.SealClaim{
		ChainID:          "aethelred-test-1",
		JobID:            "job-quorum-1",
		ModelCommitment:  make([]byte, 32),
		InputCommitment:  make([]byte, 32),
		OutputCommitment: []byte("0123456789abcdef0123456789abcdef"),
	}

	// Four validators, equal power 10 (total 40, required (40*67/100)+1 = 27).
	n := 4
	wallets := make([]*pqc.DualKeyWallet, n)
	addrs := make([]string, n)
	powerByAddr := make(map[string]int64, n)
	for i := 0; i < n; i++ {
		w, err := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
		if err != nil {
			t.Fatal(err)
		}
		addr := fmt.Sprintf("aethelvaloper1q%02d", i)
		if err := k.RegisterValidatorHybridKey(ctx, addr, w.HybridPublicKey()); err != nil {
			t.Fatal(err)
		}
		wallets[i] = w
		addrs[i] = addr
		powerByAddr[addr] = 10
	}

	sign := func(i int) sealtypes.SealSignature {
		sig, err := wallets[i].SignHybrid(claim.SigningBytes())
		if err != nil {
			t.Fatal(err)
		}
		return sealtypes.NewValidatorSealSignature(addrs[i], wallets[i].HybridPublicKey(), sig, time.Unix(0, 0))
	}

	// 3 of 4 sign (power 30 >= 27) => quorum reached.
	sigs := []sealtypes.SealSignature{sign(0), sign(1), sign(2)}
	res, err := k.VerifyJobSealQuorum(ctx, claim, sigs, powerByAddr, 67)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reached || res.AgreedPower != 30 {
		t.Fatalf("expected quorum (agreed=30): %+v", res)
	}

	// 2 of 4 (power 20 < 27) => not reached.
	res2, err := k.VerifyJobSealQuorum(ctx, claim, sigs[:2], powerByAddr, 67)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Reached {
		t.Fatalf("did not expect quorum: %+v", res2)
	}

	// A signature over a different claim must not count.
	otherClaim := claim
	otherClaim.OutputCommitment = []byte("ffffffffffffffffffffffffffffffff")
	badSig, _ := wallets[3].SignHybrid(otherClaim.SigningBytes())
	mixed := []sealtypes.SealSignature{sign(0), sign(1), sealtypes.NewValidatorSealSignature(addrs[3], wallets[3].HybridPublicKey(), badSig, time.Unix(0, 0))}
	res3, err := k.VerifyJobSealQuorum(ctx, claim, mixed, powerByAddr, 67)
	if err != nil {
		t.Fatal(err)
	}
	if res3.AgreedPower != 20 {
		t.Fatalf("wrong-claim signature should not count: agreed=%d", res3.AgreedPower)
	}
}

func TestAttachAndGetSealQuorumSignatures(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)

	claim := sealtypes.SealClaim{
		ChainID:          "aethelred-test-1",
		JobID:            "job-attach-1",
		ModelCommitment:  bytes.Repeat([]byte{0x11}, 32),
		InputCommitment:  bytes.Repeat([]byte{0x22}, 32),
		OutputCommitment: bytes.Repeat([]byte{0x33}, 32),
	}
	msg := claim.SigningBytes()

	var results []ValidatorResult

	// Three registered validators with valid signatures. ConsensusAddress is left
	// empty so the attach uses the account-address fallback path.
	for i := 0; i < 3; i++ {
		w, _ := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
		addr := sdk.AccAddress([]byte(fmt.Sprintf("attach-valid-%02d", i))).String()
		if err := k.RegisterValidatorHybridKey(ctx, addr, w.HybridPublicKey()); err != nil {
			t.Fatal(err)
		}
		sig, _ := w.SignHybrid(msg)
		results = append(results, ValidatorResult{ValidatorAddress: addr, SealClaimSignature: sig})
	}

	// An UNREGISTERED validator with an otherwise-valid signature (must be dropped).
	wU, _ := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	sigU, _ := wU.SignHybrid(msg)
	results = append(results, ValidatorResult{
		ValidatorAddress:   sdk.AccAddress([]byte("attach-unregistered")).String(),
		SealClaimSignature: sigU,
	})

	// A REGISTERED validator whose signature is over a different claim (must be dropped).
	wB, _ := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	addrB := sdk.AccAddress([]byte("attach-badsig")).String()
	if err := k.RegisterValidatorHybridKey(ctx, addrB, wB.HybridPublicKey()); err != nil {
		t.Fatal(err)
	}
	otherClaim := claim
	otherClaim.OutputCommitment = bytes.Repeat([]byte{0x99}, 32)
	badSig, _ := wB.SignHybrid(otherClaim.SigningBytes())
	results = append(results, ValidatorResult{ValidatorAddress: addrB, SealClaimSignature: badSig})

	const sealID = "seal-attach-1"
	k.AttachSealQuorumSignatures(ctx, sealID, claim, results, time.Unix(0, 0))

	stored, err := k.GetSealQuorumSignatures(ctx, sealID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 3 {
		t.Fatalf("expected 3 stored signatures (valid+registered only), got %d", len(stored))
	}
	for _, s := range stored {
		if s.SignerType != sealtypes.SealSignerTypeValidator || s.Algorithm != sealtypes.HybridSignatureAlgorithm {
			t.Fatalf("unexpected signer metadata: %+v", s)
		}
		if ok, err := pqc.VerifyHybrid(s.PublicKey, msg, s.Signature); err != nil || !ok {
			t.Fatalf("stored signature failed to verify: ok=%v err=%v", ok, err)
		}
	}

	// Unknown seal id returns no signatures (and no error).
	none, err := k.GetSealQuorumSignatures(ctx, "no-such-seal")
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("expected no signatures for unknown seal, got %d", len(none))
	}
}

// TestAttachSealQuorumSignatures_ConsensusResolution proves the live-path
// resolution: a ValidatorResult carrying only the consensus address is resolved
// through staking (consensus addr -> operator -> account) to find the hybrid key
// registered under the operator's account address.
func TestAttachSealQuorumSignatures_ConsensusResolution(t *testing.T) {
	op := make([]byte, 20)
	copy(op, []byte("operator-account-20b"))
	consBytes := make([]byte, 20)
	copy(consBytes, []byte("consensus-addr-20byt"))

	valoper := sdk.ValAddress(op).String()
	account := sdk.AccAddress(op).String()
	consAddr := sdk.ConsAddress(consBytes)

	// Staking maps the consensus address back to the validator operator.
	sk := registryStakingKeeper{
		byConsAddr: map[string]stakingtypes.Validator{
			consAddr.String(): {OperatorAddress: valoper},
		},
	}
	k, ctx := newRegistryTestKeeperWithStaking(t, sk)

	// The hybrid key is registered under the operator's ACCOUNT address.
	w, err := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.RegisterValidatorHybridKey(ctx, account, w.HybridPublicKey()); err != nil {
		t.Fatal(err)
	}

	claim := sealtypes.SealClaim{
		ChainID:          "aethelred-test-1",
		JobID:            "job-resolve-1",
		ModelCommitment:  bytes.Repeat([]byte{0x11}, 32),
		InputCommitment:  bytes.Repeat([]byte{0x22}, 32),
		OutputCommitment: bytes.Repeat([]byte{0x33}, 32),
	}
	sig, err := w.SignHybrid(claim.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}

	// The result carries ONLY the consensus address — no account address — so the
	// attach must resolve via staking to find the key.
	results := []ValidatorResult{{
		ConsensusAddress:   consAddr.String(),
		SealClaimSignature: sig,
	}}

	const sealID = "seal-resolve-1"
	k.AttachSealQuorumSignatures(ctx, sealID, claim, results, time.Unix(0, 0))

	stored, err := k.GetSealQuorumSignatures(ctx, sealID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored signature via consensus resolution, got %d", len(stored))
	}
	if stored[0].SignerAddress != account {
		t.Fatalf("stored under %q, want resolved account %q", stored[0].SignerAddress, account)
	}
	if ok, err := pqc.VerifyHybrid(stored[0].PublicKey, claim.SigningBytes(), stored[0].Signature); err != nil || !ok {
		t.Fatalf("stored signature failed verification: ok=%v err=%v", ok, err)
	}
}
