package keeper

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/aethelred/aethelred/crypto/pqc"
	"github.com/aethelred/aethelred/x/pouw/types"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// TestSealQuorumEndToEnd exercises the whole validator-quorum pipeline the way
// the production path does, minus the seal minting itself:
//
//	ed25519 consensus key -> derived hybrid wallet (as the node does)
//	-> registration -> sign the seal claim in a vote extension
//	-> aggregate into ValidatorResults (consensus address)
//	-> AttachSealQuorumSignatures (consensus->operator->account resolution)
//	-> GetSealQuorumSignatures / Query.SealQuorum
//	-> power-weighted VerifyJobSealQuorum (offline verification).
func TestSealQuorumEndToEnd(t *testing.T) {
	const n = 4
	type val struct {
		wallet   *pqc.DualKeyWallet
		account  string
		consAddr sdk.ConsAddress
		power    int64
	}

	vals := make([]val, n)
	byConsAddr := map[string]stakingtypes.Validator{}
	for i := 0; i < n; i++ {
		// Hybrid key derived from the validator's ed25519 consensus key seed,
		// exactly as app.SetValidatorPrivateKey does.
		edSeed := make([]byte, ed25519.SeedSize)
		edSeed[0] = byte(i + 1)
		priv := ed25519.NewKeyFromSeed(edSeed)
		w, err := pqc.NewDualKeyWalletFromMasterSeed(priv.Seed(), pqc.DilithiumLevel3)
		if err != nil {
			t.Fatal(err)
		}

		opBytes := make([]byte, 20)
		copy(opBytes, []byte(fmt.Sprintf("operator-account-%03d", i)))
		consBytes := make([]byte, 20)
		copy(consBytes, []byte(fmt.Sprintf("consensus-addr---%03d", i)))

		vals[i] = val{
			wallet:   w,
			account:  sdk.AccAddress(opBytes).String(),
			consAddr: sdk.ConsAddress(consBytes),
			power:    10,
		}
		byConsAddr[vals[i].consAddr.String()] = stakingtypes.Validator{
			OperatorAddress: sdk.ValAddress(opBytes).String(),
		}
	}

	k, ctx := newRegistryTestKeeperWithStaking(t, registryStakingKeeper{byConsAddr: byConsAddr})
	qs := NewQueryServerImpl(k)

	// Register every validator's hybrid key (could equally be genesis-seeded).
	for _, v := range vals {
		if err := k.RegisterValidatorHybridKey(ctx, v.account, v.wallet.HybridPublicKey()); err != nil {
			t.Fatal(err)
		}
	}

	claim := sealtypes.SealClaim{
		ChainID:          "aethelred-test-1",
		JobID:            "job-e2e-1",
		ModelCommitment:  []byte("model-commitment-32-bytes-padxx!"),
		InputCommitment:  []byte("input-commitment-32-bytes-padxx!"),
		OutputCommitment: []byte("output-commitment-32-bytes-pad!!"),
	}
	msg := claim.SigningBytes()

	// 3 of 4 validators sign (power 30 of 40; 2/3 threshold required = 27).
	var results []ValidatorResult
	for i := 0; i < 3; i++ {
		sig, err := vals[i].wallet.SignHybrid(msg)
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, ValidatorResult{
			ConsensusAddress:   vals[i].consAddr.String(),
			SealClaimSignature: sig,
		})
	}

	const sealID = "seal-e2e-1"
	k.AttachSealQuorumSignatures(ctx, sealID, claim, results, time.Unix(0, 0))

	// Stored + queryable.
	resp, err := qs.SealQuorum(sdk.WrapSDKContext(ctx), &types.QuerySealQuorumRequest{SealId: sealID})
	if err != nil {
		t.Fatal(err)
	}
	if resp.SignatureCount != 3 {
		t.Fatalf("expected 3 quorum signatures, got %d", resp.SignatureCount)
	}

	// Power-weighted quorum verification reaches the 2/3 threshold.
	powerByAcct := map[string]int64{}
	for _, v := range vals {
		powerByAcct[v.account] = v.power
	}
	stored, err := k.GetSealQuorumSignatures(ctx, sealID)
	if err != nil {
		t.Fatal(err)
	}
	res, err := k.VerifyJobSealQuorum(ctx, claim, stored, powerByAcct, 67)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reached {
		t.Fatalf("quorum not reached: agreed=%d required=%d total=%d", res.AgreedPower, res.RequiredPower, res.TotalPower)
	}
	if res.AgreedPower != 30 {
		t.Fatalf("expected agreed power 30, got %d", res.AgreedPower)
	}
}
