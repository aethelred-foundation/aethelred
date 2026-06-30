package keeper

import (
	"bytes"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/crypto/pqc"
	"github.com/aethelred/aethelred/x/pouw/types"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

func TestQuerySealQuorum(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	qs := NewQueryServerImpl(k)
	goCtx := sdk.WrapSDKContext(ctx)

	claim := sealtypes.SealClaim{
		ChainID:          "aethelred-test-1",
		JobID:            "job-query-1",
		ModelCommitment:  bytes.Repeat([]byte{0x11}, 32),
		InputCommitment:  bytes.Repeat([]byte{0x22}, 32),
		OutputCommitment: bytes.Repeat([]byte{0x33}, 32),
	}

	w, err := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	addr := sdk.AccAddress([]byte("seal-query-validator")).String()
	sig, err := w.SignHybrid(claim.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	ss := sealtypes.NewValidatorSealSignature(addr, w.HybridPublicKey(), sig, time.Unix(0, 0))

	const sealID = "seal-query-1"
	if err := k.StoreSealQuorumSignatures(ctx, sealID, []sealtypes.SealSignature{ss}); err != nil {
		t.Fatal(err)
	}

	resp, err := qs.SealQuorum(goCtx, &types.QuerySealQuorumRequest{SealId: sealID})
	if err != nil {
		t.Fatal(err)
	}
	if resp.SignatureCount != 1 || len(resp.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got count=%d len=%d", resp.SignatureCount, len(resp.Signatures))
	}
	got := resp.Signatures[0]
	if got.SignerAddress != addr || got.Algorithm != sealtypes.HybridSignatureAlgorithm {
		t.Fatalf("unexpected signer metadata: %+v", got)
	}
	// The whole point: an offline party can verify the returned signature against
	// the seal claim using the returned public key.
	if ok, err := pqc.VerifyHybrid(got.PublicKey, claim.SigningBytes(), got.Signature); err != nil || !ok {
		t.Fatalf("offline verification failed: ok=%v err=%v", ok, err)
	}

	// Unknown seal returns an empty quorum, not an error.
	empty, err := qs.SealQuorum(goCtx, &types.QuerySealQuorumRequest{SealId: "no-such-seal"})
	if err != nil {
		t.Fatal(err)
	}
	if empty.SignatureCount != 0 || len(empty.Signatures) != 0 {
		t.Fatalf("expected empty quorum for unknown seal, got %d", empty.SignatureCount)
	}

	// Empty seal_id is rejected.
	if _, err := qs.SealQuorum(goCtx, &types.QuerySealQuorumRequest{SealId: ""}); err == nil {
		t.Fatal("expected error for empty seal_id")
	}
}
