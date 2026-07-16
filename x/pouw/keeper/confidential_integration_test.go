package keeper_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"cosmossdk.io/log"
	storemetrics "cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"
)

// newSealIntegrationKeeper builds a pouw keeper wired to a REAL (in-memory)
// seal keeper so CompleteJob actually mints and stores a Digital Seal that can
// be read back — the integration surface for the CEAP attestation binding.
func newSealIntegrationKeeper(t *testing.T, allowSimulated bool) (keeper.Keeper, sealkeeper.Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	sealStoreKey := storetypes.NewKVStoreKey("seal")
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	cms.MountStoreWithDB(sealStoreKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	ctx := sdk.NewContext(cms, tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  100,
		Time:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)

	// Real seal keeper backed by its own mounted store (collections path).
	sk := sealkeeper.NewKeeper(cdc, runtime.NewKVStoreService(sealStoreKey), "")

	k := keeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(storeKey),
		nil, // staking not needed for these paths
		nil, // bank not needed (reward path is stake-gated and best-effort)
		sk,
		verifykeeper.Keeper{},
		"",
	)

	params := types.DefaultParams()
	params.AllowSimulated = allowSimulated
	require.NoError(t, k.SetParams(ctx, params))
	require.NoError(t, k.JobCount.Set(ctx, 0))

	return k, sk, ctx
}

// integrationRequester is a valid bech32 account address; CreateSeal validates
// the requester, so a placeholder string would be rejected before we can assert
// on the bound attestation.
var integrationRequester = sdk.AccAddress([]byte("integration-req-addr")).String()

func processingJob(id string, policy *types.ConfidentialityPolicy) types.ComputeJob {
	modelHash := sha256.Sum256([]byte("model-" + id))
	inputHash := sha256.Sum256([]byte("input-" + id))
	return types.ComputeJob{
		Id:                    id,
		ModelHash:             modelHash[:],
		InputHash:             inputHash[:],
		RequestedBy:           integrationRequester,
		ProofType:             types.ProofTypeTEE,
		Purpose:               "integration",
		Status:                types.JobStatusProcessing,
		ConfidentialityPolicy: policy,
	}
}

func teeVerificationResults() []types.VerificationResult {
	return []types.VerificationResult{
		{ValidatorAddress: "val1", AttestationType: "tee", TeePlatform: "amd-sev-snp", Success: true},
	}
}

// TestCompleteJob_BindsConfidentialityAttestation proves the on-chain half of
// CEAP: completing a job mints a seal whose Confidentiality attestation reflects
// the achieved backend/verification/platform and the deployment trust basis.
func TestCompleteJob_BindsConfidentialityAttestation(t *testing.T) {
	k, sk, ctx := newSealIntegrationKeeper(t, true /* simulated => test_root */)

	job := processingJob("job-bind", &types.ConfidentialityPolicy{
		AllowedBackends:  []string{"tee"},
		MinVerification:  "tee-attested",
		AllowedPlatforms: []string{"amd-sev-snp"},
	})
	require.NoError(t, k.Jobs.Set(ctx, job.Id, job))

	output := sha256.Sum256([]byte("out-bind"))
	require.NoError(t, k.CompleteJob(ctx, job.Id, output[:], teeVerificationResults()))

	seal, err := sk.GetSealByJob(ctx, job.Id)
	require.NoError(t, err)
	require.NotNil(t, seal)
	require.NotNil(t, seal.Confidentiality, "seal must carry the CEAP attestation")

	c := seal.Confidentiality
	require.Equal(t, "tee", c.Backend)
	require.Equal(t, "tee-attested", c.Verification)
	require.Equal(t, "amd-sev-snp", c.Platform)
	require.Equal(t, "test_root", c.TrustBasis, "simulated chain must report test_root")
	require.True(t, c.DataSealed)
	require.Equal(t, "val1", c.Worker)
	require.NotEmpty(t, c.PolicyHash)

	// The attestation is folded into the tamper-evident seal ID.
	require.Equal(t, seal.Id, seal.GenerateID(), "seal ID must cover the bound attestation")
}

// TestCompleteJob_RejectsPolicyViolation proves enforcement: a job whose achieved
// confidentiality cannot satisfy its policy is NOT sealed.
func TestCompleteJob_RejectsPolicyViolation(t *testing.T) {
	// Production chain (vendor_root) but the policy demands FHE, which the TEE
	// computation cannot provide — must reject with no seal.
	k, sk, ctx := newSealIntegrationKeeper(t, false)

	job := processingJob("job-reject", &types.ConfidentialityPolicy{
		AllowedBackends: []string{"fhe"},
	})
	require.NoError(t, k.Jobs.Set(ctx, job.Id, job))

	output := sha256.Sum256([]byte("out-reject"))
	err := k.CompleteJob(ctx, job.Id, output[:], teeVerificationResults())
	require.Error(t, err, "policy-violating computation must not complete")
	require.Contains(t, err.Error(), "confidentiality policy not satisfied")

	// No seal was minted.
	seal, err := sk.GetSealByJob(ctx, job.Id)
	require.True(t, err != nil || seal == nil, "no seal must exist for a rejected job")

	// The job was not transitioned to completed.
	stored, err := k.GetJob(ctx, job.Id)
	require.NoError(t, err)
	require.NotEqual(t, types.JobStatusCompleted, stored.Status)
}

// TestCompleteJob_VendorRootPolicyRejectedOnSimulatedChain proves the trust-basis
// gate: a vendor-root policy cannot be satisfied by a simulated deployment.
func TestCompleteJob_VendorRootPolicyRejectedOnSimulatedChain(t *testing.T) {
	k, sk, ctx := newSealIntegrationKeeper(t, true /* simulated */)

	job := processingJob("job-vendor", &types.ConfidentialityPolicy{
		AllowedBackends:   []string{"tee"},
		RequireVendorRoot: true,
	})
	require.NoError(t, k.Jobs.Set(ctx, job.Id, job))

	output := sha256.Sum256([]byte("out-vendor"))
	err := k.CompleteJob(ctx, job.Id, output[:], teeVerificationResults())
	require.Error(t, err)

	seal, err := sk.GetSealByJob(ctx, job.Id)
	require.True(t, err != nil || seal == nil)
}

// TestCompleteJob_NoPolicyStillRecordsAttestation proves backward compatibility:
// a policy-less job seals as before, and the seal still records the achieved
// (non-confidential) posture for the audit trail.
func TestCompleteJob_NoPolicyStillRecordsAttestation(t *testing.T) {
	k, sk, ctx := newSealIntegrationKeeper(t, false)

	job := processingJob("job-nopolicy", nil)
	require.NoError(t, k.Jobs.Set(ctx, job.Id, job))

	// A zkml-only result: correctness proven, but no confidentiality backend.
	results := []types.VerificationResult{
		{ValidatorAddress: "valZ", AttestationType: "zkml", Success: true},
	}
	output := sha256.Sum256([]byte("out-nopolicy"))
	require.NoError(t, k.CompleteJob(ctx, job.Id, output[:], results))

	seal, err := sk.GetSealByJob(ctx, job.Id)
	require.NoError(t, err)
	require.NotNil(t, seal.Confidentiality)
	require.Equal(t, "none", seal.Confidentiality.Backend)
	require.Equal(t, "zkml", seal.Confidentiality.Verification)
	require.False(t, seal.Confidentiality.DataSealed)
	require.Equal(t, "vendor_root", seal.Confidentiality.TrustBasis)
}

// TestSubmitJob_PropagatesConfidentialityPolicy proves the submit path carries
// the submitter's ConfidentialityPolicy onto the stored job, so it is available
// for enforcement at completion time.
func TestSubmitJob_PropagatesConfidentialityPolicy(t *testing.T) {
	k, _, ctx := newSealIntegrationKeeper(t, false)
	ms := keeper.NewMsgServerImpl(k)

	modelHash := sha256.Sum256([]byte("m-submit"))
	inputHash := sha256.Sum256([]byte("i-submit"))

	// A job can only be submitted against a registered model.
	_, err := ms.RegisterModel(ctx, types.NewMsgRegisterModel(
		integrationRequester, modelHash[:], "m1", "M1", "", "v1", "arch"))
	require.NoError(t, err)

	msg := types.NewMsgSubmitJob(integrationRequester, modelHash[:], inputHash[:], types.ProofTypeTEE, "purpose")
	msg.ConfidentialityPolicy = &types.ConfidentialityPolicy{
		AllowedBackends:   []string{"tee"},
		MinVerification:   "zkml",
		RequireVendorRoot: true,
	}

	resp, err := ms.SubmitJob(ctx, msg)
	require.NoError(t, err)
	require.NotEmpty(t, resp.JobId)

	stored, err := k.GetJob(ctx, resp.JobId)
	require.NoError(t, err)
	require.NotNil(t, stored.ConfidentialityPolicy)
	require.Equal(t, []string{"tee"}, stored.ConfidentialityPolicy.AllowedBackends)
	require.Equal(t, "zkml", stored.ConfidentialityPolicy.MinVerification)
	require.True(t, stored.ConfidentialityPolicy.RequireVendorRoot)
}
