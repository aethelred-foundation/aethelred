package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

func TestUpdateParamsRejectsLockedConsensusThresholdChange(t *testing.T) {
	k, ctx := newTestKeeper(t)

	current, err := k.GetParams(ctx)
	require.NoError(t, err)

	params := *current
	params.ConsensusThreshold = 80

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority: k.GetAuthority(),
		Params:    params,
	})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "locked parameter")
	require.Contains(t, err.Error(), "consensus_threshold")
}

func TestUpdateParamsRejectsLockedRequireTeeAttestationChange(t *testing.T) {
	k, ctx := newTestKeeper(t)

	current, err := k.GetParams(ctx)
	require.NoError(t, err)

	params := *current
	params.RequireTeeAttestation = false

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority:                k.GetAuthority(),
		Params:                   params,
		HasRequireTeeAttestation: true,
	})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "locked parameter")
	require.Contains(t, err.Error(), "require_tee_attestation")
}

func TestUpdateParamsRejectsLockedAllowedProofTypesChange(t *testing.T) {
	k, ctx := newTestKeeper(t)

	current, err := k.GetParams(ctx)
	require.NoError(t, err)

	params := *current
	params.AllowedProofTypes = []string{"hybrid"}

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority: k.GetAuthority(),
		Params:    params,
	})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "locked parameter")
	require.Contains(t, err.Error(), "allowed_proof_types")
}

func TestUpdateParamsAllowsOneWayDisableOfAllowSimulated(t *testing.T) {
	k, ctx := newTestKeeper(t)

	current, err := k.GetParams(ctx)
	require.NoError(t, err)
	current.AllowSimulated = true
	require.NoError(t, k.SetParams(ctx, current))

	params := *current
	params.AllowSimulated = false

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority:         k.GetAuthority(),
		Params:            params,
		HasAllowSimulated: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	updated, err := k.GetParams(ctx)
	require.NoError(t, err)
	require.False(t, updated.AllowSimulated)
}

func TestUpdateParamsAllowsMutableVerificationRewardChange(t *testing.T) {
	k, ctx := newTestKeeper(t)

	current, err := k.GetParams(ctx)
	require.NoError(t, err)

	params := *current
	params.VerificationReward = "200uaethel"

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority: k.GetAuthority(),
		Params:    params,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	updated, err := k.GetParams(ctx)
	require.NoError(t, err)
	require.Equal(t, "200uaethel", updated.VerificationReward)
}

func TestUpdateParamsRejectsLockedChangeEvenWhenProposalValidatorAllowsIt(t *testing.T) {
	k, ctx := newTestKeeper(t)

	proposal := keeper.ValidateParamChangeProposal(keeper.ParamChangeProposal{
		Field:    "consensus_threshold",
		OldValue: "67",
		NewValue: "80",
		Proposer: "gov-module",
	})
	require.True(t, proposal.Allowed)
	require.Equal(t, keeper.ParamLocked, proposal.LockStatus)

	current, err := k.GetParams(ctx)
	require.NoError(t, err)

	params := *current
	params.ConsensusThreshold = 80

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority: k.GetAuthority(),
		Params:    params,
	})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "elevated-governance execution path")
}
