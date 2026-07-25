package keeper_test

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

func chainSchedulerValidator(seed byte, power int64) stakingtypes.Validator {
	operator := bytes.Repeat([]byte{seed}, 20)
	return stakingtypes.Validator{
		OperatorAddress: sdk.ValAddress(operator).String(),
		Status:          stakingtypes.Bonded,
		Tokens:          sdkmath.NewInt(power * sdk.DefaultPowerReduction.Int64()),
	}
}

func chainSchedulerAccountAddress(t *testing.T, validator stakingtypes.Validator) string {
	t.Helper()
	operator, err := sdk.ValAddressFromBech32(validator.GetOperator())
	require.NoError(t, err)
	return sdk.AccAddress(operator).String()
}

func seedChainSchedulerJob(
	t *testing.T,
	k keeper.Keeper,
	ctx sdk.Context,
	id string,
	proofType types.ProofType,
) *types.ComputeJob {
	t.Helper()
	modelHash := sha256.Sum256([]byte("chain-scheduler-model"))
	if !k.IsModelRegistered(ctx, modelHash[:]) {
		require.NoError(t, k.RegisterModel(ctx, &types.RegisteredModel{
			ModelHash:    modelHash[:],
			ModelId:      "chain-scheduler-model",
			Name:         "Chain Scheduler Model",
			Version:      "1.0.0",
			Architecture: "test",
			Owner:        sdk.AccAddress(bytes.Repeat([]byte{0x55}, 20)).String(),
			RegisteredAt: nil,
			IsActive:     true,
		}))
	}
	inputHash := sha256.Sum256([]byte("input-" + id))
	job := types.NewComputeJobWithBlockTime(
		modelHash[:],
		inputHash[:],
		sdk.AccAddress(bytes.Repeat([]byte{0x66}, 20)).String(),
		proofType,
		"chain_scheduler_test",
		sdk.NewInt64Coin("uaethel", 1_000),
		ctx.BlockHeight(),
		ctx.BlockTime(),
	)
	job.Id = id
	job.InputDataUri = "https://inputs.example.com/" + id + ".bin"
	job.Fee = nil
	require.NoError(t, k.SubmitJob(ctx, job))
	return job
}

func TestScheduleChainBacked_PersistsAllActiveEligibleAssignments(t *testing.T) {
	validators := []stakingtypes.Validator{
		chainSchedulerValidator(0x11, 300_000),
		chainSchedulerValidator(0x22, 300_000),
		chainSchedulerValidator(0x33, 400_000),
	}
	k, ctx := newCommitteeTestKeeper(t, validators)
	params, err := k.GetParams(ctx)
	require.NoError(t, err)
	params.MinValidators = 3
	params.MaxJobsPerBlock = 10
	params.ConsensusThreshold = 67
	require.NoError(t, k.SetParams(ctx, params))

	expectedAddresses := make([]string, 0, len(validators))
	for _, validator := range validators {
		address := chainSchedulerAccountAddress(t, validator)
		expectedAddresses = append(expectedAddresses, address)
		require.NoError(t, k.ValidatorCapabilities.Set(ctx, address, types.ValidatorCapability{
			Address:           address,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 1,
			IsOnline:          true,
			ReputationScore:   80,
		}))
	}
	sort.Strings(expectedAddresses)
	job := seedChainSchedulerJob(t, k, ctx, "chain-job-1", types.ProofTypeTEE)

	scheduler := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	selected, err := scheduler.ScheduleChainBacked(ctx)
	require.NoError(t, err)
	require.Len(t, selected, 1)

	stored, err := k.GetJob(ctx, job.Id)
	require.NoError(t, err)
	require.Equal(t, types.JobStatusProcessing, stored.Status)
	require.Equal(t, ctx.BlockTime(), stored.UpdatedAt.AsTime())
	assigned, err := keeper.AssignedValidators(stored)
	require.NoError(t, err)
	require.Equal(t, expectedAddresses, assigned)

	for _, address := range expectedAddresses {
		jobs, err := k.GetAssignedProcessingJobs(ctx, address)
		require.NoError(t, err)
		require.Len(t, jobs, 1)
		require.Equal(t, job.Id, jobs[0].Id)
	}
}

func TestScheduleChainBacked_EmptyValidatorSetDoesNotHaltEmptyChain(t *testing.T) {
	k, ctx := newCommitteeTestKeeper(t, nil)
	scheduler := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	selected, err := scheduler.ScheduleChainBacked(ctx)
	require.NoError(t, err)
	require.Empty(t, selected)
}

func TestScheduleChainBacked_UsesPreEndBlockValidatorPowerSnapshot(t *testing.T) {
	validators := []stakingtypes.Validator{
		chainSchedulerValidator(0x31, 400_000),
		chainSchedulerValidator(0x32, 300_000),
		chainSchedulerValidator(0x33, 300_000),
		// Present in staking state for the update returned at H, but absent
		// from LastValidatorPower and therefore not a voter until H+2.
		chainSchedulerValidator(0x34, 500_000),
	}
	lastPowers := make(map[string]int64, 3)
	for _, validator := range validators[:3] {
		operator, err := sdk.ValAddressFromBech32(validator.GetOperator())
		require.NoError(t, err)
		lastPowers[operator.String()] = validator.GetConsensusPower(sdk.DefaultPowerReduction)
	}
	k, ctx := newCommitteeTestKeeperWithPowerSnapshot(t, validators, lastPowers)
	params, err := k.GetParams(ctx)
	require.NoError(t, err)
	params.MinValidators = 3
	params.ConsensusThreshold = 67
	require.NoError(t, k.SetParams(ctx, params))

	expected := make([]string, 0, 3)
	for i, validator := range validators {
		address := chainSchedulerAccountAddress(t, validator)
		if i < 3 {
			expected = append(expected, address)
		}
		require.NoError(t, k.ValidatorCapabilities.Set(ctx, address, types.ValidatorCapability{
			Address:           address,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 1,
			IsOnline:          true,
		}))
	}
	sort.Strings(expected)
	job := seedChainSchedulerJob(t, k, ctx, "validator-transition-job", types.ProofTypeTEE)

	scheduler := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	selected, err := scheduler.ScheduleChainBacked(ctx)
	require.NoError(t, err)
	require.Len(t, selected, 1)
	stored, err := k.GetJob(ctx, job.Id)
	require.NoError(t, err)
	assigned, err := keeper.AssignedValidators(stored)
	require.NoError(t, err)
	require.Equal(t, expected, assigned)
	require.NotContains(t, assigned, chainSchedulerAccountAddress(t, validators[3]))
}

func TestScheduleChainBacked_RestartRebuildsCapacityFromState(t *testing.T) {
	validators := []stakingtypes.Validator{
		chainSchedulerValidator(0x41, 400_000),
		chainSchedulerValidator(0x42, 300_000),
		chainSchedulerValidator(0x43, 300_000),
	}
	k, ctx := newCommitteeTestKeeper(t, validators)
	params, err := k.GetParams(ctx)
	require.NoError(t, err)
	params.MinValidators = 3
	params.MaxJobsPerBlock = 1
	params.ConsensusThreshold = 67
	require.NoError(t, k.SetParams(ctx, params))

	for _, validator := range validators {
		address := chainSchedulerAccountAddress(t, validator)
		require.NoError(t, k.ValidatorCapabilities.Set(ctx, address, types.ValidatorCapability{
			Address:           address,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 1,
			IsOnline:          true,
		}))
	}
	first := seedChainSchedulerJob(t, k, ctx, "restart-job-1", types.ProofTypeTEE)
	_ = seedChainSchedulerJob(t, k, ctx, "restart-job-2", types.ProofTypeTEE)

	schedulerA := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	selected, err := schedulerA.ScheduleChainBacked(ctx)
	require.NoError(t, err)
	require.Len(t, selected, 1)
	require.Equal(t, first.Id, selected[0].Id)

	// A fresh process-local scheduler must derive occupied slots from the
	// persisted Processing assignment and leave the second job Pending.
	schedulerB := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	selected, err = schedulerB.ScheduleChainBacked(ctx.WithBlockHeight(ctx.BlockHeight() + 1))
	require.NoError(t, err)
	require.Empty(t, selected)

	second, err := k.GetJob(ctx, "restart-job-2")
	require.NoError(t, err)
	require.Equal(t, types.JobStatusPending, second.Status)
}

func TestScheduleChainBacked_InsufficientEligiblePowerLeavesPending(t *testing.T) {
	validators := []stakingtypes.Validator{
		chainSchedulerValidator(0x71, 700_000),
		chainSchedulerValidator(0x72, 200_000),
		chainSchedulerValidator(0x73, 100_000),
	}
	k, ctx := newCommitteeTestKeeper(t, validators)
	params, err := k.GetParams(ctx)
	require.NoError(t, err)
	params.MinValidators = 2
	params.ConsensusThreshold = 67
	require.NoError(t, k.SetParams(ctx, params))

	// Only the two low-power validators are proof-capable. Their combined 30%
	// cannot satisfy the full-commit 67% aggregation denominator.
	for _, validator := range validators[1:] {
		address := chainSchedulerAccountAddress(t, validator)
		require.NoError(t, k.ValidatorCapabilities.Set(ctx, address, types.ValidatorCapability{
			Address:           address,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 1,
			IsOnline:          true,
		}))
	}
	job := seedChainSchedulerJob(t, k, ctx, "power-job", types.ProofTypeTEE)

	scheduler := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	selected, err := scheduler.ScheduleChainBacked(ctx)
	require.NoError(t, err)
	require.Empty(t, selected)
	stored, err := k.GetJob(ctx, job.Id)
	require.NoError(t, err)
	require.Equal(t, types.JobStatusPending, stored.Status)
}

func TestDeterministicJobTransitionsUseBlockTime(t *testing.T) {
	blockTime := time.Date(2026, 7, 25, 8, 30, 0, 123, time.UTC)
	job := &types.ComputeJob{Status: types.JobStatusPending}
	require.NoError(t, job.MarkProcessingAt(blockTime))
	require.Equal(t, blockTime, job.UpdatedAt.AsTime())
	require.NoError(t, job.RequeueForRetryAt(blockTime.Add(time.Second)))
	require.Equal(t, blockTime.Add(time.Second), job.UpdatedAt.AsTime())
}
