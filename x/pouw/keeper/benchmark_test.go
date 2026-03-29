package keeper_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/store"
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

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// setupBenchKeeper creates a Keeper with in-memory stores suitable for benchmarks.
func setupBenchKeeper(b *testing.B) (keeper.Keeper, sdk.Context) {
	b.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	if err := cms.LoadLatestVersion(); err != nil {
		b.Fatalf("load store: %v", err)
	}

	header := tmproto.Header{
		ChainID: "aethelred-bench-1",
		Height:  100,
		Time:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	ctx := sdk.NewContext(cms, header, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)

	var storeService store.KVStoreService = runtime.NewKVStoreService(storeKey)
	sb := collections.NewSchemaBuilder(storeService)

	k := keeper.Keeper{
		Jobs: collections.NewMap(
			sb,
			collections.NewPrefix(types.JobKeyPrefix),
			"jobs",
			collections.StringKey,
			codec.CollValue[types.ComputeJob](cdc),
		),
		PendingJobs: collections.NewMap(
			sb,
			collections.NewPrefix(types.PendingJobKeyPrefix),
			"pending_jobs",
			collections.StringKey,
			codec.CollValue[types.ComputeJob](cdc),
		),
		RegisteredModels: collections.NewMap(
			sb,
			collections.NewPrefix(types.ModelRegistryKeyPrefix),
			"registered_models",
			collections.StringKey,
			codec.CollValue[types.RegisteredModel](cdc),
		),
		ValidatorStats: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorStatsKeyPrefix),
			"validator_stats",
			collections.StringKey,
			codec.CollValue[types.ValidatorStats](cdc),
		),
		ValidatorCapabilities: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorCapabilitiesKeyPrefix),
			"validator_capabilities",
			collections.StringKey,
			codec.CollValue[types.ValidatorCapability](cdc),
		),
		ValidatorPCR0Mappings: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorPCR0KeyPrefix),
			"validator_pcr0_mappings",
			collections.StringKey,
			collections.StringValue,
		),
		RegisteredPCR0Set: collections.NewKeySet(
			sb,
			collections.NewPrefix(types.RegisteredPCR0KeyPrefix),
			"registered_pcr0_set",
			collections.StringKey,
		),
		ValidatorMeasurements: collections.NewMap(
			sb,
			collections.NewPrefix(types.ValidatorMeasurementKeyPrefix),
			"validator_measurements",
			collections.StringKey,
			collections.StringValue,
		),
		RegisteredMeasurements: collections.NewKeySet(
			sb,
			collections.NewPrefix(types.RegisteredMeasurementKeyPrefix),
			"registered_measurements_set",
			collections.StringKey,
		),
		JobCount: collections.NewItem(
			sb,
			collections.NewPrefix(types.JobCountKey),
			"job_count",
			collections.Uint64Value,
		),
		Params: collections.NewItem(
			sb,
			collections.NewPrefix(types.ParamsKey),
			"params",
			codec.CollValue[types.Params](cdc),
		),
	}

	if err := k.SetParams(ctx, types.DefaultParams()); err != nil {
		b.Fatalf("set params: %v", err)
	}
	if err := k.JobCount.Set(ctx, 0); err != nil {
		b.Fatalf("set job count: %v", err)
	}

	return k, ctx
}

// BenchmarkSubmitJob benchmarks job submission through the message server.
func BenchmarkSubmitJob(b *testing.B) {
	k, ctx := setupBenchKeeper(b)
	msgServer := keeper.NewMsgServerImpl(k)
	wrapped := sdk.WrapSDKContext(ctx)

	modelHash := sha256.Sum256([]byte("bench-model"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inputHash := sha256.Sum256([]byte(fmt.Sprintf("bench-input-%d", i)))
		_, _ = msgServer.SubmitJob(wrapped, &types.MsgSubmitJob{
			Creator:   sdk.AccAddress(bytes.Repeat([]byte{0x01}, 20)).String(),
			ModelHash: modelHash[:],
			InputHash: inputHash[:],
			ProofType: types.ProofTypeTEE,
			Purpose:   "benchmark",
		})
	}
}

// BenchmarkAssignJob benchmarks assigning a job to a validator by transitioning
// its status from Pending to Processing and writing back to the store.
func BenchmarkAssignJob(b *testing.B) {
	k, ctx := setupBenchKeeper(b)

	// Pre-seed jobs to assign.
	jobs := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		modelHash := sha256.Sum256([]byte(fmt.Sprintf("assign-model-%d", i)))
		inputHash := sha256.Sum256([]byte(fmt.Sprintf("assign-input-%d", i)))
		job := types.ComputeJob{
			Id:          fmt.Sprintf("assign-job-%d", i),
			ModelHash:   modelHash[:],
			InputHash:   inputHash[:],
			RequestedBy: "requester",
			ProofType:   types.ProofTypeTEE,
			Purpose:     "benchmark",
			Status:      types.JobStatusPending,
		}
		if err := k.Jobs.Set(ctx, job.Id, job); err != nil {
			b.Fatalf("seed job %d: %v", i, err)
		}
		jobs[i] = job.Id
	}

	validator := sdk.AccAddress(bytes.Repeat([]byte{0x02}, 20)).String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		job, err := k.Jobs.Get(ctx, jobs[i])
		if err != nil {
			b.Fatalf("get job %d: %v", i, err)
		}
		job.Status = types.JobStatusProcessing
		if job.Metadata == nil {
			job.Metadata = make(map[string]string)
		}
		job.Metadata["assigned_to"] = validator
		if err := k.Jobs.Set(ctx, job.Id, job); err != nil {
			b.Fatalf("assign job %d: %v", i, err)
		}
	}
}

// BenchmarkCompleteJob benchmarks completing a processing job by transitioning
// its status to Completed and writing the result back to the store.
func BenchmarkCompleteJob(b *testing.B) {
	k, ctx := setupBenchKeeper(b)

	// Pre-seed processing jobs to complete.
	jobs := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		modelHash := sha256.Sum256([]byte(fmt.Sprintf("complete-model-%d", i)))
		inputHash := sha256.Sum256([]byte(fmt.Sprintf("complete-input-%d", i)))
		job := types.ComputeJob{
			Id:          fmt.Sprintf("complete-job-%d", i),
			ModelHash:   modelHash[:],
			InputHash:   inputHash[:],
			RequestedBy: "requester",
			ProofType:   types.ProofTypeTEE,
			Purpose:     "benchmark",
			Status:      types.JobStatusProcessing,
		}
		if err := k.Jobs.Set(ctx, job.Id, job); err != nil {
			b.Fatalf("seed job %d: %v", i, err)
		}
		jobs[i] = job.Id
	}

	outputHash := sha256.Sum256([]byte("bench-output"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		job, err := k.Jobs.Get(ctx, jobs[i])
		if err != nil {
			b.Fatalf("get job %d: %v", i, err)
		}
		job.Status = types.JobStatusCompleted
		job.OutputHash = outputHash[:]
		if err := k.Jobs.Set(ctx, job.Id, job); err != nil {
			b.Fatalf("complete job %d: %v", i, err)
		}
	}
}
