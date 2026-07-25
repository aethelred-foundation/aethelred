package pouw_test

import (
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
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw"
	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// setupAppModule creates a test AppModule with in-memory keeper
func setupAppModule(t *testing.T) (*pouw.AppModule, *keeper.Keeper, sdk.Context, codec.Codec) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  1,
		Time:    time.Now().UTC(),
	}
	ctx := sdk.NewContext(cms, header, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	types.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)

	var storeService store.KVStoreService = runtime.NewKVStoreService(storeKey)
	sb := collections.NewSchemaBuilder(storeService)

	// Manually construct keeper since we don't have all external dependencies mocks easily valid
	// Check keeper.NewKeeper structure. It needs mocks.
	// Since we are checking module wiring, let's construct it properly.

	// We use a simplified keeper construction similar to newTestKeeperFromStore
	k := keeper.Keeper{
		Jobs:                  collections.NewMap(sb, collections.NewPrefix(types.JobKeyPrefix), "jobs", collections.StringKey, codec.CollValue[types.ComputeJob](cdc)),
		PendingJobs:           collections.NewMap(sb, collections.NewPrefix(types.PendingJobKeyPrefix), "pending_jobs", collections.StringKey, codec.CollValue[types.ComputeJob](cdc)),
		RegisteredModels:      collections.NewMap(sb, collections.NewPrefix(types.ModelRegistryKeyPrefix), "registered_models", collections.StringKey, codec.CollValue[types.RegisteredModel](cdc)),
		ValidatorStats:        collections.NewMap(sb, collections.NewPrefix(types.ValidatorStatsKeyPrefix), "validator_stats", collections.StringKey, codec.CollValue[types.ValidatorStats](cdc)),
		ValidatorCapabilities: collections.NewMap(sb, collections.NewPrefix(types.ValidatorCapabilitiesKeyPrefix), "validator_capabilities", collections.StringKey, codec.CollValue[types.ValidatorCapability](cdc)),
		JobCount:              collections.NewItem(sb, collections.NewPrefix(types.JobCountKey), "job_count", collections.Uint64Value),
		Params:                collections.NewItem(sb, collections.NewPrefix(types.ParamsKey), "params", codec.CollValue[types.Params](cdc)),
	}

	appModule := pouw.NewAppModule(cdc, &k)

	// Initialize params
	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))

	return appModule, &k, ctx, cdc
}

func TestAppModule_Lifecycle(t *testing.T) {
	am, _, ctx, cdc := setupAppModule(t)

	// 1. Export default genesis
	defaultGenesis := am.DefaultGenesis(cdc)
	require.NotNil(t, defaultGenesis)

	// 2. Validate default genesis
	err := am.ValidateGenesis(cdc, nil, defaultGenesis)
	require.NoError(t, err)

	// 3. InitGenesis with some state
	genesisState := types.DefaultGenesis()
	genesisState.Params.MinValidators = 5
	genesisState.Jobs = []*types.ComputeJob{
		{
			Id:          "job-1",
			RequestedBy: "addr1",
			Status:      types.JobStatusPending,
		},
	}

	bz := cdc.MustMarshalJSON(genesisState)
	am.InitGenesis(ctx, cdc, bz)

	// 4. Verify state was imported (via ExportGenesis)
	exportedJSON := am.ExportGenesis(ctx, cdc)

	var exportedGenesis types.GenesisState
	err = cdc.UnmarshalJSON(exportedJSON, &exportedGenesis)
	require.NoError(t, err)

	require.Equal(t, int64(5), exportedGenesis.Params.MinValidators)
	require.Len(t, exportedGenesis.Jobs, 1)
	require.Equal(t, "job-1", exportedGenesis.Jobs[0].Id)
}

func TestAppModule_EndBlockAppliesDeterministicJobTimeouts(t *testing.T) {
	am, k, ctx, _ := setupAppModule(t)
	params, err := k.GetParams(ctx)
	require.NoError(t, err)
	params.JobTimeoutBlocks = 10
	require.NoError(t, k.SetParams(ctx, params))

	for _, job := range []types.ComputeJob{
		{Id: "pending-timeout", Status: types.JobStatusPending, BlockHeight: 1},
		{Id: "processing-timeout", Status: types.JobStatusProcessing, BlockHeight: 1},
	} {
		require.NoError(t, k.Jobs.Set(ctx, job.Id, job))
		require.NoError(t, k.PendingJobs.Set(ctx, job.Id, job))
	}

	blockTime := time.Date(2026, 7, 25, 9, 30, 0, 0, time.UTC)
	endCtx := ctx.WithBlockHeight(12).WithBlockTime(blockTime)
	require.NoError(t, am.EndBlock(endCtx))

	pending, err := k.GetJob(endCtx, "pending-timeout")
	require.NoError(t, err)
	require.Equal(t, types.JobStatusExpired, pending.Status)
	require.Equal(t, blockTime, pending.UpdatedAt.AsTime())

	processing, err := k.GetJob(endCtx, "processing-timeout")
	require.NoError(t, err)
	require.Equal(t, types.JobStatusFailed, processing.Status)
	require.Equal(t, blockTime, processing.UpdatedAt.AsTime())

	hasPending, err := k.PendingJobs.Has(endCtx, pending.Id)
	require.NoError(t, err)
	require.False(t, hasPending)
	hasProcessing, err := k.PendingJobs.Has(endCtx, processing.Id)
	require.NoError(t, err)
	require.False(t, hasProcessing)
}
