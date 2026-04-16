package pouw_test

import (
	"encoding/json"
	"testing"
	"time"

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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/x/pouw"
	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"
)

// setupAppModule creates a test AppModule with in-memory keeper
func setupAppModule(t *testing.T) (*pouw.AppModule, sdk.Context, codec.Codec) {
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
	k := keeper.NewKeeper(
		cdc,
		storeService,
		nil,
		nil,
		sealkeeper.Keeper{},
		verifykeeper.Keeper{},
		"gov-authority",
	)

	appModule := pouw.NewAppModule(cdc, &k)

	// Initialize params
	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))

	return appModule, ctx, cdc
}

func TestAppModule_Lifecycle(t *testing.T) {
	am, ctx, cdc := setupAppModule(t)

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

	bz, err := json.Marshal(types.NewManagedGenesisState(genesisState, nil))
	require.NoError(t, err)
	am.InitGenesis(ctx, cdc, bz)

	// 4. Verify state was imported (via ExportGenesis)
	exportedJSON := am.ExportGenesis(ctx, cdc)

	var exportedGenesis types.ManagedGenesisState
	err = json.Unmarshal(exportedJSON, &exportedGenesis)
	require.NoError(t, err)

	require.Equal(t, int64(5), exportedGenesis.Params.MinValidators)
	require.Len(t, exportedGenesis.Jobs, 1)
	require.Equal(t, "job-1", exportedGenesis.Jobs[0].Id)
}

func TestAppModule_ManagedGenesisTrustRegistryRoundTrip(t *testing.T) {
	am, ctx, cdc := setupAppModule(t)

	genesisState := types.DefaultManagedGenesis()
	genesisState.EnterpriseAuditTrustRegistry = &types.EnterpriseAuditTrustRegistryGenesis{
		Version:              "2026.04.14",
		Source:               "genesis_registry",
		UpdatedAt:            "2026-04-14T12:00:00Z",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []types.EnterpriseAuditPolicySignerTrustEntryGenesis{{
			DID:           "did:aethelred:policy-gateway-1",
			PublicKeyHex:  "025f3c7a3bb5d7584ff6d09b13d616f6c9778f4d3146ef4740db9f9c0fdb8724e3",
			Status:        types.EnterpriseAuditTrustRegistryEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
		AllowedSponsors: []types.EnterpriseAuditSponsorTrustEntryGenesis{{
			DID:           "did:aethelred:sponsor-bank",
			Status:        types.EnterpriseAuditTrustRegistryEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
	}

	bz, err := json.Marshal(genesisState)
	require.NoError(t, err)
	am.InitGenesis(ctx, cdc, bz)

	exportedJSON := am.ExportGenesis(ctx, cdc)
	var exported types.ManagedGenesisState
	err = json.Unmarshal(exportedJSON, &exported)
	require.NoError(t, err)
	require.NotNil(t, exported.EnterpriseAuditTrustRegistry)
	require.Equal(t, "2026.04.14", exported.EnterpriseAuditTrustRegistry.Version)
	require.Equal(t, "pouw_governance", exported.EnterpriseAuditTrustRegistry.Source)
	require.Equal(t, "genesis_init", exported.EnterpriseAuditTrustRegistry.Metadata["bootstrap_mode"])
}

func TestAppModule_LegacyGenesisJSONCompatibility(t *testing.T) {
	am, ctx, cdc := setupAppModule(t)

	legacyGenesis := &types.GenesisState{
		Jobs: []*types.ComputeJob{{
			Id:          "legacy-job-1",
			Status:      types.JobStatus_JOB_STATUS_PENDING,
			RequestedBy: "did:aethelred:legacy-creator",
			ModelHash:   []byte("legacy-model-hash"),
			InputHash:   []byte("legacy-input-hash"),
			ProofType:   types.ProofTypeTEE,
			CreatedAt:   timestamppb.New(time.Now().UTC()),
		}},
		RegisteredModels:      []*types.RegisteredModel{},
		ValidatorStats:        []*types.ValidatorStats{},
		ValidatorCapabilities: []*types.ValidatorCapability{},
		Params:                types.DefaultParams(),
		CurrentEpoch:          4,
		TotalUwu:              12,
	}

	bz, err := json.Marshal(legacyGenesis)
	require.NoError(t, err)
	am.InitGenesis(ctx, cdc, bz)

	exportedJSON := am.ExportGenesis(ctx, cdc)
	var exported types.ManagedGenesisState
	err = json.Unmarshal(exportedJSON, &exported)
	require.NoError(t, err)
	require.Len(t, exported.Jobs, 1)
	require.Equal(t, "legacy-job-1", exported.Jobs[0].Id)
	require.EqualValues(t, 4, exported.CurrentEpoch)
	require.EqualValues(t, 12, exported.TotalUwu)
	require.Nil(t, exported.EnterpriseAuditTrustRegistry)
}

func TestAppModuleBasic_ValidateGenesis_RejectsInvalidManagedTrustRegistry(t *testing.T) {
	_, _, cdc := setupAppModule(t)
	moduleBasic := pouw.AppModuleBasic{}

	invalidGenesis := types.DefaultManagedGenesis()
	invalidGenesis.EnterpriseAuditTrustRegistry = &types.EnterpriseAuditTrustRegistryGenesis{
		Version:              "2026.04.14",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []types.EnterpriseAuditPolicySignerTrustEntryGenesis{{
			DID:          "did:aethelred:bad-signer",
			PublicKeyHex: "deadbeef",
		}},
	}

	bz, err := json.Marshal(invalidGenesis)
	require.NoError(t, err)
	err = moduleBasic.ValidateGenesis(cdc, nil, bz)
	require.ErrorContains(t, err, "public key is invalid")
}
