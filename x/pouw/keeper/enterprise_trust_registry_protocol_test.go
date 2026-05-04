package keeper_test

import (
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

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"
)

func TestManagedGenesis_RoundTrip_WithEnterpriseAuditTrustRegistry(t *testing.T) {
	k, ctx := newGovernedProtocolKeeper(t, "gov-authority")

	genesis := types.DefaultManagedGenesis()
	genesis.EnterpriseAuditTrustRegistry = testEnterpriseAuditTrustRegistryGenesis()

	require.NoError(t, k.InitManagedGenesis(ctx, genesis))

	exported, err := k.ExportManagedGenesis(ctx)
	require.NoError(t, err)
	require.NotNil(t, exported.EnterpriseAuditTrustRegistry)
	require.Equal(t, "2026.04.14", exported.EnterpriseAuditTrustRegistry.Version)
	require.Equal(t, "pouw_governance", exported.EnterpriseAuditTrustRegistry.Source)
	require.Equal(t, "genesis_init", exported.EnterpriseAuditTrustRegistry.Metadata["bootstrap_mode"])

	records := k.AuditLogger().GetRecordsByCategory(keeper.AuditCategoryGovernance)
	require.NotEmpty(t, records)
	require.Equal(t, "enterprise_audit_trust_registry_updated", records[len(records)-1].Action)
	require.Equal(t, "pouw_genesis", records[len(records)-1].Details["requested_by"])
}

func TestGetModuleStatus_IncludesEnterpriseAuditTrustRegistry(t *testing.T) {
	k, ctx := newGovernedProtocolKeeper(t, "gov-authority")

	genesis := types.DefaultManagedGenesis()
	genesis.EnterpriseAuditTrustRegistry = testEnterpriseAuditTrustRegistryGenesis()
	require.NoError(t, k.InitManagedGenesis(ctx, genesis))

	status, err := k.GetModuleStatus(ctx)
	require.NoError(t, err)
	require.True(t, status.EnterpriseTrustRegistryConfigured)
	require.Equal(t, "2026.04.14", status.EnterpriseTrustRegistryVersion)
	require.Equal(t, "pouw_governance", status.EnterpriseTrustRegistrySource)
	require.Equal(t, 1, status.EnterpriseTrustPolicySignerCount)
	require.Equal(t, 1, status.EnterpriseTrustActiveSignerCount)
}

func TestPreUpgradeValidation_WarnsForNonGovernedEnterpriseAuditTrustRegistry(t *testing.T) {
	k, ctx := newGovernedProtocolKeeper(t, "gov-authority")
	require.NoError(t, k.SetEnterpriseAuditTrustRegistry(ctx, testEnterpriseAuditTrustRegistryKeeper("runtime_registry")))

	warnings := keeper.PreUpgradeValidation(ctx, k)
	require.NotEmpty(t, warnings)
	require.Contains(t, warnings[len(warnings)-1], "expected pouw_governance")
}

func TestPostUpgradeValidation_RejectsNonGovernedEnterpriseAuditTrustRegistry(t *testing.T) {
	k, ctx := newGovernedProtocolKeeper(t, "gov-authority")
	require.NoError(t, k.SetEnterpriseAuditTrustRegistry(ctx, testEnterpriseAuditTrustRegistryKeeper("runtime_registry")))

	err := keeper.PostUpgradeValidation(ctx, k)
	require.ErrorContains(t, err, "enterprise audit trust registry source invalid")
}

func newGovernedProtocolKeeper(t *testing.T, authority string) (keeper.Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	header := tmproto.Header{
		ChainID: "aethelred-protocol-test-1",
		Height:  100,
		Time:    time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC),
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
		authority,
	)

	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))
	require.NoError(t, k.JobCount.Set(ctx, 0))
	return k, ctx
}

func testEnterpriseAuditTrustRegistryGenesis() *types.EnterpriseAuditTrustRegistryGenesis {
	return &types.EnterpriseAuditTrustRegistryGenesis{
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
}

func testEnterpriseAuditTrustRegistryKeeper(source string) *keeper.EnterpriseAuditTrustRegistry {
	return &keeper.EnterpriseAuditTrustRegistry{
		Version:              "2026.04.14",
		Source:               source,
		UpdatedAt:            "2026-04-14T12:00:00Z",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []keeper.EnterpriseAuditPolicySignerTrustEntry{{
			DID:           "did:aethelred:policy-gateway-1",
			PublicKeyHex:  "025f3c7a3bb5d7584ff6d09b13d616f6c9778f4d3146ef4740db9f9c0fdb8724e3",
			Status:        keeper.EnterpriseAuditTrustEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
		AllowedSponsors: []keeper.EnterpriseAuditSponsorTrustEntry{{
			DID:           "did:aethelred:sponsor-bank",
			Status:        keeper.EnterpriseAuditTrustEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
	}
}
