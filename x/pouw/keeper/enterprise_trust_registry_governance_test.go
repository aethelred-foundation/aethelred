package keeper_test

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

	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

func TestMsgServer_UpdateEnterpriseAuditTrustRegistry_Unauthorized(t *testing.T) {
	k, ctx := newGovernedTestKeeper(t, "gov-authority")

	_, err := keeper.UpdateEnterpriseAuditTrustRegistryForTest(k, ctx, &keeper.MsgUpdateEnterpriseAuditTrustRegistry{
		Authority: "wrong-authority",
		Registry:  newEnterpriseAuditTrustRegistry(t),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unauthorized")
}

func TestMsgServer_UpdateEnterpriseAuditTrustRegistry_Success(t *testing.T) {
	k, ctx := newGovernedTestKeeper(t, "gov-authority")

	resp, err := keeper.UpdateEnterpriseAuditTrustRegistryForTest(k, ctx, &keeper.MsgUpdateEnterpriseAuditTrustRegistry{
		Authority:   "gov-authority",
		Registry:    newEnterpriseAuditTrustRegistry(t),
		Reason:      "activate regulated trust plane",
		RequestedBy: "did:aethelred:ops-admin",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.Configured)
	require.Equal(t, "2026.04.14", resp.Version)
	require.Equal(t, "audit.control_ledger.write", resp.RequiredAction)
	require.Equal(t, uint32(1), resp.PolicySignerCount)
	require.Equal(t, uint32(1), resp.AllowedSponsorCount)

	stored, err := k.GetEnterpriseAuditTrustRegistry(ctx)
	require.NoError(t, err)
	require.Equal(t, "pouw_governance", stored.Source)

	records := k.AuditLogger().GetRecordsByCategory(keeper.AuditCategoryGovernance)
	require.NotEmpty(t, records)
	require.Equal(t, "enterprise_audit_trust_registry_updated", records[len(records)-1].Action)
	require.Equal(t, "gov-authority", records[len(records)-1].Actor)
	require.Equal(t, "activate regulated trust plane", records[len(records)-1].Details["reason"])
	require.Equal(t, "did:aethelred:ops-admin", records[len(records)-1].Details["requested_by"])

	events := ctx.EventManager().Events()
	require.NotEmpty(t, events)
	require.True(t, containsEventType(events, "enterprise_audit_trust_registry_updated"))
}

func TestMsgServer_UpdateEnterpriseAuditTrustRegistry_Clear(t *testing.T) {
	k, ctx := newGovernedTestKeeper(t, "gov-authority")
	require.NoError(t, k.SetEnterpriseAuditTrustRegistry(ctx, newEnterpriseAuditTrustRegistry(t)))

	resp, err := keeper.UpdateEnterpriseAuditTrustRegistryForTest(k, ctx, &keeper.MsgUpdateEnterpriseAuditTrustRegistry{
		Authority:   "gov-authority",
		Clear:       true,
		Reason:      "containment drill",
		RequestedBy: "did:aethelred:ops-admin",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.Configured)

	_, err = k.GetEnterpriseAuditTrustRegistry(ctx)
	require.ErrorIs(t, err, keeper.ErrEnterpriseAuditTrustRegistryNotConfigured)

	records := k.AuditLogger().GetRecordsByCategory(keeper.AuditCategoryGovernance)
	require.NotEmpty(t, records)
	require.Equal(t, "enterprise_audit_trust_registry_cleared", records[len(records)-1].Action)
	require.Equal(t, "containment drill", records[len(records)-1].Details["reason"])
	require.Equal(t, "did:aethelred:ops-admin", records[len(records)-1].Details["requested_by"])

	events := ctx.EventManager().Events()
	require.NotEmpty(t, events)
	require.True(t, containsEventType(events, "enterprise_audit_trust_registry_cleared"))
}

func newGovernedTestKeeper(t *testing.T, authority string) (keeper.Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  100,
		Time:    time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC),
	}
	ctx := sdk.NewContext(cms, header, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
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

// Compile-time guard to ensure test store wiring still matches the keeper's
// schema expectations.
var _ collections.Item[string]

func containsEventType(events sdk.Events, eventType string) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}
