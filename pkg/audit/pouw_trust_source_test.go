package audit

import (
	"context"
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

	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

func TestPouwKeeperEnterpriseControlLedgerTrustSource_SnapshotPromotesFallbackViaGovernance(t *testing.T) {
	keeper, keeperCtx := newGovernedAuditTestKeeper(t, "gov-authority")

	registry := newTrustRegistryForTest(t, "bootstrap-static-config", "UAE")
	registry.Source = "startup_config"
	snapshot, err := registry.ToSnapshot()
	if err != nil {
		t.Fatalf("registry to snapshot: %v", err)
	}
	ensureEnterpriseTrustSnapshotProvider(snapshot, "static_source")

	fallback, err := NewStaticEnterpriseControlLedgerTrustSource(snapshot)
	if err != nil {
		t.Fatalf("new static trust source: %v", err)
	}

	trustSource, err := NewPouwKeeperEnterpriseControlLedgerTrustSource(
		&keeper,
		func() context.Context { return keeperCtx },
		fallback,
	)
	if err != nil {
		t.Fatalf("new keeper trust source: %v", err)
	}

	promotedSnapshot, err := trustSource.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("promote fallback trust source: %v", err)
	}
	if promotedSnapshot.Source != "pouw_governance" {
		t.Fatalf("expected governed trust source after promotion, got %q", promotedSnapshot.Source)
	}
	if promotedSnapshot.Metadata["provider"] != "pouw_keeper" {
		t.Fatalf("expected keeper provider metadata after promotion, got %+v", promotedSnapshot.Metadata)
	}

	storedRegistry, err := keeper.GetEnterpriseAuditTrustRegistry(keeperCtx)
	if err != nil {
		t.Fatalf("get promoted registry: %v", err)
	}
	if storedRegistry.Source != "pouw_governance" {
		t.Fatalf("expected stored registry source pouw_governance, got %q", storedRegistry.Source)
	}
	if storedRegistry.Metadata["bootstrap_mode"] != "lazy_fallback_promotion" {
		t.Fatalf("expected lazy fallback bootstrap metadata, got %+v", storedRegistry.Metadata)
	}
	if storedRegistry.Metadata["bootstrap_declared_source"] != "startup_config" {
		t.Fatalf("expected declared source metadata to be preserved, got %+v", storedRegistry.Metadata)
	}
	if storedRegistry.Metadata["bootstrap_declared_provider"] != "static_source" {
		t.Fatalf("expected declared provider metadata to be preserved, got %+v", storedRegistry.Metadata)
	}

	governanceRecords := keeper.AuditLogger().GetRecordsByCategory(pouwkeeper.AuditCategoryGovernance)
	if len(governanceRecords) == 0 {
		t.Fatal("expected governance audit record for fallback promotion")
	}
	lastRecord := governanceRecords[len(governanceRecords)-1]
	if lastRecord.Action != "enterprise_audit_trust_registry_updated" {
		t.Fatalf("expected governance update action, got %q", lastRecord.Action)
	}
	if lastRecord.Details["requested_by"] != "audit_trust_source_promotion" {
		t.Fatalf("expected requested_by detail for fallback promotion, got %+v", lastRecord.Details)
	}
}

func newGovernedAuditTestKeeper(t *testing.T, authority string) (pouwkeeper.Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(pouwtypes.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	if err := cms.LoadLatestVersion(); err != nil {
		t.Fatalf("load latest version: %v", err)
	}

	header := tmproto.Header{
		ChainID: "aethelred-audit-test-1",
		Height:  100,
		Time:    time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC),
	}
	ctx := sdk.NewContext(cms, header, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)
	var storeService store.KVStoreService = runtime.NewKVStoreService(storeKey)

	keeper := pouwkeeper.NewKeeper(
		cdc,
		storeService,
		nil,
		nil,
		sealkeeper.Keeper{},
		verifykeeper.Keeper{},
		authority,
	)

	if err := keeper.SetParams(ctx, pouwtypes.DefaultParams()); err != nil {
		t.Fatalf("set params: %v", err)
	}
	if err := keeper.JobCount.Set(ctx, 0); err != nil {
		t.Fatalf("set job count: %v", err)
	}
	return keeper, ctx
}

var _ collections.Item[string]
