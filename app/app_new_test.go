package app

import (
	"path/filepath"
	"testing"

	"cosmossdk.io/log"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func TestNewApp_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("app.New panicked: %v", r)
		}
	}()

	opts := sims.AppOptionsMap{"aethelred.pqc.mode": "simulated"}
	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")
	_ = New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
}

func TestNewApp_InitializesAuditAPI(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	if app.auditStudio == nil {
		t.Fatal("expected audit studio to be initialized")
	}
	if app.auditServer == nil {
		t.Fatal("expected audit server to be initialized")
	}

	wantDir := filepath.Join(homeDir, "data", "audit", "control-ledgers")
	if app.auditControlLedgerDir != wantDir {
		t.Fatalf("expected audit control ledger dir %q, got %q", wantDir, app.auditControlLedgerDir)
	}
}
