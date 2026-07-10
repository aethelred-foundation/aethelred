package app

import (
	"encoding/json"
	"fmt"

	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/bank"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	distrkeeper "github.com/cosmos/cosmos-sdk/x/distribution/keeper"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"

	evmaddress "github.com/cosmos/evm/encoding/address"
	distprecompile "github.com/cosmos/evm/precompiles/distribution"
	stakingprecompile "github.com/cosmos/evm/precompiles/staking"

	erc20 "github.com/cosmos/evm/x/erc20"
	erc20keeper "github.com/cosmos/evm/x/erc20/keeper"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	feemarket "github.com/cosmos/evm/x/feemarket"
	feemarketkeeper "github.com/cosmos/evm/x/feemarket/keeper"
	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
	precisebank "github.com/cosmos/evm/x/precisebank"
	precisebankkeeper "github.com/cosmos/evm/x/precisebank/keeper"
	precisebanktypes "github.com/cosmos/evm/x/precisebank/types"
	evmmodule "github.com/cosmos/evm/x/vm"
	evmkeeper "github.com/cosmos/evm/x/vm/keeper"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	"github.com/aethelred/aethelred/app/evmconfig"
	precompileevm "github.com/aethelred/aethelred/precompiles/evm"
)

// evm.go wires the cosmos/evm stack (x/vm, x/feemarket, x/erc20,
// x/precisebank) into the Aethelred app — ADR-0001 Phase 1. All EVM-specific
// wiring lives here so app.go carries only the four integration touch points
// (store keys, keeper init call, module registration, ordering); the two
// audit-sensitive decisions (decimal bridge, precompile permissioning) live in
// app/evmconfig.

func init() {
	// The x/vm chain config is a process-global installed inside
	// evmkeeper.NewKeeper. Its re-set guard only permits reconfiguration when
	// the stored config's chain id equals evmtypes.DefaultEVMChainID. The CLI
	// constructs the app twice per process (a throwaway instance for autocli,
	// then the node instance), so align the default with Aethelred's chain id —
	// both constructions then install the IDENTICAL config instead of the
	// second one panicking ("chainConfig already set"). evmd avoids this only
	// because its example chain uses the upstream default id.
	evmtypes.DefaultEVMChainID = evmconfig.EVMChainID
}

// evmStoreKeys are the KV store keys the EVM stack mounts.
func evmStoreKeys() []string {
	return []string{
		evmtypes.StoreKey,
		feemarkettypes.StoreKey,
		erc20types.StoreKey,
		precisebanktypes.StoreKey,
	}
}

// evmTransientKeys are the transient store keys the EVM stack mounts.
func evmTransientKeys() []string {
	return []string{
		evmtypes.TransientKey,
		feemarkettypes.TransientKey,
	}
}

// initEVMKeepers constructs the EVM keeper graph. Order matters:
// feemarket → precisebank → evm (with the verifiable-AI static precompiles
// mounted at construction) → erc20 (which closes the evm↔erc20 cycle via the
// pointer handed to the EVM keeper).
func (app *AethelredApp) initEVMKeepers(
	keys map[string]*storetypes.KVStoreKey,
	tkeys map[string]*storetypes.TransientStoreKey,
	appCodec codec.Codec,
) {
	// Fail fast on a misconfigured EVM foundation (decimal bridge, precompile
	// list) — surface at construction, not at first block.
	if err := evmconfig.Validate(); err != nil {
		panic(fmt.Errorf("EVM configuration invalid: %w", err))
	}

	authority := authtypes.NewModuleAddress(govtypes.ModuleName)

	app.FeeMarketKeeper = feemarketkeeper.NewKeeper(
		appCodec,
		authority,
		keys[feemarkettypes.StoreKey],
		tkeys[feemarkettypes.TransientKey],
	)

	// precisebank wraps x/bank with 18-decimal sub-unit accounting for the EVM
	// (uaethel ↔ aaethel at a fixed 1e12 factor — see evmconfig).
	app.PreciseBankKeeper = precisebankkeeper.NewKeeper(
		appCodec,
		keys[precisebanktypes.StoreKey],
		app.BankKeeper,
		app.AccountKeeper,
	)

	// The verifiable-AI precompile surface (ISeal 0x0900, IVerify 0x0901,
	// IPoUW 0x0902), backed by the real module keepers.
	staticPrecompiles, err := precompileevm.NewStaticPrecompiles(
		&app.SealKeeper,
		app.VerifyKeeper,
		app.PouwKeeper,
	)
	if err != nil {
		panic(fmt.Errorf("failed to build verifiable-AI precompiles: %w", err))
	}

	// Native-staking surface (ADR-0004 Phase 2 — real liquid-staking yield):
	// cosmos/evm's upstream staking (0x800) and distribution (0x801)
	// precompiles, so EVM contracts (the Cruzible vault) can delegate pooled
	// AETHEL to validators and withdraw EARNED x/staking rewards instead of
	// operator-pushed ones. Amount arguments are in the BOND DENOM's base
	// units (uaethel, 6 decimals) — callers on the 18-decimal EVM face must
	// divide by the precisebank 1e12 conversion factor. The bank view handed
	// to both is PreciseBankKeeper, matching the EVM keeper's own bank view,
	// so balance mutations stay consistent with the decimal bridge.
	addrCodec := evmaddress.NewEvmCodec(sdk.GetConfig().GetBech32AccountAddrPrefix())
	stakingP := stakingprecompile.NewPrecompile(
		*app.StakingKeeper,
		stakingkeeper.NewMsgServerImpl(app.StakingKeeper),
		stakingkeeper.NewQuerier(app.StakingKeeper),
		app.PreciseBankKeeper,
		addrCodec,
	)
	staticPrecompiles[stakingP.Address()] = stakingP
	distP := distprecompile.NewPrecompile(
		app.DistrKeeper,
		distrkeeper.NewMsgServerImpl(app.DistrKeeper),
		distrkeeper.NewQuerier(app.DistrKeeper),
		*app.StakingKeeper,
		app.PreciseBankKeeper,
		addrCodec,
	)
	staticPrecompiles[distP.Address()] = distP

	app.EVMKeeper = evmkeeper.NewKeeper(
		appCodec,
		keys[evmtypes.StoreKey],
		tkeys[evmtypes.TransientKey],
		keys,
		authority,
		app.AccountKeeper,
		app.PreciseBankKeeper, // the EVM's bank view is the 18-decimal bridge
		app.StakingKeeper,
		app.FeeMarketKeeper,
		&app.ConsensusParamsKeeper,
		&app.Erc20Keeper, // pointer: erc20 keeper is constructed just below
		evmconfig.EVMChainID,
		"", // tracer: none by default (JSON-RPC debug namespace stays off)
	).WithStaticPrecompiles(staticPrecompiles)

	// IBC transfer keeper is nil: this chain does not enable erc20's IBC-coin
	// conversion paths (no IBC transfer module wired); the nil pointer is only
	// reachable through those paths.
	app.Erc20Keeper = erc20keeper.NewKeeper(
		keys[erc20types.StoreKey],
		appCodec,
		authority,
		app.AccountKeeper,
		app.BankKeeper,
		app.EVMKeeper,
		app.StakingKeeper,
		nil,
	)
}

// evmAppModules returns the EVM stack's modules for the module manager.
func (app *AethelredApp) evmAppModules() []module.AppModule {
	return []module.AppModule{
		evmmodule.NewAppModule(app.EVMKeeper, app.AccountKeeper, app.PreciseBankKeeper, app.AccountKeeper.AddressCodec()),
		feemarket.NewAppModule(app.FeeMarketKeeper),
		erc20.NewAppModule(app.Erc20Keeper, app.AccountKeeper),
		precisebank.NewAppModule(app.PreciseBankKeeper, app.BankKeeper, app.AccountKeeper),
	}
}

// EVM stack ordering: feemarket's BeginBlock sets the block's base fee before
// any EVM tx executes; the EVM's EndBlock runs before feemarket's (which reads
// the block gas wanted). InitGenesis: vm needs bank denom metadata (bank runs
// earlier in the app order) and feemarket params.
var (
	evmBeginBlockers = []string{
		feemarkettypes.ModuleName,
		evmtypes.ModuleName,
	}
	evmEndBlockers = []string{
		evmtypes.ModuleName,
		feemarkettypes.ModuleName,
	}
	evmInitGenesis = []string{
		feemarkettypes.ModuleName,
		evmtypes.ModuleName,
		erc20types.ModuleName,
		precisebanktypes.ModuleName,
	}
)

// aethelredVMModuleBasic overrides x/vm's default genesis with Aethelred's EVM
// configuration (aaethel denom, verifiable-AI precompiles active) so a chain
// initialized with `aethelredd init` is correct without manual genesis edits.
type aethelredVMModuleBasic struct {
	evmmodule.AppModuleBasic
}

func (aethelredVMModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(evmconfig.VMGenesis())
}

// aethelredFeeMarketModuleBasic overrides x/feemarket's default genesis with
// the base fee rescaled to the 6-decimal bank denom (see
// evmconfig.InitialBaseFee — the upstream default assumes 18 decimals and
// makes gas ~1e12× too expensive here).
type aethelredFeeMarketModuleBasic struct {
	feemarket.AppModuleBasic
}

func (aethelredFeeMarketModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(evmconfig.FeeMarketGenesis())
}

// aethelredBankModuleBasic extends x/bank's default genesis with the uaethel
// denom metadata the EVM stack requires (the vm module resolves the EVM coin
// info from bank metadata; a missing entry fails InitGenesis).
type aethelredBankModuleBasic struct {
	bank.AppModuleBasic
}

func (b aethelredBankModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	gs := banktypes.DefaultGenesisState()
	gs.DenomMetadata = append(gs.DenomMetadata, AethelDenomMetadata())
	return cdc.MustMarshalJSON(gs)
}

// AethelDenomMetadata is the bank metadata for the native token, keyed by the
// INTEGER bank denom uaethel (what x/bank actually holds). x/vm resolves the
// EVM decimals from the display unit's exponent here (aethel at 6), which is
// what routes balances through the x/precisebank 1e12 bridge to the virtual
// 18-decimal aaethel; aaethel is NOT a bank denom and must not appear as a
// metadata base (its metadata lookup happens under params.EvmDenom = uaethel).
func AethelDenomMetadata() banktypes.Metadata {
	return banktypes.Metadata{
		Description: "The native token of the Aethelred network.",
		DenomUnits: []*banktypes.DenomUnit{
			{Denom: evmconfig.BankDenom, Exponent: 0, Aliases: []string{"microaethel"}},
			{Denom: evmconfig.DisplayDenom, Exponent: 6},
		},
		Base:    evmconfig.BankDenom,
		Display: evmconfig.DisplayDenom,
		Name:    "Aethelred",
		Symbol:  "AETHEL",
	}
}

// Compile-time proof the genesis overrides keep the module-basic contracts.
var (
	_ module.HasGenesisBasics = aethelredVMModuleBasic{}
	_ module.HasGenesisBasics = aethelredBankModuleBasic{}
	_ module.HasGenesisBasics = aethelredFeeMarketModuleBasic{}
)
