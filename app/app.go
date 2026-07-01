package app

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	dbm "github.com/cosmos/cosmos-db"
	"github.com/spf13/cast"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/tmhash"

	"cosmossdk.io/client/v2/autocli"
	"cosmossdk.io/core/appmodule"
	storetypes "cosmossdk.io/store/types"
	"cosmossdk.io/x/evidence"
	evidencekeeper "cosmossdk.io/x/evidence/keeper"
	evidencetypes "cosmossdk.io/x/evidence/types"
	"cosmossdk.io/x/feegrant"
	feegrantkeeper "cosmossdk.io/x/feegrant/keeper"
	feegrantmodule "cosmossdk.io/x/feegrant/module"
	"cosmossdk.io/x/upgrade"
	upgradekeeper "cosmossdk.io/x/upgrade/keeper"
	upgradetypes "cosmossdk.io/x/upgrade/types"

	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	authcodec "github.com/cosmos/cosmos-sdk/codec/address"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	runtimeservices "github.com/cosmos/cosmos-sdk/runtime/services"
	"github.com/cosmos/cosmos-sdk/server/api"
	"github.com/cosmos/cosmos-sdk/server/config"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/x/auth"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/auth/vesting"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	authzkeeper "github.com/cosmos/cosmos-sdk/x/authz/keeper"
	authzmodule "github.com/cosmos/cosmos-sdk/x/authz/module"
	"github.com/cosmos/cosmos-sdk/x/bank"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/consensus"
	consensuskeeper "github.com/cosmos/cosmos-sdk/x/consensus/keeper"
	"github.com/cosmos/cosmos-sdk/x/crisis"
	crisiskeeper "github.com/cosmos/cosmos-sdk/x/crisis/keeper"
	crisistypes "github.com/cosmos/cosmos-sdk/x/crisis/types"
	distr "github.com/cosmos/cosmos-sdk/x/distribution"
	distrkeeper "github.com/cosmos/cosmos-sdk/x/distribution/keeper"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/cosmos/cosmos-sdk/x/gov"
	govclient "github.com/cosmos/cosmos-sdk/x/gov/client"
	govkeeper "github.com/cosmos/cosmos-sdk/x/gov/keeper"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	govv1beta1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1beta1"
	"github.com/cosmos/cosmos-sdk/x/mint"
	mintkeeper "github.com/cosmos/cosmos-sdk/x/mint/keeper"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
	"github.com/cosmos/cosmos-sdk/x/params"
	paramsclient "github.com/cosmos/cosmos-sdk/x/params/client"
	paramskeeper "github.com/cosmos/cosmos-sdk/x/params/keeper"
	paramstypes "github.com/cosmos/cosmos-sdk/x/params/types"
	paramproposal "github.com/cosmos/cosmos-sdk/x/params/types/proposal"
	"github.com/cosmos/cosmos-sdk/x/slashing"
	slashingkeeper "github.com/cosmos/cosmos-sdk/x/slashing/keeper"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	"github.com/cosmos/cosmos-sdk/x/staking"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/gogoproto/grpc"

	// Aethelred custom modules
	pqc "github.com/aethelred/aethelred/crypto/pqc"
	sovereigncrisiskeeper "github.com/aethelred/aethelred/x/crisis/keeper"
	sovereigncrisistypes "github.com/aethelred/aethelred/x/crisis/types"
	ibcmodule "github.com/aethelred/aethelred/x/ibc"
	ibckeeper "github.com/aethelred/aethelred/x/ibc/keeper"
	ibctypes "github.com/aethelred/aethelred/x/ibc/types"
	insurancekeeper "github.com/aethelred/aethelred/x/insurance/keeper"
	insurancetypes "github.com/aethelred/aethelred/x/insurance/types"
	"github.com/aethelred/aethelred/x/pouw"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	"github.com/aethelred/aethelred/x/seal"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	erc20 "github.com/cosmos/evm/x/erc20"
	erc20keeper "github.com/cosmos/evm/x/erc20/keeper"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	feemarket "github.com/cosmos/evm/x/feemarket"
	feemarketkeeper "github.com/cosmos/evm/x/feemarket/keeper"
	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
	precisebank "github.com/cosmos/evm/x/precisebank"
	precisebankkeeper "github.com/cosmos/evm/x/precisebank/keeper"
	precisebanktypes "github.com/cosmos/evm/x/precisebank/types"
	evmkeeper "github.com/cosmos/evm/x/vm/keeper"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	gethcommon "github.com/ethereum/go-ethereum/common"

	sealtypes "github.com/aethelred/aethelred/x/seal/types"
	"github.com/aethelred/aethelred/x/verify"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

const (
	// Name is the name of the application
	Name = "aethelred"
	// AccountAddressPrefix is the prefix for account addresses
	AccountAddressPrefix = "aethel"
	// BondDenom is the staking token denomination
	BondDenom = "uaethel"
)

var (
	// DefaultNodeHome is the default home directory for the application
	DefaultNodeHome string

	// ModuleBasics defines the module BasicManager that is in charge of setting up basic,
	// non-dependant module elements, such as codec registration and genesis verification.
	ModuleBasics = module.NewBasicManager(
		auth.AppModuleBasic{},
		genutil.NewAppModuleBasic(genutiltypes.DefaultMessageValidator),
		// bank with Aethelred's denom metadata in the default genesis (the EVM
		// stack resolves its coin info from bank metadata — see evm.go).
		aethelredBankModuleBasic{},
		staking.AppModuleBasic{},
		mint.AppModuleBasic{},
		distr.AppModuleBasic{},
		gov.NewAppModuleBasic([]govclient.ProposalHandler{
			paramsclient.ProposalHandler,
		}),
		params.AppModuleBasic{},
		crisis.AppModuleBasic{},
		slashing.AppModuleBasic{},
		feegrantmodule.AppModuleBasic{},
		authzmodule.AppModuleBasic{},
		consensus.AppModuleBasic{},
		vesting.AppModuleBasic{},
		upgrade.AppModuleBasic{},
		evidence.AppModuleBasic{},
		// Aethelred custom modules
		seal.AppModuleBasic{},
		pouw.AppModuleBasic{},
		verify.AppModuleBasic{},
		ibcmodule.AppModuleBasic{},
		// cosmos/evm stack (vm genesis overridden with Aethelred's EVM config)
		aethelredVMModuleBasic{},
		feemarket.AppModuleBasic{},
		erc20.AppModuleBasic{},
		precisebank.NewAppModuleBasic(),
	)
)

func init() {
	// Use SafeGetDefaultNodeHome for graceful degradation instead of panic
	home, err := SafeGetDefaultNodeHome()
	if err != nil {
		// Log warning but continue with the fallback path
		fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
	}
	DefaultNodeHome = home
}

// AethelredApp extends an ABCI application with Proof-of-Useful-Work consensus
type AethelredApp struct {
	*baseapp.BaseApp

	legacyAmino       *codec.LegacyAmino
	appCodec          codec.Codec
	txConfig          client.TxConfig
	interfaceRegistry codectypes.InterfaceRegistry

	// keys to access the substores
	keys    map[string]*storetypes.KVStoreKey
	tkeys   map[string]*storetypes.TransientStoreKey
	memKeys map[string]*storetypes.MemoryStoreKey

	// keepers - standard Cosmos SDK modules
	AccountKeeper         authkeeper.AccountKeeper
	BankKeeper            bankkeeper.Keeper
	StakingKeeper         *stakingkeeper.Keeper
	SlashingKeeper        slashingkeeper.Keeper
	MintKeeper            mintkeeper.Keeper
	DistrKeeper           distrkeeper.Keeper
	GovKeeper             govkeeper.Keeper
	CrisisKeeper          *crisiskeeper.Keeper
	UpgradeKeeper         *upgradekeeper.Keeper
	ParamsKeeper          paramskeeper.Keeper
	AuthzKeeper           authzkeeper.Keeper
	EvidenceKeeper        evidencekeeper.Keeper
	FeeGrantKeeper        feegrantkeeper.Keeper
	ConsensusParamsKeeper consensuskeeper.Keeper

	// keepers - Aethelred custom modules
	SealKeeper            sealkeeper.Keeper
	PouwKeeper            pouwkeeper.Keeper
	VerifyKeeper          verifykeeper.Keeper
	InsuranceKeeper       insurancekeeper.Keeper
	SovereignCrisisKeeper sovereigncrisiskeeper.Keeper
	IBCKeeper             ibckeeper.Keeper

	// keepers - cosmos/evm stack (ADR-0001 Phase 1; wiring in evm.go)
	FeeMarketKeeper   feemarketkeeper.Keeper
	EVMKeeper         *evmkeeper.Keeper
	Erc20Keeper       erc20keeper.Keeper
	PreciseBankKeeper precisebankkeeper.Keeper

	// pendingTxListeners back the JSON-RPC newPendingTransactions stream
	// (AppWithPendingTxStream); see jsonrpc.go.
	pendingTxListeners []func(gethcommon.Hash)

	// TEE client for compute verification
	teeClient TEEClient

	// orchestrator coordinates zkML and TEE verification services.
	// Created during initVerificationPipeline().
	orchestrator *verify.VerificationOrchestrator

	// consensusHandler manages Proof-of-Useful-Work consensus logic.
	// It holds the JobVerifier (OrchestratorBridge) that delegates to
	// the real TEE/zkML verification pipeline.
	consensusHandler *pouwkeeper.ConsensusHandler

	// evidenceProcessor handles downtime and equivocation evidence processing.
	evidenceProcessor *pouwkeeper.EvidenceProcessor

	// Module manager
	ModuleManager *module.Manager

	// Module configurator
	configurator module.Configurator

	// readinessChecked tracks whether the one-time production readiness
	// check has been performed. It runs on the first BeginBlock.
	readinessChecked bool

	// validatorPrivKey is the validator's ed25519 private key for signing
	// vote extensions. This is REQUIRED in production mode (AllowSimulated=false).
	// Set via SetValidatorPrivateKey() during node initialization.
	// SECURITY: This key MUST be kept secure and never exposed.
	validatorPrivKey []byte

	// validatorConsAddr is the consensus address derived from validatorPrivKey.
	// This is used to stamp vote extensions with the validator's own address.
	validatorConsAddr []byte

	// validatorHybridWallet is the validator's hybrid (secp256k1 + ML-DSA) key,
	// derived deterministically from the ed25519 validator key seed. It signs
	// Digital Seal claims in vote extensions so a 2/3+ quorum of these signatures
	// can be aggregated onto each seal. Derived in SetValidatorPrivateKey.
	validatorHybridWallet *pqc.DualKeyWallet

	// voteExtensionCache stores verified vote extensions by height so
	// ProcessProposal can enforce computation finality.
	voteExtensionCache *VoteExtensionCache

	// shutdownManager coordinates graceful shutdown of all components.
	// Initialized via InitShutdownManager() during app creation.
	shutdownManager *ShutdownManager

	// rateLimiter provides rate limiting for API endpoints and transactions.
	// Initialized via InitRateLimiter() during app creation.
	rateLimiter *RateLimiter

	// integratedEvidenceProcessor handles downtime and equivocation evidence
	// with full Cosmos SDK slashing module integration (AS-16).
	integratedEvidenceProcessor *pouwkeeper.IntegratedEvidenceProcessor

	// voteExtensionSigner handles application-level signing of vote extensions (AS-17).
	voteExtensionSigner *VoteExtensionSigner

	// voteExtensionVerifier verifies vote extensions from other validators (AS-17).
	voteExtensionVerifier *VoteExtensionVerifier

	// encryptedMempoolBridge handles decryption of encrypted mempool transactions
	// during PrepareProposal to prevent front-running and censorship.
	encryptedMempoolBridge *EncryptedMempoolBridge
}

// New returns a reference to an initialized AethelredApp.
func New(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	loadLatest bool,
	appOpts servertypes.AppOptions,
	baseAppOptions ...func(*baseapp.BaseApp),
) *AethelredApp {
	// Initialize encodings
	encodingConfig := MakeEncodingConfig()
	appCodec := encodingConfig.Codec
	legacyAmino := encodingConfig.Amino
	interfaceRegistry := encodingConfig.InterfaceRegistry
	txConfig := encodingConfig.TxConfig

	// Create base application
	bApp := baseapp.NewBaseApp(
		Name,
		logger,
		db,
		txConfig.TxDecoder(),
		baseAppOptions...,
	)
	bApp.SetCommitMultiStoreTracer(traceStore)
	bApp.SetVersion(Version)
	bApp.SetInterfaceRegistry(interfaceRegistry)
	bApp.SetTxEncoder(txConfig.TxEncoder())

	// Use safe PQC initialization with graceful degradation (AS-16 compliance)
	if err := SafeInitPQCMode(logger, appOpts); err != nil {
		logger.Error("PQC initialization returned error, continuing with classical crypto", "error", err)
	}

	// Initialize store keys
	keys := storetypes.NewKVStoreKeys(
		authtypes.StoreKey,
		banktypes.StoreKey,
		stakingtypes.StoreKey,
		minttypes.StoreKey,
		distrtypes.StoreKey,
		slashingtypes.StoreKey,
		paramstypes.StoreKey,
		upgradetypes.StoreKey,
		govtypes.StoreKey,
		authzkeeper.StoreKey,
		feegrant.StoreKey,
		evidencetypes.StoreKey,
		crisistypes.StoreKey,
		// Every mounted store belongs to a module registered in the module manager,
		// so InitGenesis + the per-block commit keep it versioned. Modules whose
		// genesis leaves the store empty (authz/feegrant/evidence) are seeded with a
		// marker in InitChainer — an empty mounted IAVL store that never commits data
		// cannot be loaded by version under iavl v1.x. Mount a store key only for a
		// module that is actually wired.
		// Aethelred custom module store keys
		sealtypes.StoreKey,
		pouwtypes.StoreKey,
		verifytypes.StoreKey,
		insurancetypes.StoreKey,
		sovereigncrisistypes.StoreKey,
		ibctypes.StoreKey,
	)
	for _, k := range evmStoreKeys() {
		keys[k] = storetypes.NewKVStoreKey(k)
	}
	tkeys := storetypes.NewTransientStoreKeys(paramstypes.TStoreKey)
	for _, k := range evmTransientKeys() {
		tkeys[k] = storetypes.NewTransientStoreKey(k)
	}
	memKeys := storetypes.NewMemoryStoreKeys()

	// Create the application
	app := &AethelredApp{
		BaseApp:            bApp,
		legacyAmino:        legacyAmino,
		appCodec:           appCodec,
		txConfig:           txConfig,
		interfaceRegistry:  interfaceRegistry,
		keys:               keys,
		tkeys:              tkeys,
		memKeys:            memKeys,
		voteExtensionCache: NewVoteExtensionCache(4, ""), // VC-03: chainID set below after appOpts parsed
	}
	app.InitShutdownManager()
	app.InitRateLimiter()
	app.encryptedMempoolBridge = NewEncryptedMempoolBridge(logger, DefaultEncryptedMempoolBridgeConfig())

	// Initialize params keeper and subspaces
	app.ParamsKeeper = initParamsKeeper(
		appCodec,
		legacyAmino,
		keys[paramstypes.StoreKey],
		tkeys[paramstypes.TStoreKey],
	)

	// Set the BaseApp's parameter store
	app.ConsensusParamsKeeper = consensuskeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[paramstypes.StoreKey]),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
		runtime.EventService{},
	)
	bApp.SetParamStore(app.ConsensusParamsKeeper.ParamsStore)

	// Initialize keepers for standard modules
	app.initStandardKeepers(keys, appCodec, legacyAmino)
	app.initUpgradeKeeper(keys, appCodec, appOpts)

	// Initialize Aethelred custom module keepers
	app.initAethelredKeepers(keys, appCodec)

	// Initialize the cosmos/evm stack (feemarket → precisebank → evm+precompiles
	// → erc20); needs the account/bank/staking and seal/verify/pouw keepers.
	app.initEVMKeepers(keys, tkeys, appCodec)

	// Create module manager with all modules
	app.setupModuleManager()

	// Register every module's invariants with the crisis keeper so they can be
	// checked (on demand via the crisis tx; automatic checks are disabled with
	// invCheckPeriod=0). Must run after the module manager is populated.
	app.ModuleManager.RegisterInvariants(app.CrisisKeeper)

	app.configurator = module.NewConfigurator(app.appCodec, app.MsgServiceRouter(), app.GRPCQueryRouter())
	if err := app.ModuleManager.RegisterServices(app.configurator); err != nil {
		panic(fmt.Errorf("failed to register module services: %w", err))
	}
	app.RegisterUpgradeHandlers()
	app.UpgradeKeeper.SetInitVersionMap(app.ModuleManager.GetVersionMap())

	// Initialize TEE client (required for production verification)
	app.initTEEClient(appOpts)

	// Build the full verification pipeline:
	// VerificationOrchestrator → OrchestratorBridge → ConsensusHandler
	app.initVerificationPipeline()
	app.RegisterShutdownComponents()

	// Initialize integrated slashing system (AS-16)
	app.InitIntegratedSlashing()

	// Initialize vote extension signing/verification (AS-17)
	chainID := cast.ToString(appOpts.Get("chain-id"))
	if chainID == "" {
		chainID = "aethelred-mainnet-1"
	}
	app.InitVoteExtensionSigner(chainID)
	app.InitVoteExtensionVerifier(chainID)

	// VC-03: Recreate vote extension cache with proper chain-id namespace.
	app.voteExtensionCache = NewVoteExtensionCache(4, chainID)

	// Initialize stores
	app.MountKVStores(keys)
	app.MountTransientStores(tkeys)
	app.MountMemoryStores(memKeys)

	// Initialize BaseApp
	app.SetInitChainer(app.InitChainer)
	app.SetPreBlocker(app.PreBlocker)
	app.SetBeginBlocker(app.BeginBlocker)
	app.SetEndBlocker(app.EndBlocker)

	// Set ABCI++ handlers for Proof-of-Useful-Work
	app.SetExtendVoteHandler(app.ExtendVoteHandler())
	app.SetVerifyVoteExtensionHandler(app.VerifyVoteExtensionHandler())
	app.SetPrepareProposal(app.PrepareProposalHandler())
	app.SetProcessProposal(app.ProcessProposalHandler())

	// Set ante handler
	app.SetAnteHandler(NewAnteHandler(app))

	app.SetupUpgradeStoreLoader()

	if loadLatest {
		if err := SafeLoadLatestVersion(app, logger); err != nil {
			// Critical error - cannot recover from state loading failure
			logger.Error("CRITICAL: Failed to load latest version, cannot continue", "error", err)
			panic(err) // This panic is intentional - state corruption is unrecoverable
		}
	}

	return app
}

// initStandardKeepers initializes all standard Cosmos SDK keepers
func (app *AethelredApp) initStandardKeepers(
	keys map[string]*storetypes.KVStoreKey,
	appCodec codec.Codec,
	legacyAmino *codec.LegacyAmino,
) {
	// Account keeper
	app.AccountKeeper = authkeeper.NewAccountKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[authtypes.StoreKey]),
		authtypes.ProtoBaseAccount,
		maccPerms,
		authcodec.NewBech32Codec(AccountAddressPrefix),
		AccountAddressPrefix,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Bank keeper
	app.BankKeeper = bankkeeper.NewBaseKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[banktypes.StoreKey]),
		app.AccountKeeper,
		BlockedAddresses(),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
		app.Logger(),
	)

	// Staking keeper
	app.StakingKeeper = stakingkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[stakingtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
		authcodec.NewBech32Codec(sdk.GetConfig().GetBech32ValidatorAddrPrefix()),
		authcodec.NewBech32Codec(sdk.GetConfig().GetBech32ConsensusAddrPrefix()),
	)

	// Mint keeper
	app.MintKeeper = mintkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[minttypes.StoreKey]),
		app.StakingKeeper,
		app.AccountKeeper,
		app.BankKeeper,
		authtypes.FeeCollectorName,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Distribution keeper
	app.DistrKeeper = distrkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[distrtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		app.StakingKeeper,
		authtypes.FeeCollectorName,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Slashing keeper
	app.SlashingKeeper = slashingkeeper.NewKeeper(
		appCodec,
		legacyAmino,
		runtime.NewKVStoreService(keys[slashingtypes.StoreKey]),
		app.StakingKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Register staking hooks so distribution and slashing receive validator
	// lifecycle events (AfterValidatorCreated / AfterValidatorBonded / ...).
	// Without this, the slashing module never creates ValidatorSigningInfo for
	// genesis validators, which causes a "no validator signing info found"
	// consensus failure at height 2 (height 1 has no commit to check; height 2
	// processes height 1's vote and looks up the missing signing info). It also
	// wires distribution's per-validator reward accounting. SetHooks must be
	// called exactly once, after the staking, distribution, and slashing keepers
	// all exist.
	app.StakingKeeper.SetHooks(
		stakingtypes.NewMultiStakingHooks(
			app.DistrKeeper.Hooks(),
			app.SlashingKeeper.Hooks(),
		),
	)

	govAuthority := authtypes.NewModuleAddress(govtypes.ModuleName).String()

	// FeeGrant keeper — lets accounts grant fee allowances to others.
	app.FeeGrantKeeper = feegrantkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[feegrant.StoreKey]),
		app.AccountKeeper,
	)

	// Authz keeper — generic message authorization/delegation.
	app.AuthzKeeper = authzkeeper.NewKeeper(
		runtime.NewKVStoreService(keys[authzkeeper.StoreKey]),
		appCodec,
		app.MsgServiceRouter(),
		app.AccountKeeper,
	)

	// Evidence keeper — handles equivocation/downtime evidence and routes it to
	// the slashing keeper. Uses the consensus-aware CometInfo service.
	evidenceKeeper := evidencekeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[evidencetypes.StoreKey]),
		app.StakingKeeper,
		app.SlashingKeeper,
		app.AccountKeeper.AddressCodec(),
		runtime.ProvideCometInfoService(),
	)
	app.EvidenceKeeper = *evidenceKeeper

	// Gov keeper — on-chain governance (proposals, deposits, voting, tallying).
	// The gov module account (maccPerms) is the authority for privileged module
	// params. Proposals are routed through the msg service router.
	govKeeper := govkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[govtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		app.StakingKeeper,
		app.DistrKeeper,
		app.MsgServiceRouter(),
		govtypes.DefaultConfig(),
		govAuthority,
	)

	// Legacy proposal-content router (gov v1beta1). Lets legacy proposals — text
	// and parameter-change — be submitted (tx gov submit-legacy-proposal) and
	// executed, alongside the modern msg-based gov v1 path (MsgUpdateParams etc.)
	// which routes through the msg service router. Must be set before the keeper
	// seals its router on first use.
	govRouter := govv1beta1.NewRouter()
	govRouter.AddRoute(govtypes.RouterKey, govv1beta1.ProposalHandler)
	govRouter.AddRoute(paramproposal.RouterKey, params.NewParamChangeProposalHandler(app.ParamsKeeper))
	govKeeper.SetLegacyRouter(govRouter)

	app.GovKeeper = *govKeeper

	// Crisis keeper — runs the registered module invariants. invCheckPeriod=0
	// disables automatic per-block checks (invariants stay runnable on demand via
	// the crisis "invariant-broken" tx); the constant fee is charged to the caller.
	app.CrisisKeeper = crisiskeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[crisistypes.StoreKey]),
		0,
		app.BankKeeper,
		authtypes.FeeCollectorName,
		govAuthority,
		app.AccountKeeper.AddressCodec(),
	)
}

// initAethelredKeepers initializes Aethelred custom module keepers
func (app *AethelredApp) initAethelredKeepers(
	keys map[string]*storetypes.KVStoreKey,
	appCodec codec.Codec,
) {
	// Seal keeper - manages Digital Seals for verified computations
	app.SealKeeper = sealkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[sealtypes.StoreKey]),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Verify keeper - handles zkML and TEE verification
	app.VerifyKeeper = verifykeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[verifytypes.StoreKey]),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// PoUW keeper - manages Proof-of-Useful-Work consensus and jobs
	app.PouwKeeper = pouwkeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[pouwtypes.StoreKey]),
		app.StakingKeeper,
		app.BankKeeper,
		app.SealKeeper,
		app.VerifyKeeper,
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Insurance keeper - escrow and appeal tribunal for fraud slashes.
	app.InsuranceKeeper = insurancekeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[insurancetypes.StoreKey]),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)
	app.InsuranceKeeper.SetValidatorSource(NewPoUWTribunalValidatorSource(&app.PouwKeeper))

	// Sovereign crisis keeper - emergency halt controls for bridge and PoUW allocation.
	app.SovereignCrisisKeeper = sovereigncrisiskeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[sovereigncrisistypes.StoreKey]),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// IBC keeper - cross-chain proof relay for verified AI computations
	app.IBCKeeper = ibckeeper.NewKeeper(
		appCodec,
		runtime.NewKVStoreService(keys[ibctypes.StoreKey]),
		app.Logger(),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)
}

// initTEEClient configures the TEE client based on app options.
// Supported modes:
// - disabled (default)
// - remote / http / nitro (requires aethelred.tee.endpoint)
// - nitro-simulated (dev/test only)
// - mock (dev/test only)
func (app *AethelredApp) initTEEClient(appOpts servertypes.AppOptions) {
	mode := strings.ToLower(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.tee.mode")),
		cast.ToString(appOpts.Get("tee.mode")),
	))
	if mode == "" {
		mode = strings.ToLower(os.Getenv("AETHELRED_TEE_MODE"))
	}
	if mode == "" {
		mode = "disabled"
	}

	if mode == "disabled" {
		app.Logger().Info("TEE client disabled")
		return
	}

	endpoint := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.tee.endpoint")),
		cast.ToString(appOpts.Get("tee.endpoint")),
	)
	if endpoint == "" {
		endpoint = os.Getenv("AETHELRED_TEE_ENDPOINT")
	}
	factory := NewTEEClientFactory(app.Logger())
	client, err := factory.Create(mode, map[string]string{
		"endpoint": endpoint,
	})
	if err != nil {
		// Log error but don't panic - allow graceful degradation
		app.Logger().Error("TEE client initialization failed, running in degraded mode",
			"error", err,
			"mode", mode,
		)
		return // Continue without TEE client
	}

	app.teeClient = client
	app.Logger().Info("TEE client initialized",
		"mode", mode,
		"endpoint", endpoint,
	)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// setupModuleManager creates and configures the module manager
func (app *AethelredApp) setupModuleManager() {
	modules := []module.AppModule{
		genutil.NewAppModule(app.AccountKeeper, app.StakingKeeper, app, app.txConfig),
		auth.NewAppModule(app.appCodec, app.AccountKeeper, nil, app.GetSubspace(authtypes.ModuleName)),
		vesting.NewAppModule(app.AccountKeeper, app.BankKeeper),
		bank.NewAppModule(app.appCodec, app.BankKeeper, app.AccountKeeper, app.GetSubspace(banktypes.ModuleName)),
		staking.NewAppModule(app.appCodec, app.StakingKeeper, app.AccountKeeper, app.BankKeeper, app.GetSubspace(stakingtypes.ModuleName)),
		mint.NewAppModule(app.appCodec, app.MintKeeper, app.AccountKeeper, nil, app.GetSubspace(minttypes.ModuleName)),
		distr.NewAppModule(app.appCodec, app.DistrKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper, app.GetSubspace(distrtypes.ModuleName)),
		slashing.NewAppModule(app.appCodec, app.SlashingKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper, app.GetSubspace(slashingtypes.ModuleName), app.interfaceRegistry),
		gov.NewAppModule(app.appCodec, &app.GovKeeper, app.AccountKeeper, app.BankKeeper, app.GetSubspace(govtypes.ModuleName)),
		authzmodule.NewAppModule(app.appCodec, app.AuthzKeeper, app.AccountKeeper, app.BankKeeper, app.interfaceRegistry),
		feegrantmodule.NewAppModule(app.appCodec, app.AccountKeeper, app.BankKeeper, app.FeeGrantKeeper, app.interfaceRegistry),
		evidence.NewAppModule(app.EvidenceKeeper),
		crisis.NewAppModule(app.CrisisKeeper, true, app.GetSubspace(crisistypes.ModuleName)),
		params.NewAppModule(app.ParamsKeeper),
		consensus.NewAppModule(app.appCodec, app.ConsensusParamsKeeper),
		// Aethelred custom modules
		seal.NewAppModule(app.appCodec, &app.SealKeeper),
		pouw.NewAppModule(app.appCodec, &app.PouwKeeper),
		verify.NewAppModule(app.appCodec, app.VerifyKeeper),
		ibcmodule.NewAppModule(app.appCodec, app.IBCKeeper),
	}
	// cosmos/evm stack (constructed in evm.go)
	modules = append(modules, app.evmAppModules()...)
	app.ModuleManager = module.NewManager(modules...)

	// Set order of module operations
	app.ModuleManager.SetOrderBeginBlockers(append([]string{
		upgradetypes.ModuleName,
		minttypes.ModuleName,
		distrtypes.ModuleName,
		slashingtypes.ModuleName,
		evidencetypes.ModuleName,
		stakingtypes.ModuleName,
		authtypes.ModuleName,
		banktypes.ModuleName,
		govtypes.ModuleName,
		crisistypes.ModuleName,
		genutiltypes.ModuleName,
		authz.ModuleName,
		feegrant.ModuleName,
		paramstypes.ModuleName,
		vestingtypes.ModuleName,
		// Aethelred modules
		pouwtypes.ModuleName,
		sealtypes.ModuleName,
		verifytypes.ModuleName,
		ibctypes.ModuleName,
	}, evmBeginBlockers...)...)

	app.ModuleManager.SetOrderEndBlockers(append([]string{
		crisistypes.ModuleName,
		govtypes.ModuleName,
		stakingtypes.ModuleName,
		feegrant.ModuleName,
		// Aethelred modules - process compute jobs at end of block
		pouwtypes.ModuleName,
		sealtypes.ModuleName,
		verifytypes.ModuleName,
		ibctypes.ModuleName,
	}, evmEndBlockers...)...)

	app.ModuleManager.SetOrderInitGenesis(append([]string{
		authtypes.ModuleName,
		banktypes.ModuleName,
		distrtypes.ModuleName,
		stakingtypes.ModuleName,
		slashingtypes.ModuleName,
		govtypes.ModuleName,
		minttypes.ModuleName,
		crisistypes.ModuleName,
		genutiltypes.ModuleName,
		evidencetypes.ModuleName,
		authz.ModuleName,
		feegrant.ModuleName,
		paramstypes.ModuleName,
		upgradetypes.ModuleName,
		vestingtypes.ModuleName,
		// Aethelred modules
		sealtypes.ModuleName,
		verifytypes.ModuleName,
		pouwtypes.ModuleName,
		ibctypes.ModuleName,
	}, evmInitGenesis...)...)
}

// Name returns the name of the App
func (app *AethelredApp) Name() string { return Name }

// BeginBlocker application updates at every begin block
// PreBlocker runs at the start of FinalizeBlock, before BeginBlock. It applies
// the injected "create_seal_from_consensus" transactions that PrepareProposal
// produced from the aggregated vote-extension verification results: each is
// handed to the consensus handler, which creates the Digital Seal and marks the
// job completed. Doing this here (deterministically, from the block's own txs)
// is what turns a verified PoUW job into an on-chain Digital Seal. Module
// PreBlock migrations then run as usual.
func (app *AethelredApp) PreBlocker(ctx sdk.Context, req *abci.RequestFinalizeBlock) (resp *sdk.ResponsePreBlock, err error) {
	defer app.recoverABCI("PreBlocker", &err)

	if app.consensusHandler != nil && req != nil {
		for _, txBytes := range req.Txs {
			if !pouwkeeper.IsSealTransaction(txBytes) {
				continue
			}
			if procErr := app.consensusHandler.ProcessSealTransaction(ctx, txBytes); procErr != nil {
				// Log but don't fail the block: a seal that can't be applied (e.g.
				// the job already completed in an earlier block) must not halt
				// consensus. The result is deterministic across validators.
				app.Logger().Error("Failed to process injected seal transaction", "error", procErr)
			}
		}
	}

	return app.ModuleManager.PreBlock(ctx)
}

func (app *AethelredApp) BeginBlocker(ctx sdk.Context) (resp sdk.BeginBlock, err error) {
	defer app.recoverABCI("BeginBlocker", &err)

	app.persistLastBlockTime(ctx)

	// Run the one-time production readiness check on the first block.
	// This ensures genesis state is loaded and params are available.
	if !app.readinessChecked {
		app.readinessChecked = true
		app.RunProductionReadinessChecks(ctx)
	}

	if metrics := app.PouwKeeper.Metrics(); metrics != nil {
		metrics.BlocksProcessed.Inc()
		metrics.LastBlockHeight.Set(ctx.BlockHeight())
		total, online := app.PouwKeeper.CountValidators(ctx)
		metrics.TotalValidators.Set(int64(total))
		metrics.ActiveValidators.Set(int64(online))
	}

	if expired, processErr := app.InsuranceKeeper.ProcessEscrowExpiries(ctx); processErr != nil {
		app.Logger().Error("Insurance escrow expiry processing failed", "error", processErr)
	} else if expired > 0 {
		app.Logger().Info("Insurance escrows forfeited after expiry", "count", expired)
	}

	return app.ModuleManager.BeginBlock(ctx)
}

// EndBlocker application updates at every end block
func (app *AethelredApp) EndBlocker(ctx sdk.Context) (resp sdk.EndBlock, err error) {
	defer app.recoverABCI("EndBlocker", &err)

	resp, err = app.ModuleManager.EndBlock(ctx)
	if err != nil {
		return resp, err
	}

	app.processEndBlockEvidence(ctx)

	return resp, nil
}

// InitChainer application update at chain initialization
func (app *AethelredApp) InitChainer(ctx sdk.Context, req *abci.RequestInitChain) (resp *abci.ResponseInitChain, err error) {
	defer app.recoverABCI("InitChainer", &err)

	var genesisState GenesisState
	if err := json.Unmarshal(req.AppStateBytes, &genesisState); err != nil {
		return nil, err
	}

	// Persist the initial module version map to the upgrade store. Without this
	// the upgrade store is never written at genesis and stays empty; an empty
	// mounted IAVL store cannot be loaded by version (iavl v1.x), which would
	// break versioned state queries and node restarts. This is also the standard
	// cosmos-sdk InitChainer pattern for enabling in-place store migrations.
	if err := app.UpgradeKeeper.SetModuleVersionMap(ctx, app.ModuleManager.GetVersionMap()); err != nil {
		return nil, err
	}

	// Seed the keeper-only custom modules (insurance escrow, sovereign crisis)
	// at genesis. These keepers are not registered in the module manager, so they
	// have no InitGenesis and their stores would otherwise stay empty until the
	// first escrow/halt write — and an empty mounted IAVL store cannot be loaded
	// by version (iavl v1.x), breaking all versioned queries and restart. Writing
	// their initial state here keeps every mounted store non-empty from height 1.
	if err := app.InsuranceKeeper.EscrowCount.Set(ctx, 0); err != nil {
		return nil, err
	}
	if err := app.InsuranceKeeper.AppealCount.Set(ctx, 0); err != nil {
		return nil, err
	}
	if err := app.SovereignCrisisKeeper.ClearHaltByAuthority(ctx, app.SovereignCrisisKeeper.GetAuthority()); err != nil {
		return nil, err
	}

	// Seed the authz, feegrant, and evidence stores. Their genesis state is empty
	// (no grants/evidence at launch), so their IAVL stores would never be written
	// and — under iavl v1.x — a mounted store that never commits data cannot be
	// loaded by version on restart ("version does not exist"). Write one reserved
	// marker key per store so each is non-empty from height 1. The 0xFF-prefixed
	// key sits outside every module's key prefixes, so it is invisible to the
	// keepers and to ExportGenesis, and it is written identically on every
	// validator (deterministic). gov is not seeded — its InitGenesis writes params.
	storeInitMarker := append([]byte{0xFF}, []byte("aethelred_store_init")...)
	// precisebank is seeded too: its default genesis (zero remainder, no
	// fractional balances) writes nothing until the first EVM sub-unit
	// operation, which would leave an empty mounted IAVL store.
	for _, storeKey := range []string{authzkeeper.StoreKey, feegrant.StoreKey, evidencetypes.StoreKey, precisebanktypes.StoreKey} {
		if key, ok := app.keys[storeKey]; ok {
			ctx.KVStore(key).Set(storeInitMarker, []byte{1})
		}
	}

	return app.ModuleManager.InitGenesis(ctx, app.appCodec, genesisState)
}

// LoadHeight loads a particular height
func (app *AethelredApp) LoadHeight(height int64) error {
	return app.LoadVersion(height)
}

// AutoCliOpts returns the autocli options used to generate CLI tx and query
// commands for every module directly from its protobuf service definitions.
// This is how the standard cosmos-sdk modules (bank, staking, distribution, gov,
// slashing, mint, feegrant, authz, …) get their CLI in v0.50 — their commands
// live in autocli, not a legacy client/cli package.
func (app *AethelredApp) AutoCliOpts() autocli.AppOptions {
	modules := make(map[string]appmodule.AppModule)
	for _, m := range app.ModuleManager.Modules {
		if moduleWithName, ok := m.(module.HasName); ok {
			if appModule, ok := moduleWithName.(appmodule.AppModule); ok {
				modules[moduleWithName.Name()] = appModule
			}
		}
	}

	return autocli.AppOptions{
		Modules:               modules,
		ModuleOptions:         runtimeservices.ExtractAutoCLIOptions(app.ModuleManager.Modules),
		AddressCodec:          authcodec.NewBech32Codec(AccountAddressPrefix),
		ValidatorAddressCodec: authcodec.NewBech32Codec(AccountAddressPrefix + "valoper"),
		ConsensusAddressCodec: authcodec.NewBech32Codec(AccountAddressPrefix + "valcons"),
	}
}

// LegacyAmino returns the legacy amino codec
func (app *AethelredApp) LegacyAmino() *codec.LegacyAmino {
	return app.legacyAmino
}

// AppCodec returns the app codec
func (app *AethelredApp) AppCodec() codec.Codec {
	return app.appCodec
}

// InterfaceRegistry returns the interface registry
func (app *AethelredApp) InterfaceRegistry() codectypes.InterfaceRegistry {
	return app.interfaceRegistry
}

// TxConfig returns the tx config
func (app *AethelredApp) TxConfig() client.TxConfig {
	return app.txConfig
}

// GetSubspace returns a param subspace for a given module name
func (app *AethelredApp) GetSubspace(moduleName string) paramstypes.Subspace {
	subspace, _ := app.ParamsKeeper.GetSubspace(moduleName)
	return subspace
}

// RegisterAPIRoutes registers all application module routes with the provided API server
func (app *AethelredApp) RegisterAPIRoutes(apiSvr *api.Server, apiConfig config.APIConfig) {
	// In Cosmos SDK v0.50, gRPC gateway routes are registered via the module manager
	ModuleBasics.RegisterGRPCGatewayRoutes(apiSvr.ClientCtx, apiSvr.GRPCGatewayRouter)

	// Aethelred-specific metrics endpoint
	apiSvr.Router.Handle("/metrics/aethelred", app.MetricsHandler()).Methods("GET")
	// Aethelred-specific health endpoint (component-level)
	apiSvr.Router.Handle("/health/aethelred", app.HealthHandler()).Methods("GET")
	// Admin endpoint for deterministic pre-proposal consensus evidence auditing.
	apiSvr.Router.Handle("/admin/consensus/evidence/audit", app.ConsensusEvidenceAuditHandler()).Methods("POST")
}

// GetMaccPerms returns a copy of the module account permissions
func GetMaccPerms() map[string][]string {
	dupMaccPerms := make(map[string][]string)
	for k, v := range maccPerms {
		dupMaccPerms[k] = v
	}
	return dupMaccPerms
}

// BlockedAddresses returns all the app's blocked account addresses
func BlockedAddresses() map[string]bool {
	modAccAddrs := make(map[string]bool)
	for acc := range GetMaccPerms() {
		modAccAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}
	return modAccAddrs
}

// initParamsKeeper initializes the params keeper and subspaces
func initParamsKeeper(
	appCodec codec.Codec,
	legacyAmino *codec.LegacyAmino,
	key storetypes.StoreKey,
	tkey storetypes.StoreKey,
) paramskeeper.Keeper {
	paramsKeeper := paramskeeper.NewKeeper(appCodec, legacyAmino, key, tkey)

	// Register param subspaces
	paramsKeeper.Subspace(authtypes.ModuleName)
	paramsKeeper.Subspace(banktypes.ModuleName)
	paramsKeeper.Subspace(stakingtypes.ModuleName)
	paramsKeeper.Subspace(minttypes.ModuleName)
	paramsKeeper.Subspace(distrtypes.ModuleName)
	paramsKeeper.Subspace(slashingtypes.ModuleName)
	paramsKeeper.Subspace(govtypes.ModuleName)
	paramsKeeper.Subspace(crisistypes.ModuleName)
	// Aethelred custom modules
	paramsKeeper.Subspace(sealtypes.ModuleName)
	paramsKeeper.Subspace(pouwtypes.ModuleName)
	paramsKeeper.Subspace(verifytypes.ModuleName)
	paramsKeeper.Subspace(insurancetypes.ModuleName)
	paramsKeeper.Subspace(sovereigncrisistypes.ModuleName)
	paramsKeeper.Subspace(ibctypes.ModuleName)

	return paramsKeeper
}

// maccPerms is a map of module account permissions
var maccPerms = map[string][]string{
	authtypes.FeeCollectorName:     nil,
	distrtypes.ModuleName:          nil,
	minttypes.ModuleName:           {authtypes.Minter},
	stakingtypes.BondedPoolName:    {authtypes.Burner, authtypes.Staking},
	stakingtypes.NotBondedPoolName: {authtypes.Burner, authtypes.Staking},
	govtypes.ModuleName:            {authtypes.Burner},
	// Aethelred modules - pouw module can mint rewards and burn slashed tokens
	pouwtypes.ModuleName:          {authtypes.Minter, authtypes.Burner},
	pouwtypes.TreasuryModuleName:  nil,
	pouwtypes.InsuranceModuleName: nil,
	// cosmos/evm stack: the vm module escrows gas fees and mints/burns during
	// EVM state transitions; erc20 mints/burns for token-pair conversions;
	// precisebank mints/burns the sub-unit reserve for the 6→18 decimal bridge.
	evmtypes.ModuleName:         {authtypes.Minter, authtypes.Burner},
	feemarkettypes.ModuleName:   nil,
	erc20types.ModuleName:       {authtypes.Minter, authtypes.Burner},
	precisebanktypes.ModuleName: {authtypes.Minter, authtypes.Burner},
}

// Version is the application version
const Version = "0.1.0"

// GenesisState represents the genesis state of the blockchain
type GenesisState map[string]json.RawMessage

// NewDefaultGenesisState generates the default state for the application
func NewDefaultGenesisState(cdc codec.Codec) GenesisState {
	return ModuleBasics.DefaultGenesis(cdc)
}

// SetValidatorPrivateKey sets the validator's ed25519 private key for signing
// vote extensions. This MUST be called during node initialization before the
// chain starts producing blocks.
//
// SECURITY REQUIREMENTS:
//   - The key must be exactly 64 bytes (ed25519 private key format)
//   - The key must be kept secure and never logged or exposed
//   - In production mode (AllowSimulated=false), unsigned vote extensions
//     will be rejected by other validators
//
// This method should be called from the node's startup sequence after loading
// the validator's key from the keyring or secure storage.
func (app *AethelredApp) SetValidatorPrivateKey(privKey []byte) error {
	if len(privKey) != 64 {
		return fmt.Errorf("invalid ed25519 private key length: expected 64, got %d", len(privKey))
	}

	// Make a copy to prevent external modification
	app.validatorPrivKey = make([]byte, 64)
	copy(app.validatorPrivKey, privKey)

	consAddr, err := app.validatorConsensusAddress()
	if err != nil {
		return fmt.Errorf("failed to derive validator consensus address: %w", err)
	}
	app.validatorConsAddr = make([]byte, len(consAddr))
	copy(app.validatorConsAddr, consAddr)

	// Derive the validator's hybrid (secp256k1 + ML-DSA) key deterministically
	// from the ed25519 key seed. This ties the seal-signing key to the consensus
	// key with no extra key files, and is reproducible for on-chain registration.
	hybridWallet, err := pqc.NewDualKeyWalletFromMasterSeed(ed25519.PrivateKey(app.validatorPrivKey).Seed(), pqc.DilithiumLevel3)
	if err != nil {
		return fmt.Errorf("failed to derive validator hybrid key: %w", err)
	}
	app.validatorHybridWallet = hybridWallet

	// Log the derived hybrid public key so the operator can register it on-chain
	// (`aethelredd tx pouw register-hybrid-key <hex>`) unless it was seeded at genesis.
	app.Logger().Info("Validator private key configured for vote extension signing",
		"hybrid_public_key", hex.EncodeToString(hybridWallet.HybridPublicKey()),
	)
	return nil
}

// ValidatorHybridPublicKey returns the serialized hybrid public key the validator
// uses to sign Digital Seal claims, or nil if no validator key is configured.
// This is the value a validator registers on-chain via the pouw module.
func (app *AethelredApp) ValidatorHybridPublicKey() []byte {
	if app.validatorHybridWallet == nil {
		return nil
	}
	return app.validatorHybridWallet.HybridPublicKey()
}

// validatorConsensusAddress derives the consensus address from the configured
// ed25519 private key. It does not mutate app state.
func (app *AethelredApp) validatorConsensusAddress() ([]byte, error) {
	if len(app.validatorPrivKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("validator private key not configured")
	}

	pubKey := ed25519.PrivateKey(app.validatorPrivKey).Public().(ed25519.PublicKey)
	return tmhash.SumTruncated(pubKey), nil
}

// HasValidatorPrivateKey returns true if the validator private key is configured
func (app *AethelredApp) HasValidatorPrivateKey() bool {
	return len(app.validatorPrivKey) == 64
}

// RegisterNodeService implements the Application.RegisterNodeService method
func (app *AethelredApp) RegisterNodeService(clientCtx client.Context, cfg config.Config) {
	// Node service registration for Cosmos SDK v0.50+
	// This is called by the server to register node-related services
}

// RegisterTendermintService implements the Application.RegisterTendermintService method
func (app *AethelredApp) RegisterTendermintService(clientCtx client.Context) {
	// CometBFT service registration for Cosmos SDK v0.50+
}

// RegisterTxService implements the Application.RegisterTxService method
func (app *AethelredApp) RegisterTxService(clientCtx client.Context) {
	// Tx service registration for Cosmos SDK v0.50+
}

// RegisterGRPCServer implements the Application.RegisterGRPCServer method
func (app *AethelredApp) RegisterGRPCServer(grpcServer grpc.Server) {
	// gRPC server registration
}

// ExportAppStateAndValidators exports the application state for genesis export
func (app *AethelredApp) ExportAppStateAndValidators(
	forZeroHeight bool,
	jailAllowedAddrs []string,
	modulesToExport []string,
) (servertypes.ExportedApp, error) {
	// Export genesis state from all modules
	ctx := app.NewContext(true)

	// Get the genesis state
	genState, err := app.ModuleManager.ExportGenesis(ctx, app.appCodec)
	if err != nil {
		return servertypes.ExportedApp{}, err
	}

	appState, err := json.MarshalIndent(genState, "", "  ")
	if err != nil {
		return servertypes.ExportedApp{}, err
	}

	return servertypes.ExportedApp{
		AppState:        appState,
		Height:          app.LastBlockHeight(),
		ConsensusParams: app.GetConsensusParams(ctx),
	}, nil
}
