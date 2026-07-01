package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	cmtcfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/privval"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"

	"cosmossdk.io/log"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/config"
	"github.com/cosmos/cosmos-sdk/client/debug"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/client/rpc"
	"github.com/cosmos/cosmos-sdk/server"
	serverconfig "github.com/cosmos/cosmos-sdk/server/config"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	"github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"

	"github.com/aethelred/aethelred/app"
	"github.com/aethelred/aethelred/x/pouw"
	"github.com/aethelred/aethelred/x/seal"
	"github.com/aethelred/aethelred/x/verify"

	// Suppress unused import warning - these are registered via imports
	_ "github.com/cosmos/cosmos-sdk/client/rpc"
)

// NewRootCmd creates the root command for aethelredd
func NewRootCmd() *cobra.Command {
	// Set config
	initConfig()

	encodingConfig := app.MakeEncodingConfig()
	initClientCtx := client.Context{}.
		WithCodec(encodingConfig.Codec).
		WithInterfaceRegistry(encodingConfig.InterfaceRegistry).
		WithTxConfig(encodingConfig.TxConfig).
		WithLegacyAmino(encodingConfig.Amino).
		WithInput(os.Stdin).
		WithAccountRetriever(types.AccountRetriever{}).
		WithHomeDir(app.DefaultNodeHome).
		WithViper("AETHELRED")

	rootCmd := &cobra.Command{
		Use:   "aethelredd",
		Short: "Aethelred - The Digital Seal for Verifiable Intelligence",
		Long: `Aethelred is a sovereign Layer 1 blockchain with Proof-of-Useful-Work consensus
for cryptographic verification of AI computations.

Key Features:
- Proof-of-Useful-Work consensus with zkML and TEE verification
- Digital Seals for immutable AI audit trails
- Enterprise-grade compliance for regulated industries
- Cross-chain interoperability for verification proofs

Learn more at https://aethelred.io`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			initClientCtx, err := client.ReadPersistentCommandFlags(initClientCtx, cmd.Flags())
			if err != nil {
				return err
			}
			initClientCtx, err = config.ReadFromClientConfig(initClientCtx)
			if err != nil {
				return err
			}
			if err := client.SetCmdClientContextHandler(initClientCtx, cmd); err != nil {
				return err
			}
			customAppTemplate, customAppConfig := initAppConfig()
			customCMTConfig := initCometBFTConfig()
			if err := server.InterceptConfigsPreRunHandler(cmd, customAppTemplate, customAppConfig, customCMTConfig); err != nil {
				return err
			}
			return validateAppConfig(cmd)
		},
	}

	initRootCmd(rootCmd, encodingConfig)

	// Generate CLI tx/query commands for the standard cosmos-sdk modules (bank,
	// staking, distribution, gov, slashing, mint, feegrant, authz, …) from their
	// protobuf service definitions via autocli. A throwaway in-memory app instance
	// supplies the module reflection and is discarded immediately. Custom modules
	// (seal/pouw/verify) are registered manually in initRootCmd; autocli skips any
	// command already present, so there are no duplicates.
	//
	// This CLI process is not a running node, so allow the throwaway app's
	// verification-pipeline init to degrade to a warning (instead of panicking when
	// no TEE endpoint is configured) by scoping AETHELRED_ALLOW_SIMULATED to just
	// this construction — the real node app built later stays strict.
	prevAllow, hadAllow := os.LookupEnv("AETHELRED_ALLOW_SIMULATED")
	os.Setenv("AETHELRED_ALLOW_SIMULATED", "true")
	tempApp := app.New(log.NewNopLogger(), dbm.NewMemDB(), nil, false, emptyAppOptions{})
	if hadAllow {
		os.Setenv("AETHELRED_ALLOW_SIMULATED", prevAllow)
	} else {
		os.Unsetenv("AETHELRED_ALLOW_SIMULATED")
	}
	// autocli's flag builder needs a proto file resolver; it reads it from
	// AppOptions.ClientCtx.InterfaceRegistry, so wire the client context in.
	autoCliOpts := tempApp.AutoCliOpts()
	autoCliOpts.ClientCtx = initClientCtx
	if err := autoCliOpts.EnhanceRootCommand(rootCmd); err != nil {
		panic(err)
	}

	return rootCmd
}

// emptyAppOptions is a no-op AppOptions used only to construct the throwaway app
// instance that provides autocli module reflection in NewRootCmd.
type emptyAppOptions struct{}

func (emptyAppOptions) Get(string) interface{} { return nil }

// initConfig sets the SDK configuration
func initConfig() {
	// Set the address prefixes
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount(app.AccountAddressPrefix, app.AccountAddressPrefix+"pub")
	config.SetBech32PrefixForValidator(app.AccountAddressPrefix+"valoper", app.AccountAddressPrefix+"valoperpub")
	config.SetBech32PrefixForConsensusNode(app.AccountAddressPrefix+"valcons", app.AccountAddressPrefix+"valconspub")
	config.Seal()
}

// AppConfig defines custom app configuration for Aethelred.
type AppConfig struct {
	// ",squash" flattens the embedded server config so its keys (e.g.
	// minimum-gas-prices) unmarshal from app.toml. Without it, viper/mapstructure
	// leaves Config zero-valued and ValidateBasic falsely reports an unset min gas
	// price.
	serverconfig.Config `mapstructure:",squash"`
	TEE                 TEEConfig `mapstructure:"tee"`
}

// TEEConfig defines configuration for the TEE worker integration.
type TEEConfig struct {
	Mode     string `mapstructure:"mode"`
	Endpoint string `mapstructure:"endpoint"`
}

// initAppConfig sets custom app configuration
func initAppConfig() (string, interface{}) {
	customAppTemplate := strings.TrimSpace(serverconfig.DefaultConfigTemplate) + "\n\n" + strings.TrimSpace(`
[tee]
# TEE client mode: disabled | remote | http | nitro | mock | nitro-simulated
mode = "{{ .TEE.Mode }}"

# Remote TEE worker endpoint (required for remote/http/nitro)
endpoint = "{{ .TEE.Endpoint }}"
`) + "\n"

	customAppConfig := AppConfig{
		Config: *serverconfig.DefaultConfig(),
		TEE: TEEConfig{
			Mode:     "disabled",
			Endpoint: "",
		},
	}
	customAppConfig.MinGasPrices = "0.001uaethel"

	return customAppTemplate, customAppConfig
}

// initCometBFTConfig returns the CometBFT (consensus) config used to seed
// config.toml on first run. It MUST be non-nil: cosmos-sdk's
// InterceptConfigsPreRunHandler calls ValidateBasic() on this value when
// config.toml does not yet exist (e.g. during `init`), so passing nil panics
// with a nil-pointer dereference in cometbft/config.(*Config).ValidateBasic.
func initCometBFTConfig() *cmtcfg.Config {
	return cmtcfg.DefaultConfig()
}

// initRootCmd adds subcommands to the root command
func initRootCmd(rootCmd *cobra.Command, encodingConfig app.EncodingConfig) {
	cfg := sdk.GetConfig()
	cfg.Seal()

	rootCmd.AddCommand(
		genutilcli.InitCmd(app.ModuleBasics, app.DefaultNodeHome),
		// Genesis-bootstrap commands registered at the top level (Osmosis-style):
		// `aethelredd add-genesis-account | gentx | collect-gentxs |
		// validate-genesis | migrate`. Previously only init + migrate were
		// registered, so these were missing entirely and a chain could not be set
		// up via CLI. Address codecs come from the tx config's signing context.
		genutilcli.AddGenesisAccountCmd(app.DefaultNodeHome, encodingConfig.TxConfig.SigningContext().AddressCodec()),
		genutilcli.GenTxCmd(app.ModuleBasics, encodingConfig.TxConfig, banktypes.GenesisBalancesIterator{}, app.DefaultNodeHome, encodingConfig.TxConfig.SigningContext().ValidatorAddressCodec()),
		genutilcli.CollectGenTxsCmd(banktypes.GenesisBalancesIterator{}, app.DefaultNodeHome, genutiltypes.DefaultMessageValidator, encodingConfig.TxConfig.SigningContext().ValidatorAddressCodec()),
		genutilcli.ValidateGenesisCmd(app.ModuleBasics),
		genutilcli.MigrateGenesisCmd(genesisMigrationMap()),
		debug.Cmd(),
	)

	server.AddCommands(rootCmd, app.DefaultNodeHome, newApp, appExport, addModuleInitFlags)

	// Add query and tx commands
	rootCmd.AddCommand(
		queryCommand(),
		txCommand(),
		auditCommand(),
		keys.Commands(),
	)
}

// newApp creates a new Aethelred app for the server
func newApp(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	appOpts servertypes.AppOptions,
) servertypes.Application {
	// DefaultBaseappOptions wires chain-id (baseapp.SetChainID), pruning,
	// min-gas-prices, snapshot, halt-height, and mempool settings from appOpts.
	// Without these the baseapp chain-id stays empty and InitChain fails with
	// "invalid chain-id on InitChain; expected: , got: <chain>".
	baseappOptions := server.DefaultBaseappOptions(appOpts)
	aethelredApp := app.New(
		logger,
		db,
		traceStore,
		true,
		appOpts,
		baseappOptions...,
	)

	// Configure the validator's signing key from priv_validator_key.json so the
	// node can sign vote extensions and Digital Seal claims, and so it logs its
	// derived hybrid (secp256k1 + ML-DSA) public key for on-chain registration
	// (`aethelredd tx pouw register-hybrid-key <hex>`). Validator nodes have this
	// key file; non-validator nodes do not, so this is best-effort and silently
	// skipped when the file is absent.
	if home := cast.ToString(appOpts.Get(flags.FlagHome)); home != "" {
		keyFile := filepath.Join(home, "config", "priv_validator_key.json")
		if _, statErr := os.Stat(keyFile); statErr == nil {
			stateFile := filepath.Join(home, "data", "priv_validator_state.json")
			filePV := privval.LoadFilePVEmptyState(keyFile, stateFile)
			if keyErr := aethelredApp.SetValidatorPrivateKey(filePV.Key.PrivKey.Bytes()); keyErr != nil {
				logger.Error("failed to configure validator signing key from priv_validator_key.json", "error", keyErr)
			}
		}
	}

	return aethelredApp
}

// appExport exports app state
func appExport(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	height int64,
	forZeroHeight bool,
	jailAllowedAddrs []string,
	appOpts servertypes.AppOptions,
	modulesToExport []string,
) (servertypes.ExportedApp, error) {
	aethelredApp := app.New(
		logger,
		db,
		traceStore,
		false,
		appOpts,
	)

	// Export genesis
	return aethelredApp.ExportAppStateAndValidators(forZeroHeight, jailAllowedAddrs, modulesToExport)
}

// addModuleInitFlags adds module-specific init flags
func addModuleInitFlags(startCmd *cobra.Command) {
	// Add custom flags here
}

// queryCommand returns the query command group
func queryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "query",
		Aliases:                    []string{"q"},
		Short:                      "Querying subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		rpc.ValidatorCommand(),
		rpc.QueryEventForTxCmd(),
		rpc.WaitTxCmd(),
		authcmd.QueryTxsByEventsCmd(),
		authcmd.QueryTxCmd(),
	)

	// Custom module query commands. The standard cosmos-sdk modules (bank,
	// staking, distribution, gov, slashing, mint, …) are added separately via
	// autocli in NewRootCmd (EnhanceRootCommand), which generates their commands
	// from proto; autocli skips any module already registered here.
	cmd.AddCommand(seal.GetQueryCmd())
	cmd.AddCommand(pouw.GetQueryCmd())
	cmd.AddCommand(verify.GetQueryCmd())

	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}

// txCommand returns the tx command group
func txCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "tx",
		Short:                      "Transactions subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		authcmd.GetSignCommand(),
		authcmd.GetSignBatchCommand(),
		authcmd.GetMultiSignCommand(),
		authcmd.GetMultiSignBatchCmd(),
		authcmd.GetValidateSignaturesCommand(),
		authcmd.GetBroadcastCommand(),
		authcmd.GetEncodeCommand(),
		authcmd.GetDecodeCommand(),
	)

	// Custom module tx commands. The standard cosmos-sdk modules (bank send,
	// staking delegate, distribution withdraw-rewards, gov vote, slashing unjail,
	// …) are added separately via autocli in NewRootCmd (EnhanceRootCommand),
	// which generates their commands from proto; autocli skips any module already
	// registered here.
	cmd.AddCommand(seal.GetTxCmd())
	cmd.AddCommand(pouw.GetTxCmd())
	cmd.AddCommand(verify.GetTxCmd())
	cmd.AddCommand(attestationTxCommand())

	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}
