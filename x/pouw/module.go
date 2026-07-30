package pouw

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spf13/cobra"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"

	"github.com/aethelred/aethelred/x/pouw/client/cli"
	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

var (
	_ module.AppModule      = (*AppModule)(nil)
	_ module.AppModuleBasic = AppModuleBasic{}
)

// AppModuleBasic implements the AppModuleBasic interface for the pouw (Proof-of-Useful-Work) module.
type AppModuleBasic struct{}

// Name returns the module's name.
func (AppModuleBasic) Name() string {
	return types.ModuleName
}

// RegisterLegacyAminoCodec registers the module's types on the LegacyAmino codec.
func (AppModuleBasic) RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	types.RegisterLegacyAminoCodec(cdc)
}

// RegisterInterfaces registers the module's interface types.
func (AppModuleBasic) RegisterInterfaces(reg cdctypes.InterfaceRegistry) {
	types.RegisterInterfaces(reg)
}

// DefaultGenesis returns the module's default genesis state.
func (AppModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(types.DefaultGenesis())
}

// ValidateGenesis performs genesis state validation.
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var gs types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &gs); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}
	return gs.Validate()
}

// RegisterGRPCGatewayRoutes registers the gRPC Gateway routes for the module.
func (AppModuleBasic) RegisterGRPCGatewayRoutes(clientCtx client.Context, mux *runtime.ServeMux) {
	// Register gRPC gateway routes here
}

// GetTxCmd returns the module's root tx command.
func (AppModuleBasic) GetTxCmd() *cobra.Command {
	return GetTxCmd()
}

// GetQueryCmd returns the module's root query command.
func (AppModuleBasic) GetQueryCmd() *cobra.Command {
	return GetQueryCmd()
}

// AppModule implements the AppModule interface for the pouw module.
type AppModule struct {
	AppModuleBasic

	keeper *keeper.Keeper
}

// NewAppModule creates a new AppModule object.
func NewAppModule(cdc codec.Codec, k *keeper.Keeper) *AppModule {
	return &AppModule{
		AppModuleBasic: AppModuleBasic{},
		keeper:         k,
	}
}

// Name returns the module's name.
func (am *AppModule) Name() string {
	return types.ModuleName
}

// RegisterServices registers module services.
func (am *AppModule) RegisterServices(cfg module.Configurator) {
	// Register msg server
	types.RegisterMsgServer(cfg.MsgServer(), keeper.NewMsgServerImpl(*am.keeper))

	// Register query server
	types.RegisterQueryServer(cfg.QueryServer(), keeper.NewQueryServerImpl(*am.keeper))

	// Register migrations
	k := am.keeper
	if err := cfg.RegisterMigration(types.ModuleName, 1, func(ctx sdk.Context) error {
		return keeper.RunMigrations(ctx, *k, 1, 2)
	}); err != nil {
		panic(err)
	}
}

// RegisterInvariants registers the module's invariants.
func (am *AppModule) RegisterInvariants(ir sdk.InvariantRegistry) {
	keeper.RegisterInvariants(ir, *am.keeper)
}

// InitGenesis performs the module's genesis initialization.
func (am *AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, gs json.RawMessage) []abci.ValidatorUpdate {
	var genesisState types.GenesisState
	cdc.MustUnmarshalJSON(gs, &genesisState)

	if err := am.keeper.InitGenesis(ctx, &genesisState); err != nil {
		panic(err)
	}

	return []abci.ValidatorUpdate{}
}

// ExportGenesis returns the module's exported genesis state.
func (am *AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	gs, err := am.keeper.ExportGenesis(ctx)
	if err != nil {
		panic(err)
	}
	return cdc.MustMarshalJSON(gs)
}

// ConsensusVersion implements AppModule/ConsensusVersion.
func (am *AppModule) ConsensusVersion() uint64 { return keeper.ModuleConsensusVersion }

// BeginBlock executes all ABCI BeginBlock logic.
func (am *AppModule) BeginBlock(ctx context.Context) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Process any pending jobs that have reached consensus
	// This is handled by the ABCI++ vote extensions in app/abci.go
	_ = sdkCtx

	return nil
}

// EndBlock executes all ABCI EndBlock logic.
func (am *AppModule) EndBlock(ctx context.Context) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Apply deterministic block-height-based timeouts before the app-level
	// scheduler rebuilds its cache. GetOpenJobs deliberately includes overdue
	// entries; GetPendingJobs filters them and therefore cannot drive cleanup.
	openJobs, err := am.keeper.GetOpenJobs(sdkCtx)
	if err != nil {
		return err
	}
	params, err := am.keeper.GetParams(ctx)
	if err != nil {
		return fmt.Errorf("load PoUW timeout params: %w", err)
	}
	if params == nil || params.JobTimeoutBlocks <= 0 {
		return fmt.Errorf("invalid PoUW job timeout parameter")
	}

	currentHeight := sdkCtx.BlockHeight()
	for _, job := range openJobs {
		if job == nil {
			continue
		}
		if currentHeight <= job.BlockHeight ||
			currentHeight-job.BlockHeight <= params.JobTimeoutBlocks {
			continue
		}

		eventType := "job_expired"
		switch job.Status {
		case types.JobStatusPending:
			if err := job.MarkExpiredAt(sdkCtx.BlockTime()); err != nil {
				return fmt.Errorf("expire pending job %s: %w", job.Id, err)
			}
		case types.JobStatusProcessing:
			// Processing → Expired is not a valid state-machine edge. A job
			// that failed to reach verification finality before the governed
			// timeout is terminally failed instead.
			eventType = "job_timed_out"
			if err := job.MarkFailedAt(sdkCtx.BlockTime()); err != nil {
				return fmt.Errorf("fail timed-out processing job %s: %w", job.Id, err)
			}
		default:
			return fmt.Errorf("unexpected open job status %s for %s", job.Status, job.Id)
		}

		if err := am.keeper.UpdateJob(ctx, job); err != nil {
			return fmt.Errorf("persist timed-out job %s: %w", job.Id, err)
		}

		sdkCtx.EventManager().EmitEvent(
			sdk.NewEvent(
				eventType,
				sdk.NewAttribute("job_id", job.Id),
				sdk.NewAttribute("block_height", fmt.Sprintf("%d", currentHeight)),
			),
		)
	}

	return nil
}

// IsOnePerModuleType implements the depinject.OnePerModuleType interface.
func (am *AppModule) IsOnePerModuleType() {}

// IsAppModule implements the appmodule.AppModule interface.
func (am *AppModule) IsAppModule() {}

// GetTxCmd returns the transaction commands for the module
func GetTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      fmt.Sprintf("%s transactions subcommands", types.ModuleName),
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	// Add tx commands here
	// cmd.AddCommand(CmdSubmitJob())
	// cmd.AddCommand(CmdRegisterModel())
	cmd.AddCommand(cli.CmdStakeForPoUW())
	cmd.AddCommand(cli.CmdRegisterValidatorCapability())
	cmd.AddCommand(cli.CmdRegisterValidatorPCR0())

	return cmd
}

// GetQueryCmd returns the query commands for the module
func GetQueryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      fmt.Sprintf("Querying commands for the %s module", types.ModuleName),
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	// Add query commands here
	// cmd.AddCommand(CmdQueryJob())
	// cmd.AddCommand(CmdListJobs())
	cmd.AddCommand(cli.CmdQueryPoUWStatus())
	cmd.AddCommand(cli.CmdQueryValidatorPCR0())
	cmd.AddCommand(cli.CmdQueryIsPCR0Registered())

	return cmd
}
