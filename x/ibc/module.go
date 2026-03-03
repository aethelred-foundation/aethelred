// Package ibc implements the Aethelred IBC (Inter-Blockchain Communication)
// module for cross-chain proof relay.
//
// This module enables Aethelred to interoperate with the Cosmos ecosystem (50+
// chains) by relaying verified AI computation results (TEE attestations and ZK
// proofs) through standardized IBC channels.
//
// Capabilities:
//   - Relay verified computation proofs to any IBC-connected chain
//   - Receive computation requests from external chains
//   - Subscribe to ongoing proof notifications
//   - Cross-chain proof verification with full consensus evidence
//   - BLS aggregate signature support for compact consensus proofs
//
// This gives Aethelred access to the entire Cosmos ecosystem with standardized
// security guarantees, complementing the existing custom Ethereum bridge.
package ibc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"

	"github.com/aethelred/aethelred/x/ibc/keeper"
	"github.com/aethelred/aethelred/x/ibc/types"
)

var (
	_ module.AppModuleBasic = AppModuleBasic{}
	_ module.AppModule      = AppModule{}
)

// =============================================================================
// AppModuleBasic
// =============================================================================

// AppModuleBasic implements the AppModuleBasic interface for the IBC module.
type AppModuleBasic struct{}

// Name returns the module's name
func (AppModuleBasic) Name() string {
	return types.ModuleName
}

// RegisterLegacyAminoCodec registers the module's types on the Amino codec
func (AppModuleBasic) RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	types.RegisterLegacyAminoCodec(cdc)
}

// RegisterInterfaces registers the module's interface types
func (AppModuleBasic) RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	types.RegisterInterfaces(registry)
}

// DefaultGenesis returns the module's default genesis state
func (AppModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	gs := types.DefaultGenesis()
	data, _ := json.Marshal(gs)
	return data
}

// ValidateGenesis validates the module's genesis state
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, _ client.TxEncodingConfig, bz json.RawMessage) error {
	var gs types.GenesisState
	if err := json.Unmarshal(bz, &gs); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}
	return gs.Validate()
}

// RegisterGRPCGatewayRoutes registers the gRPC Gateway routes for the module.
func (AppModuleBasic) RegisterGRPCGatewayRoutes(clientCtx client.Context, mux *runtime.ServeMux) {
}

// =============================================================================
// AppModule
// =============================================================================

// AppModule implements the AppModule interface for the IBC module.
type AppModule struct {
	AppModuleBasic
	keeper keeper.Keeper
}

// NewAppModule creates a new AppModule
func NewAppModule(cdc codec.Codec, keeper keeper.Keeper) AppModule {
	return AppModule{
		AppModuleBasic: AppModuleBasic{},
		keeper:         keeper,
	}
}

// RegisterServices registers the module's gRPC services
func (am AppModule) RegisterServices(cfg module.Configurator) {
	// Message and query servers will be registered here once proto types
	// are generated. For now, the keeper methods are called directly by
	// the IBC middleware/callbacks.
}

// RegisterInvariants registers module invariants
func (am AppModule) RegisterInvariants(ir sdk.InvariantRegistry) {}

// InitGenesis initializes the module's genesis state
func (am AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, data json.RawMessage) {
	var gs types.GenesisState
	if err := json.Unmarshal(data, &gs); err != nil {
		panic(fmt.Sprintf("failed to unmarshal %s genesis state: %v", types.ModuleName, err))
	}
	am.keeper.InitGenesis(ctx, &gs)
}

// ExportGenesis exports the module's genesis state
func (am AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	gs := am.keeper.ExportGenesis(ctx)
	data, _ := json.Marshal(gs)
	return data
}

// ConsensusVersion returns the module's consensus version
func (am AppModule) ConsensusVersion() uint64 {
	return 1
}

// BeginBlock executes logic at the beginning of each block
func (am AppModule) BeginBlock(_ context.Context) error {
	return nil
}

// EndBlock executes logic at the end of each block.
// This is where we check for newly finalized proofs and notify IBC subscribers.
func (am AppModule) EndBlock(_ context.Context) error {
	// In a full implementation, this would:
	// 1. Query the seal/verify module for newly finalized proofs
	// 2. Check against active subscriptions
	// 3. Auto-relay matching proofs to subscriber channels
	//
	// For now, proof relay is initiated explicitly via MsgRelayProof.
	return nil
}

// IsOnePerModuleType implements the depinject.OnePerModuleType interface.
func (am AppModule) IsOnePerModuleType() {}

// IsAppModule implements the appmodule.AppModule interface.
func (am AppModule) IsAppModule() {}

// =============================================================================
// IBC Module Callbacks (IBCModule interface)
// =============================================================================

// IBCModule wraps the keeper to implement the IBC module callback interface.
type IBCModule struct {
	keeper keeper.Keeper
}

// NewIBCModule creates a new IBCModule
func NewIBCModule(k keeper.Keeper) IBCModule {
	return IBCModule{keeper: k}
}

// OnChanOpenInit implements the IBCModule interface
func (m IBCModule) OnChanOpenInit(
	ctx sdk.Context,
	channelID string,
	portID string,
	version string,
	connectionID string,
) (string, error) {
	if err := m.keeper.OnChanOpenInit(ctx, channelID, portID, version, connectionID); err != nil {
		return "", err
	}
	return types.Version, nil
}

// OnChanOpenTry implements the IBCModule interface
func (m IBCModule) OnChanOpenTry(
	ctx sdk.Context,
	channelID string,
	portID string,
	counterpartyVersion string,
	connectionID string,
) (string, error) {
	return m.keeper.OnChanOpenTry(ctx, channelID, portID, counterpartyVersion, connectionID)
}

// OnChanOpenAck implements the IBCModule interface
func (m IBCModule) OnChanOpenAck(
	ctx sdk.Context,
	channelID string,
	portID string,
	counterpartyChannelID string,
	counterpartyVersion string,
) error {
	return m.keeper.OnChanOpenAck(ctx, channelID, portID, counterpartyChannelID, counterpartyVersion)
}

// OnChanOpenConfirm implements the IBCModule interface
func (m IBCModule) OnChanOpenConfirm(
	ctx sdk.Context,
	channelID string,
	portID string,
) error {
	return m.keeper.OnChanOpenConfirm(ctx, channelID, portID)
}

// OnChanCloseInit implements the IBCModule interface
func (m IBCModule) OnChanCloseInit(
	ctx sdk.Context,
	channelID string,
	portID string,
) error {
	return m.keeper.OnChanCloseInit(ctx, channelID, portID)
}

// OnChanCloseConfirm implements the IBCModule interface
func (m IBCModule) OnChanCloseConfirm(
	ctx sdk.Context,
	channelID string,
	portID string,
) error {
	return m.keeper.OnChanCloseConfirm(ctx, channelID, portID)
}

// OnRecvPacket implements the IBCModule interface
func (m IBCModule) OnRecvPacket(
	ctx sdk.Context,
	packetData []byte,
	channelID string,
	sequence uint64,
) ([]byte, error) {
	return m.keeper.OnRecvPacket(ctx, packetData, channelID, sequence)
}

// OnAcknowledgementPacket implements the IBCModule interface
func (m IBCModule) OnAcknowledgementPacket(
	ctx sdk.Context,
	packetData []byte,
	ackData []byte,
	channelID string,
	sequence uint64,
) error {
	return m.keeper.OnAcknowledgementPacket(ctx, packetData, ackData, channelID, sequence)
}

// OnTimeoutPacket implements the IBCModule interface
func (m IBCModule) OnTimeoutPacket(
	ctx sdk.Context,
	packetData []byte,
	channelID string,
	sequence uint64,
) error {
	return m.keeper.OnTimeoutPacket(ctx, packetData, channelID, sequence)
}
