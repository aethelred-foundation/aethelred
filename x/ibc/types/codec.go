package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ModuleCdc is the codec for the module
var ModuleCdc = codec.NewProtoCodec(cdctypes.NewInterfaceRegistry())

// RegisterLegacyAminoCodec registers Amino codec types
func RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	cdc.RegisterConcrete(&MsgRelayProof{}, "aethelred/ibc/MsgRelayProof", nil)
	cdc.RegisterConcrete(&MsgRequestProof{}, "aethelred/ibc/MsgRequestProof", nil)
	cdc.RegisterConcrete(&MsgSubscribeProofs{}, "aethelred/ibc/MsgSubscribeProofs", nil)
}

// RegisterInterfaces registers protobuf interface implementations
func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgRelayProof{},
		&MsgRequestProof{},
		&MsgSubscribeProofs{},
	)
}
