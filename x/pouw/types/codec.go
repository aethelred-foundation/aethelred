package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
	"github.com/cosmos/cosmos-sdk/types/tx"
	gogoproto "github.com/cosmos/gogoproto/proto"
)

// The generated pb.go registers message types with the modern protoregistry,
// but the SDK's unknownproto tx-decode check (codec/unknownproto) resolves
// nested message types through gogoproto's legacy type registry. Msg request
// types are bridged into that registry by RegisterImplementations below, but a
// plain nested message used only as a Msg field is not — so a tx that populates
// such a field is rejected at decode with:
//
//	failed to retrieve the message of type "aethelred.pouw.v1.ConfidentialityPolicy"
//
// ConfidentialityPolicy is the sole nested-message field across pouw Msgs
// (MsgSubmitJob.confidentiality_policy). Registering it here makes CEAP-bound
// job submissions decodable — without it, --conf-* flags on submit-job always
// fail and no seal can carry a jurisdiction/backend policy. Guarded so repeated
// app construction (tests) does not double-register and panic.
func init() {
	if gogoproto.MessageType("aethelred.pouw.v1.ConfidentialityPolicy") == nil {
		gogoproto.RegisterType((*ConfidentialityPolicy)(nil), "aethelred.pouw.v1.ConfidentialityPolicy")
	}
}

// ModuleCdc is the codec for the module
var ModuleCdc = codec.NewProtoCodec(cdctypes.NewInterfaceRegistry())

// RegisterLegacyAminoCodec registers the necessary interfaces and concrete types
// for amino serialization.
func RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	cdc.RegisterConcrete(&MsgSubmitJob{}, "aethelred/pouw/MsgSubmitJob", nil)
	cdc.RegisterConcrete(&MsgRegisterModel{}, "aethelred/pouw/MsgRegisterModel", nil)
	cdc.RegisterConcrete(&MsgCancelJob{}, "aethelred/pouw/MsgCancelJob", nil)
	cdc.RegisterConcrete(&MsgRegisterValidatorCapability{}, "aethelred/pouw/MsgRegisterValidatorCapability", nil)
	cdc.RegisterConcrete(&MsgRegisterValidatorPCR0{}, "aethelred/pouw/MsgRegisterValidatorPCR0", nil)
	cdc.RegisterConcrete(&MsgRegisterValidatorHybridKey{}, "aethelred/pouw/MsgRegisterValidatorHybridKey", nil)
}

// RegisterInterfaces registers the interfaces types with the interface registry.
func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgSubmitJob{},
		&MsgRegisterModel{},
		&MsgCancelJob{},
		&MsgRegisterValidatorCapability{},
		&MsgRegisterValidatorPCR0{},
		&MsgRegisterValidatorHybridKey{},
	)

	registry.RegisterImplementations((*tx.MsgResponse)(nil),
		&MsgSubmitJobResponse{},
		&MsgRegisterModelResponse{},
		&MsgCancelJobResponse{},
		&MsgRegisterValidatorCapabilityResponse{},
		&MsgRegisterValidatorPCR0Response{},
		&MsgRegisterValidatorHybridKeyResponse{},
	)

	// Best-effort registration: avoid panic when proto descriptors are not
	// registered via gogoproto in certain builds/tests.
	func() {
		defer func() {
			_ = recover()
		}()
		msgservice.RegisterMsgServiceDesc(registry, &Msg_ServiceDesc)
	}()
}
