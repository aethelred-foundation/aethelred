package app

import (
	"fmt"

	addresscodec "cosmossdk.io/core/address"
	"cosmossdk.io/x/tx/signing"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	"github.com/cosmos/cosmos-sdk/x/auth/tx"
	"github.com/cosmos/gogoproto/proto"
	protov2 "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	evmcryptocodec "github.com/cosmos/evm/crypto/codec"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	// Aethelred custom modules
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

// signerFromField returns a signing.GetSignersFunc that derives the signer from
// the named address field of a message. The Aethelred custom-module protos do not
// carry the (cosmos.msg.v1.signer) option, so the x/tx signing context cannot
// otherwise determine their signers and every custom-module tx fails CheckTx with
// "no cosmos.msg.v1.signer option found". This registers that getter in Go,
// matching each message's legacy GetSigners() field.
func signerFromField(codec addresscodec.Codec, field string) signing.GetSignersFunc {
	name := protoreflect.Name(field)
	return func(msg protov2.Message) ([][]byte, error) {
		m := msg.ProtoReflect()
		fd := m.Descriptor().Fields().ByName(name)
		if fd == nil {
			return nil, fmt.Errorf("signer field %q not found in %s", field, m.Descriptor().FullName())
		}
		bz, err := codec.StringToBytes(m.Get(fd).String())
		if err != nil {
			return nil, err
		}
		return [][]byte{bz}, nil
	}
}

// EncodingConfig specifies the concrete encoding types to use for the Aethelred app
type EncodingConfig struct {
	InterfaceRegistry types.InterfaceRegistry
	Codec             codec.Codec
	TxConfig          client.TxConfig
	Amino             *codec.LegacyAmino
}

// MakeEncodingConfig creates an EncodingConfig for the Aethelred app
func MakeEncodingConfig() EncodingConfig {
	amino := codec.NewLegacyAmino()
	// The interface registry MUST be built with address codecs. Without them,
	// any command that signs (notably `genesis gentx`) fails with
	// "InterfaceRegistry requires a proper address codec implementation to do
	// address conversion".
	accCodec := address.NewBech32Codec(AccountAddressPrefix)
	interfaceRegistry, err := types.NewInterfaceRegistryWithOptions(types.InterfaceRegistryOptions{
		ProtoFiles: proto.HybridResolver,
		SigningOptions: signing.Options{
			AddressCodec:          accCodec,
			ValidatorAddressCodec: address.NewBech32Codec(AccountAddressPrefix + "valoper"),
			// Custom-module protos lack the (cosmos.msg.v1.signer) option, so their
			// signers must be resolved explicitly (see signerFromField). The
			// cosmos/evm messages recover their signer from the Ethereum
			// signature itself, via the getters the module exports.
			CustomGetSigners: map[protoreflect.FullName]signing.GetSignersFunc{
				evmtypes.MsgEthereumTxCustomGetSigner.MsgType:      evmtypes.MsgEthereumTxCustomGetSigner.Fn,
				erc20types.MsgConvertERC20CustomGetSigner.MsgType:  erc20types.MsgConvertERC20CustomGetSigner.Fn,
				"aethelred.pouw.v1.MsgSubmitJob":                   signerFromField(accCodec, "creator"),
				"aethelred.pouw.v1.MsgRegisterModel":               signerFromField(accCodec, "owner"),
				"aethelred.pouw.v1.MsgCancelJob":                   signerFromField(accCodec, "creator"),
				"aethelred.pouw.v1.MsgRegisterValidatorCapability": signerFromField(accCodec, "creator"),
				"aethelred.pouw.v1.MsgRegisterValidatorPCR0":       signerFromField(accCodec, "creator"),
				"aethelred.pouw.v1.MsgRegisterValidatorHybridKey":  signerFromField(accCodec, "creator"),
				"aethelred.seal.v1.MsgCreateSeal":                  signerFromField(accCodec, "creator"),
				"aethelred.seal.v1.MsgRevokeSeal":                  signerFromField(accCodec, "authority"),
				"aethelred.verify.v1.MsgRegisterVerifyingKey":      signerFromField(accCodec, "creator"),
				"aethelred.verify.v1.MsgRegisterCircuit":           signerFromField(accCodec, "creator"),
				"aethelred.verify.v1.MsgVerifyZKProof":             signerFromField(accCodec, "verifier"),
			},
		},
	})
	if err != nil {
		panic(err)
	}

	// Register standard Cosmos SDK types
	std.RegisterLegacyAminoCodec(amino)
	std.RegisterInterfaces(interfaceRegistry)

	// Register all module interfaces (including Msg services) to avoid
	// MsgServiceRouter panics when app.New() registers services.
	ModuleBasics.RegisterInterfaces(interfaceRegistry)

	// Register Aethelred custom module types
	sealtypes.RegisterInterfaces(interfaceRegistry)
	pouwtypes.RegisterInterfaces(interfaceRegistry)
	verifytypes.RegisterInterfaces(interfaceRegistry)

	// Register the cosmos/evm crypto types (eth_secp256k1 pub/priv keys) so EVM
	// accounts unmarshal and sign; EVM module msg/tx types come via ModuleBasics.
	evmcryptocodec.RegisterInterfaces(interfaceRegistry)

	// Register legacy amino codecs for custom modules.
	// NOTE: evmcryptocodec.RegisterCrypto is NOT called — it re-registers the
	// std crypto amino types (already registered above) and panics with
	// "TypeInfo already exists". Amino registration of eth keys is only needed
	// for legacy amino signing (Ledger/EIP-712), which this chain does not use.
	sealtypes.RegisterLegacyAminoCodec(amino)
	pouwtypes.RegisterLegacyAminoCodec(amino)
	verifytypes.RegisterLegacyAminoCodec(amino)

	// Create the codec
	cdc := codec.NewProtoCodec(interfaceRegistry)

	// Create tx config
	txConfig := tx.NewTxConfig(cdc, tx.DefaultSignModes)

	return EncodingConfig{
		InterfaceRegistry: interfaceRegistry,
		Codec:             cdc,
		TxConfig:          txConfig,
		Amino:             amino,
	}
}
