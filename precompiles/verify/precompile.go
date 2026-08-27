// Package verify implements the IVerify precompiled contract: read access to
// the on-chain zkML registry (circuits, Groth16 verifying keys) so contracts
// can require that results were proven against registered key material.
//
// Read-only by design: registration is a chain transaction, and heavy pairing
// checks stay asynchronous in the PoUW verification path — never synchronous
// inside a precompile (DoS surface, see ADR-0001).
package verify

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/precompiles/internal/prec"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

// Address is the fixed precompile address (0x0900 ISeal, 0x0901 IVerify,
// 0x0902 IPoUW).
var Address = common.HexToAddress("0x0000000000000000000000000000000000000901")

//go:embed abi.json
var abiJSON string

// Method names (must match abi.json / IVerify.sol).
const (
	MethodGetCircuit      = "getCircuit"
	MethodGetVerifyingKey = "getVerifyingKey"
	MethodIsCircuitActive = "isCircuitActive"
)

// Gas schedule: flat per-method read costs.
const (
	GasGetCircuit      = 3000
	GasGetVerifyingKey = 3000
	GasIsCircuitActive = 2000
)

// RegistryReader is the state surface the precompile needs; x/verify/keeper
// satisfies it.
type RegistryReader interface {
	GetCircuit(ctx context.Context, hash []byte) (*verifytypes.Circuit, error)
	GetVerifyingKey(ctx context.Context, hash []byte) (*verifytypes.VerifyingKey, error)
}

// Precompile is the IVerify precompiled contract.
type Precompile struct {
	abi    abi.ABI
	reader RegistryReader
}

// NewPrecompile parses the embedded ABI and binds the registry reader.
func NewPrecompile(reader RegistryReader) (*Precompile, error) {
	if reader == nil {
		return nil, fmt.Errorf("iverify: registry reader required")
	}
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, fmt.Errorf("iverify: parse ABI: %w", err)
	}
	return &Precompile{abi: parsed, reader: reader}, nil
}

// ABI exposes the parsed ABI.
func (p *Precompile) ABI() abi.ABI { return p.abi }

// RequiredGas implements the go-ethereum PrecompiledContract gas hook.
func (p *Precompile) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return 0
	}
	method, err := p.abi.MethodById(input[:4])
	if err != nil {
		return 0
	}
	switch method.Name {
	case MethodGetCircuit:
		return GasGetCircuit
	case MethodGetVerifyingKey:
		return GasGetVerifyingKey
	case MethodIsCircuitActive:
		return GasIsCircuitActive
	default:
		return 0
	}
}

// Run dispatches an ABI-encoded call against chain state.
func (p *Precompile) Run(ctx sdk.Context, input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("iverify: input shorter than a method selector")
	}
	method, err := p.abi.MethodById(input[:4])
	if err != nil {
		return nil, fmt.Errorf("iverify: unknown method selector: %w", err)
	}
	args, err := method.Inputs.Unpack(input[4:])
	if err != nil {
		return nil, fmt.Errorf("iverify: %s: decode arguments: %w", method.Name, err)
	}

	switch method.Name {
	case MethodGetCircuit:
		return p.getCircuit(ctx, method, args)
	case MethodGetVerifyingKey:
		return p.getVerifyingKey(ctx, method, args)
	case MethodIsCircuitActive:
		return p.isCircuitActive(ctx, method, args)
	default:
		return nil, fmt.Errorf("iverify: method %q not implemented", method.Name)
	}
}

func (p *Precompile) getCircuit(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	hash, err := prec.Bytes32Arg(args, 0, "circuitHash")
	if err != nil {
		return nil, fmt.Errorf("iverify: %w", err)
	}
	circuit, err := p.reader.GetCircuit(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("iverify: %w", err)
	}
	var ts uint64
	if circuit.RegisteredAt != nil {
		ts = uint64(circuit.RegisteredAt.AsTime().Unix()) //nolint:gosec // post-1970
	}
	return method.Outputs.Pack(
		circuit.IsActive,
		circuit.ProofSystem,
		prec.ToBytes32(circuit.ModelHash),
		circuit.RegisteredBy,
		ts,
	)
}

func (p *Precompile) getVerifyingKey(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	hash, err := prec.Bytes32Arg(args, 0, "vkHash")
	if err != nil {
		return nil, fmt.Errorf("iverify: %w", err)
	}
	vk, err := p.reader.GetVerifyingKey(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("iverify: %w", err)
	}
	var ts uint64
	if vk.RegisteredAt != nil {
		ts = uint64(vk.RegisteredAt.AsTime().Unix()) //nolint:gosec // post-1970
	}
	return method.Outputs.Pack(
		vk.IsActive,
		vk.ProofSystem,
		prec.ToBytes32(vk.CircuitHash),
		prec.ToBytes32(vk.ModelHash),
		vk.RegisteredBy,
		ts,
	)
}

func (p *Precompile) isCircuitActive(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	hash, err := prec.Bytes32Arg(args, 0, "circuitHash")
	if err != nil {
		return nil, fmt.Errorf("iverify: %w", err)
	}
	circuit, err := p.reader.GetCircuit(ctx, hash)
	if err != nil {
		// Gating form: missing circuit is a clean false, not a revert.
		return method.Outputs.Pack(false)
	}
	return method.Outputs.Pack(circuit.IsActive)
}
