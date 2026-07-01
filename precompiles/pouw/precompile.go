// Package pouw implements the IPoUW precompiled contract: read access to the
// Proof-of-Useful-Work job registry and the on-chain model registry, so
// contracts can walk job → seal → confidentiality attestation (with ISeal)
// without an oracle.
//
// Read-only by design: job submission / model registration are chain
// transactions; EVM-originated writes arrive with the cosmos/evm transaction
// layer (ADR-0001 Phase 1).
package pouw

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/precompiles/internal/prec"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

// Address is the fixed precompile address (0x0900 ISeal, 0x0901 IVerify,
// 0x0902 IPoUW).
var Address = common.HexToAddress("0x0000000000000000000000000000000000000902")

//go:embed abi.json
var abiJSON string

// Method names (must match abi.json / IPoUW.sol).
const (
	MethodGetJob         = "getJob"
	MethodGetModel       = "getModel"
	MethodIsModelActive  = "isModelActive"
	MethodIsJobCompleted = "isJobCompleted"
)

// Gas schedule: flat per-method read costs.
const (
	GasGetJob         = 3000
	GasGetModel       = 3000
	GasIsModelActive  = 2000
	GasIsJobCompleted = 2000
)

// JobReader is the state surface the precompile needs; x/pouw/keeper
// satisfies it.
type JobReader interface {
	GetJob(ctx context.Context, id string) (*pouwtypes.ComputeJob, error)
	GetRegisteredModel(ctx context.Context, modelHash []byte) (*pouwtypes.RegisteredModel, error)
}

// Precompile is the IPoUW precompiled contract.
type Precompile struct {
	abi    abi.ABI
	reader JobReader
}

// NewPrecompile parses the embedded ABI and binds the job reader.
func NewPrecompile(reader JobReader) (*Precompile, error) {
	if reader == nil {
		return nil, fmt.Errorf("ipouw: job reader required")
	}
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, fmt.Errorf("ipouw: parse ABI: %w", err)
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
	case MethodGetJob:
		return GasGetJob
	case MethodGetModel:
		return GasGetModel
	case MethodIsModelActive:
		return GasIsModelActive
	case MethodIsJobCompleted:
		return GasIsJobCompleted
	default:
		return 0
	}
}

// Run dispatches an ABI-encoded call against chain state.
func (p *Precompile) Run(ctx sdk.Context, input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("ipouw: input shorter than a method selector")
	}
	method, err := p.abi.MethodById(input[:4])
	if err != nil {
		return nil, fmt.Errorf("ipouw: unknown method selector: %w", err)
	}
	args, err := method.Inputs.Unpack(input[4:])
	if err != nil {
		return nil, fmt.Errorf("ipouw: %s: decode arguments: %w", method.Name, err)
	}

	switch method.Name {
	case MethodGetJob:
		return p.getJob(ctx, method, args)
	case MethodGetModel:
		return p.getModel(ctx, method, args)
	case MethodIsModelActive:
		return p.isModelActive(ctx, method, args)
	case MethodIsJobCompleted:
		return p.isJobCompleted(ctx, method, args)
	default:
		return nil, fmt.Errorf("ipouw: method %q not implemented", method.Name)
	}
}

func (p *Precompile) getJob(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	jobID, err := prec.StringArg(args, 0, "jobId")
	if err != nil {
		return nil, fmt.Errorf("ipouw: %w", err)
	}
	job, err := p.reader.GetJob(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("ipouw: %w", err)
	}
	return method.Outputs.Pack(
		uint8(job.Status), //nolint:gosec // enum range 0..5
		prec.ToBytes32(job.ModelHash),
		prec.ToBytes32(job.InputHash),
		prec.ToBytes32(job.OutputHash),
		job.RequestedBy,
		job.SealId,
		job.BlockHeight,
		job.UsefulWorkUnits,
	)
}

func (p *Precompile) getModel(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	hash, err := prec.Bytes32Arg(args, 0, "modelHash")
	if err != nil {
		return nil, fmt.Errorf("ipouw: %w", err)
	}
	model, err := p.reader.GetRegisteredModel(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("ipouw: %w", err)
	}
	return method.Outputs.Pack(
		model.IsActive,
		model.ModelId,
		model.Name,
		model.Version,
		model.Owner,
		prec.ToBytes32(model.CircuitHash),
		prec.ToBytes32(model.VerifyingKeyHash),
	)
}

func (p *Precompile) isModelActive(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	hash, err := prec.Bytes32Arg(args, 0, "modelHash")
	if err != nil {
		return nil, fmt.Errorf("ipouw: %w", err)
	}
	model, err := p.reader.GetRegisteredModel(ctx, hash)
	if err != nil {
		// Gating form: missing model is a clean false, not a revert.
		return method.Outputs.Pack(false)
	}
	return method.Outputs.Pack(model.IsActive)
}

func (p *Precompile) isJobCompleted(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	jobID, err := prec.StringArg(args, 0, "jobId")
	if err != nil {
		return nil, fmt.Errorf("ipouw: %w", err)
	}
	job, err := p.reader.GetJob(ctx, jobID)
	if err != nil {
		return method.Outputs.Pack(false)
	}
	return method.Outputs.Pack(job.Status == pouwtypes.JobStatusCompleted)
}
