// Package seal implements the ISeal precompiled contract (ADR-0003 step 3):
// it exposes Digital Seals — including the CEAP confidentiality attestation —
// to Solidity at a fixed address, so contracts can gate value transfer on
// verifiable-AI facts ("this inference ran under TEE, vendor-root, in the EU")
// with no oracle in the loop.
//
// The ABI layer, method dispatch, gas schedule, and keeper-backed reads are
// complete and fully tested here. Mounting into the EVM is the thin adapter
// left to the cosmos/evm integration (ADR-0001 Phase 1): the host extracts
// sdk.Context from its StateDB and calls Run — the contract surface defined by
// ISeal.sol and abi.json does not change.
package seal

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/internal/attestation"
	"github.com/aethelred/aethelred/internal/confidential"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// Address is the fixed precompile address. Aethelred verifiable-AI range:
// 0x0900 ISeal, 0x0901 IVerify (reserved), 0x0902 IPoUW (reserved).
var Address = common.HexToAddress("0x0000000000000000000000000000000000000900")

//go:embed abi.json
var abiJSON string

// Method names (must match abi.json / ISeal.sol).
const (
	MethodGetSeal                = "getSeal"
	MethodGetConfidentiality     = "getConfidentiality"
	MethodGetSealIDByJob         = "getSealIdByJob"
	MethodVerifySeal             = "verifySeal"
	MethodRequireConfidentiality = "requireConfidentiality"
)

// Gas schedule: flat per-method read costs, in the same band as cosmos-sdk
// precompile reads. requireConfidentiality pays extra for policy evaluation.
const (
	GasGetSeal                = 3000
	GasGetConfidentiality     = 3000
	GasGetSealIDByJob         = 3000
	GasVerifySeal             = 2000
	GasRequireConfidentiality = 5000
)

// SealReader is the state surface the precompile needs; *x/seal/keeper.Keeper
// satisfies it. Methods take context.Context (sdk.Context implements it), so
// the keeper is used directly with no adapter.
type SealReader interface {
	GetSeal(ctx context.Context, id string) (*sealtypes.DigitalSeal, error)
	GetSealByJob(ctx context.Context, jobID string) (*sealtypes.DigitalSeal, error)
}

// Precompile is the ISeal precompiled contract.
type Precompile struct {
	abi    abi.ABI
	reader SealReader
}

// NewPrecompile parses the embedded ABI and binds the seal reader.
func NewPrecompile(reader SealReader) (*Precompile, error) {
	if reader == nil {
		return nil, fmt.Errorf("iseal: seal reader required")
	}
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, fmt.Errorf("iseal: parse ABI: %w", err)
	}
	return &Precompile{abi: parsed, reader: reader}, nil
}

// ABI exposes the parsed ABI (callers pack inputs / unpack outputs with it).
func (p *Precompile) ABI() abi.ABI { return p.abi }

// RequiredGas implements the go-ethereum PrecompiledContract gas hook.
// Unknown selectors report 0 — Run will reject them.
func (p *Precompile) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return 0
	}
	method, err := p.abi.MethodById(input[:4])
	if err != nil {
		return 0
	}
	switch method.Name {
	case MethodGetSeal:
		return GasGetSeal
	case MethodGetConfidentiality:
		return GasGetConfidentiality
	case MethodGetSealIDByJob:
		return GasGetSealIDByJob
	case MethodVerifySeal:
		return GasVerifySeal
	case MethodRequireConfidentiality:
		return GasRequireConfidentiality
	default:
		return 0
	}
}

// Run dispatches an ABI-encoded call against chain state. The host EVM
// supplies the sdk.Context (read-only view of the current block's state).
func (p *Precompile) Run(ctx sdk.Context, input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("iseal: input shorter than a method selector")
	}
	method, err := p.abi.MethodById(input[:4])
	if err != nil {
		return nil, fmt.Errorf("iseal: unknown method selector: %w", err)
	}
	args, err := method.Inputs.Unpack(input[4:])
	if err != nil {
		return nil, fmt.Errorf("iseal: %s: decode arguments: %w", method.Name, err)
	}

	switch method.Name {
	case MethodGetSeal:
		return p.getSeal(ctx, method, args)
	case MethodGetConfidentiality:
		return p.getConfidentiality(ctx, method, args)
	case MethodGetSealIDByJob:
		return p.getSealIDByJob(ctx, method, args)
	case MethodVerifySeal:
		return p.verifySeal(ctx, method, args)
	case MethodRequireConfidentiality:
		return p.requireConfidentiality(ctx, method, args)
	default:
		return nil, fmt.Errorf("iseal: method %q not implemented", method.Name)
	}
}

// ── methods ───────────────────────────────────────────────────────────────────

func (p *Precompile) getSeal(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	sealID, err := stringArg(args, 0, "sealId")
	if err != nil {
		return nil, err
	}
	seal, err := p.reader.GetSeal(ctx, sealID)
	if err != nil {
		return nil, fmt.Errorf("iseal: %w", err)
	}
	var ts uint64
	if seal.Timestamp != nil {
		ts = uint64(seal.Timestamp.AsTime().Unix())
	}
	return method.Outputs.Pack(
		toBytes32(seal.ModelCommitment),
		toBytes32(seal.InputCommitment),
		toBytes32(seal.OutputCommitment),
		int64(seal.BlockHeight),
		ts,
		seal.RequestedBy,
		seal.Purpose,
		uint8(seal.Status), //nolint:gosec // enum range 0..4
		seal.JobId,
	)
}

func (p *Precompile) getConfidentiality(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	sealID, err := stringArg(args, 0, "sealId")
	if err != nil {
		return nil, err
	}
	seal, err := p.reader.GetSeal(ctx, sealID)
	if err != nil {
		return nil, fmt.Errorf("iseal: %w", err)
	}
	c := seal.Confidentiality
	if c == nil {
		// Pre-CEAP seals carry no attestation: report the honest zero posture.
		c = &sealtypes.ConfidentialityAttestation{
			Backend:      string(confidential.BackendNone),
			Verification: string(confidential.VerificationNone),
		}
	}
	return method.Outputs.Pack(
		c.Backend, c.Verification, c.Platform,
		nonNilBytes(c.Measurement), c.TrustBasis, c.Jurisdiction,
		c.DataSealed, nonNilBytes(c.PolicyHash), c.Worker,
	)
}

func (p *Precompile) getSealIDByJob(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	jobID, err := stringArg(args, 0, "jobId")
	if err != nil {
		return nil, err
	}
	seal, err := p.reader.GetSealByJob(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("iseal: %w", err)
	}
	return method.Outputs.Pack(seal.Id)
}

func (p *Precompile) verifySeal(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	sealID, err := stringArg(args, 0, "sealId")
	if err != nil {
		return nil, err
	}
	seal, err := p.reader.GetSeal(ctx, sealID)
	if err != nil {
		// A missing seal is not a revert for verifySeal — it is "not valid".
		return method.Outputs.Pack(false)
	}
	return method.Outputs.Pack(seal.Status == sealtypes.SealStatus_SEAL_STATUS_ACTIVE)
}

func (p *Precompile) requireConfidentiality(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	if len(args) != 6 {
		return nil, fmt.Errorf("iseal: requireConfidentiality expects 6 arguments, got %d", len(args))
	}
	sealID, err := stringArg(args, 0, "sealId")
	if err != nil {
		return nil, err
	}
	allowedBackends, err := stringSliceArg(args, 1, "allowedBackends")
	if err != nil {
		return nil, err
	}
	minVerification, err := stringArg(args, 2, "minVerification")
	if err != nil {
		return nil, err
	}
	allowedPlatforms, err := stringSliceArg(args, 3, "allowedPlatforms")
	if err != nil {
		return nil, err
	}
	requireVendorRoot, ok := args[4].(bool)
	if !ok {
		return nil, fmt.Errorf("iseal: argument requireVendorRoot is not a bool")
	}
	dataResidency, err := stringSliceArg(args, 5, "dataResidency")
	if err != nil {
		return nil, err
	}

	seal, err := p.reader.GetSeal(ctx, sealID)
	if err != nil {
		return nil, fmt.Errorf("iseal: %w", err)
	}

	// Build the CEAP policy and attestation and run the SAME Satisfies check
	// consensus ran when the seal was minted — bit-identical semantics.
	policy := confidential.ConfidentialityPolicy{
		MinVerification:   confidential.Verification(minVerification),
		RequireVendorRoot: requireVendorRoot,
	}
	for _, b := range allowedBackends {
		policy.AllowedBackends = append(policy.AllowedBackends, confidential.Backend(b))
	}
	for _, pl := range allowedPlatforms {
		policy.AllowedPlatforms = append(policy.AllowedPlatforms, attestation.Platform(pl))
	}
	for _, j := range dataResidency {
		policy.DataResidency = append(policy.DataResidency, confidential.Jurisdiction(j))
	}

	att := confidential.ConfidentialityAttestation{Backend: confidential.BackendNone, Verification: confidential.VerificationNone}
	if c := seal.Confidentiality; c != nil {
		att = confidential.ConfidentialityAttestation{
			Backend:      confidential.Backend(c.Backend),
			Verification: confidential.Verification(c.Verification),
			Platform:     attestation.Platform(c.Platform),
			Measurement:  c.Measurement,
			TrustBasis:   attestation.TrustBasis(c.TrustBasis),
			Jurisdiction: confidential.Jurisdiction(c.Jurisdiction),
			DataSealed:   c.DataSealed,
			PolicyHash:   c.PolicyHash,
			Worker:       c.Worker,
		}
	}

	if satErr := att.Satisfies(policy); satErr != nil {
		return method.Outputs.Pack(false, satErr.Error())
	}
	return method.Outputs.Pack(true, "")
}

// ── argument / encoding helpers ───────────────────────────────────────────────

func stringArg(args []interface{}, i int, name string) (string, error) {
	if i >= len(args) {
		return "", fmt.Errorf("iseal: missing argument %s", name)
	}
	s, ok := args[i].(string)
	if !ok {
		return "", fmt.Errorf("iseal: argument %s is not a string", name)
	}
	return s, nil
}

func stringSliceArg(args []interface{}, i int, name string) ([]string, error) {
	if i >= len(args) {
		return nil, fmt.Errorf("iseal: missing argument %s", name)
	}
	s, ok := args[i].([]string)
	if !ok {
		return nil, fmt.Errorf("iseal: argument %s is not a string[]", name)
	}
	return s, nil
}

// toBytes32 copies a commitment into a fixed 32-byte word (zero-padded /
// truncated — commitments on this chain are sha256, exactly 32 bytes).
func toBytes32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], b)
	return out
}

// nonNilBytes maps nil to an empty slice so ABI packing never sees nil.
func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
