// Package evmhost embeds the real go-ethereum EVM interpreter (core/vm) as the
// execution layer for Aethelred's verifiable-AI precompiles (ADR-0001 Phase 1,
// execution-layer half). It mounts context-aware precompiles (ISeal at 0x0900)
// into the interpreter's precompile map, so real Solidity bytecode CALLs them
// exactly like a built-in contract — no oracle, no mock interpreter.
//
// Scope, stated honestly: this is the EVM EXECUTION layer against real chain
// state. The full cosmos/evm module (EVM transactions, JSON-RPC, ante
// handlers, feemarket) requires cosmos-sdk v0.53 — every cosmos/evm release
// pins SDK ≥ v0.53 plus a forked go-ethereum — while this chain runs SDK
// v0.50.14 with a live testnet. Hosting EVM transactions therefore lands with
// the SDK v0.53 upgrade; the precompiles, their ABI surface, and this
// execution layer carry over unchanged (cosmos/evm wraps the same core/vm and
// exposes the same SetPrecompiles-style extension point).
package evmhost

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// AethelredChainID is the EVM chain id the dApp stack targets (Wallet,
// Cruzible, ZeroID, TerraQura are configured for 7332).
const AethelredChainID = 7332

// ContextPrecompile is a chain-state-aware precompiled contract: geth's
// PrecompiledContract plus the sdk.Context the read path needs. The ISeal
// precompile (precompiles/seal) implements it directly.
type ContextPrecompile interface {
	RequiredGas(input []byte) uint64
	Run(ctx sdk.Context, input []byte) ([]byte, error)
}

// boundPrecompile adapts a ContextPrecompile to the cosmos/evm-fork
// vm.PrecompiledContract interface by binding an injected sdk.Context for the
// duration of one EVM execution. Unlike the app-path adapter (precompiles/evm,
// which sources ctx from the cosmos StateDB), this standalone test host injects
// the ctx directly — the harness is not driven by a cosmos StateDB.
type boundPrecompile struct {
	addr common.Address
	p    ContextPrecompile
	ctx  sdk.Context
}

func (b boundPrecompile) Address() common.Address         { return b.addr }
func (b boundPrecompile) RequiredGas(input []byte) uint64 { return b.p.RequiredGas(input) }
func (b boundPrecompile) Run(_ *vm.EVM, contract *vm.Contract, _ bool) ([]byte, error) {
	return b.p.Run(b.ctx, contract.Input)
}

// Host is an embedded EVM with Aethelred precompiles mounted. EVM accounts,
// code, and storage live in the host's StateDB; verifiable-AI state (seals)
// is read through the mounted precompiles from the Cosmos multistore via the
// per-call sdk.Context.
type Host struct {
	chainConfig *params.ChainConfig
	statedb     *state.StateDB
	mounts      map[common.Address]ContextPrecompile
	gasLimit    uint64
}

// NewHost builds a host with every supported fork active (post-merge rules,
// PUSH0 available) and the given chain id.
func NewHost(chainID int64) (*Host, error) {
	if chainID <= 0 {
		return nil, fmt.Errorf("evmhost: chain id must be positive, got %d", chainID)
	}
	cfg := *params.MergedTestChainConfig // copy — every fork enabled at genesis
	cfg.ChainID = big.NewInt(chainID)

	sdb, err := state.New(gethtypes.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		return nil, fmt.Errorf("evmhost: state: %w", err)
	}
	return &Host{
		chainConfig: &cfg,
		statedb:     sdb,
		mounts:      make(map[common.Address]ContextPrecompile),
		gasLimit:    30_000_000,
	}, nil
}

// Mount installs a context-aware precompile at addr (last mount wins).
func (h *Host) Mount(addr common.Address, p ContextPrecompile) {
	h.mounts[addr] = p
}

// Mounted reports the mounted precompile addresses.
func (h *Host) Mounted() []common.Address {
	out := make([]common.Address, 0, len(h.mounts))
	for a := range h.mounts {
		out = append(out, a)
	}
	return out
}

// FundAccount credits an EVM account (dev/test plumbing for value transfers).
func (h *Host) FundAccount(addr common.Address, amount *uint256.Int) {
	h.statedb.AddBalance(addr, amount, tracing.BalanceChangeUnspecified)
}

// newEVM builds a fresh interpreter for one execution, with the default
// precompile set extended by the mounted Aethelred precompiles bound to ctx.
func (h *Host) newEVM(ctx sdk.Context) *vm.EVM {
	random := common.Hash{} // non-nil => post-merge rules
	blockCtx := vm.BlockContext{
		CanTransfer: func(db vm.StateDB, addr common.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db vm.StateDB, from, to common.Address, amount *uint256.Int) {
			db.SubBalance(from, amount, tracing.BalanceChangeUnspecified)
			db.AddBalance(to, amount, tracing.BalanceChangeUnspecified)
		},
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.Address{},
		GasLimit:    h.gasLimit,
		BlockNumber: big.NewInt(ctx.BlockHeight()),
		Time:        uint64(ctx.BlockTime().Unix()), //nolint:gosec // block time is post-1970
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(0),
		BlobBaseFee: big.NewInt(0),
		Random:      &random,
	}
	evm := vm.NewEVM(blockCtx, h.statedb, h.chainConfig, vm.Config{})

	rules := h.chainConfig.Rules(blockCtx.BlockNumber, true, blockCtx.Time)
	precompiles := vm.ActivePrecompiledContracts(rules)
	for addr, p := range h.mounts {
		precompiles[addr] = boundPrecompile{addr: addr, p: p, ctx: ctx}
	}
	evm.SetPrecompiles(precompiles)
	return evm
}

// Deploy executes initcode through the real interpreter and returns the new
// contract address.
func (h *Host) Deploy(ctx sdk.Context, creator common.Address, initcode []byte, gas uint64) (common.Address, error) {
	if len(initcode) == 0 {
		return common.Address{}, fmt.Errorf("evmhost: empty initcode")
	}
	evm := h.newEVM(ctx)
	_, addr, _, err := evm.Create(creator, initcode, gas, uint256.NewInt(0))
	if err != nil {
		return common.Address{}, fmt.Errorf("evmhost: deploy: %w", err)
	}
	return addr, nil
}

// Call executes a message call (value 0) against a contract or precompile.
func (h *Host) Call(ctx sdk.Context, from, to common.Address, calldata []byte, gas uint64) ([]byte, error) {
	return h.CallValue(ctx, from, to, calldata, gas, uint256.NewInt(0))
}

// CallValue executes a value-bearing message call (payable functions,
// receive()). The sender must hold the balance (see FundAccount).
func (h *Host) CallValue(ctx sdk.Context, from, to common.Address, calldata []byte, gas uint64, value *uint256.Int) ([]byte, error) {
	evm := h.newEVM(ctx)
	ret, _, err := evm.Call(from, to, calldata, gas, value)
	if err != nil {
		return ret, fmt.Errorf("evmhost: call %s: %w", to.Hex(), err)
	}
	return ret, nil
}

// Balance reports an EVM account's balance from the host state.
func (h *Host) Balance(addr common.Address) *uint256.Int {
	return h.statedb.GetBalance(addr)
}

// StaticCall executes a read-only call (state mutation forbidden by the
// interpreter) — the natural entry point for query-layer contract reads.
func (h *Host) StaticCall(ctx sdk.Context, from, to common.Address, calldata []byte, gas uint64) ([]byte, error) {
	evm := h.newEVM(ctx)
	ret, _, err := evm.StaticCall(from, to, calldata, gas)
	if err != nil {
		return ret, fmt.Errorf("evmhost: staticcall %s: %w", to.Hex(), err)
	}
	return ret, nil
}

// ForwardingProxyRuntime is a 27-byte handwritten contract that forwards its
// entire calldata to the ISeal precompile via STATICCALL and bubbles up the
// result — the minimal REAL contract proving the contract→precompile path
// through the interpreter. Opcode by opcode:
//
//	CALLDATASIZE PUSH0 PUSH0 CALLDATACOPY          ; mem[0:cds] = calldata
//	PUSH0 PUSH0                                    ; retSize, retOffset
//	CALLDATASIZE PUSH0                             ; argsSize, argsOffset
//	PUSH2 0x0900 GAS STATICCALL                    ; call ISeal
//	RETURNDATASIZE PUSH0 PUSH0 RETURNDATACOPY      ; mem[0:rds] = returndata
//	PUSH1 0x17 JUMPI                               ; success -> 0x17
//	RETURNDATASIZE PUSH0 REVERT                    ; bubble revert
//	JUMPDEST RETURNDATASIZE PUSH0 RETURN           ; bubble return
var ForwardingProxyRuntime = []byte{
	0x36, 0x5f, 0x5f, 0x37, // calldatacopy(0, 0, calldatasize)
	0x5f, 0x5f, // retSize=0 retOffset=0
	0x36, 0x5f, // argsSize=calldatasize argsOffset=0
	0x61, 0x09, 0x00, // PUSH2 0x0900
	0x5a, 0xfa, // GAS STATICCALL
	0x3d, 0x5f, 0x5f, 0x3e, // returndatacopy(0, 0, returndatasize)
	0x60, 0x17, 0x57, // PUSH1 0x17 JUMPI
	0x3d, 0x5f, 0xfd, // revert(0, returndatasize)
	0x5b, 0x3d, 0x5f, 0xf3, // JUMPDEST return(0, returndatasize)
}

// ForwardingProxyInitcode wraps the runtime in standard deployment initcode:
//
//	PUSH1 len PUSH1 0x0a PUSH0 CODECOPY   ; mem[0:len] = code[10:10+len]
//	PUSH1 len PUSH0 RETURN                ; return runtime
func ForwardingProxyInitcode() []byte {
	l := byte(len(ForwardingProxyRuntime))
	header := []byte{0x60, l, 0x60, 0x0a, 0x5f, 0x39, 0x60, l, 0x5f, 0xf3}
	return append(header, ForwardingProxyRuntime...)
}
