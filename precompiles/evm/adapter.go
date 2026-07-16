// Package evm adapts Aethelred's verifiable-AI precompiles (ISeal 0x0900,
// IVerify 0x0901, IPoUW 0x0902) to the cosmos/evm stateful-precompile
// interface, so they mount into the x/vm keeper via WithStaticPrecompiles and
// answer real eth_call / contract CALLs against live chain state.
//
// This is the integration seam. The precompiles themselves
// (precompiles/{seal,verify,pouw}) depend only on accounts/abi + common + the
// keeper interfaces — they know nothing about the EVM. This package is the one
// place that couples them to core/vm and the cosmos/evm StateDB, keeping the
// audited precompile logic free of EVM-host concerns.
package evm

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/evm/x/vm/statedb"

	pouwprecompile "github.com/aethelred/aethelred/precompiles/pouw"
	sealprecompile "github.com/aethelred/aethelred/precompiles/seal"
	verifyprecompile "github.com/aethelred/aethelred/precompiles/verify"
)

// ErrNotInEVM is returned when a precompile is invoked with a StateDB that is
// not the cosmos/evm StateDB (i.e. not inside a real EVM state transition).
var ErrNotInEVM = errors.New("aethelred precompile: not run inside the cosmos/evm StateDB")

// ContextPrecompile is the minimal surface every Aethelred precompile exposes:
// a gas cost and a chain-state read keyed by ABI-encoded input. All three
// precompiles satisfy it already.
type ContextPrecompile interface {
	RequiredGas(input []byte) uint64
	Run(ctx sdk.Context, input []byte) ([]byte, error)
}

// Adapter wraps a ContextPrecompile as a cosmos/evm-fork vm.PrecompiledContract.
// It sources the sdk.Context from the EVM StateDB's cache context — the same
// mechanism cosmos/evm's own native precompiles use — so reads observe the
// exact in-flight state of the current EVM transaction.
type Adapter struct {
	address common.Address
	inner   ContextPrecompile
}

// NewAdapter binds a precompile to its fixed address.
func NewAdapter(address common.Address, inner ContextPrecompile) *Adapter {
	return &Adapter{address: address, inner: inner}
}

// Address implements vm.PrecompiledContract (fork extension).
func (a *Adapter) Address() common.Address { return a.address }

// RequiredGas implements vm.PrecompiledContract.
func (a *Adapter) RequiredGas(input []byte) uint64 { return a.inner.RequiredGas(input) }

// Run implements vm.PrecompiledContract. The precompiles are read-only, so the
// readonly flag needs no special handling — they never mutate state.
func (a *Adapter) Run(evm *vm.EVM, contract *vm.Contract, _ bool) ([]byte, error) {
	stateDB, ok := evm.StateDB.(*statedb.StateDB)
	if !ok {
		return nil, ErrNotInEVM
	}
	ctx, err := stateDB.GetCacheContext()
	if err != nil {
		return nil, err
	}
	return a.inner.Run(ctx, contract.Input)
}

// NewStaticPrecompiles builds the address→precompile map for the x/vm keeper's
// WithStaticPrecompiles, wiring the full verifiable-AI surface from the
// supplied keepers. Callers pass the concrete keeper values (which satisfy the
// per-precompile reader interfaces).
func NewStaticPrecompiles(
	sealReader sealprecompile.SealReader,
	registryReader verifyprecompile.RegistryReader,
	jobReader pouwprecompile.JobReader,
) (map[common.Address]vm.PrecompiledContract, error) {
	sealP, err := sealprecompile.NewPrecompile(sealReader)
	if err != nil {
		return nil, err
	}
	verifyP, err := verifyprecompile.NewPrecompile(registryReader)
	if err != nil {
		return nil, err
	}
	pouwP, err := pouwprecompile.NewPrecompile(jobReader)
	if err != nil {
		return nil, err
	}
	return map[common.Address]vm.PrecompiledContract{
		sealprecompile.Address:   NewAdapter(sealprecompile.Address, sealP),
		verifyprecompile.Address: NewAdapter(verifyprecompile.Address, verifyP),
		pouwprecompile.Address:   NewAdapter(pouwprecompile.Address, pouwP),
	}, nil
}

// Addresses returns the fixed precompile addresses, for the x/vm params'
// ActiveStaticPrecompiles list (which must be sorted/unique — this returns them
// in ascending address order).
func Addresses() []string {
	return []string{
		sealprecompile.Address.Hex(),   // 0x...0900
		verifyprecompile.Address.Hex(), // 0x...0901
		pouwprecompile.Address.Hex(),   // 0x...0902
	}
}
