package evm

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethstate "github.com/ethereum/go-ethereum/core/state"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"

	pouwprecompile "github.com/aethelred/aethelred/precompiles/pouw"
	sealprecompile "github.com/aethelred/aethelred/precompiles/seal"
	verifyprecompile "github.com/aethelred/aethelred/precompiles/verify"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

// echo is a trivial ContextPrecompile for adapter-surface tests.
type echo struct{ gas uint64 }

func (e echo) RequiredGas([]byte) uint64                       { return e.gas }
func (e echo) Run(_ sdk.Context, input []byte) ([]byte, error) { return input, nil }

func TestAdapter_Surface(t *testing.T) {
	addr := common.HexToAddress("0x0900")
	a := NewAdapter(addr, echo{gas: 42})
	require.Equal(t, addr, a.Address())
	require.Equal(t, uint64(42), a.RequiredGas(nil))
}

// TestAdapter_Run_NotInEVM: a precompile invoked with a StateDB that is not the
// cosmos/evm StateDB (e.g. a vanilla geth interpreter) must fail closed with
// ErrNotInEVM, never panic.
func TestAdapter_Run_NotInEVM(t *testing.T) {
	sdb, err := gethstate.New(gethtypes.EmptyRootHash, gethstate.NewDatabaseForTesting())
	require.NoError(t, err)

	blockCtx := vm.BlockContext{
		CanTransfer: func(vm.StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(vm.StateDB, common.Address, common.Address, *uint256.Int) {},
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		BlockNumber: big.NewInt(1),
		Time:        1,
	}
	evm := vm.NewEVM(blockCtx, sdb, params.MergedTestChainConfig, vm.Config{})

	a := NewAdapter(common.HexToAddress("0x0900"), echo{})
	contract := &vm.Contract{Input: []byte{1, 2, 3}}
	_, err = a.Run(evm, contract, false)
	require.ErrorIs(t, err, ErrNotInEVM)
}

// --- stub readers for the wiring helper ---

type stubSeal struct{}

func (stubSeal) GetSeal(context.Context, string) (*sealtypes.DigitalSeal, error) {
	return &sealtypes.DigitalSeal{}, nil
}
func (stubSeal) GetSealByJob(context.Context, string) (*sealtypes.DigitalSeal, error) {
	return &sealtypes.DigitalSeal{}, nil
}

type stubRegistry struct{}

func (stubRegistry) GetCircuit(context.Context, []byte) (*verifytypes.Circuit, error) {
	return &verifytypes.Circuit{}, nil
}
func (stubRegistry) GetVerifyingKey(context.Context, []byte) (*verifytypes.VerifyingKey, error) {
	return &verifytypes.VerifyingKey{}, nil
}

type stubJobs struct{}

func (stubJobs) GetJob(context.Context, string) (*pouwtypes.ComputeJob, error) {
	return &pouwtypes.ComputeJob{}, nil
}
func (stubJobs) GetRegisteredModel(context.Context, []byte) (*pouwtypes.RegisteredModel, error) {
	return &pouwtypes.RegisteredModel{}, nil
}

func TestNewStaticPrecompiles(t *testing.T) {
	m, err := NewStaticPrecompiles(stubSeal{}, stubRegistry{}, stubJobs{})
	require.NoError(t, err)
	require.Len(t, m, 3)

	// Each address maps to an adapter that reports its own address.
	for _, addr := range []common.Address{
		sealprecompile.Address, verifyprecompile.Address, pouwprecompile.Address,
	} {
		p, ok := m[addr]
		require.True(t, ok, "missing precompile at %s", addr.Hex())
		require.Equal(t, addr, p.Address())
		require.Zero(t, p.RequiredGas(nil)) // short input -> no method -> 0 gas
	}

	// Nil readers fail closed (the underlying NewPrecompile rejects them).
	_, err = NewStaticPrecompiles(nil, stubRegistry{}, stubJobs{})
	require.Error(t, err)
	_, err = NewStaticPrecompiles(stubSeal{}, nil, stubJobs{})
	require.Error(t, err)
	_, err = NewStaticPrecompiles(stubSeal{}, stubRegistry{}, nil)
	require.Error(t, err)
}

func TestAddresses(t *testing.T) {
	addrs := Addresses()
	require.Equal(t, []string{
		sealprecompile.Address.Hex(),
		verifyprecompile.Address.Hex(),
		pouwprecompile.Address.Hex(),
	}, addrs)
	// Ascending, unique — the x/vm ActiveStaticPrecompiles invariant.
	require.Less(t, addrs[0], addrs[1])
	require.Less(t, addrs[1], addrs[2])
}
