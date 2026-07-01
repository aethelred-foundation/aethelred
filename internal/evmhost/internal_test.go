package evmhost

import (
	"testing"
	"time"

	"cosmossdk.io/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/holiman/uint256"
)

type echoPrecompile struct{}

func (echoPrecompile) RequiredGas([]byte) uint64 { return 10 }
func (echoPrecompile) Run(_ sdk.Context, input []byte) ([]byte, error) {
	return input, nil
}

func testCtx() sdk.Context {
	return sdk.NewContext(nil, tmproto.Header{
		Height: 5,
		Time:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}, false, log.NewNopLogger())
}

// TestBoundPrecompileAdapter covers the geth-interface adapter directly:
// RequiredGas and Run delegate; Name satisfies geth's tracing surface.
func TestBoundPrecompileAdapter(t *testing.T) {
	b := boundPrecompile{p: echoPrecompile{}, ctx: testCtx()}
	if b.RequiredGas([]byte{1}) != 10 {
		t.Error("RequiredGas must delegate")
	}
	out, err := b.Run([]byte{1, 2, 3})
	if err != nil || len(out) != 3 {
		t.Errorf("Run must delegate: %v %v", out, err)
	}
	if b.Name() == "" {
		t.Error("Name must be non-empty for geth tracing")
	}
}

// TestBlockContextTransferPlumbing exercises the CanTransfer/Transfer funcs the
// host installs (invoked by the interpreter only on value-bearing calls).
func TestBlockContextTransferPlumbing(t *testing.T) {
	h, err := NewHost(AethelredChainID)
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	evm := h.newEVM(testCtx())

	from := common.HexToAddress("0x01")
	to := common.HexToAddress("0x02")
	amount := uint256.NewInt(500)

	if evm.Context.CanTransfer(h.statedb, from, amount) {
		t.Error("unfunded account must not be able to transfer")
	}
	h.statedb.AddBalance(from, uint256.NewInt(1000), tracing.BalanceChangeUnspecified)
	if !evm.Context.CanTransfer(h.statedb, from, amount) {
		t.Error("funded account must be able to transfer")
	}
	evm.Context.Transfer(h.statedb, from, to, amount, nil)
	if h.statedb.GetBalance(to).Uint64() != 500 || h.statedb.GetBalance(from).Uint64() != 500 {
		t.Errorf("transfer did not move balance: from=%s to=%s",
			h.statedb.GetBalance(from), h.statedb.GetBalance(to))
	}
	if evm.Context.GetHash(1) != (common.Hash{}) {
		t.Error("GetHash must return the zero hash (no ancestry)")
	}
}
