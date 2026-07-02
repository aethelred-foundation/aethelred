package evmconfig

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	evmtypes "github.com/cosmos/evm/x/vm/types"

	pouwprecompile "github.com/aethelred/aethelred/precompiles/pouw"
	sealprecompile "github.com/aethelred/aethelred/precompiles/seal"
	verifyprecompile "github.com/aethelred/aethelred/precompiles/verify"
)

func TestCoinInfo_SixDecimalBridge(t *testing.T) {
	ci := CoinInfo()
	require.Equal(t, "uaethel", ci.Denom)
	require.Equal(t, "aaethel", ci.ExtendedDenom)
	require.Equal(t, "aethel", ci.DisplayDenom)
	require.Equal(t, uint32(6), ci.Decimals)
	// The bridge is only meaningful if the bank and EVM denoms differ.
	require.NotEqual(t, ci.Denom, ci.ExtendedDenom)
}

func TestActiveStaticPrecompiles_SortedUniqueAndComplete(t *testing.T) {
	got := ActiveStaticPrecompiles()
	require.Len(t, got, 3)

	// Must be exactly the verifiable-AI surface.
	require.Contains(t, got, normalizeAddr(sealprecompile.Address.Hex()))
	require.Contains(t, got, normalizeAddr(verifyprecompile.Address.Hex()))
	require.Contains(t, got, normalizeAddr(pouwprecompile.Address.Hex()))

	// x/vm requires the list sorted (determinism) and unique.
	require.True(t, slices.IsSorted(got), "ActiveStaticPrecompiles must be sorted")
	seen := map[string]bool{}
	for _, a := range got {
		require.False(t, seen[a], "duplicate precompile %s", a)
		seen[a] = true
	}

	// And x/vm's own validator must accept it.
	require.NoError(t, evmtypes.ValidatePrecompiles(got))
}

func TestNormalizeAddr(t *testing.T) {
	require.Equal(t, "0xabcdef", normalizeAddr("0xABCDEF"))
	require.Equal(t, "0x0900", normalizeAddr("0x0900"))
	// Leading 0x is preserved; digits untouched.
	require.Equal(t, "0x00ff", normalizeAddr("0x00FF"))
}

func TestVMParams_ValidAndPermissioned(t *testing.T) {
	p := VMParams()
	require.Equal(t, BankDenom, p.EvmDenom, "EvmDenom is the INTEGER bank denom; x/vm resolves 6 decimals from bank metadata and bridges to the extended denom")
	require.NotNil(t, p.ExtendedDenomOptions)
	require.Equal(t, ExtendedDenom, p.ExtendedDenomOptions.ExtendedDenom)
	require.Equal(t, ActiveStaticPrecompiles(), p.ActiveStaticPrecompiles)
	require.NoError(t, p.Validate())
}

func TestVMGenesis_Valid(t *testing.T) {
	gs := VMGenesis()
	require.NoError(t, gs.Validate())
	require.Equal(t, VMParams(), gs.Params)
	require.Empty(t, gs.Accounts)
}

func TestValidate(t *testing.T) {
	require.NoError(t, Validate())
}

func TestValidateCoinInfo_Guards(t *testing.T) {
	// The real config passes.
	require.NoError(t, validateCoinInfo(CoinInfo()))

	// Decimals out of range.
	require.Error(t, validateCoinInfo(evmtypes.EvmCoinInfo{Denom: "a", ExtendedDenom: "b", Decimals: 0}))
	require.Error(t, validateCoinInfo(evmtypes.EvmCoinInfo{Denom: "a", ExtendedDenom: "b", Decimals: 19}))

	// Sub-18-decimal chain reusing the bank denom as the extended denom.
	require.Error(t, validateCoinInfo(evmtypes.EvmCoinInfo{Denom: "uaethel", ExtendedDenom: "uaethel", Decimals: 6}))

	// An 18-decimal chain may legitimately reuse one denom.
	require.NoError(t, validateCoinInfo(evmtypes.EvmCoinInfo{Denom: "aaethel", ExtendedDenom: "aaethel", Decimals: 18}))
}

func TestEVMChainID(t *testing.T) {
	// The dApp stack is pinned to 7332; a drift here breaks every wallet config.
	require.Equal(t, uint64(7332), EVMChainID)
}
