// Package evmconfig holds Aethelred's cosmos/evm configuration: the EVM chain
// id, the coin-decimal bridge, and the x/vm genesis that activates the
// verifiable-AI precompiles. It is the single, tested source of truth the app
// wiring consumes, so the two most audit-sensitive decisions — the 6→18
// decimal mapping and which precompiles are permissioned into the EVM — live in
// one reviewable place, independent of the (large) app.go integration.
package evmconfig

import (
	"fmt"
	"slices"

	evmtypes "github.com/cosmos/evm/x/vm/types"

	precompileevm "github.com/aethelred/aethelred/precompiles/evm"
)

const (
	// EVMChainID is the EIP-155 chain id the Aethelred EVM presents. The dApp
	// stack (Wallet, Cruzible, ZeroID, TerraQura) is configured for 7332.
	EVMChainID uint64 = 7332

	// BankDenom is the chain's native bank denom (6 decimals, as minted in
	// genesis: 1 AETHEL = 1_000_000 uaethel).
	BankDenom = "uaethel"

	// ExtendedDenom is the 18-decimal representation the EVM operates in. The
	// x/precisebank module bridges BankDenom↔ExtendedDenom with a fixed 1e12
	// conversion factor (18 − 6 = 12), so EVM balances are exact and no wei is
	// silently truncated on the Cosmos side.
	ExtendedDenom = "aaethel"

	// DisplayDenom is the human-facing unit.
	DisplayDenom = "aethel"

	// Decimals is the native bank denom's decimal precision.
	Decimals = uint32(6)
)

// CoinInfo returns the EVM coin metadata for Aethelred. Using SixDecimals with
// a distinct ExtendedDenom is cosmos/evm's supported pattern for non-18-decimal
// chains — the EVM sees 18-decimal `aaethel`, the bank holds 6-decimal
// `uaethel`, and precisebank reconciles them.
func CoinInfo() evmtypes.EvmCoinInfo {
	return evmtypes.EvmCoinInfo{
		Denom:         BankDenom,
		ExtendedDenom: ExtendedDenom,
		DisplayDenom:  DisplayDenom,
		Decimals:      Decimals,
	}
}

// ActiveStaticPrecompiles is the sorted, unique list of precompile addresses
// permissioned into the EVM at genesis: the verifiable-AI surface (ISeal
// 0x0900, IVerify 0x0901, IPoUW 0x0902). x/vm requires this list to be sorted
// for determinism (ValidatePrecompiles).
func ActiveStaticPrecompiles() []string {
	addrs := append([]string(nil), precompileevm.Addresses()...)
	// Normalize to the lowercase form cosmos/evm's own addresses use, then sort
	// so ValidatePrecompiles' determinism check passes regardless of source
	// order.
	for i, a := range addrs {
		addrs[i] = normalizeAddr(a)
	}
	slices.Sort(addrs)
	return addrs
}

// normalizeAddr lowercases a 0x-hex address. Our precompile addresses have no
// letter nibbles so this is a no-op today, but it keeps the invariant explicit
// (cosmos/evm compares/sorts these as raw strings).
func normalizeAddr(a string) string {
	b := []byte(a)
	for i := 2; i < len(b); i++ { // skip "0x"
		if b[i] >= 'A' && b[i] <= 'F' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// VMParams returns the x/vm module parameters for Aethelred: the default EVM
// configuration with the EVM denom set to the extended (18-decimal) denom and
// the verifiable-AI precompiles activated.
func VMParams() evmtypes.Params {
	p := evmtypes.DefaultParams()
	p.EvmDenom = ExtendedDenom
	p.ExtendedDenomOptions = &evmtypes.ExtendedDenomOptions{ExtendedDenom: ExtendedDenom}
	p.ActiveStaticPrecompiles = ActiveStaticPrecompiles()
	return p
}

// VMGenesis returns the x/vm genesis state for Aethelred (params only; no
// pre-funded EVM accounts or preinstalled contracts at genesis).
func VMGenesis() *evmtypes.GenesisState {
	return evmtypes.NewGenesisState(VMParams(), nil, nil)
}

// Validate checks the configuration is internally consistent and accepted by
// x/vm — a fail-fast guard the app calls before wiring, so a misconfiguration
// surfaces at construction rather than at first block.
func Validate() error {
	if err := validateCoinInfo(CoinInfo()); err != nil {
		return err
	}
	if err := VMParams().Validate(); err != nil {
		return fmt.Errorf("evmconfig: x/vm params invalid: %w", err)
	}
	if err := VMGenesis().Validate(); err != nil {
		return fmt.Errorf("evmconfig: x/vm genesis invalid: %w", err)
	}
	return nil
}

// validateCoinInfo enforces the decimal-bridge invariants independently of the
// package constants, so the guards are exercised against adversarial inputs.
func validateCoinInfo(ci evmtypes.EvmCoinInfo) error {
	if ci.Decimals == 0 || ci.Decimals > 18 {
		return fmt.Errorf("evmconfig: decimals %d out of range (1..18)", ci.Decimals)
	}
	// A sub-18-decimal chain MUST expose a distinct 18-decimal extended denom;
	// reusing the bank denom would truncate wei-scale EVM balances.
	if ci.Decimals < 18 && ci.Denom == ci.ExtendedDenom {
		return fmt.Errorf("evmconfig: %d-decimal chain requires a distinct extended denom, got %q for both", ci.Decimals, ci.Denom)
	}
	return nil
}
