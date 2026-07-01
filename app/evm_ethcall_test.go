package app

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	evmtypes "github.com/cosmos/evm/x/vm/types"

	"github.com/aethelred/aethelred/app/evmconfig"
	sealprecompile "github.com/aethelred/aethelred/precompiles/seal"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// bootAppWithGenesis constructs the full app and runs InitChain with the
// default genesis (which includes the Aethelred EVM config), returning a
// committed-state context ready for queries.
func bootAppWithGenesis(t *testing.T) (*AethelredApp, sdk.Context) {
	t.Helper()

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")

	const chainID = "aethelred-evm-test-1"
	opts := sims.AppOptionsMap{"aethelred.pqc.mode": "simulated"}
	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts, baseapp.SetChainID(chainID))

	// A funded genesis account + a single bonded validator over it, so staking
	// InitGenesis has a non-empty validator set.
	privKey := secp256k1.GenPrivKey()
	acc := authtypes.NewBaseAccount(privKey.PubKey().Address().Bytes(), privKey.PubKey(), 0, 0)
	valPriv := ed25519.GenPrivKey()
	tmVal := cmttypes.NewValidator(valPriv.PubKey(), 1)
	valSet := cmttypes.NewValidatorSet([]*cmttypes.Validator{tmVal})
	bondAmt := sdk.DefaultPowerReduction
	balance := banktypes.Balance{
		Address: sdk.AccAddress(acc.GetAddress()).String(),
		Coins:   sdk.NewCoins(sdk.NewCoin(evmconfig.BankDenom, bondAmt.MulRaw(2))),
	}

	genesisState, err := simtestutil.GenesisStateWithValSet(
		app.AppCodec(), ModuleBasics.DefaultGenesis(app.AppCodec()),
		valSet, []authtypes.GenesisAccount{acc}, balance,
	)
	require.NoError(t, err)

	// GenesisStateWithValSet rebuilds the bank genesis and drops the denom
	// metadata our default bank genesis carried; the vm module resolves EVM
	// coin info from it, so re-inject the aaethel/uaethel/aethel metadata.
	var bankGen banktypes.GenesisState
	app.AppCodec().MustUnmarshalJSON(genesisState[banktypes.ModuleName], &bankGen)
	bankGen.DenomMetadata = append(bankGen.DenomMetadata, AethelDenomMetadata())
	genesisState[banktypes.ModuleName] = app.AppCodec().MustMarshalJSON(&bankGen)

	stateBytes, err := json.Marshal(genesisState)
	require.NoError(t, err)

	_, err = app.InitChain(&abci.RequestInitChain{
		ChainId:         chainID,
		Time:            time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		ConsensusParams: sims.DefaultConsensusParams,
		AppStateBytes:   stateBytes,
	})
	require.NoError(t, err)

	// Stay in the post-InitChain deliver state (not committed): it holds the
	// full genesis state and is writable, so the test can both seed a seal and
	// run eth_call against the same state. ProposerAddress is the bonded
	// validator's consensus address, which EthCall resolves to the EVM coinbase.
	ctx := app.NewContextLegacy(false, tmproto.Header{
		ChainID:         chainID,
		Height:          1,
		Time:            time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC),
		ProposerAddress: valPriv.PubKey().Address(),
	})
	return app, ctx
}

// TestEVM_EthCall_ReachesISealPrecompile is the ADR-0001 Phase 1 capstone: a
// real eth_call (the exact query the JSON-RPC eth_call dispatches to) reaches
// the ISeal precompile at 0x0900 through the live cosmos/evm StateDB, reads a
// Digital Seal from chain state, and returns the ABI-encoded verdict. This is
// the whole moat, reachable from the EVM.
func TestEVM_EthCall_ReachesISealPrecompile(t *testing.T) {
	app, ctx := bootAppWithGenesis(t)

	// The EVM config actually landed in state.
	vmParams := app.EVMKeeper.GetParams(ctx)
	require.Equal(t, evmconfig.ExtendedDenom, vmParams.EvmDenom)
	require.Contains(t, vmParams.ActiveStaticPrecompiles, sealprecompile.Address.Hex())

	// Seed an ACTIVE Digital Seal for ISeal to read.
	model := sha256.Sum256([]byte("model"))
	input := sha256.Sum256([]byte("input"))
	output := sha256.Sum256([]byte("output"))
	requester := sdk.AccAddress([]byte("ethcall-test-req-addr")).String()
	seal := sealtypes.NewDigitalSeal(model[:], input[:], output[:], 1, requester, "eth_call test")
	seal.Timestamp = timestamppb.New(ctx.BlockTime())
	seal.JobId = "job-ethcall-1"
	seal.Confidentiality = &sealtypes.ConfidentialityAttestation{
		Backend: "fhe", Verification: "none", Jurisdiction: "EU", DataSealed: true,
	}
	seal.Id = seal.GenerateID()
	seal.Activate()
	require.NoError(t, app.SealKeeper.CreateSeal(ctx, seal))

	sealP, err := sealprecompile.NewPrecompile(&app.SealKeeper)
	require.NoError(t, err)
	sealABI := sealP.ABI()

	// eth_call verifySeal(sealId) → true.
	callData, err := sealABI.Pack(sealprecompile.MethodVerifySeal, seal.Id)
	require.NoError(t, err)
	ret := ethCall(t, app, ctx, sealprecompile.Address, callData)
	out, err := sealABI.Methods[sealprecompile.MethodVerifySeal].Outputs.Unpack(ret)
	require.NoError(t, err)
	require.True(t, out[0].(bool), "ISeal.verifySeal must return true via eth_call")

	// eth_call requireConfidentiality(...) with an FHE+EU policy → satisfied.
	callData, err = sealABI.Pack(sealprecompile.MethodRequireConfidentiality,
		seal.Id, []string{"fhe"}, "", []string{}, false, []string{"EU"})
	require.NoError(t, err)
	ret = ethCall(t, app, ctx, sealprecompile.Address, callData)
	out, err = sealABI.Methods[sealprecompile.MethodRequireConfidentiality].Outputs.Unpack(ret)
	require.NoError(t, err)
	require.True(t, out[0].(bool), "reason: %v", out[1])

	// A vendor-root demand the FHE seal cannot meet → clean false with reason.
	callData, err = sealABI.Pack(sealprecompile.MethodRequireConfidentiality,
		seal.Id, []string{"fhe"}, "", []string{}, true, []string{})
	require.NoError(t, err)
	ret = ethCall(t, app, ctx, sealprecompile.Address, callData)
	out, err = sealABI.Methods[sealprecompile.MethodRequireConfidentiality].Outputs.Unpack(ret)
	require.NoError(t, err)
	require.False(t, out[0].(bool))
	require.Contains(t, out[1].(string), "vendor root")
}

// ethCall issues an eth_call against a contract/precompile via the EVMKeeper's
// EthCall gRPC query — the exact path the JSON-RPC eth_call endpoint uses.
func ethCall(t *testing.T, app *AethelredApp, ctx sdk.Context, to common.Address, data []byte) []byte {
	t.Helper()
	from := common.HexToAddress("0x00000000000000000000000000000000000000AA")
	gas := hexutil.Uint64(500_000)
	input := hexutil.Bytes(data)
	args := evmtypes.TransactionArgs{From: &from, To: &to, Gas: &gas, Input: &input}
	argsJSON, err := json.Marshal(args)
	require.NoError(t, err)

	resp, err := app.EVMKeeper.EthCall(ctx, &evmtypes.EthCallRequest{
		Args:    argsJSON,
		GasCap:  25_000_000,
		ChainId: int64(evmconfig.EVMChainID),
	})
	require.NoError(t, err)
	require.Empty(t, resp.VmError, "EVM returned an error: %s", resp.VmError)
	return resp.Ret
}
