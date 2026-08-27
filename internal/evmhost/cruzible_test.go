package evmhost_test

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log"
	storemetrics "cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	gethabi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/internal/evmhost"
	precompile "github.com/aethelred/aethelred/precompiles/seal"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// The Cruzible EVM artifacts, compiled from the cruzible repo
// (backend/contracts-evm, solc 0.8.20 via-ir) and vendored here so this test
// exercises the exact reviewed bytecode against the REAL ISeal precompile.
const cruzibleArtifacts = "testdata/cruzible"

func loadArtifact(t *testing.T, name string) ([]byte, gethabi.ABI) {
	t.Helper()
	binHex, err := os.ReadFile(cruzibleArtifacts + "/" + name + ".bin")
	require.NoError(t, err, "compile with cruzible/backend/contracts-evm/build.sh")
	bin, err := hex.DecodeString(strings.TrimSpace(string(binHex)))
	require.NoError(t, err)
	abiJSON, err := os.ReadFile(cruzibleArtifacts + "/" + name + ".abi")
	require.NoError(t, err)
	parsed, err := gethabi.JSON(strings.NewReader(string(abiJSON)))
	require.NoError(t, err)
	return bin, parsed
}

// newCruzibleStack builds an evmhost with ISeal mounted over a real seal
// keeper, returning the host, the keeper (to seed seals), and a query ctx.
func newCruzibleStack(t *testing.T) (*evmhost.Host, *sealkeeper.Keeper, sdk.Context) {
	t.Helper()
	storeKey := storetypes.NewKVStoreKey("seal")
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())
	ctx := sdk.NewContext(cms, tmproto.Header{
		ChainID: "aethelred-cruzible-test", Height: 10,
		Time: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)
	k := sealkeeper.NewKeeper(cdc, runtime.NewKVStoreService(storeKey), "")

	p, err := precompile.NewPrecompile(&k)
	require.NoError(t, err)
	host, err := evmhost.NewHost(evmhost.AethelredChainID)
	require.NoError(t, err)
	host.Mount(precompile.Address, p)
	return host, &k, ctx
}

// seedStakerSeal mints an ACTIVE seal whose PoUW job purpose binds the given
// EVM staker (cruzible-stake:0x<addr>), with an FHE + EU attestation.
func seedStakerSeal(t *testing.T, k *sealkeeper.Keeper, ctx sdk.Context, jobID string, staker common.Address) {
	t.Helper()
	model := sha256.Sum256([]byte(jobID + "-model"))
	input := sha256.Sum256([]byte(jobID + "-input"))
	output := sha256.Sum256([]byte(jobID + "-output"))
	purpose := "cruzible-stake:" + strings.ToLower(staker.Hex())
	seal := sealtypes.NewDigitalSeal(model[:], input[:], output[:], 10,
		sdk.AccAddress([]byte("cruzible-req-addr-01")).String(), purpose)
	seal.Timestamp = timestamppb.New(ctx.BlockTime())
	seal.JobId = jobID
	seal.Confidentiality = &sealtypes.ConfidentialityAttestation{
		Backend: "fhe", Verification: "none", Jurisdiction: "EU", DataSealed: true,
	}
	seal.Id = seal.GenerateID()
	seal.Activate()
	require.NoError(t, k.CreateSeal(ctx, seal))
}

// TestCruzible_SealGatedStaking_RealPrecompile is the enterprise-moat proof:
// the compiled Cruzible vault, running in the real interpreter, admits a staker
// ONLY when a policy-satisfying Digital Seal bound to that staker exists —
// evaluated by the REAL ISeal precompile (0x0900) over a REAL seal keeper.
func TestCruzible_SealGatedStaking_RealPrecompile(t *testing.T) {
	host, k, ctx := newCruzibleStack(t)

	gov := common.HexToAddress("0x00000000000000000000000000000000000000A1")
	alice := common.HexToAddress("0x00000000000000000000000000000000000000A2")
	mallory := common.HexToAddress("0x00000000000000000000000000000000000000A3")

	vaultBin, vaultABI := loadArtifact(t, "Cruzible")
	tokenBin, tokenABI := loadArtifact(t, "StAETHEL")

	// Deploy Cruzible(governance, rewarder, pauser, unbondingPeriod).
	ctorArgs, err := vaultABI.Pack("", gov, gov, gov, uint256.NewInt(60).ToBig())
	require.NoError(t, err)
	vault, err := host.Deploy(ctx, gov, append(append([]byte{}, vaultBin...), ctorArgs...), 6_000_000)
	require.NoError(t, err)

	// Deploy StAETHEL(vault) and wire it.
	tokenCtor, err := tokenABI.Pack("", vault)
	require.NoError(t, err)
	token, err := host.Deploy(ctx, gov, append(append([]byte{}, tokenBin...), tokenCtor...), 3_000_000)
	require.NoError(t, err)
	mustCall(t, host, ctx, vaultABI, gov, vault, "setStAethel", token)

	// Turn on compliance mode + set the CEAP policy (FHE backend, EU residency).
	mustCall(t, host, ctx, vaultABI, gov, vault, "setComplianceRequired", true)
	mustCall(t, host, ctx, vaultABI, gov, vault, "setCompliancePolicy",
		[]string{"fhe"}, "", []string{}, false, []string{"EU"})

	// Without a seal, alice is blocked.
	host.FundAccount(alice, uint256.NewInt(10_000_000_000_000_000_000)) // 10 AETHEL
	stakeData, err := vaultABI.Pack("stake")
	require.NoError(t, err)
	_, err = host.CallValue(ctx, alice, vault, stakeData, 2_000_000, uint256.NewInt(5_000_000_000_000_000_000))
	require.Error(t, err, "compliance gate must block an unadmitted staker")

	// Seed alice's seal, then stakeWithSeal admits her and mints stAETHEL.
	seedStakerSeal(t, k, ctx, "job-alice", alice)
	swsData, err := vaultABI.Pack("stakeWithSeal", "job-alice")
	require.NoError(t, err)
	_, err = host.CallValue(ctx, alice, vault, swsData, 3_000_000, uint256.NewInt(5_000_000_000_000_000_000))
	require.NoError(t, err, "policy-satisfying, alice-bound seal must admit")

	// 5 AETHEL minus the 1000-wei MINIMUM_LIQUIDITY dead-shares bootstrap lock.
	bal := callUint(t, host, ctx, tokenABI, alice, token, "balanceOf", alice)
	require.Equal(t, "4999999999999999000", bal.String(), "admitted staker holds ~5 stAETHEL (net of dead-shares lock)")

	admitted := callBool(t, host, ctx, vaultABI, alice, vault, "complianceAdmitted", alice)
	require.True(t, admitted, "alice recorded as admitted")

	// A seal bound to alice cannot admit mallory (purpose binding).
	seedStakerSeal(t, k, ctx, "job-alice-2", alice) // still bound to alice
	host.FundAccount(mallory, uint256.NewInt(10_000_000_000_000_000_000))
	mData, err := vaultABI.Pack("stakeWithSeal", "job-alice-2")
	require.NoError(t, err)
	_, err = host.CallValue(ctx, mallory, vault, mData, 3_000_000, uint256.NewInt(5_000_000_000_000_000_000))
	require.Error(t, err, "a seal bound to alice must not admit mallory")

	// A mallory-bound seal whose jurisdiction violates the EU policy is rejected
	// by the REAL requireConfidentiality (consensus-parity Satisfies).
	badJob := "job-mallory-us"
	model := sha256.Sum256([]byte(badJob))
	seal := sealtypes.NewDigitalSeal(model[:], model[:], model[:], 10,
		sdk.AccAddress([]byte("cruzible-req-addr-02")).String(),
		"cruzible-stake:"+strings.ToLower(mallory.Hex()))
	seal.Timestamp = timestamppb.New(ctx.BlockTime())
	seal.JobId = badJob
	seal.Confidentiality = &sealtypes.ConfidentialityAttestation{
		Backend: "fhe", Verification: "none", Jurisdiction: "US", DataSealed: true,
	}
	seal.Id = seal.GenerateID()
	seal.Activate()
	require.NoError(t, k.CreateSeal(ctx, seal))
	usData, err := vaultABI.Pack("stakeWithSeal", badJob)
	require.NoError(t, err)
	_, err = host.CallValue(ctx, mallory, vault, usData, 3_000_000, uint256.NewInt(5_000_000_000_000_000_000))
	require.Error(t, err, "US-jurisdiction seal must fail the EU policy via the real precompile")
}

// ── call helpers ───────────────────────────────────────────────────────────────

func mustCall(t *testing.T, host *evmhost.Host, ctx sdk.Context, abi gethabi.ABI, from, to common.Address, method string, args ...interface{}) {
	t.Helper()
	data, err := abi.Pack(method, args...)
	require.NoError(t, err)
	_, err = host.Call(ctx, from, to, data, 3_000_000)
	require.NoError(t, err, method)
}

func callUint(t *testing.T, host *evmhost.Host, ctx sdk.Context, abi gethabi.ABI, from, to common.Address, method string, args ...interface{}) *big.Int {
	t.Helper()
	data, err := abi.Pack(method, args...)
	require.NoError(t, err)
	ret, err := host.StaticCall(ctx, from, to, data, 1_000_000)
	require.NoError(t, err)
	vals, err := abi.Methods[method].Outputs.Unpack(ret)
	require.NoError(t, err)
	return vals[0].(*big.Int)
}

func callBool(t *testing.T, host *evmhost.Host, ctx sdk.Context, abi gethabi.ABI, from, to common.Address, method string, args ...interface{}) bool {
	t.Helper()
	data, err := abi.Pack(method, args...)
	require.NoError(t, err)
	ret, err := host.StaticCall(ctx, from, to, data, 1_000_000)
	require.NoError(t, err)
	vals, err := abi.Methods[method].Outputs.Unpack(ret)
	require.NoError(t, err)
	return vals[0].(bool)
}
