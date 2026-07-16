package evmhost_test

import (
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/internal/evmhost"
	precompile "github.com/aethelred/aethelred/precompiles/seal"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// NoblePay's SealSettlementGate, compiled from the noblepay repo (hardhat v3,
// solc 0.8.19, via-ir, paris) and vendored here so this test runs the exact
// reviewed bytecode against the REAL ISeal precompile + a real seal keeper.
const noblepayArtifacts = "testdata/noblepay"

func loadNoblePayArtifact(t *testing.T, name string) ([]byte, gethabi.ABI) {
	t.Helper()
	binHex, err := os.ReadFile(noblepayArtifacts + "/" + name + ".bin")
	require.NoError(t, err, "compile with noblepay `npx hardhat compile` and re-vendor")
	bin, err := hex.DecodeString(strings.TrimSpace(string(binHex)))
	require.NoError(t, err)
	abiJSON, err := os.ReadFile(noblepayArtifacts + "/" + name + ".abi")
	require.NoError(t, err)
	parsed, err := gethabi.JSON(strings.NewReader(string(abiJSON)))
	require.NoError(t, err)
	return bin, parsed
}

func newNoblePayStack(t *testing.T) (*evmhost.Host, *sealkeeper.Keeper, sdk.Context) {
	t.Helper()
	storeKey := storetypes.NewKVStoreKey("seal")
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())
	ctx := sdk.NewContext(cms, tmproto.Header{
		ChainID: "aethelred-noblepay-test", Height: 13,
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

// seedCorridorSeal mints an ACTIVE seal whose purpose binds a NoblePay
// payer→payee corridor: noblepay:0x<payer>:0x<payee>.
func seedCorridorSeal(t *testing.T, k *sealkeeper.Keeper, ctx sdk.Context, jobID string, payer, payee common.Address, jurisdiction string) {
	t.Helper()
	purpose := "noblepay:" + strings.ToLower(payer.Hex()) + ":" + strings.ToLower(payee.Hex())
	seed := sha256.Sum256([]byte(jobID))
	seal := sealtypes.NewDigitalSeal(seed[:], seed[:], seed[:], 13,
		sdk.AccAddress([]byte("noblepay-req-addr-01")).String(), purpose)
	seal.Timestamp = timestamppb.New(ctx.BlockTime())
	seal.JobId = jobID
	seal.Confidentiality = &sealtypes.ConfidentialityAttestation{
		Backend: "tee", Verification: "tee-attested", Jurisdiction: jurisdiction, DataSealed: true,
	}
	seal.Id = seal.GenerateID()
	seal.Activate()
	require.NoError(t, k.CreateSeal(ctx, seal))
}

// TestNoblePay_SealSettlementGate_RealPrecompile proves NoblePay's
// consensus-anchored settlement gate against the REAL ISeal precompile: the
// compiled SealSettlementGate admits a corridor clearance only when a Digital
// Seal bound to the exact payer→payee pair exists and satisfies the CEAP
// policy; the corridor closes live when the chain revokes the seal; and a
// revoked/withdrawn corridor cannot be re-opened through the permissionless
// path (clearance permanence).
func TestNoblePay_SealSettlementGate_RealPrecompile(t *testing.T) {
	host, k, ctx := newNoblePayStack(t)

	gov := common.HexToAddress("0x00000000000000000000000000000000000000D1")
	payer := common.HexToAddress("0x00000000000000000000000000000000000000D2")
	payee := common.HexToAddress("0x00000000000000000000000000000000000000D3")

	bin, abi := loadNoblePayArtifact(t, "SealSettlementGate")

	// Deploy SealSettlementGate(governance).
	ctorArgs, err := abi.Pack("", gov)
	require.NoError(t, err)
	gate, err := host.Deploy(ctx, gov, append(append([]byte{}, bin...), ctorArgs...), 6_000_000)
	require.NoError(t, err)

	// Governance sets the CEAP policy: TEE backend, UAE residency.
	setPolicy, err := abi.Pack("setCompliancePolicy", []string{"tee"}, "", []string{}, false, []string{"AE"})
	require.NoError(t, err)
	_, err = host.Call(ctx, gov, gate, setPolicy, 2_000_000)
	require.NoError(t, err)

	// No seal yet → corridor closed.
	require.False(t, noblepayCleared(t, host, ctx, abi, gate, payer, payee), "corridor closed before a seal exists")

	// Seed the AE-jurisdiction screening seal for this exact corridor; clear
	// (as a permissionless third party — the seal itself binds the corridor).
	seedCorridorSeal(t, k, ctx, "job-screen-001", payer, payee, "AE")
	clearCall, err := abi.Pack("clear", payer, payee, "job-screen-001")
	require.NoError(t, err)
	_, err = host.Call(ctx, payee, gate, clearCall, 3_000_000)
	require.NoError(t, err, "policy-satisfying, corridor-bound seal must clear")
	require.True(t, noblepayCleared(t, host, ctx, abi, gate, payer, payee), "corridor open after seal-backed clear()")

	// Direction sensitivity via the real precompile: the payer→payee seal does
	// NOT clear payee→payer.
	require.False(t, noblepayCleared(t, host, ctx, abi, gate, payee, payer), "reverse corridor stays closed")

	// A US-jurisdiction seal fails the AE policy via the real precompile.
	other := common.HexToAddress("0x00000000000000000000000000000000000000D4")
	seedCorridorSeal(t, k, ctx, "job-screen-002", payer, other, "US")
	clearUS, err := abi.Pack("clear", payer, other, "job-screen-002")
	require.NoError(t, err)
	_, err = host.Call(ctx, payer, gate, clearUS, 3_000_000)
	require.Error(t, err, "US-jurisdiction seal must fail the AE policy via the real precompile")

	// Live revocation: the chain revokes the seal (sanctions update) → the
	// corridor closes with no NoblePay transaction.
	seal, err := k.GetSealByJob(ctx, "job-screen-001")
	require.NoError(t, err)
	seal.Revoke()
	require.NoError(t, k.UpdateSeal(ctx, seal))
	require.False(t, noblepayCleared(t, host, ctx, abi, gate, payer, payee), "seal revocation closes the corridor live")

	// Clearance permanence: even a FRESH, policy-satisfying, corridor-bound
	// seal cannot re-open the corridor (AlreadyCleared) — a withdrawn corridor
	// cannot be resurrected through the permissionless path.
	seedCorridorSeal(t, k, ctx, "job-screen-003", payer, payee, "AE")
	clearFresh, err := abi.Pack("clear", payer, payee, "job-screen-003")
	require.NoError(t, err)
	_, err = host.Call(ctx, payer, gate, clearFresh, 3_000_000)
	require.Error(t, err, "re-clearing a revoked corridor with a fresh seal must fail (AlreadyCleared)")
	require.False(t, noblepayCleared(t, host, ctx, abi, gate, payer, payee), "corridor stays closed after attempted re-clear")
}

func noblepayCleared(t *testing.T, host *evmhost.Host, ctx sdk.Context, abi gethabi.ABI, gate common.Address, payer, payee common.Address) bool {
	t.Helper()
	data, err := abi.Pack("isCleared", payer, payee)
	require.NoError(t, err)
	ret, err := host.StaticCall(ctx, payer, gate, data, 1_000_000)
	require.NoError(t, err)
	vals, err := abi.Methods["isCleared"].Outputs.Unpack(ret)
	require.NoError(t, err)
	return vals[0].(bool)
}
