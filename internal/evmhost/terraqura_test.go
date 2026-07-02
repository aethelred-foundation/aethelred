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

// TerraQura's SealProofOfPhysics, compiled from the terraqura repo (hardhat,
// solc 0.8.20, via-ir, cancun) and vendored here so this test runs the exact
// reviewed bytecode against the REAL ISeal precompile + a real seal keeper.
const terraquraArtifacts = "testdata/terraqura"

func loadTerraQuraArtifact(t *testing.T, name string) ([]byte, gethabi.ABI) {
	t.Helper()
	binHex, err := os.ReadFile(terraquraArtifacts + "/" + name + ".bin")
	require.NoError(t, err, "compile with terraqura `npx hardhat compile` and re-vendor")
	bin, err := hex.DecodeString(strings.TrimSpace(string(binHex)))
	require.NoError(t, err)
	abiJSON, err := os.ReadFile(terraquraArtifacts + "/" + name + ".abi")
	require.NoError(t, err)
	parsed, err := gethabi.JSON(strings.NewReader(string(abiJSON)))
	require.NoError(t, err)
	return bin, parsed
}

func newTerraQuraStack(t *testing.T) (*evmhost.Host, *sealkeeper.Keeper, sdk.Context) {
	t.Helper()
	storeKey := storetypes.NewKVStoreKey("seal")
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())
	ctx := sdk.NewContext(cms, tmproto.Header{
		ChainID: "aethelred-terraqura-test", Height: 12,
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

// seedMRVSeal mints an ACTIVE seal whose purpose binds a TerraQura MRV claim:
// terraqura:0x<dacUnitId>:0x<sourceDataHash>.
func seedMRVSeal(t *testing.T, k *sealkeeper.Keeper, ctx sdk.Context, jobID string, dacUnitID, sourceDataHash [32]byte, jurisdiction string) {
	t.Helper()
	purpose := "terraqura:0x" + hex.EncodeToString(dacUnitID[:]) + ":0x" + hex.EncodeToString(sourceDataHash[:])
	seed := sha256.Sum256([]byte(jobID))
	seal := sealtypes.NewDigitalSeal(seed[:], seed[:], seed[:], 12,
		sdk.AccAddress([]byte("terraqura-req-addr-1")).String(), purpose)
	seal.Timestamp = timestamppb.New(ctx.BlockTime())
	seal.JobId = jobID
	seal.Confidentiality = &sealtypes.ConfidentialityAttestation{
		Backend: "tee", Verification: "tee-attested", Jurisdiction: jurisdiction, DataSealed: true,
	}
	seal.Id = seal.GenerateID()
	seal.Activate()
	require.NoError(t, k.CreateSeal(ctx, seal))
}

// TestTerraQura_SealProofOfPhysics_RealPrecompile proves TerraQura's
// consensus-anchored MRV registry against the REAL ISeal precompile: the
// compiled SealProofOfPhysics admits an anchor only when a Digital Seal bound
// to the exact (dacUnitId, sourceDataHash) claim exists and satisfies the CEAP
// policy, and the anchor goes invalid live when the chain revokes the seal.
func TestTerraQura_SealProofOfPhysics_RealPrecompile(t *testing.T) {
	host, k, ctx := newTerraQuraStack(t)

	gov := common.HexToAddress("0x00000000000000000000000000000000000000C1")
	operator := common.HexToAddress("0x00000000000000000000000000000000000000C2")
	var dacUnit, batch [32]byte
	copy(dacUnit[:], sha256Bytes("DAC_UNIT_001"))
	copy(batch[:], sha256Bytes("sensor_data_batch_001"))

	bin, abi := loadTerraQuraArtifact(t, "SealProofOfPhysics")

	// Deploy SealProofOfPhysics(governance).
	ctorArgs, err := abi.Pack("", gov)
	require.NoError(t, err)
	reg, err := host.Deploy(ctx, gov, append(append([]byte{}, bin...), ctorArgs...), 6_000_000)
	require.NoError(t, err)

	// Governance sets the CEAP policy: TEE backend, UAE residency.
	setPolicy, err := abi.Pack("setCompliancePolicy", []string{"tee"}, "", []string{}, false, []string{"AE"})
	require.NoError(t, err)
	_, err = host.Call(ctx, gov, reg, setPolicy, 2_000_000)
	require.NoError(t, err)

	// No seal yet → claim not anchored.
	require.False(t, terraquraAnchored(t, host, ctx, abi, reg, operator, dacUnit, batch), "no anchor before a seal exists")

	// Seed the AE-jurisdiction MRV seal for this exact claim; anchor (as a
	// permissionless third party — the seal itself binds the claim).
	seedMRVSeal(t, k, ctx, "job-mrv-001", dacUnit, batch, "AE")
	anchorCall, err := abi.Pack("anchor", dacUnit, batch, "job-mrv-001")
	require.NoError(t, err)
	_, err = host.Call(ctx, operator, reg, anchorCall, 3_000_000)
	require.NoError(t, err, "policy-satisfying, claim-bound seal must anchor")
	require.True(t, terraquraAnchored(t, host, ctx, abi, reg, operator, dacUnit, batch), "claim anchored after seal-backed anchor()")

	// A US-jurisdiction seal fails the AE policy via the real precompile. Use a
	// fresh claim bound to a US seal to isolate the policy rejection.
	var batch2 [32]byte
	copy(batch2[:], sha256Bytes("sensor_data_batch_002"))
	seedMRVSeal(t, k, ctx, "job-mrv-002", dacUnit, batch2, "US")
	anchorUS, err := abi.Pack("anchor", dacUnit, batch2, "job-mrv-002")
	require.NoError(t, err)
	_, err = host.Call(ctx, operator, reg, anchorUS, 3_000_000)
	require.Error(t, err, "US-jurisdiction seal must fail the AE policy via the real precompile")

	// Live revocation: the chain revokes the seal → the anchor is invalid with
	// no TerraQura transaction (liveness flows from consensus).
	seal, err := k.GetSealByJob(ctx, "job-mrv-001")
	require.NoError(t, err)
	seal.Revoke()
	require.NoError(t, k.UpdateSeal(ctx, seal))
	require.False(t, terraquraAnchored(t, host, ctx, abi, reg, operator, dacUnit, batch), "seal revocation invalidates the anchor live")
}

func terraquraAnchored(t *testing.T, host *evmhost.Host, ctx sdk.Context, abi gethabi.ABI, reg, caller common.Address, dacUnit, batch [32]byte) bool {
	t.Helper()
	data, err := abi.Pack("isAnchored", dacUnit, batch)
	require.NoError(t, err)
	ret, err := host.StaticCall(ctx, caller, reg, data, 1_000_000)
	require.NoError(t, err)
	vals, err := abi.Methods["isAnchored"].Outputs.Unpack(ret)
	require.NoError(t, err)
	return vals[0].(bool)
}
