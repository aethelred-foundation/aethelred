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

// Shiora's ShioraSealAttestation, compiled from the shiora repo (hardhat, solc
// 0.8.20, via-ir, paris) and vendored here so this test runs the exact reviewed
// bytecode against the REAL ISeal precompile + a real seal keeper.
const shioraArtifacts = "testdata/shiora"

func loadShioraArtifact(t *testing.T, name string) ([]byte, gethabi.ABI) {
	t.Helper()
	binHex, err := os.ReadFile(shioraArtifacts + "/" + name + ".bin")
	require.NoError(t, err, "compile with shiora `npx hardhat compile` and re-vendor")
	bin, err := hex.DecodeString(strings.TrimSpace(string(binHex)))
	require.NoError(t, err)
	abiJSON, err := os.ReadFile(shioraArtifacts + "/" + name + ".abi")
	require.NoError(t, err)
	parsed, err := gethabi.JSON(strings.NewReader(string(abiJSON)))
	require.NoError(t, err)
	return bin, parsed
}

func newShioraStack(t *testing.T) (*evmhost.Host, *sealkeeper.Keeper, sdk.Context) {
	t.Helper()
	storeKey := storetypes.NewKVStoreKey("seal")
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())
	ctx := sdk.NewContext(cms, tmproto.Header{
		ChainID: "aethelred-shiora-test", Height: 14,
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

// seedShioraSeal mints an ACTIVE seal whose purpose binds a Shiora
// (subject, scope) attestation: shiora:0x<subject>:0x<scope>.
func seedShioraSeal(t *testing.T, k *sealkeeper.Keeper, ctx sdk.Context, jobID string, subject common.Address, scope [32]byte, jurisdiction string) {
	t.Helper()
	purpose := "shiora:" + strings.ToLower(subject.Hex()) + ":0x" + hex.EncodeToString(scope[:])
	seed := sha256.Sum256([]byte(jobID))
	seal := sealtypes.NewDigitalSeal(seed[:], seed[:], seed[:], 14,
		sdk.AccAddress([]byte("shiora-req-addr-0001")).String(), purpose)
	seal.Timestamp = timestamppb.New(ctx.BlockTime())
	seal.JobId = jobID
	seal.Confidentiality = &sealtypes.ConfidentialityAttestation{
		Backend: "fhe", Verification: "none", Jurisdiction: jurisdiction, DataSealed: true,
	}
	seal.Id = seal.GenerateID()
	seal.Activate()
	require.NoError(t, k.CreateSeal(ctx, seal))
}

// TestShiora_SealAttestation_RealPrecompile proves Shiora's consensus-anchored
// attestation tier against the REAL ISeal precompile: the compiled
// ShioraSealAttestation admits an attestation only when a Digital Seal bound to
// the exact (subject, scope) exists and satisfies the CEAP policy; an
// attestation goes invalid live when the chain revokes the seal; and a revoked
// (subject, scope) cannot be re-attested with a fresh seal (revocation
// permanence).
func TestShiora_SealAttestation_RealPrecompile(t *testing.T) {
	host, k, ctx := newShioraStack(t)

	gov := common.HexToAddress("0x00000000000000000000000000000000000000E1")
	patient := common.HexToAddress("0x00000000000000000000000000000000000000E2")
	var scope [32]byte
	copy(scope[:], sha256Bytes("clinical:cycle_prediction"))

	bin, abi := loadShioraArtifact(t, "ShioraSealAttestation")

	// Deploy ShioraSealAttestation(governance).
	ctorArgs, err := abi.Pack("", gov)
	require.NoError(t, err)
	reg, err := host.Deploy(ctx, gov, append(append([]byte{}, bin...), ctorArgs...), 6_000_000)
	require.NoError(t, err)

	// Governance sets the CEAP policy: FHE backend, EU residency.
	setPolicy, err := abi.Pack("setCompliancePolicy", []string{"fhe"}, "", []string{}, false, []string{"EU"})
	require.NoError(t, err)
	_, err = host.Call(ctx, gov, reg, setPolicy, 2_000_000)
	require.NoError(t, err)

	// No seal yet → not attested.
	require.False(t, shioraAttested(t, host, ctx, abi, reg, patient, scope), "no attestation before a seal exists")

	// Seed the patient's EU-jurisdiction seal for this scope; attest (as a
	// permissionless relayer — the seal itself binds subject + scope).
	seedShioraSeal(t, k, ctx, "job-clinical-001", patient, scope, "EU")
	attest, err := abi.Pack("attest", patient, scope, "job-clinical-001")
	require.NoError(t, err)
	_, err = host.Call(ctx, gov, reg, attest, 3_000_000)
	require.NoError(t, err, "policy-satisfying, subject+scope-bound seal must attest")
	require.True(t, shioraAttested(t, host, ctx, abi, reg, patient, scope), "attested after seal-backed attest()")

	// A US-jurisdiction seal fails the EU policy via the real precompile. Use a
	// fresh scope bound to a US seal to isolate the policy rejection.
	var scope2 [32]byte
	copy(scope2[:], sha256Bytes("clinical:condition_flag"))
	seedShioraSeal(t, k, ctx, "job-us", patient, scope2, "US")
	attestUS, err := abi.Pack("attest", patient, scope2, "job-us")
	require.NoError(t, err)
	_, err = host.Call(ctx, gov, reg, attestUS, 3_000_000)
	require.Error(t, err, "US-jurisdiction seal must fail the EU policy via the real precompile")

	// Live revocation: the chain revokes the patient's seal → attestation
	// invalid with no Shiora transaction (liveness flows from consensus).
	seal, err := k.GetSealByJob(ctx, "job-clinical-001")
	require.NoError(t, err)
	seal.Revoke()
	require.NoError(t, k.UpdateSeal(ctx, seal))
	require.False(t, shioraAttested(t, host, ctx, abi, reg, patient, scope), "seal revocation invalidates the attestation live")

	// Revocation permanence: even a FRESH, policy-satisfying, bound seal cannot
	// re-attest the (subject, scope) (AlreadyAttested).
	seedShioraSeal(t, k, ctx, "job-fresh", patient, scope, "EU")
	attestFresh, err := abi.Pack("attest", patient, scope, "job-fresh")
	require.NoError(t, err)
	_, err = host.Call(ctx, gov, reg, attestFresh, 3_000_000)
	require.Error(t, err, "re-attesting a revoked (subject, scope) with a fresh seal must fail (AlreadyAttested)")
	require.False(t, shioraAttested(t, host, ctx, abi, reg, patient, scope), "stays invalid after attempted re-attest")
}

func shioraAttested(t *testing.T, host *evmhost.Host, ctx sdk.Context, abi gethabi.ABI, reg, subject common.Address, scope [32]byte) bool {
	t.Helper()
	data, err := abi.Pack("isAttested", subject, scope)
	require.NoError(t, err)
	ret, err := host.StaticCall(ctx, subject, reg, data, 1_000_000)
	require.NoError(t, err)
	vals, err := abi.Methods["isAttested"].Outputs.Unpack(ret)
	require.NoError(t, err)
	return vals[0].(bool)
}
