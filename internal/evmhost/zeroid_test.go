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

// ZeroID's SealAttestationRegistry, compiled from the zeroid repo (solc 0.8.28,
// via-ir) and vendored here so this test runs the exact reviewed bytecode
// against the REAL ISeal precompile + a real seal keeper.
const zeroidArtifacts = "testdata/zeroid"

func loadZeroIDArtifact(t *testing.T, name string) ([]byte, gethabi.ABI) {
	t.Helper()
	binHex, err := os.ReadFile(zeroidArtifacts + "/" + name + ".bin")
	require.NoError(t, err, "compile with zeroid `forge build` and re-vendor")
	bin, err := hex.DecodeString(strings.TrimSpace(string(binHex)))
	require.NoError(t, err)
	abiJSON, err := os.ReadFile(zeroidArtifacts + "/" + name + ".abi")
	require.NoError(t, err)
	parsed, err := gethabi.JSON(strings.NewReader(string(abiJSON)))
	require.NoError(t, err)
	return bin, parsed
}

func newZeroIDStack(t *testing.T) (*evmhost.Host, *sealkeeper.Keeper, sdk.Context) {
	t.Helper()
	storeKey := storetypes.NewKVStoreKey("seal")
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())
	ctx := sdk.NewContext(cms, tmproto.Header{
		ChainID: "aethelred-zeroid-test", Height: 11,
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

// seedZeroIDSeal mints an ACTIVE seal whose purpose binds a ZeroID
// (subject, schema) credential: zeroid:<schemaHex>:0x<subject>.
func seedZeroIDSeal(t *testing.T, k *sealkeeper.Keeper, ctx sdk.Context, jobID string, subject common.Address, schema [32]byte, jurisdiction string) {
	t.Helper()
	purpose := "zeroid:0x" + hex.EncodeToString(schema[:]) + ":" + strings.ToLower(subject.Hex())
	seed := sha256.Sum256([]byte(jobID))
	seal := sealtypes.NewDigitalSeal(seed[:], seed[:], seed[:], 11,
		sdk.AccAddress([]byte("zeroid-req-addr-0001")).String(), purpose)
	seal.Timestamp = timestamppb.New(ctx.BlockTime())
	seal.JobId = jobID
	seal.Confidentiality = &sealtypes.ConfidentialityAttestation{
		Backend: "fhe", Verification: "none", Jurisdiction: jurisdiction, DataSealed: true,
	}
	seal.Id = seal.GenerateID()
	seal.Activate()
	require.NoError(t, k.CreateSeal(ctx, seal))
}

// TestZeroID_SealAttestation_RealPrecompile proves ZeroID's consensus-anchored
// identity layer against the REAL ISeal precompile: the compiled
// SealAttestationRegistry admits a credential only when a Digital Seal bound to
// the exact (subject, schema) exists and satisfies the CEAP policy, and a
// credential goes invalid live when the chain revokes the seal.
func TestZeroID_SealAttestation_RealPrecompile(t *testing.T) {
	host, k, ctx := newZeroIDStack(t)

	gov := common.HexToAddress("0x00000000000000000000000000000000000000B1")
	alice := common.HexToAddress("0x00000000000000000000000000000000000000B2")
	var kyc [32]byte
	copy(kyc[:], sha256Bytes("kyc-tier-2"))

	bin, abi := loadZeroIDArtifact(t, "SealAttestationRegistry")

	// Deploy SealAttestationRegistry(governance).
	ctorArgs, err := abi.Pack("", gov)
	require.NoError(t, err)
	reg, err := host.Deploy(ctx, gov, append(append([]byte{}, bin...), ctorArgs...), 6_000_000)
	require.NoError(t, err)

	// Governance sets the CEAP policy: FHE backend, EU residency.
	setPolicy, err := abi.Pack("setCompliancePolicy", []string{"fhe"}, "", []string{}, false, []string{"EU"})
	require.NoError(t, err)
	_, err = host.Call(ctx, gov, reg, setPolicy, 2_000_000)
	require.NoError(t, err)

	// No seal yet → credential invalid.
	require.False(t, zeroidValid(t, host, ctx, abi, reg, alice, kyc), "no credential before attestation")

	// Seed alice's EU-jurisdiction seal for the KYC schema; attest.
	seedZeroIDSeal(t, k, ctx, "job-alice-kyc", alice, kyc, "EU")
	attest, err := abi.Pack("attest", kyc, "job-alice-kyc")
	require.NoError(t, err)
	_, err = host.Call(ctx, alice, reg, attest, 3_000_000)
	require.NoError(t, err, "policy-satisfying, subject+schema-bound seal must attest")
	require.True(t, zeroidValid(t, host, ctx, abi, reg, alice, kyc), "credential valid after attestation")

	// A US-jurisdiction seal fails the EU policy via the real precompile. Use a
	// fresh subject bound to a US seal to isolate the policy rejection.
	bobUS := common.HexToAddress("0x00000000000000000000000000000000000000B3")
	seedZeroIDSeal(t, k, ctx, "job-bob-us", bobUS, kyc, "US")
	attestBobUS, err := abi.Pack("attest", kyc, "job-bob-us")
	require.NoError(t, err)
	_, err = host.Call(ctx, bobUS, reg, attestBobUS, 3_000_000)
	require.Error(t, err, "US-jurisdiction seal must fail the EU policy via the real precompile")

	// Live revocation: the chain revokes alice's seal → credential invalid with
	// no ZeroID transaction (liveness flows from consensus). Fetch the seal by
	// job, revoke it in the keeper, re-check.
	seal, err := k.GetSealByJob(ctx, "job-alice-kyc")
	require.NoError(t, err)
	seal.Revoke()
	require.NoError(t, k.UpdateSeal(ctx, seal))
	require.False(t, zeroidValid(t, host, ctx, abi, reg, alice, kyc), "seal revocation invalidates credential live")
}

func zeroidValid(t *testing.T, host *evmhost.Host, ctx sdk.Context, abi gethabi.ABI, reg, subject common.Address, schema [32]byte) bool {
	t.Helper()
	data, err := abi.Pack("isCredentialValid", subject, schema)
	require.NoError(t, err)
	ret, err := host.StaticCall(ctx, subject, reg, data, 1_000_000)
	require.NoError(t, err)
	vals, err := abi.Methods["isCredentialValid"].Outputs.Unpack(ret)
	require.NoError(t, err)
	return vals[0].(bool)
}

func sha256Bytes(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}
