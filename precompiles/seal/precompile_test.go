package seal_test

import (
	"crypto/sha256"
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
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	precompile "github.com/aethelred/aethelred/precompiles/seal"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// Compile-time proof the real seal keeper satisfies the precompile's reader.
var _ precompile.SealReader = (*sealkeeper.Keeper)(nil)

var testRequester = sdk.AccAddress([]byte("iseal-test-requester")).String()

// newHarness builds a REAL seal keeper on a mounted IAVL store, mints a seal
// with a CEAP attestation, and returns the precompile bound to it.
func newHarness(t *testing.T) (*precompile.Precompile, sdk.Context, *sealtypes.DigitalSeal) {
	p, ctx, seal, _ := newHarnessWithKeeper(t)
	return p, ctx, seal
}

func newHarnessWithKeeper(t *testing.T) (*precompile.Precompile, sdk.Context, *sealtypes.DigitalSeal, *sealkeeper.Keeper) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey("seal")
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	ctx := sdk.NewContext(cms, tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  42,
		Time:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)

	k := sealkeeper.NewKeeper(cdc, runtime.NewKVStoreService(storeKey), "")

	model := sha256.Sum256([]byte("model"))
	input := sha256.Sum256([]byte("input"))
	output := sha256.Sum256([]byte("output"))
	seal := sealtypes.NewDigitalSeal(model[:], input[:], output[:], 42, testRequester, "iseal test")
	seal.Timestamp = timestamppb.New(ctx.BlockTime())
	seal.JobId = "job-77"
	seal.Confidentiality = &sealtypes.ConfidentialityAttestation{
		Backend:      "tee",
		Verification: "zkml",
		Platform:     "amd-sev-snp",
		Measurement:  []byte("meas"),
		TrustBasis:   "vendor_root",
		Jurisdiction: "EU",
		DataSealed:   true,
		PolicyHash:   []byte("ph"),
		Worker:       "val1",
	}
	seal.Id = seal.GenerateID()
	seal.Activate()
	require.NoError(t, k.CreateSeal(ctx, seal))

	p, err := precompile.NewPrecompile(&k)
	require.NoError(t, err)
	return p, ctx, seal, &k
}

// call packs a method call through the real ABI (exactly what a contract
// does), runs the precompile, and unpacks the outputs.
func call(t *testing.T, p *precompile.Precompile, ctx sdk.Context, method string, args ...interface{}) []interface{} {
	t.Helper()
	input, err := p.ABI().Pack(method, args...)
	require.NoError(t, err)
	out, err := p.Run(ctx, input)
	require.NoError(t, err)
	vals, err := p.ABI().Methods[method].Outputs.Unpack(out)
	require.NoError(t, err)
	return vals
}

func TestPrecompile_Construction(t *testing.T) {
	_, err := precompile.NewPrecompile(nil)
	require.Error(t, err, "nil reader must be rejected")
}

func TestPrecompile_GetSeal(t *testing.T) {
	p, ctx, seal := newHarness(t)
	vals := call(t, p, ctx, precompile.MethodGetSeal, seal.Id)

	model := vals[0].([32]byte)
	require.Equal(t, seal.ModelCommitment, model[:])
	require.Equal(t, int64(42), vals[3].(int64))
	require.Equal(t, uint64(ctx.BlockTime().Unix()), vals[4].(uint64))
	require.Equal(t, testRequester, vals[5].(string))
	require.Equal(t, "iseal test", vals[6].(string))
	require.Equal(t, uint8(sealtypes.SealStatus_SEAL_STATUS_ACTIVE), vals[7].(uint8))
	require.Equal(t, "job-77", vals[8].(string))

	// Missing seal reverts.
	input, err := p.ABI().Pack(precompile.MethodGetSeal, "no-such-seal")
	require.NoError(t, err)
	_, err = p.Run(ctx, input)
	require.Error(t, err)
}

func TestPrecompile_GetConfidentiality(t *testing.T) {
	p, ctx, seal := newHarness(t)
	vals := call(t, p, ctx, precompile.MethodGetConfidentiality, seal.Id)

	require.Equal(t, "tee", vals[0].(string))
	require.Equal(t, "zkml", vals[1].(string))
	require.Equal(t, "amd-sev-snp", vals[2].(string))
	require.Equal(t, []byte("meas"), vals[3].([]byte))
	require.Equal(t, "vendor_root", vals[4].(string))
	require.Equal(t, "EU", vals[5].(string))
	require.True(t, vals[6].(bool))
	require.Equal(t, []byte("ph"), vals[7].([]byte))
	require.Equal(t, "val1", vals[8].(string))
}

func TestPrecompile_GetConfidentiality_PreCEAPSeal(t *testing.T) {
	p, ctx, seal, k := newHarnessWithKeeper(t)

	// Strip the attestation to model a pre-CEAP seal: the precompile must
	// report the honest zero posture, not fabricate one.
	seal.Confidentiality = nil
	vals := call(t, p, ctx, precompile.MethodGetConfidentiality, mintExtraSeal(t, k, ctx, seal))
	require.Equal(t, "none", vals[0].(string))
	require.Equal(t, "none", vals[1].(string))
	require.False(t, vals[6].(bool))
}

// mintExtraSeal stores a variant seal (fresh identity) and returns its id.
// Test-only writes; the precompile itself only reads.
func mintExtraSeal(t *testing.T, k *sealkeeper.Keeper, ctx sdk.Context, template *sealtypes.DigitalSeal) string {
	t.Helper()
	template.Purpose = template.Purpose + " (variant)"
	template.JobId = template.JobId + "-variant"
	template.Id = template.GenerateID()
	require.NoError(t, k.CreateSeal(ctx, template))
	return template.Id
}

func TestPrecompile_GetSealIdByJob(t *testing.T) {
	p, ctx, seal := newHarness(t)
	vals := call(t, p, ctx, precompile.MethodGetSealIDByJob, "job-77")
	require.Equal(t, seal.Id, vals[0].(string))

	input, err := p.ABI().Pack(precompile.MethodGetSealIDByJob, "unknown-job")
	require.NoError(t, err)
	_, err = p.Run(ctx, input)
	require.Error(t, err)
}

func TestPrecompile_VerifySeal(t *testing.T) {
	p, ctx, seal := newHarness(t)
	vals := call(t, p, ctx, precompile.MethodVerifySeal, seal.Id)
	require.True(t, vals[0].(bool))

	// Missing seal: NOT a revert — a clean false.
	vals = call(t, p, ctx, precompile.MethodVerifySeal, "no-such-seal")
	require.False(t, vals[0].(bool))
}

func TestPrecompile_RequireConfidentiality(t *testing.T) {
	p, ctx, seal := newHarness(t)

	// Satisfied: TEE backend, zkml ≥ tee-attested, right platform, vendor root, EU.
	vals := call(t, p, ctx, precompile.MethodRequireConfidentiality,
		seal.Id, []string{"tee", "fhe"}, "tee-attested", []string{"amd-sev-snp"}, true, []string{"EU"})
	require.True(t, vals[0].(bool), "reason: %s", vals[1].(string))
	require.Empty(t, vals[1].(string))

	// Unrestricted policy: satisfied.
	vals = call(t, p, ctx, precompile.MethodRequireConfidentiality,
		seal.Id, []string{}, "", []string{}, false, []string{})
	require.True(t, vals[0].(bool))

	// Backend not allowed: clean false with a reason, not a revert.
	vals = call(t, p, ctx, precompile.MethodRequireConfidentiality,
		seal.Id, []string{"fhe"}, "", []string{}, false, []string{})
	require.False(t, vals[0].(bool))
	require.Contains(t, vals[1].(string), "not permitted")

	// Residency violation.
	vals = call(t, p, ctx, precompile.MethodRequireConfidentiality,
		seal.Id, []string{}, "", []string{}, false, []string{"US"})
	require.False(t, vals[0].(bool))

	// Missing seal reverts (unlike verifySeal, the caller asked for a policy
	// evaluation on a specific seal).
	input, err := p.ABI().Pack(precompile.MethodRequireConfidentiality,
		"no-such-seal", []string{}, "", []string{}, false, []string{})
	require.NoError(t, err)
	_, err = p.Run(ctx, input)
	require.Error(t, err)
}

func TestPrecompile_RequireConfidentiality_PreCEAPSeal(t *testing.T) {
	p, ctx, seal, k := newHarnessWithKeeper(t)
	seal.Confidentiality = nil
	id := mintExtraSeal(t, k, ctx, seal)

	// Zero posture passes an empty policy…
	vals := call(t, p, ctx, precompile.MethodRequireConfidentiality,
		id, []string{}, "", []string{}, false, []string{})
	require.True(t, vals[0].(bool))

	// …and fails any real requirement.
	vals = call(t, p, ctx, precompile.MethodRequireConfidentiality,
		id, []string{"tee"}, "", []string{}, false, []string{})
	require.False(t, vals[0].(bool))
}

func TestPrecompile_RequiredGas(t *testing.T) {
	p, _, seal := newHarness(t)
	cases := map[string]uint64{
		precompile.MethodGetSeal:            precompile.GasGetSeal,
		precompile.MethodGetConfidentiality: precompile.GasGetConfidentiality,
		precompile.MethodGetSealIDByJob:     precompile.GasGetSealIDByJob,
		precompile.MethodVerifySeal:         precompile.GasVerifySeal,
	}
	for method, want := range cases {
		input, err := p.ABI().Pack(method, seal.Id)
		require.NoError(t, err)
		require.Equal(t, want, p.RequiredGas(input), method)
	}
	input, err := p.ABI().Pack(precompile.MethodRequireConfidentiality,
		seal.Id, []string{}, "", []string{}, false, []string{})
	require.NoError(t, err)
	require.Equal(t, uint64(precompile.GasRequireConfidentiality), p.RequiredGas(input))

	// Degenerate inputs.
	require.Zero(t, p.RequiredGas(nil))
	require.Zero(t, p.RequiredGas([]byte{1, 2}))
	require.Zero(t, p.RequiredGas([]byte{0xde, 0xad, 0xbe, 0xef}))
}

func TestPrecompile_RunInputErrors(t *testing.T) {
	p, ctx, seal := newHarness(t)

	// Short input.
	_, err := p.Run(ctx, []byte{1, 2})
	require.Error(t, err)

	// Unknown selector.
	_, err = p.Run(ctx, []byte{0xde, 0xad, 0xbe, 0xef})
	require.Error(t, err)

	// Valid selector, malformed argument payload.
	input, err := p.ABI().Pack(precompile.MethodGetSeal, seal.Id)
	require.NoError(t, err)
	_, err = p.Run(ctx, input[:8])
	require.Error(t, err)
}

func TestPrecompile_AddressAndABI(t *testing.T) {
	p, _, _ := newHarness(t)
	require.Equal(t, "0x0000000000000000000000000000000000000900", precompile.Address.Hex())
	// Every method in the schedule exists in the ABI.
	for _, m := range []string{
		precompile.MethodGetSeal, precompile.MethodGetConfidentiality,
		precompile.MethodGetSealIDByJob, precompile.MethodVerifySeal,
		precompile.MethodRequireConfidentiality,
	} {
		_, ok := p.ABI().Methods[m]
		require.True(t, ok, "%s missing from ABI", m)
	}
	// The Solidity interface file ships alongside the ABI.
	require.True(t, strings.HasPrefix(precompile.Address.Hex(), "0x"))
}
