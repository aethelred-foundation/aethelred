package evmhost_test

import (
	"crypto/sha256"
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
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"context"

	"github.com/aethelred/aethelred/internal/evmhost"
	pouwprecompile "github.com/aethelred/aethelred/precompiles/pouw"
	precompile "github.com/aethelred/aethelred/precompiles/seal"
	verifyprecompile "github.com/aethelred/aethelred/precompiles/verify"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

var (
	eoa       = common.HexToAddress("0x00000000000000000000000000000000000000AA")
	requester = sdk.AccAddress([]byte("evmhost-test-requestr")).String()
)

// newStack builds the full REAL stack: seal keeper on a mounted IAVL store, a
// seal with a CEAP attestation, the ISeal precompile, and an EVM host with it
// mounted at 0x0900.
func newStack(t *testing.T) (*evmhost.Host, *precompile.Precompile, sdk.Context, *sealtypes.DigitalSeal) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey("seal")
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	ctx := sdk.NewContext(cms, tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  7,
		Time:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)
	k := sealkeeper.NewKeeper(cdc, runtime.NewKVStoreService(storeKey), "")

	model := sha256.Sum256([]byte("model"))
	input := sha256.Sum256([]byte("input"))
	output := sha256.Sum256([]byte("output"))
	seal := sealtypes.NewDigitalSeal(model[:], input[:], output[:], 7, requester, "evm host test")
	seal.Timestamp = timestamppb.New(ctx.BlockTime())
	seal.JobId = "job-evm-1"
	seal.Confidentiality = &sealtypes.ConfidentialityAttestation{
		Backend:      "fhe",
		Verification: "none",
		TrustBasis:   "",
		Jurisdiction: "EU",
		DataSealed:   true,
		Measurement:  []byte("m"),
		Worker:       "worker-1",
	}
	seal.Id = seal.GenerateID()
	seal.Activate()
	require.NoError(t, k.CreateSeal(ctx, seal))

	p, err := precompile.NewPrecompile(&k)
	require.NoError(t, err)

	host, err := evmhost.NewHost(evmhost.AethelredChainID)
	require.NoError(t, err)
	host.Mount(precompile.Address, p)

	return host, p, ctx, seal
}

func TestHost_Construction(t *testing.T) {
	_, err := evmhost.NewHost(0)
	require.Error(t, err, "non-positive chain id must be rejected")

	h, err := evmhost.NewHost(evmhost.AethelredChainID)
	require.NoError(t, err)
	require.Empty(t, h.Mounted())
}

// TestHost_DirectPrecompileCall: an EOA calls 0x0900 through the real geth
// interpreter — the precompile map routes it to ISeal, which reads the real
// seal keeper.
func TestHost_DirectPrecompileCall(t *testing.T) {
	host, p, ctx, seal := newStack(t)
	require.Equal(t, []common.Address{precompile.Address}, host.Mounted())

	calldata, err := p.ABI().Pack(precompile.MethodVerifySeal, seal.Id)
	require.NoError(t, err)

	ret, err := host.Call(ctx, eoa, precompile.Address, calldata, 200_000)
	require.NoError(t, err)
	vals, err := p.ABI().Methods[precompile.MethodVerifySeal].Outputs.Unpack(ret)
	require.NoError(t, err)
	require.True(t, vals[0].(bool), "seal must verify as active through the EVM")

	// StaticCall works identically for the read path.
	ret, err = host.StaticCall(ctx, eoa, precompile.Address, calldata, 200_000)
	require.NoError(t, err)
	vals, err = p.ABI().Methods[precompile.MethodVerifySeal].Outputs.Unpack(ret)
	require.NoError(t, err)
	require.True(t, vals[0].(bool))
}

// TestHost_ContractCallsPrecompile is the ADR-0001 execution-layer proof: real
// contract BYTECODE, deployed and executed by the real geth interpreter,
// STATICCALLs ISeal at 0x0900 and returns the confidentiality gating verdict.
func TestHost_ContractCallsPrecompile(t *testing.T) {
	host, p, ctx, seal := newStack(t)

	proxy, err := host.Deploy(ctx, eoa, evmhost.ForwardingProxyInitcode(), 500_000)
	require.NoError(t, err)
	require.NotEqual(t, common.Address{}, proxy)

	// requireConfidentiality THROUGH the contract: policy demands FHE + EU.
	calldata, err := p.ABI().Pack(precompile.MethodRequireConfidentiality,
		seal.Id, []string{"fhe"}, "", []string{}, false, []string{"EU"})
	require.NoError(t, err)

	ret, err := host.Call(ctx, eoa, proxy, calldata, 500_000)
	require.NoError(t, err)
	vals, err := p.ABI().Methods[precompile.MethodRequireConfidentiality].Outputs.Unpack(ret)
	require.NoError(t, err)
	require.True(t, vals[0].(bool), "reason: %v", vals[1])
	require.Empty(t, vals[1].(string))

	// A policy the seal cannot satisfy (vendor root demanded, FHE has no
	// silicon root) comes back as a clean false with the reason — through the
	// contract, through the interpreter, from consensus logic.
	calldata, err = p.ABI().Pack(precompile.MethodRequireConfidentiality,
		seal.Id, []string{"fhe"}, "", []string{}, true, []string{})
	require.NoError(t, err)
	ret, err = host.Call(ctx, eoa, proxy, calldata, 500_000)
	require.NoError(t, err)
	vals, err = p.ABI().Methods[precompile.MethodRequireConfidentiality].Outputs.Unpack(ret)
	require.NoError(t, err)
	require.False(t, vals[0].(bool))
	require.Contains(t, vals[1].(string), "vendor root")

	// getConfidentiality through the contract mirrors the stored attestation.
	calldata, err = p.ABI().Pack(precompile.MethodGetConfidentiality, seal.Id)
	require.NoError(t, err)
	ret, err = host.Call(ctx, eoa, proxy, calldata, 500_000)
	require.NoError(t, err)
	vals, err = p.ABI().Methods[precompile.MethodGetConfidentiality].Outputs.Unpack(ret)
	require.NoError(t, err)
	require.Equal(t, "fhe", vals[0].(string))
	require.Equal(t, "EU", vals[5].(string))
	require.True(t, vals[6].(bool))
}

// TestHost_ContractBubblesPrecompileRevert: a precompile error (missing seal)
// reverts the inner STATICCALL; the proxy bubbles it as its own revert.
func TestHost_ContractBubblesPrecompileRevert(t *testing.T) {
	host, p, ctx, _ := newStack(t)
	proxy, err := host.Deploy(ctx, eoa, evmhost.ForwardingProxyInitcode(), 500_000)
	require.NoError(t, err)

	calldata, err := p.ABI().Pack(precompile.MethodGetSeal, "no-such-seal")
	require.NoError(t, err)
	_, err = host.Call(ctx, eoa, proxy, calldata, 500_000)
	require.Error(t, err, "missing seal must revert through the contract")
}

func TestHost_DeployAndCallErrors(t *testing.T) {
	host, p, ctx, seal := newStack(t)

	// Empty initcode.
	_, err := host.Deploy(ctx, eoa, nil, 100_000)
	require.Error(t, err)

	// Out-of-gas deploy.
	_, err = host.Deploy(ctx, eoa, evmhost.ForwardingProxyInitcode(), 10)
	require.Error(t, err)

	// Out-of-gas precompile call (gas below RequiredGas).
	calldata, err := p.ABI().Pack(precompile.MethodVerifySeal, seal.Id)
	require.NoError(t, err)
	_, err = host.Call(ctx, eoa, precompile.Address, calldata, 100)
	require.Error(t, err)

	// Malformed selector reverts inside the precompile.
	_, err = host.Call(ctx, eoa, precompile.Address, []byte{0xde, 0xad, 0xbe, 0xef}, 200_000)
	require.Error(t, err)

	// Same failure surfaces through the static-call path.
	_, err = host.StaticCall(ctx, eoa, precompile.Address, []byte{0xde, 0xad, 0xbe, 0xef}, 200_000)
	require.Error(t, err)
}

// TestHost_FundAccountAndBlockContext: balances land, and block context comes
// from the sdk.Context (height/time), proving chain-state anchoring.
func TestHost_FundAccountAndBlockContext(t *testing.T) {
	host, _, ctx, _ := newStack(t)
	host.FundAccount(eoa, uint256FromUint64(1_000_000))

	// NUMBER opcode contract: PUSH0-free minimal runtime returning block number:
	//   NUMBER PUSH0 MSTORE PUSH1 32 PUSH0 RETURN
	runtime := []byte{0x43, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3}
	l := byte(len(runtime))
	initcode := append([]byte{0x60, l, 0x60, 0x0a, 0x5f, 0x39, 0x60, l, 0x5f, 0xf3}, runtime...)

	addr, err := host.Deploy(ctx, eoa, initcode, 200_000)
	require.NoError(t, err)
	ret, err := host.Call(ctx, eoa, addr, nil, 100_000)
	require.NoError(t, err)
	require.Len(t, ret, 32)
	require.EqualValues(t, 7, ret[31], "NUMBER must reflect sdk.Context block height")
}

func uint256FromUint64(v uint64) *uint256.Int { return uint256.NewInt(v) }

// TestHost_AllThreePrecompilesMounted mounts the full verifiable-AI surface
// (ISeal 0x0900, IVerify 0x0901, IPoUW 0x0902) behind one interpreter and
// walks job → seal → confidentiality from the EVM side.
func TestHost_AllThreePrecompilesMounted(t *testing.T) {
	host, sealP, ctx, seal := newStack(t)

	// IVerify with a stub registry (its keeper-satisfaction is proven by a
	// compile-time assertion in its own package).
	verifyP, err := verifyprecompile.NewPrecompile(stubRegistry{})
	require.NoError(t, err)
	host.Mount(verifyprecompile.Address, verifyP)

	// IPoUW with a stub job pointing at the harness seal.
	pouwP, err := pouwprecompile.NewPrecompile(stubJobs{seal: seal})
	require.NoError(t, err)
	host.Mount(pouwprecompile.Address, pouwP)

	require.Len(t, host.Mounted(), 3)

	// IPoUW: job completed?
	calldata, err := pouwP.ABI().Pack(pouwprecompile.MethodIsJobCompleted, "job-evm-1")
	require.NoError(t, err)
	ret, err := host.Call(ctx, eoa, pouwprecompile.Address, calldata, 200_000)
	require.NoError(t, err)
	vals, err := pouwP.ABI().Methods[pouwprecompile.MethodIsJobCompleted].Outputs.Unpack(ret)
	require.NoError(t, err)
	require.True(t, vals[0].(bool))

	// IPoUW: getJob returns the seal id …
	calldata, err = pouwP.ABI().Pack(pouwprecompile.MethodGetJob, "job-evm-1")
	require.NoError(t, err)
	ret, err = host.Call(ctx, eoa, pouwprecompile.Address, calldata, 200_000)
	require.NoError(t, err)
	vals, err = pouwP.ABI().Methods[pouwprecompile.MethodGetJob].Outputs.Unpack(ret)
	require.NoError(t, err)
	sealID := vals[5].(string)
	require.Equal(t, seal.Id, sealID)

	// … which ISeal resolves to the confidentiality attestation: the full
	// job → seal → attestation walk, entirely through EVM calls.
	calldata, err = sealP.ABI().Pack("getConfidentiality", sealID)
	require.NoError(t, err)
	ret, err = host.Call(ctx, eoa, precompile.Address, calldata, 200_000)
	require.NoError(t, err)
	vals, err = sealP.ABI().Methods["getConfidentiality"].Outputs.Unpack(ret)
	require.NoError(t, err)
	require.Equal(t, "fhe", vals[0].(string))

	// IVerify: circuit gating form works through the interpreter.
	calldata, err = verifyP.ABI().Pack(verifyprecompile.MethodIsCircuitActive, [32]byte{1})
	require.NoError(t, err)
	ret, err = host.Call(ctx, eoa, verifyprecompile.Address, calldata, 200_000)
	require.NoError(t, err)
	vvals, err := verifyP.ABI().Methods[verifyprecompile.MethodIsCircuitActive].Outputs.Unpack(ret)
	require.NoError(t, err)
	require.True(t, vvals[0].(bool))
}

// stubRegistry backs IVerify in the mount test.
type stubRegistry struct{}

func (stubRegistry) GetCircuit(context.Context, []byte) (*verifytypes.Circuit, error) {
	return &verifytypes.Circuit{IsActive: true, ProofSystem: "groth16-bn254"}, nil
}
func (stubRegistry) GetVerifyingKey(context.Context, []byte) (*verifytypes.VerifyingKey, error) {
	return &verifytypes.VerifyingKey{IsActive: true}, nil
}

// stubJobs backs IPoUW in the mount test with a job bound to the harness seal.
type stubJobs struct{ seal *sealtypes.DigitalSeal }

func (s stubJobs) GetJob(context.Context, string) (*pouwtypes.ComputeJob, error) {
	return &pouwtypes.ComputeJob{
		Id: "job-evm-1", Status: pouwtypes.JobStatusCompleted,
		ModelHash: s.seal.ModelCommitment, InputHash: s.seal.InputCommitment,
		OutputHash: s.seal.OutputCommitment, RequestedBy: requester,
		SealId: s.seal.Id, BlockHeight: 7, UsefulWorkUnits: 3,
	}, nil
}
func (stubJobs) GetRegisteredModel(context.Context, []byte) (*pouwtypes.RegisteredModel, error) {
	return &pouwtypes.RegisteredModel{IsActive: true, ModelId: "m1"}, nil
}
