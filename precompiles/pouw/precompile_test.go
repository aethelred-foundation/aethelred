package pouw

import (
	"context"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

// Compile-time proof the real x/pouw keeper satisfies the reader surface.
var _ JobReader = pouwkeeper.Keeper{}

type stubJobs struct {
	job   *pouwtypes.ComputeJob
	model *pouwtypes.RegisteredModel
	err   error
}

func (s stubJobs) GetJob(context.Context, string) (*pouwtypes.ComputeJob, error) {
	return s.job, s.err
}
func (s stubJobs) GetRegisteredModel(context.Context, []byte) (*pouwtypes.RegisteredModel, error) {
	return s.model, s.err
}

func hash32(seed byte) []byte {
	h := make([]byte, 32)
	h[0], h[31] = seed, seed
	return h
}

func newP(t *testing.T, r JobReader) *Precompile {
	t.Helper()
	p, err := NewPrecompile(r)
	require.NoError(t, err)
	return p
}

func call(t *testing.T, p *Precompile, method string, args ...interface{}) []interface{} {
	t.Helper()
	input, err := p.ABI().Pack(method, args...)
	require.NoError(t, err)
	out, err := p.Run(sdk.Context{}, input)
	require.NoError(t, err)
	vals, err := p.ABI().Methods[method].Outputs.Unpack(out)
	require.NoError(t, err)
	return vals
}

func TestIPoUW_Construction(t *testing.T) {
	_, err := NewPrecompile(nil)
	require.Error(t, err)
}

func TestIPoUW_GetJob(t *testing.T) {
	job := &pouwtypes.ComputeJob{
		Id: "job-1", Status: pouwtypes.JobStatusCompleted,
		ModelHash: hash32(1), InputHash: hash32(2), OutputHash: hash32(3),
		RequestedBy: "req", SealId: "seal-1", BlockHeight: 42, UsefulWorkUnits: 7,
	}
	p := newP(t, stubJobs{job: job})
	vals := call(t, p, MethodGetJob, "job-1")
	require.Equal(t, uint8(pouwtypes.JobStatusCompleted), vals[0].(uint8))
	model := vals[1].([32]byte)
	require.Equal(t, hash32(1), model[:])
	require.Equal(t, "req", vals[4].(string))
	require.Equal(t, "seal-1", vals[5].(string))
	require.Equal(t, int64(42), vals[6].(int64))
	require.Equal(t, uint64(7), vals[7].(uint64))

	// Missing job reverts.
	pErr := newP(t, stubJobs{err: fmt.Errorf("not found")})
	input, err := pErr.ABI().Pack(MethodGetJob, "nope")
	require.NoError(t, err)
	_, err = pErr.Run(sdk.Context{}, input)
	require.Error(t, err)
}

func TestIPoUW_GetModel(t *testing.T) {
	model := &pouwtypes.RegisteredModel{
		ModelHash: hash32(1), ModelId: "m1", Name: "Risk", Version: "v1",
		Owner: "owner", CircuitHash: hash32(4), VerifyingKeyHash: hash32(5), IsActive: true,
	}
	p := newP(t, stubJobs{model: model})
	vals := call(t, p, MethodGetModel, [32]byte(([32]byte)(hash32(1))))
	require.True(t, vals[0].(bool))
	require.Equal(t, "m1", vals[1].(string))
	require.Equal(t, "Risk", vals[2].(string))
	require.Equal(t, "owner", vals[4].(string))
	ch := vals[5].([32]byte)
	require.Equal(t, hash32(4), ch[:])

	// Missing model reverts.
	pErr := newP(t, stubJobs{err: fmt.Errorf("not found")})
	input, err := pErr.ABI().Pack(MethodGetModel, [32]byte{})
	require.NoError(t, err)
	_, err = pErr.Run(sdk.Context{}, input)
	require.Error(t, err)
}

func TestIPoUW_GatingForms(t *testing.T) {
	// isModelActive: active, inactive, missing.
	p := newP(t, stubJobs{model: &pouwtypes.RegisteredModel{IsActive: true}})
	require.True(t, call(t, p, MethodIsModelActive, [32]byte{})[0].(bool))
	p = newP(t, stubJobs{model: &pouwtypes.RegisteredModel{IsActive: false}})
	require.False(t, call(t, p, MethodIsModelActive, [32]byte{})[0].(bool))
	p = newP(t, stubJobs{err: fmt.Errorf("not found")})
	require.False(t, call(t, p, MethodIsModelActive, [32]byte{})[0].(bool))

	// isJobCompleted: completed, processing, missing.
	p = newP(t, stubJobs{job: &pouwtypes.ComputeJob{Status: pouwtypes.JobStatusCompleted}})
	require.True(t, call(t, p, MethodIsJobCompleted, "j")[0].(bool))
	p = newP(t, stubJobs{job: &pouwtypes.ComputeJob{Status: pouwtypes.JobStatusProcessing}})
	require.False(t, call(t, p, MethodIsJobCompleted, "j")[0].(bool))
	p = newP(t, stubJobs{err: fmt.Errorf("not found")})
	require.False(t, call(t, p, MethodIsJobCompleted, "j")[0].(bool))
}

func TestIPoUW_GasAndDispatchGuards(t *testing.T) {
	p := newP(t, stubJobs{})

	for method, want := range map[string]uint64{
		MethodGetJob:         GasGetJob,
		MethodIsJobCompleted: GasIsJobCompleted,
	} {
		input, err := p.ABI().Pack(method, "job-1")
		require.NoError(t, err)
		require.Equal(t, want, p.RequiredGas(input), method)
	}
	for method, want := range map[string]uint64{
		MethodGetModel:      GasGetModel,
		MethodIsModelActive: GasIsModelActive,
	} {
		input, err := p.ABI().Pack(method, [32]byte{})
		require.NoError(t, err)
		require.Equal(t, want, p.RequiredGas(input), method)
	}

	require.Zero(t, p.RequiredGas(nil))
	require.Zero(t, p.RequiredGas([]byte{1, 2}))
	require.Zero(t, p.RequiredGas([]byte{0xde, 0xad, 0xbe, 0xef}))

	_, err := p.Run(sdk.Context{}, []byte{1})
	require.Error(t, err)
	_, err = p.Run(sdk.Context{}, []byte{0xde, 0xad, 0xbe, 0xef})
	require.Error(t, err)
	input, err := p.ABI().Pack(MethodGetJob, "job-1")
	require.NoError(t, err)
	_, err = p.Run(sdk.Context{}, input[:8])
	require.Error(t, err)
}

func TestIPoUW_ArgTypeGuardsAndUnknownArm(t *testing.T) {
	p := newP(t, stubJobs{})
	for name, fn := range map[string]func(sdk.Context, *abi.Method, []interface{}) ([]byte, error){
		MethodGetJob:         p.getJob,
		MethodIsJobCompleted: p.isJobCompleted,
	} {
		m := p.abi.Methods[name]
		_, err := fn(sdk.Context{}, &m, []interface{}{12345})
		require.Error(t, err, name)
	}
	for name, fn := range map[string]func(sdk.Context, *abi.Method, []interface{}) ([]byte, error){
		MethodGetModel:      p.getModel,
		MethodIsModelActive: p.isModelActive,
	} {
		m := p.abi.Methods[name]
		_, err := fn(sdk.Context{}, &m, []interface{}{"not-bytes32"})
		require.Error(t, err, name)
	}

	foreign := abi.NewMethod("foreign", "foreign", abi.Function, "view", false, false, nil, nil)
	p.abi.Methods["foreign"] = foreign
	require.Zero(t, p.RequiredGas(foreign.ID))
	_, err := p.Run(sdk.Context{}, foreign.ID)
	require.Error(t, err)
}
