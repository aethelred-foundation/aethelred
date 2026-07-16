package verify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	sdk "github.com/cosmos/cosmos-sdk/types"

	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

// Compile-time proof the real x/verify keeper satisfies the reader surface.
var _ RegistryReader = verifykeeper.Keeper{}

type stubRegistry struct {
	circuit *verifytypes.Circuit
	vk      *verifytypes.VerifyingKey
	err     error
}

func (s stubRegistry) GetCircuit(context.Context, []byte) (*verifytypes.Circuit, error) {
	return s.circuit, s.err
}
func (s stubRegistry) GetVerifyingKey(context.Context, []byte) (*verifytypes.VerifyingKey, error) {
	return s.vk, s.err
}

func hash32(seed byte) []byte {
	h := make([]byte, 32)
	h[0], h[31] = seed, seed
	return h
}

func registeredAt() *timestamppb.Timestamp {
	return timestamppb.New(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
}

func newP(t *testing.T, r RegistryReader) *Precompile {
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

func TestIVerify_Construction(t *testing.T) {
	_, err := NewPrecompile(nil)
	require.Error(t, err)
}

func TestIVerify_GetCircuit(t *testing.T) {
	circuit := &verifytypes.Circuit{
		Hash: hash32(1), ProofSystem: "groth16-bn254", ModelHash: hash32(2),
		RegisteredBy: "owner", RegisteredAt: registeredAt(), IsActive: true,
	}
	p := newP(t, stubRegistry{circuit: circuit})

	vals := call(t, p, MethodGetCircuit, [32]byte(([32]byte)(hash32(1))))
	require.True(t, vals[0].(bool))
	require.Equal(t, "groth16-bn254", vals[1].(string))
	model := vals[2].([32]byte)
	require.Equal(t, hash32(2), model[:])
	require.Equal(t, "owner", vals[3].(string))
	require.NotZero(t, vals[4].(uint64))

	// Nil timestamp encodes 0.
	circuit.RegisteredAt = nil
	vals = call(t, p, MethodGetCircuit, [32]byte(([32]byte)(hash32(1))))
	require.Zero(t, vals[4].(uint64))

	// Missing circuit reverts.
	pErr := newP(t, stubRegistry{err: fmt.Errorf("not found")})
	input, err := pErr.ABI().Pack(MethodGetCircuit, [32]byte{})
	require.NoError(t, err)
	_, err = pErr.Run(sdk.Context{}, input)
	require.Error(t, err)
}

func TestIVerify_GetVerifyingKey(t *testing.T) {
	vk := &verifytypes.VerifyingKey{
		Hash: hash32(3), ProofSystem: "groth16-bn254", CircuitHash: hash32(1),
		ModelHash: hash32(2), RegisteredBy: "owner", RegisteredAt: registeredAt(), IsActive: true,
	}
	p := newP(t, stubRegistry{vk: vk})
	vals := call(t, p, MethodGetVerifyingKey, [32]byte(([32]byte)(hash32(3))))
	require.True(t, vals[0].(bool))
	circuitHash := vals[2].([32]byte)
	require.Equal(t, hash32(1), circuitHash[:])
	require.Equal(t, "owner", vals[4].(string))

	// Nil timestamp.
	vk.RegisteredAt = nil
	vals = call(t, p, MethodGetVerifyingKey, [32]byte(([32]byte)(hash32(3))))
	require.Zero(t, vals[5].(uint64))

	// Reader error reverts.
	pErr := newP(t, stubRegistry{err: fmt.Errorf("not found")})
	input, err := pErr.ABI().Pack(MethodGetVerifyingKey, [32]byte{})
	require.NoError(t, err)
	_, err = pErr.Run(sdk.Context{}, input)
	require.Error(t, err)
}

func TestIVerify_IsCircuitActive(t *testing.T) {
	active := &verifytypes.Circuit{IsActive: true}
	p := newP(t, stubRegistry{circuit: active})
	vals := call(t, p, MethodIsCircuitActive, [32]byte{})
	require.True(t, vals[0].(bool))

	inactive := &verifytypes.Circuit{IsActive: false}
	p = newP(t, stubRegistry{circuit: inactive})
	vals = call(t, p, MethodIsCircuitActive, [32]byte{})
	require.False(t, vals[0].(bool))

	// Missing circuit: clean false, no revert.
	p = newP(t, stubRegistry{err: fmt.Errorf("not found")})
	vals = call(t, p, MethodIsCircuitActive, [32]byte{})
	require.False(t, vals[0].(bool))
}

func TestIVerify_GasAndDispatchGuards(t *testing.T) {
	p := newP(t, stubRegistry{})

	input, err := p.ABI().Pack(MethodGetCircuit, [32]byte{})
	require.NoError(t, err)
	require.Equal(t, uint64(GasGetCircuit), p.RequiredGas(input))

	input, err = p.ABI().Pack(MethodGetVerifyingKey, [32]byte{})
	require.NoError(t, err)
	require.Equal(t, uint64(GasGetVerifyingKey), p.RequiredGas(input))

	input, err = p.ABI().Pack(MethodIsCircuitActive, [32]byte{})
	require.NoError(t, err)
	require.Equal(t, uint64(GasIsCircuitActive), p.RequiredGas(input))

	require.Zero(t, p.RequiredGas(nil))
	require.Zero(t, p.RequiredGas([]byte{1, 2, 3}))
	require.Zero(t, p.RequiredGas([]byte{0xde, 0xad, 0xbe, 0xef}))

	// Run guards: short input, unknown selector, malformed args.
	_, err = p.Run(sdk.Context{}, []byte{1})
	require.Error(t, err)
	_, err = p.Run(sdk.Context{}, []byte{0xde, 0xad, 0xbe, 0xef})
	require.Error(t, err)
	input, err = p.ABI().Pack(MethodGetCircuit, [32]byte{})
	require.NoError(t, err)
	_, err = p.Run(sdk.Context{}, input[:8])
	require.Error(t, err)
}

func TestIVerify_ArgTypeGuardsAndUnknownArm(t *testing.T) {
	p := newP(t, stubRegistry{})
	bad := []interface{}{"not-bytes32"}
	for name, fn := range map[string]func(sdk.Context, *abi.Method, []interface{}) ([]byte, error){
		MethodGetCircuit:      p.getCircuit,
		MethodGetVerifyingKey: p.getVerifyingKey,
		MethodIsCircuitActive: p.isCircuitActive,
	} {
		m := p.abi.Methods[name]
		_, err := fn(sdk.Context{}, &m, bad)
		require.Error(t, err, name)
	}

	// Defensive default arms via an injected foreign method.
	foreign := abi.NewMethod("foreign", "foreign", abi.Function, "view", false, false, nil, nil)
	p.abi.Methods["foreign"] = foreign
	require.Zero(t, p.RequiredGas(foreign.ID))
	_, err := p.Run(sdk.Context{}, foreign.ID)
	require.Error(t, err)
}
