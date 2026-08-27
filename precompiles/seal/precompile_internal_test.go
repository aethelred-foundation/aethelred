package seal

import (
	"context"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"

	sdk "github.com/cosmos/cosmos-sdk/types"

	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// stubReader lets the guards and error paths be exercised without a store.
type stubReader struct {
	seal *sealtypes.DigitalSeal
	err  error
}

func (s stubReader) GetSeal(context.Context, string) (*sealtypes.DigitalSeal, error) {
	return s.seal, s.err
}
func (s stubReader) GetSealByJob(context.Context, string) (*sealtypes.DigitalSeal, error) {
	return s.seal, s.err
}

func newStubPrecompile(t *testing.T, r SealReader) *Precompile {
	t.Helper()
	p, err := NewPrecompile(r)
	if err != nil {
		t.Fatalf("precompile: %v", err)
	}
	return p
}

// Argument-guard primitives are covered in precompiles/internal/prec; here we
// verify each METHOD rejects mistyped arguments through those guards.
func TestInternal_MethodTypeGuards(t *testing.T) {
	p := newStubPrecompile(t, stubReader{err: fmt.Errorf("nope")})
	ctx := sdk.Context{}
	bad := []interface{}{12345}

	for name, fn := range map[string]func(sdk.Context, *abi.Method, []interface{}) ([]byte, error){
		MethodGetSeal:            p.getSeal,
		MethodGetConfidentiality: p.getConfidentiality,
		MethodGetSealIDByJob:     p.getSealIDByJob,
		MethodVerifySeal:         p.verifySeal,
	} {
		m := p.abi.Methods[name]
		if _, err := fn(ctx, &m, bad); err == nil {
			t.Errorf("%s: non-string arg must error", name)
		}
	}

	// getConfidentiality / getSealIDByJob propagate reader errors.
	mConf := p.abi.Methods[MethodGetConfidentiality]
	if _, err := p.getConfidentiality(ctx, &mConf, []interface{}{"id"}); err == nil {
		t.Error("getConfidentiality must propagate reader error")
	}

	// requireConfidentiality guards: arity, per-arg types, reader error.
	mReq := p.abi.Methods[MethodRequireConfidentiality]
	if _, err := p.requireConfidentiality(ctx, &mReq, []interface{}{"only-one"}); err == nil {
		t.Error("wrong arity must error")
	}
	mk := func(i int, v interface{}) []interface{} {
		args := []interface{}{"id", []string{}, "", []string{}, false, []string{}}
		args[i] = v
		return args
	}
	for i := 0; i < 6; i++ {
		if i == 4 {
			continue // bool slot handled below
		}
		if _, err := p.requireConfidentiality(ctx, &mReq, mk(i, 42)); err == nil {
			t.Errorf("arg %d wrong type must error", i)
		}
	}
	if _, err := p.requireConfidentiality(ctx, &mReq, mk(4, "not-bool")); err == nil {
		t.Error("non-bool requireVendorRoot must error")
	}
	if _, err := p.requireConfidentiality(ctx, &mReq, mk(0, "id")); err == nil {
		t.Error("reader error must propagate")
	}
}

func TestInternal_NilTimestampSeal(t *testing.T) {
	seal := &sealtypes.DigitalSeal{
		Id:     "s1",
		Status: sealtypes.SealStatus_SEAL_STATUS_ACTIVE,
		// Timestamp deliberately nil (legacy seal).
	}
	p := newStubPrecompile(t, stubReader{seal: seal})
	m := p.abi.Methods[MethodGetSeal]
	out, err := p.getSeal(sdk.Context{}, &m, []interface{}{"s1"})
	if err != nil {
		t.Fatalf("getSeal: %v", err)
	}
	vals, err := m.Outputs.Unpack(out)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if vals[4].(uint64) != 0 {
		t.Error("nil timestamp must encode as 0")
	}
}

// TestInternal_UnknownMethodArms covers the defensive default arms in Run and
// RequiredGas by injecting a foreign method into the parsed ABI.
func TestInternal_UnknownMethodArms(t *testing.T) {
	p := newStubPrecompile(t, stubReader{})
	foreign := abi.NewMethod("foreign", "foreign", abi.Function, "view", false, false, nil, nil)
	p.abi.Methods["foreign"] = foreign

	if got := p.RequiredGas(foreign.ID); got != 0 {
		t.Errorf("unknown method gas = %d, want 0", got)
	}
	if _, err := p.Run(sdk.Context{}, foreign.ID); err == nil {
		t.Error("unknown method must error in Run")
	}
}
