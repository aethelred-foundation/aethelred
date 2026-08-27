package seal

import (
	"context"
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// fuzzReader returns a fixed seal for any id — the fuzz target exercises the
// DISPATCH and DECODE surface, which is what attacker-controlled calldata hits.
type fuzzReader struct{}

func (fuzzReader) GetSeal(context.Context, string) (*sealtypes.DigitalSeal, error) {
	return &sealtypes.DigitalSeal{
		Id:     "s",
		Status: sealtypes.SealStatus_SEAL_STATUS_ACTIVE,
		Confidentiality: &sealtypes.ConfidentialityAttestation{
			Backend: "tee", Verification: "zkml", DataSealed: true,
		},
	}, nil
}
func (fuzzReader) GetSealByJob(context.Context, string) (*sealtypes.DigitalSeal, error) {
	return nil, fmt.Errorf("not found")
}

// FuzzPrecompileRun asserts the no-panic invariant on the EVM-facing entry:
// arbitrary calldata (attacker-controlled, permissionless once mounted) must
// yield a result or an error — NEVER a panic, which would crash the node.
func FuzzPrecompileRun(f *testing.F) {
	p, err := NewPrecompile(fuzzReader{})
	if err != nil {
		f.Fatal(err)
	}
	// Seeds: every method selector with valid + truncated + oversized payloads.
	for name := range p.abi.Methods {
		m := p.abi.Methods[name]
		f.Add(m.ID)
		f.Add(append(m.ID, make([]byte, 32)...))
		f.Add(append(m.ID, make([]byte, 4096)...))
	}
	f.Add([]byte{})
	f.Add([]byte{0xde, 0xad, 0xbe, 0xef})

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Run panicked on %x: %v", input, r)
			}
		}()
		_, _ = p.Run(sdk.Context{}, input)
		_ = p.RequiredGas(input)
	})
}
