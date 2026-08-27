package confidential

import (
	"context"
	"errors"
	"testing"

	"github.com/aethelred/aethelred/internal/attestation"
)

// fakeBackend is an operational stand-in used only to exercise multi-backend
// registry paths (real deployments have exactly one operational backend today).
type fakeBackend struct{ kind Backend }

func (f fakeBackend) Kind() Backend                       { return f.kind }
func (f fakeBackend) Available() error                    { return nil }
func (f fakeBackend) SatisfiesPlatform(Platform) bool     { return true }
func (f fakeBackend) Prepare(context.Context, ConfidentialityPolicy) (Session, error) {
	return noopSession{}, nil
}
func (f fakeBackend) Execute(context.Context, Session, EncryptedInput, ModelRef) (Output, ConfidentialityAttestation, error) {
	return Output{}, ConfidentialityAttestation{}, nil
}

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()
	r.Register(NewTEEBackend(nil))
	if b, ok := r.Get(BackendTEE); !ok || b.Kind() != BackendTEE {
		t.Fatal("expected to get registered TEE backend")
	}
	if _, ok := r.Get(BackendFHE); ok {
		t.Fatal("expected FHE not registered")
	}
}

func TestAvailableBackends_SortsMultiple(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeBackend{kind: BackendTEE})
	r.Register(fakeBackend{kind: BackendFHE})
	got := r.AvailableBackends()
	if len(got) != 2 || got[0] != BackendFHE || got[1] != BackendTEE {
		t.Fatalf("expected sorted [fhe tee], got %v", got)
	}
}

func TestBackendStrength_AllArms(t *testing.T) {
	cases := map[Backend]int{
		BackendNone: 0, BackendTEE: 1, BackendGPUCC: 1,
		BackendMPC: 2, BackendFHE: 3, BackendHybrid: 4, Backend("x"): -1,
	}
	for b, want := range cases {
		if got := b.confidentialityStrength(); got != want {
			t.Errorf("%q strength=%d want %d", b, got, want)
		}
	}
}

func TestVerificationStrength_AllArms(t *testing.T) {
	cases := map[Verification]int{
		VerificationNone: 0, VerificationTEEAttested: 1, VerificationFreivalds: 2,
		VerificationOptimistic: 3, VerificationReexec: 4, VerificationZKML: 5, Verification("x"): -1,
	}
	for v, want := range cases {
		if got := v.strength(); got != want {
			t.Errorf("%q strength=%d want %d", v, got, want)
		}
	}
}

func TestTEEBackend_SatisfiesPlatform(t *testing.T) {
	b := NewTEEBackend(nil)
	for _, p := range []attestation.Platform{
		attestation.PlatformAMDSEVSNP, attestation.PlatformIntelTDX,
		attestation.PlatformAWSNitro, attestation.PlatformAzureMAA,
		attestation.PlatformGCPConfSpace,
	} {
		if !b.SatisfiesPlatform(string(p)) {
			t.Errorf("TEE should satisfy platform %q", p)
		}
	}
	if b.SatisfiesPlatform(string(attestation.PlatformNVIDIAGPU)) {
		t.Error("TEE should not satisfy nvidia-gpu (GPU-CC territory)")
	}
}

func TestTEEBackend_Execute(t *testing.T) {
	// nil executor: prepare succeeds, execute reports an honest error.
	b := NewTEEBackend(nil)
	sess, err := b.Prepare(context.Background(), ConfidentialityPolicy{})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, _, err := b.Execute(context.Background(), sess, EncryptedInput("x"), ModelRef{}); err == nil {
		t.Fatal("expected errNoExecutor with nil executor")
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// real executor: output returned, raw attestation lifted to a full attestation.
	exec := func(_ context.Context, _ EncryptedInput, _ ModelRef) (Output, RawAttestation, error) {
		return Output{OutputCommitment: []byte("oc")}, RawAttestation{
			Platform: attestation.PlatformAMDSEVSNP, Measurement: []byte("m"),
			TrustBasis: attestation.TrustVendorRoot, Jurisdiction: "EU", Worker: "w1",
		}, nil
	}
	out, att, err := NewTEEBackend(exec).Execute(context.Background(), noopSession{}, EncryptedInput("in"), ModelRef{ModelID: "m1"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if string(out.OutputCommitment) != "oc" {
		t.Error("output commitment not returned")
	}
	if att.Backend != BackendTEE || att.Verification != VerificationTEEAttested || !att.DataSealed {
		t.Errorf("attestation not lifted: %+v", att)
	}
	if att.Platform != attestation.PlatformAMDSEVSNP || att.Worker != "w1" || string(att.Measurement) != "m" {
		t.Errorf("attestation fields wrong: %+v", att)
	}

	// executor error propagates.
	execErr := func(_ context.Context, _ EncryptedInput, _ ModelRef) (Output, RawAttestation, error) {
		return Output{}, RawAttestation{}, errors.New("boom")
	}
	if _, _, err := NewTEEBackend(execErr).Execute(context.Background(), noopSession{}, nil, ModelRef{}); err == nil {
		t.Fatal("expected executor error to propagate")
	}
}

func TestUnavailableBackends(t *testing.T) {
	for _, b := range []ConfidentialBackend{NewGPUCCBackend(), NewMPCBackend(), NewFHEBackend()} {
		if b.Available() == nil {
			t.Errorf("%q must report unavailable (honest)", b.Kind())
		}
		if _, err := b.Prepare(context.Background(), ConfidentialityPolicy{}); err == nil {
			t.Errorf("%q prepare must fail", b.Kind())
		}
		if _, _, err := b.Execute(context.Background(), nil, nil, ModelRef{}); err == nil {
			t.Errorf("%q execute must fail", b.Kind())
		}
	}
	if !NewGPUCCBackend().SatisfiesPlatform(string(attestation.PlatformNVIDIAGPU)) {
		t.Error("gpu-cc should satisfy nvidia-gpu")
	}
	if NewGPUCCBackend().SatisfiesPlatform(string(attestation.PlatformAMDSEVSNP)) {
		t.Error("gpu-cc should not satisfy amd-sev-snp")
	}
	if NewFHEBackend().SatisfiesPlatform(string(attestation.PlatformNVIDIAGPU)) {
		t.Error("fhe declares no platforms")
	}
}

func TestPolicy_PlatformAndResidencyFalseBranches(t *testing.T) {
	pol := ConfidentialityPolicy{AllowedPlatforms: []attestation.Platform{attestation.PlatformIntelTDX}}
	if pol.platformAllowed(attestation.PlatformAMDSEVSNP) {
		t.Error("amd should not be allowed under a tdx-only policy")
	}
	pol = ConfidentialityPolicy{DataResidency: []Jurisdiction{"EU"}}
	if pol.residencyAllowed("US") {
		t.Error("US should not be allowed under an EU-only policy")
	}
}

func TestSatisfies_PlatformAndResidencyRejections(t *testing.T) {
	att := ConfidentialityAttestation{
		Backend: BackendTEE, Verification: VerificationTEEAttested,
		Platform: attestation.PlatformAMDSEVSNP, TrustBasis: attestation.TrustVendorRoot,
		Jurisdiction: "US", DataSealed: true,
	}
	if err := att.Satisfies(ConfidentialityPolicy{AllowedPlatforms: []attestation.Platform{attestation.PlatformIntelTDX}}); err == nil {
		t.Fatal("expected platform rejection")
	}
	if err := att.Satisfies(ConfidentialityPolicy{DataResidency: []Jurisdiction{"EU"}}); err == nil {
		t.Fatal("expected residency rejection")
	}
}
