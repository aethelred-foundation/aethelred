package confidential

import (
	"context"
	"errors"
	"testing"

	"github.com/aethelred/aethelred/internal/attestation"
)

func ccOn() error  { return nil }
func ccOff() error { return errors.New("gpu-cc: confidential compute not ready") }

func gpuExec(_ context.Context, _ EncryptedInput, _ ModelRef) (Output, RawAttestation, error) {
	return Output{OutputCommitment: []byte("oc")}, RawAttestation{
		Platform:    attestation.PlatformNVIDIAGPU,
		Measurement: []byte("gpu-measurement"),
		TrustBasis:  attestation.TrustVendorRoot,
		Worker:      "h100-worker",
	}, nil
}

func TestGPUCC_Construction(t *testing.T) {
	if _, err := NewGPUCCBackendWithExecutor(gpuExec, nil); err == nil {
		t.Error("nil detector must be rejected")
	}
}

func TestGPUCC_AvailabilityIsDetectionDriven(t *testing.T) {
	// CC mode off: unavailable regardless of executor.
	b, err := NewGPUCCBackendWithExecutor(gpuExec, ccOff)
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	if b.Available() == nil {
		t.Error("CC-off host must report unavailable")
	}
	if _, err := b.Prepare(context.Background(), ConfidentialityPolicy{}); err == nil {
		t.Error("prepare must fail on a CC-off host")
	}
	if _, _, err := b.Execute(context.Background(), nil, nil, ModelRef{}); err == nil {
		t.Error("execute must fail on a CC-off host")
	}

	// CC mode on but no executor wired: still unavailable (honest).
	b, err = NewGPUCCBackendWithExecutor(nil, ccOn)
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	if b.Available() == nil {
		t.Error("executor-less backend must report unavailable")
	}

	// CC on + executor: operational.
	b, err = NewGPUCCBackendWithExecutor(gpuExec, ccOn)
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	if err := b.Available(); err != nil {
		t.Errorf("CC-on host with executor must be available: %v", err)
	}
}

func TestGPUCC_ExecuteLiftsAttestation(t *testing.T) {
	b, err := NewGPUCCBackendWithExecutor(gpuExec, ccOn)
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	if b.Kind() != BackendGPUCC {
		t.Errorf("kind = %q", b.Kind())
	}
	if !b.SatisfiesPlatform(string(attestation.PlatformNVIDIAGPU)) {
		t.Error("must satisfy nvidia-gpu")
	}
	if b.SatisfiesPlatform(string(attestation.PlatformAMDSEVSNP)) {
		t.Error("must not satisfy CPU TEE platforms")
	}

	sess, err := b.Prepare(context.Background(), ConfidentialityPolicy{})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer func() {
		if err := sess.Close(); err != nil {
			t.Errorf("close GPU confidential-computing session: %v", err)
		}
	}()

	out, att, err := b.Execute(context.Background(), sess, EncryptedInput("in"), ModelRef{ModelID: "m"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if string(out.OutputCommitment) != "oc" {
		t.Error("output not returned")
	}
	if att.Backend != BackendGPUCC || att.Verification != VerificationTEEAttested {
		t.Errorf("attestation dims wrong: %+v", att)
	}
	if att.Platform != attestation.PlatformNVIDIAGPU || !att.DataSealed {
		t.Errorf("platform/sealing wrong: %+v", att)
	}
	if att.TrustBasis != attestation.TrustVendorRoot || att.Worker != "h100-worker" {
		t.Errorf("trust/worker wrong: %+v", att)
	}

	// Executor errors propagate.
	failing := func(context.Context, EncryptedInput, ModelRef) (Output, RawAttestation, error) {
		return Output{}, RawAttestation{}, errors.New("cuda launch failed")
	}
	b, err = NewGPUCCBackendWithExecutor(failing, ccOn)
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	if _, _, err := b.Execute(context.Background(), noopSession{}, nil, ModelRef{}); err == nil {
		t.Error("executor error must propagate")
	}
}

// TestGPUCC_ProductionDetectorHonesty: on this machine (no NVIDIA CC hardware)
// the production detector must report unavailable — the backend can never be
// faked into availability by configuration alone.
func TestGPUCC_ProductionDetectorHonesty(t *testing.T) {
	err := DetectNVIDIACC()
	if err == nil {
		// If this host genuinely runs NVIDIA CC, availability is legitimate.
		t.Skip("host reports real NVIDIA confidential-compute mode")
	}
	b, berr := NewGPUCCBackendWithExecutor(gpuExec, DetectNVIDIACC)
	if berr != nil {
		t.Fatalf("backend: %v", berr)
	}
	if b.Available() == nil {
		t.Error("backend must be unavailable without real CC hardware")
	}
}

// TestGPUCC_RegistryIntegration: a detection-off GPU-CC backend is never
// selected; a detection-on one participates at TEE-class strength.
func TestGPUCC_RegistryIntegration(t *testing.T) {
	off, err := NewGPUCCBackendWithExecutor(gpuExec, ccOff)
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	r := NewRegistry()
	r.Register(off)
	if _, err := r.Select(ConfidentialityPolicy{AllowedBackends: []Backend{BackendGPUCC}}); err == nil {
		t.Error("CC-off backend must never be selected")
	}

	on, err := NewGPUCCBackendWithExecutor(gpuExec, ccOn)
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	r.Register(on)
	b, err := r.Select(ConfidentialityPolicy{AllowedBackends: []Backend{BackendGPUCC}})
	if err != nil || b.Kind() != BackendGPUCC {
		t.Fatalf("CC-on backend must be selectable, got %v err=%v", b, err)
	}
}
