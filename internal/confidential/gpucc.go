package confidential

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/aethelred/aethelred/internal/attestation"
)

// gpucc.go implements the GPU confidential-computing backend (NVIDIA Hopper/
// Blackwell CC mode). Unlike FHE/MPC this is a hardware boundary, so the
// backend is operational ONLY when real confidential-compute mode is detected
// on the host — Available() is driven by detection, never by configuration
// alone. Without CC-capable silicon the backend honestly reports unavailable;
// the executor wiring and the attestation lift are real and fully tested, so
// enabling it on an H100 CC host is a deployment step, not an engineering one.

// CCDetect probes the host for active NVIDIA confidential-compute mode. A nil
// return means CC is ON; an error describes why it is not.
type CCDetect func() error

// DetectNVIDIACC is the production detector: it queries nvidia-smi for the
// confidential-compute readiness state. It fails honestly on hosts without an
// NVIDIA driver or with CC disabled.
func DetectNVIDIACC() error {
	path, err := exec.LookPath("nvidia-smi")
	if err != nil {
		return fmt.Errorf("gpu-cc: nvidia-smi not found: %w", err)
	}
	out, err := exec.Command(path, "conf-compute", "-grs").CombinedOutput()
	if err != nil {
		return fmt.Errorf("gpu-cc: conf-compute query failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	// nvidia-smi reports e.g. "Confidential Compute GPUs Ready state: ready".
	text := strings.ToLower(string(out))
	if !strings.Contains(text, "ready") || strings.Contains(text, "not ready") {
		return fmt.Errorf("gpu-cc: confidential compute not ready: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// gpuccBackend is the operational GPU-CC backend: detection-gated, executor-
// driven, attesting as the NVIDIA platform through the NRAS trust path in
// internal/attestation.
type gpuccBackend struct {
	exec   Executor
	detect CCDetect
}

// NewGPUCCBackendWithExecutor builds the GPU-CC backend. exec runs the workload
// inside the CC boundary (CUDA in CC mode + NRAS attestation); detect gates
// availability on real hardware state (DetectNVIDIACC in production, injected
// in tests).
func NewGPUCCBackendWithExecutor(exec Executor, detect CCDetect) (ConfidentialBackend, error) {
	if detect == nil {
		return nil, fmt.Errorf("gpu-cc: detector required")
	}
	return &gpuccBackend{exec: exec, detect: detect}, nil
}

func (g *gpuccBackend) Kind() Backend { return BackendGPUCC }

// Available is detection-driven: the backend is operational only when the host
// genuinely runs in confidential-compute mode AND an executor is wired.
func (g *gpuccBackend) Available() error {
	if err := g.detect(); err != nil {
		return err
	}
	if g.exec == nil {
		return errNoExecutor
	}
	return nil
}

func (g *gpuccBackend) SatisfiesPlatform(p Platform) bool {
	return attestation.Platform(p) == attestation.PlatformNVIDIAGPU
}

func (g *gpuccBackend) Prepare(_ context.Context, _ ConfidentialityPolicy) (Session, error) {
	if err := g.Available(); err != nil {
		return nil, err
	}
	return noopSession{}, nil
}

func (g *gpuccBackend) Execute(ctx context.Context, _ Session, in EncryptedInput, m ModelRef) (Output, ConfidentialityAttestation, error) {
	if err := g.Available(); err != nil {
		return Output{}, ConfidentialityAttestation{}, err
	}
	out, raw, err := g.exec(ctx, in, m)
	if err != nil {
		return Output{}, ConfidentialityAttestation{}, err
	}
	att := ConfidentialityAttestation{
		Backend: BackendGPUCC,
		// CC-mode execution is attested by the GPU's device certificate chain
		// (NRAS) — the same class of claim as a CPU TEE.
		Verification: VerificationTEEAttested,
		Platform:     raw.Platform,
		Measurement:  raw.Measurement,
		TrustBasis:   raw.TrustBasis,
		Jurisdiction: raw.Jurisdiction,
		DataSealed:   true, // data is encrypted to the CC boundary; the operator holds no plaintext
		Worker:       raw.Worker,
	}
	return out, att, nil
}
