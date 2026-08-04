package verify

import (
	"context"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/internal/confidential"
)

// confidential.go wires the CEAP confidential-execution layer (ADR-0003) into
// the verification orchestrator — the worker-side composition root. A job that
// carries a ConfidentialityPolicy is executed through a policy-selected
// confidential backend (TEE / GPU-CC / MPC / FHE); the resulting attestation is
// pre-flighted against the SAME Satisfies check consensus will run at sealing,
// so an honest worker never submits a result the chain is guaranteed to reject
// (e.g. a colocated MPC cluster against a data-sealing policy).

// ConfidentialExecutionResult is what the worker feeds into its verification
// wire: the committed output, the attestation to be bound into the seal, and
// the wire-level attestation-type signal consensus folds via DeriveAttestation.
type ConfidentialExecutionResult struct {
	Output      confidential.Output
	Attestation confidential.ConfidentialityAttestation
	// AttestationType is the VerificationResult.AttestationType wire signal
	// ("tee" | "gpu-cc" | "mpc" | "fhe" | "hybrid").
	AttestationType string
	ExecutionTimeMs int64
}

// SetConfidentialRegistry installs the deployment's confidential backends.
// The registry is assembled at the composition root from what is GENUINELY
// operational (engine-backed FHE, a configured MPC cluster, detection-gated
// GPU-CC, an executor-backed TEE) — never from wishful configuration.
func (vo *VerificationOrchestrator) SetConfidentialRegistry(r *confidential.Registry) {
	vo.confidentialRegistry = r
}

// ConfidentialBackendsAvailable reports the operational backends (sorted,
// deterministic) — used by readiness endpoints and worker capability adverts.
func (vo *VerificationOrchestrator) ConfidentialBackendsAvailable() []confidential.Backend {
	if vo.confidentialRegistry == nil {
		return nil
	}
	return vo.confidentialRegistry.AvailableBackends()
}

// ExecuteConfidential runs a confidential workload under the given policy:
// select the strongest permitted operational backend (never downgrade),
// execute inside its boundary, bind the policy hash, and pre-flight the
// attestation against the policy with the same check consensus runs.
func (vo *VerificationOrchestrator) ExecuteConfidential(
	ctx context.Context,
	policy confidential.ConfidentialityPolicy,
	in confidential.EncryptedInput,
	ref confidential.ModelRef,
) (result *ConfidentialExecutionResult, err error) {
	if vo.confidentialRegistry == nil {
		return nil, fmt.Errorf("confidential execution not configured: no backend registry installed")
	}

	backend, err := vo.confidentialRegistry.Select(policy)
	if err != nil {
		return nil, fmt.Errorf("confidential backend selection: %w", err)
	}

	start := time.Now()
	sess, err := backend.Prepare(ctx, policy)
	if err != nil {
		return nil, fmt.Errorf("confidential session (%s): %w", backend.Kind(), err)
	}
	defer func() {
		if closeErr := sess.Close(); err == nil && closeErr != nil {
			result = nil
			err = fmt.Errorf("close confidential session (%s): %w", backend.Kind(), closeErr)
		}
	}()

	out, att, err := backend.Execute(ctx, sess, in, ref)
	if err != nil {
		return nil, fmt.Errorf("confidential execution (%s): %w", backend.Kind(), err)
	}
	elapsed := time.Since(start).Milliseconds()

	// Bind the exact policy this execution answered to.
	att.PolicyHash = policy.CanonicalHash()

	// PRE-FLIGHT: the same consensus check CompleteJob runs. If the achieved
	// attestation cannot satisfy the policy (colocated MPC vs a sealing
	// requirement, test root vs vendor-root, wrong jurisdiction), fail HERE —
	// the worker never submits a result the chain must reject.
	if satErr := att.Satisfies(policy); satErr != nil {
		return nil, fmt.Errorf("confidential result rejected pre-flight (%s): %w", backend.Kind(), satErr)
	}

	signal := WireSignalForBackend(att.Backend)

	vo.metrics.mutex.Lock()
	vo.metrics.ConfidentialExecutions++
	vo.metrics.mutex.Unlock()

	vo.logger.Info("Confidential execution complete",
		"backend", att.Backend,
		"verification", att.Verification,
		"data_sealed", att.DataSealed,
		"jurisdiction", att.Jurisdiction,
		"elapsed_ms", elapsed,
	)

	return &ConfidentialExecutionResult{
		Output:          out,
		Attestation:     att,
		AttestationType: signal,
		ExecutionTimeMs: elapsed,
	}, nil
}

// WireSignalForBackend maps a confidentiality backend to the wire-level
// AttestationType consensus folds back via confidential.DeriveAttestation —
// the two mappings are inverses, so the seal reports exactly what ran.
func WireSignalForBackend(b confidential.Backend) string {
	switch b {
	case confidential.BackendTEE:
		return "tee"
	case confidential.BackendGPUCC:
		return "gpu-cc"
	case confidential.BackendMPC:
		return "mpc"
	case confidential.BackendFHE:
		return "fhe"
	case confidential.BackendHybrid:
		return "hybrid"
	default:
		return ""
	}
}
