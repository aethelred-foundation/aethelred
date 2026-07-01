package confidential

import (
	"strings"

	"github.com/aethelred/aethelred/internal/attestation"
)

// ResultSignal is the minimal per-verification evidence the chain feeds the
// CEAP derivation. It is populated from a consensus-agreed verification result
// (attestation type + platform), so DeriveAttestation is a pure, deterministic
// fold that every validator computes identically.
type ResultSignal struct {
	// AttestationType is the verifier's self-declared method: "tee", "zkml",
	// "hybrid", "reexec", … (case-insensitive). It is the primary signal.
	AttestationType string
	// Platform is the attesting hardware platform for TEE/GPU-CC results.
	Platform attestation.Platform
	// Succeeded reports whether this verification passed; failed results
	// contribute nothing to the achieved confidentiality/verification.
	Succeeded bool
}

// backendForType maps a verifier's attestation type to the confidentiality
// backend it implies. Only methods that actually protect the data in a boundary
// (a TEE / GPU-CC enclave) yield a confidentiality backend; a bare zk proof
// proves correctness without hiding the input, so it implies no backend.
func backendForType(attestationType string) Backend {
	switch strings.ToLower(strings.TrimSpace(attestationType)) {
	case "tee", "hybrid":
		return BackendTEE
	case "gpu-cc", "gpucc":
		return BackendGPUCC
	default:
		return BackendNone
	}
}

// verificationForType maps a verifier's attestation type to the verification
// method it proves.
func verificationForType(attestationType string) Verification {
	switch strings.ToLower(strings.TrimSpace(attestationType)) {
	case "zkml", "hybrid": // hybrid folds a succinct proof over attested execution
		return VerificationZKML
	case "reexec", "reexecution":
		return VerificationReexec
	case "freivalds":
		return VerificationFreivalds
	case "optimistic":
		return VerificationOptimistic
	case "tee", "gpu-cc", "gpucc":
		return VerificationTEEAttested
	default:
		return VerificationNone
	}
}

// DeriveAttestation folds the per-result signals and the deployment trust basis
// into the single ConfidentialityAttestation bound into the Digital Seal.
//
// It reports the strongest confidentiality backend and the strongest
// verification method actually achieved across the successful results (all
// validators re-execute, so a single successful TEE result means the workload
// ran in an enclave). It is deterministic: identical inputs yield identical
// output on every validator, which is what makes Satisfies a safe consensus
// check.
//
// Fields it cannot yet witness on-chain are left honestly empty: Measurement is
// nil (the raw quote is carried separately on the seal's TEEAttestation) and
// Jurisdiction is empty until a deployment pins its region, so a residency-
// restricted policy fails closed rather than being granted a fabricated region.
func DeriveAttestation(signals []ResultSignal, trustBasis attestation.TrustBasis, policyHash []byte, worker string) ConfidentialityAttestation {
	backend := BackendNone
	verification := VerificationNone
	var platform attestation.Platform

	for _, s := range signals {
		if !s.Succeeded {
			continue
		}
		if b := backendForType(s.AttestationType); b.confidentialityStrength() > backend.confidentialityStrength() {
			backend = b
		}
		if v := verificationForType(s.AttestationType); v.strength() > verification.strength() {
			verification = v
		}
		if platform == "" && s.Platform != "" {
			platform = s.Platform
		}
	}

	return ConfidentialityAttestation{
		Backend:      backend,
		Verification: verification,
		Platform:     platform,
		TrustBasis:   trustBasis,
		// A non-none confidentiality backend seals the input to its boundary;
		// "none" leaves the data public, so it is not sealed.
		DataSealed: backend != BackendNone,
		PolicyHash: policyHash,
		Worker:     worker,
	}
}
