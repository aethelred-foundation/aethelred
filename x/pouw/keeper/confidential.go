package keeper

import (
	"fmt"

	"github.com/aethelred/aethelred/internal/attestation"
	"github.com/aethelred/aethelred/internal/confidential"
	"github.com/aethelred/aethelred/x/pouw/types"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// confidential.go is the on-chain half of the Confidential Execution &
// Attestation Protocol (CEAP, see docs/architecture/ADR-0003). It translates
// between the on-chain proto messages and the internal/confidential domain,
// derives the ConfidentialityAttestation achieved by a completed job, and
// enforces the job's ConfidentialityPolicy before the Digital Seal is minted.
//
// The derivation and the Satisfies check are pure, deterministic functions of
// consensus-agreed inputs (the verification results, the job policy, and the
// chain's verification mode), so every validator computes the same attestation
// and reaches the same accept/reject verdict — no app-hash divergence.

// confidentialPolicyFromProto converts the on-chain policy a submitter attached
// to a job into the domain policy the CEAP engine enforces. A nil policy means
// "no confidentiality required" (an unrestricted, always-satisfied policy).
func confidentialPolicyFromProto(p *types.ConfidentialityPolicy) confidential.ConfidentialityPolicy {
	if p == nil {
		return confidential.ConfidentialityPolicy{}
	}
	out := confidential.ConfidentialityPolicy{
		MinVerification:   confidential.Verification(p.MinVerification),
		RequireVendorRoot: p.RequireVendorRoot,
	}
	for _, b := range p.AllowedBackends {
		out.AllowedBackends = append(out.AllowedBackends, confidential.Backend(b))
	}
	for _, pl := range p.AllowedPlatforms {
		out.AllowedPlatforms = append(out.AllowedPlatforms, attestation.Platform(pl))
	}
	for _, j := range p.DataResidency {
		out.DataResidency = append(out.DataResidency, confidential.Jurisdiction(j))
	}
	return out
}

// trustBasisFromParams derives the attestation trust basis from the chain's
// verification mode. A chain that permits simulated TEE cannot honestly claim
// the silicon vendor's production root, so it reports test_root; a chain that
// forbids simulation reports vendor_root.
func trustBasisFromParams(params *types.Params) attestation.TrustBasis {
	if params != nil && params.AllowSimulated {
		return attestation.TrustTestRoot
	}
	return attestation.TrustVendorRoot
}

// resultSignals projects consensus-agreed verification results onto the minimal
// per-result evidence the CEAP derivation consumes.
func resultSignals(results []types.VerificationResult) []confidential.ResultSignal {
	signals := make([]confidential.ResultSignal, 0, len(results))
	for i := range results {
		signals = append(signals, confidential.ResultSignal{
			AttestationType: results[i].AttestationType,
			Platform:        attestation.Platform(results[i].TeePlatform),
			Succeeded:       results[i].Success,
		})
	}
	return signals
}

// primaryWorker is the validator address of the first successful result,
// recorded on the attestation as the executing worker.
func primaryWorker(results []types.VerificationResult) string {
	for i := range results {
		if results[i].Success {
			return results[i].ValidatorAddress
		}
	}
	return ""
}

// confidentialAttestationToSeal converts the domain attestation into the seal
// proto message bound into the Digital Seal.
func confidentialAttestationToSeal(a confidential.ConfidentialityAttestation) *sealtypes.ConfidentialityAttestation {
	return &sealtypes.ConfidentialityAttestation{
		Backend:      string(a.Backend),
		Verification: string(a.Verification),
		Platform:     string(a.Platform),
		Measurement:  a.Measurement,
		TrustBasis:   string(a.TrustBasis),
		Jurisdiction: string(a.Jurisdiction),
		DataSealed:   a.DataSealed,
		PolicyHash:   a.PolicyHash,
		Worker:       a.Worker,
	}
}

// deriveConfidentiality builds the ConfidentialityAttestation a completed job
// achieved and enforces the job's ConfidentialityPolicy. It returns the
// seal-proto attestation to bind into the Digital Seal, or an error if the
// achieved confidentiality does not satisfy the policy — in which case the job
// MUST NOT be sealed. Deterministic: every validator reaches the same verdict.
func deriveConfidentiality(job *types.ComputeJob, results []types.VerificationResult, params *types.Params) (*sealtypes.ConfidentialityAttestation, error) {
	policy := confidentialPolicyFromProto(job.ConfidentialityPolicy)
	att := confidential.DeriveAttestation(
		resultSignals(results),
		trustBasisFromParams(params),
		policy.CanonicalHash(),
		primaryWorker(results),
	)
	if err := att.Satisfies(policy); err != nil {
		return nil, fmt.Errorf("confidentiality policy not satisfied: %w", err)
	}
	return confidentialAttestationToSeal(att), nil
}
