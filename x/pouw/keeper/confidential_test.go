package keeper

import (
	"bytes"
	"testing"

	"github.com/aethelred/aethelred/internal/attestation"
	"github.com/aethelred/aethelred/internal/confidential"
	"github.com/aethelred/aethelred/x/pouw/types"
)

func TestConfidentialPolicyFromProto(t *testing.T) {
	if got := confidentialPolicyFromProto(nil); len(got.AllowedBackends) != 0 || got.MinVerification != "" {
		t.Fatalf("nil proto policy must map to empty domain policy, got %+v", got)
	}
	proto := &types.ConfidentialityPolicy{
		AllowedBackends:   []string{"tee", "fhe"},
		MinVerification:   "zkml",
		AllowedPlatforms:  []string{"amd-sev-snp", "intel-tdx"},
		RequireVendorRoot: true,
		DataResidency:     []string{"EU", "UK"},
	}
	got := confidentialPolicyFromProto(proto)
	if len(got.AllowedBackends) != 2 || got.AllowedBackends[0] != confidential.BackendTEE || got.AllowedBackends[1] != confidential.BackendFHE {
		t.Errorf("allowed backends mapped wrong: %v", got.AllowedBackends)
	}
	if got.MinVerification != confidential.VerificationZKML {
		t.Errorf("min verification = %q", got.MinVerification)
	}
	if len(got.AllowedPlatforms) != 2 || got.AllowedPlatforms[0] != attestation.PlatformAMDSEVSNP {
		t.Errorf("platforms mapped wrong: %v", got.AllowedPlatforms)
	}
	if !got.RequireVendorRoot {
		t.Error("require vendor root not mapped")
	}
	if len(got.DataResidency) != 2 || got.DataResidency[0] != confidential.Jurisdiction("EU") {
		t.Errorf("residency mapped wrong: %v", got.DataResidency)
	}
}

func TestTrustBasisFromParams(t *testing.T) {
	if got := trustBasisFromParams(nil); got != attestation.TrustVendorRoot {
		t.Errorf("nil params = %q, want vendor_root", got)
	}
	if got := trustBasisFromParams(&types.Params{AllowSimulated: true}); got != attestation.TrustTestRoot {
		t.Errorf("simulated = %q, want test_root", got)
	}
	if got := trustBasisFromParams(&types.Params{AllowSimulated: false}); got != attestation.TrustVendorRoot {
		t.Errorf("production = %q, want vendor_root", got)
	}
}

func TestResultSignalsAndPrimaryWorker(t *testing.T) {
	results := []types.VerificationResult{
		{ValidatorAddress: "valA", AttestationType: "", TeePlatform: "", Success: false},
		{ValidatorAddress: "valB", AttestationType: "tee", TeePlatform: "amd-sev-snp", Success: true},
	}
	sig := resultSignals(results)
	if len(sig) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(sig))
	}
	if sig[1].AttestationType != "tee" || sig[1].Platform != attestation.PlatformAMDSEVSNP || !sig[1].Succeeded {
		t.Errorf("signal[1] wrong: %+v", sig[1])
	}
	if w := primaryWorker(results); w != "valB" {
		t.Errorf("primary worker = %q, want valB (first successful)", w)
	}
	if w := primaryWorker([]types.VerificationResult{{Success: false}}); w != "" {
		t.Errorf("no successful result must yield empty worker, got %q", w)
	}
}

func TestConfidentialAttestationToSeal(t *testing.T) {
	a := confidential.ConfidentialityAttestation{
		Backend: confidential.BackendTEE, Verification: confidential.VerificationZKML,
		Platform: attestation.PlatformIntelTDX, Measurement: []byte("m"),
		TrustBasis: attestation.TrustVendorRoot, Jurisdiction: "EU",
		DataSealed: true, PolicyHash: []byte("ph"), Worker: "w",
	}
	s := confidentialAttestationToSeal(a)
	if s.Backend != "tee" || s.Verification != "zkml" || s.Platform != "intel-tdx" {
		t.Errorf("string fields wrong: %+v", s)
	}
	if s.TrustBasis != "vendor_root" || s.Jurisdiction != "EU" || !s.DataSealed {
		t.Errorf("meta fields wrong: %+v", s)
	}
	if !bytes.Equal(s.Measurement, []byte("m")) || !bytes.Equal(s.PolicyHash, []byte("ph")) || s.Worker != "w" {
		t.Errorf("byte/worker fields wrong: %+v", s)
	}
}

func teeResults() []types.VerificationResult {
	return []types.VerificationResult{
		{ValidatorAddress: "val1", AttestationType: "tee", TeePlatform: "amd-sev-snp", Success: true},
	}
}

func TestDeriveConfidentiality_NoPolicyAlwaysSeals(t *testing.T) {
	// A job with no confidentiality policy is always sealable, and the seal still
	// records the achieved confidentiality.
	job := &types.ComputeJob{}
	att, err := deriveConfidentiality(job, teeResults(), &types.Params{AllowSimulated: true})
	if err != nil {
		t.Fatalf("policy-less job must seal, got %v", err)
	}
	if att.Backend != "tee" || att.Verification != "tee-attested" {
		t.Errorf("attestation not derived: %+v", att)
	}
	if att.TrustBasis != "test_root" {
		t.Errorf("simulated chain must report test_root, got %q", att.TrustBasis)
	}
	if att.Worker != "val1" {
		t.Errorf("worker = %q", att.Worker)
	}
	if len(att.PolicyHash) == 0 {
		t.Error("policy hash must be bound even for empty policy")
	}
}

func TestDeriveConfidentiality_VendorRootEnforced(t *testing.T) {
	// Policy requires a vendor root; a simulated chain only reaches a test root,
	// so the seal must be rejected.
	job := &types.ComputeJob{ConfidentialityPolicy: &types.ConfidentialityPolicy{
		AllowedBackends:   []string{"tee"},
		RequireVendorRoot: true,
	}}
	if _, err := deriveConfidentiality(job, teeResults(), &types.Params{AllowSimulated: true}); err == nil {
		t.Fatal("expected rejection: vendor root required but chain is simulated")
	}
	// Same policy on a production chain (vendor root) is satisfied.
	if _, err := deriveConfidentiality(job, teeResults(), &types.Params{AllowSimulated: false}); err != nil {
		t.Fatalf("production chain should satisfy vendor-root policy, got %v", err)
	}
}

func TestDeriveConfidentiality_BackendAndVerificationEnforced(t *testing.T) {
	// Policy demands FHE; the job only achieved TEE -> rejected (never downgraded).
	fheJob := &types.ComputeJob{ConfidentialityPolicy: &types.ConfidentialityPolicy{
		AllowedBackends: []string{"fhe"},
	}}
	if _, err := deriveConfidentiality(fheJob, teeResults(), &types.Params{}); err == nil {
		t.Fatal("expected rejection: FHE required but only TEE achieved")
	}

	// Policy demands zkML verification; a plain TEE result is weaker -> rejected.
	zkJob := &types.ComputeJob{ConfidentialityPolicy: &types.ConfidentialityPolicy{
		MinVerification: "zkml",
	}}
	if _, err := deriveConfidentiality(zkJob, teeResults(), &types.Params{}); err == nil {
		t.Fatal("expected rejection: zkML required but only TEE-attested achieved")
	}

	// A hybrid result satisfies a zkML-minimum policy on a production chain.
	hybrid := []types.VerificationResult{
		{ValidatorAddress: "val1", AttestationType: "hybrid", TeePlatform: "intel-tdx", Success: true},
	}
	okJob := &types.ComputeJob{ConfidentialityPolicy: &types.ConfidentialityPolicy{
		AllowedBackends: []string{"tee"}, MinVerification: "zkml",
		AllowedPlatforms: []string{"intel-tdx"},
	}}
	att, err := deriveConfidentiality(okJob, hybrid, &types.Params{})
	if err != nil {
		t.Fatalf("hybrid TEE+zk should satisfy policy, got %v", err)
	}
	if att.Backend != "tee" || att.Verification != "zkml" || att.Platform != "intel-tdx" {
		t.Errorf("bound attestation wrong: %+v", att)
	}
}
