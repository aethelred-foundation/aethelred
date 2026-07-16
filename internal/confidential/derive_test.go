package confidential

import (
	"bytes"
	"testing"

	"github.com/aethelred/aethelred/internal/attestation"
)

func TestBackendForType(t *testing.T) {
	cases := map[string]Backend{
		"tee":      BackendTEE,
		"TEE":      BackendTEE,
		" hybrid ": BackendTEE,
		"hybrid":   BackendTEE,
		"gpu-cc":   BackendGPUCC,
		"gpucc":    BackendGPUCC,
		"fhe":      BackendFHE,
		"FHE":      BackendFHE,
		"mpc":      BackendMPC,
		"zkml":     BackendNone,
		"reexec":   BackendNone,
		"":         BackendNone,
		"unknown":  BackendNone,
	}
	for in, want := range cases {
		if got := backendForType(in); got != want {
			t.Errorf("backendForType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerificationForType(t *testing.T) {
	cases := map[string]Verification{
		"zkml":        VerificationZKML,
		"hybrid":      VerificationZKML,
		"HYBRID":      VerificationZKML,
		"reexec":      VerificationReexec,
		"reexecution": VerificationReexec,
		"freivalds":   VerificationFreivalds,
		"optimistic":  VerificationOptimistic,
		"tee":         VerificationTEEAttested,
		"gpu-cc":      VerificationTEEAttested,
		"gpucc":       VerificationTEEAttested,
		"fhe":         VerificationNone,
		"mpc":         VerificationNone,
		"":            VerificationNone,
		"nonsense":    VerificationNone,
	}
	for in, want := range cases {
		if got := verificationForType(in); got != want {
			t.Errorf("verificationForType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeriveAttestation_RegionBindsJurisdictionAndSatisfiesResidency(t *testing.T) {
	teeSignal := []ResultSignal{
		{AttestationType: "tee", Platform: attestation.PlatformAMDSEVSNP, Succeeded: true},
	}

	// Empty region -> empty jurisdiction -> a residency-restricted policy fails
	// closed (the pre-existing honest behavior must be preserved).
	noRegion := DeriveAttestation(teeSignal, attestation.TrustVendorRoot, nil, "val1", "")
	if noRegion.Jurisdiction != "" {
		t.Fatalf("empty region must yield empty jurisdiction, got %q", noRegion.Jurisdiction)
	}
	if err := noRegion.Satisfies(ConfidentialityPolicy{DataResidency: []Jurisdiction{"AE"}}); err == nil {
		t.Fatal("residency-restricted policy must fail closed with no region")
	}

	// A governance-declared region binds the seal jurisdiction and satisfies a
	// matching residency policy.
	ae := DeriveAttestation(teeSignal, attestation.TrustVendorRoot, nil, "val1", "AE")
	if ae.Jurisdiction != "AE" {
		t.Fatalf("region AE must bind jurisdiction, got %q", ae.Jurisdiction)
	}
	if err := ae.Satisfies(ConfidentialityPolicy{DataResidency: []Jurisdiction{"AE"}}); err != nil {
		t.Fatalf("AE region must satisfy AE residency policy: %v", err)
	}
	// A region outside the permitted set still fails closed.
	if err := ae.Satisfies(ConfidentialityPolicy{DataResidency: []Jurisdiction{"EU"}}); err == nil {
		t.Fatal("AE region must NOT satisfy an EU-only residency policy")
	}
}

func TestDeriveAttestation_EmptyAndFailedYieldNone(t *testing.T) {
	// No signals at all.
	att := DeriveAttestation(nil, attestation.TrustTestRoot, []byte("h"), "val1", "")
	if att.Backend != BackendNone || att.Verification != VerificationNone {
		t.Fatalf("empty signals: got backend=%q verification=%q", att.Backend, att.Verification)
	}
	if att.DataSealed {
		t.Fatal("none backend must not claim data sealing")
	}
	// Only a failed TEE result — must not count.
	att = DeriveAttestation([]ResultSignal{
		{AttestationType: "tee", Platform: attestation.PlatformAMDSEVSNP, Succeeded: false},
	}, attestation.TrustVendorRoot, nil, "val1", "")
	if att.Backend != BackendNone || att.Verification != VerificationNone || att.Platform != "" {
		t.Fatalf("failed-only signals must yield none, got %+v", att)
	}
}

func TestDeriveAttestation_TEE(t *testing.T) {
	att := DeriveAttestation([]ResultSignal{
		{AttestationType: "tee", Platform: attestation.PlatformIntelTDX, Succeeded: true},
	}, attestation.TrustVendorRoot, []byte("policy-hash"), "validator-x", "")

	if att.Backend != BackendTEE {
		t.Errorf("backend = %q, want tee", att.Backend)
	}
	if att.Verification != VerificationTEEAttested {
		t.Errorf("verification = %q, want tee-attested", att.Verification)
	}
	if att.Platform != attestation.PlatformIntelTDX {
		t.Errorf("platform = %q, want %q", att.Platform, attestation.PlatformIntelTDX)
	}
	if !att.DataSealed {
		t.Error("tee backend must claim data sealing")
	}
	if att.TrustBasis != attestation.TrustVendorRoot {
		t.Errorf("trust basis = %q, want vendor_root", att.TrustBasis)
	}
	if !bytes.Equal(att.PolicyHash, []byte("policy-hash")) {
		t.Error("policy hash not passed through")
	}
	if att.Worker != "validator-x" {
		t.Errorf("worker = %q, want validator-x", att.Worker)
	}
}

func TestDeriveAttestation_ZKMLIsNotConfidential(t *testing.T) {
	// A bare zk proof proves correctness but does not hide the input, so it
	// yields the strongest verification with NO confidentiality backend.
	att := DeriveAttestation([]ResultSignal{
		{AttestationType: "zkml", Succeeded: true},
	}, attestation.TrustTestRoot, nil, "w", "")
	if att.Backend != BackendNone {
		t.Errorf("backend = %q, want none (zkml is not confidentiality)", att.Backend)
	}
	if att.Verification != VerificationZKML {
		t.Errorf("verification = %q, want zkml", att.Verification)
	}
	if att.DataSealed {
		t.Error("zkml-only must not claim data sealing")
	}
}

func TestDeriveAttestation_HybridAndMixedTakeStrongest(t *testing.T) {
	// Hybrid: TEE confidentiality + zk verification in one result.
	att := DeriveAttestation([]ResultSignal{
		{AttestationType: "hybrid", Platform: attestation.PlatformAMDSEVSNP, Succeeded: true},
	}, attestation.TrustVendorRoot, nil, "w", "")
	if att.Backend != BackendTEE || att.Verification != VerificationZKML {
		t.Fatalf("hybrid: got backend=%q verification=%q", att.Backend, att.Verification)
	}

	// Mixed quorum: one plain TEE result and one zkml result. The seal must
	// report the strongest of each dimension: TEE backend, zkML verification.
	att = DeriveAttestation([]ResultSignal{
		{AttestationType: "zkml", Succeeded: true},
		{AttestationType: "tee", Platform: attestation.PlatformAWSNitro, Succeeded: true},
	}, attestation.TrustVendorRoot, nil, "w", "")
	if att.Backend != BackendTEE {
		t.Errorf("mixed backend = %q, want tee", att.Backend)
	}
	if att.Verification != VerificationZKML {
		t.Errorf("mixed verification = %q, want zkml", att.Verification)
	}
	if att.Platform != attestation.PlatformAWSNitro {
		t.Errorf("platform = %q, want first non-empty (aws-nitro)", att.Platform)
	}
}

func TestDeriveAttestation_GPUCC(t *testing.T) {
	att := DeriveAttestation([]ResultSignal{
		{AttestationType: "gpu-cc", Platform: attestation.PlatformNVIDIAGPU, Succeeded: true},
	}, attestation.TrustVendorRoot, nil, "w", "")
	if att.Backend != BackendGPUCC {
		t.Errorf("backend = %q, want gpu-cc", att.Backend)
	}
	if !att.DataSealed {
		t.Error("gpu-cc backend must claim data sealing")
	}
	if att.Verification != VerificationTEEAttested {
		t.Errorf("verification = %q, want tee-attested", att.Verification)
	}
}

func TestDeriveAttestation_PlatformPrefersFirstNonEmpty(t *testing.T) {
	att := DeriveAttestation([]ResultSignal{
		{AttestationType: "tee", Platform: "", Succeeded: true},
		{AttestationType: "tee", Platform: attestation.PlatformGCPConfSpace, Succeeded: true},
	}, attestation.TrustTestRoot, nil, "w", "")
	if att.Platform != attestation.PlatformGCPConfSpace {
		t.Errorf("platform = %q, want gcp (first non-empty)", att.Platform)
	}
}
