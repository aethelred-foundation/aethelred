package confidential

import (
	"bytes"
	"testing"

	"github.com/aethelred/aethelred/internal/attestation"
)

func teeAttestation() ConfidentialityAttestation {
	return ConfidentialityAttestation{
		Backend:      BackendTEE,
		Verification: VerificationTEEAttested,
		Platform:     attestation.PlatformAMDSEVSNP,
		TrustBasis:   attestation.TrustVendorRoot,
		Jurisdiction: "EU",
		DataSealed:   true,
	}
}

func TestSatisfies_AllowsMatching(t *testing.T) {
	pol := ConfidentialityPolicy{
		AllowedBackends:   []Backend{BackendTEE, BackendFHE},
		MinVerification:   VerificationTEEAttested,
		AllowedPlatforms:  []attestation.Platform{attestation.PlatformAMDSEVSNP, attestation.PlatformIntelTDX},
		RequireVendorRoot: true,
		DataResidency:     []Jurisdiction{"EU"},
	}
	if err := teeAttestation().Satisfies(pol); err != nil {
		t.Fatalf("expected policy satisfied, got %v", err)
	}
}

func TestSatisfies_Rejections(t *testing.T) {
	base := ConfidentialityPolicy{
		AllowedBackends:   []Backend{BackendFHE}, // TEE not allowed
		MinVerification:   VerificationZKML,      // stronger than TEE-attested
		AllowedPlatforms:  []attestation.Platform{attestation.PlatformIntelTDX},
		RequireVendorRoot: true,
		DataResidency:     []Jurisdiction{"US"},
	}
	if err := teeAttestation().Satisfies(base); err == nil {
		t.Fatal("expected rejection (backend not allowed)")
	}

	// vendor-root enforcement
	polVendor := ConfidentialityPolicy{RequireVendorRoot: true}
	att := teeAttestation()
	att.TrustBasis = attestation.TrustTestRoot
	if err := att.Satisfies(polVendor); err == nil {
		t.Fatal("expected rejection (test root under vendor-root policy)")
	}

	// min-verification enforcement
	polZK := ConfidentialityPolicy{MinVerification: VerificationZKML}
	if err := teeAttestation().Satisfies(polZK); err == nil {
		t.Fatal("expected rejection (verification weaker than zkML)")
	}

	// data-sealing enforcement
	polSeal := ConfidentialityPolicy{AllowedBackends: []Backend{BackendTEE}}
	att2 := teeAttestation()
	att2.DataSealed = false
	if err := att2.Satisfies(polSeal); err == nil {
		t.Fatal("expected rejection (backend claims no data sealing)")
	}
}

func TestRegistry_SelectHonoursPolicyAndAvailability(t *testing.T) {
	r := NewRegistry()
	r.Register(NewTEEBackend(nil)) // operational
	r.Register(NewFHEBackend())    // not operational
	r.Register(NewMPCBackend())    // not operational
	r.Register(NewGPUCCBackend())  // not operational

	// Only TEE is operational, so even an unrestricted policy selects TEE.
	b, err := r.Select(ConfidentialityPolicy{})
	if err != nil || b.Kind() != BackendTEE {
		t.Fatalf("expected TEE selected, got %v err=%v", b, err)
	}

	// A policy that demands FHE (not operational) must be rejected, never
	// downgraded to a weaker-but-available backend.
	if _, err := r.Select(ConfidentialityPolicy{AllowedBackends: []Backend{BackendFHE}}); err == nil {
		t.Fatal("expected rejection when the only allowed backend is unavailable")
	}

	// Unavailable backends are not reported as available.
	avail := r.AvailableBackends()
	if len(avail) != 1 || avail[0] != BackendTEE {
		t.Fatalf("expected only TEE available, got %v", avail)
	}
}

func TestCanonicalHash_StableAndOrderInsensitive(t *testing.T) {
	p1 := ConfidentialityPolicy{
		AllowedBackends:  []Backend{BackendTEE, BackendFHE},
		AllowedPlatforms: []attestation.Platform{attestation.PlatformAMDSEVSNP, attestation.PlatformIntelTDX},
		DataResidency:    []Jurisdiction{"EU", "UK"},
	}
	p2 := ConfidentialityPolicy{
		AllowedBackends:  []Backend{BackendFHE, BackendTEE},                                                   // reordered
		AllowedPlatforms: []attestation.Platform{attestation.PlatformIntelTDX, attestation.PlatformAMDSEVSNP}, // reordered
		DataResidency:    []Jurisdiction{"UK", "EU"},                                                          // reordered
	}
	if !bytes.Equal(p1.CanonicalHash(), p2.CanonicalHash()) {
		t.Fatal("canonical hash must be order-insensitive")
	}
	p3 := p1
	p3.RequireVendorRoot = true
	if bytes.Equal(p1.CanonicalHash(), p3.CanonicalHash()) {
		t.Fatal("canonical hash must change when a field changes")
	}
}
