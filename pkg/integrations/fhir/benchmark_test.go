package fhir

import (
	"context"
	"testing"

	"github.com/aethelred/aethelred/pkg/seal/sdk"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

func benchNewBridge(b *testing.B) *FHIRBridge {
	b.Helper()
	keeper := newMockSealKeeper()
	sealSDK, err := sdk.NewSealSDK(sdk.Config{
		ChainID:       "bench-chain",
		SignerAddress: "aethelred1bench",
	}, keeper)
	if err != nil {
		b.Fatalf("setup: NewSealSDK failed: %v", err)
	}

	bridge, err := NewFHIRBridge(BridgeConfig{
		DefaultJurisdiction:  "US",
		DefaultRetentionDays: 2555,
	}, sealSDK)
	if err != nil {
		b.Fatalf("setup: NewFHIRBridge failed: %v", err)
	}
	return bridge
}

func benchPatientResource() *Patient {
	return &Patient{
		ResourceType: string(ResourceTypePatient),
		ID:           "patient-bench-001",
		Active:       true,
		Name: []HumanName{
			{Family: "Benchworth", Given: []string{"Test"}},
		},
		Gender:    "male",
		BirthDate: "1990-01-15",
		Identifier: []Identifier{
			{System: "http://example.org/mrn", Value: "MRN-BENCH-001"},
		},
	}
}

func BenchmarkSealResource(b *testing.B) {
	bridge := benchNewBridge(b)
	ctx := context.Background()
	patient := benchPatientResource()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bridge.SealResource(ctx, patient)
	}
}

func BenchmarkValidateResource(b *testing.B) {
	validator := NewValidator()
	patient := benchPatientResource()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidatePatient(patient)
	}
}

func BenchmarkConsentValidation(b *testing.B) {
	bridge := benchNewBridge(b)
	cm := NewConsentManager(bridge, ConsentPolicy{
		RequireExplicit: false,
		DefaultScope:    "patient-data",
		AllowedPurposes: []string{"treatment", "research"},
	})

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cm.ValidateConsent(ctx, "Patient/patient-bench-001", "treatment")
	}
}

// Interface checks to keep imports satisfied.
var (
	_ sdk.SealKeeper = (*mockSealKeeper)(nil)
	_ = sealtypes.SealStatusActive
)
