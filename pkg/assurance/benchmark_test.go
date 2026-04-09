package assurance

import (
	"context"
	"testing"
	"time"
)

// benchAuditProvider implements AuditProvider for benchmarks.
type benchAuditProvider struct{}

func (p *benchAuditProvider) GetAuditEvidence(_ context.Context, _ string) (*AuditEvidence, error) {
	return &AuditEvidence{
		RecordCount:  100,
		ChainIntact:  true,
		FirstRecord:  time.Now().Add(-24 * time.Hour),
		LastRecord:   time.Now(),
		CoverageGaps: nil,
	}, nil
}

// benchSealProvider implements SealProvider for benchmarks.
type benchSealProvider struct{}

func (p *benchSealProvider) GetSealEvidence(_ context.Context, jobID string) ([]SealEvidence, error) {
	return []SealEvidence{
		{
			SealID:         "seal-bench-001",
			JobID:          jobID,
			OutputHash:     "abc123",
			ValidatorCount: 3,
			BlockHeight:    1000,
			Timestamp:      time.Now(),
			Status:         "active",
		},
	}, nil
}

// benchVerificationProvider implements VerificationProvider for benchmarks.
type benchVerificationProvider struct{}

func (p *benchVerificationProvider) GetVerificationEvidence(_ context.Context, _ string) (*VerificationEvidence, error) {
	return &VerificationEvidence{
		HasTEEAttestation: true,
		HasZKProof:        true,
		AttestationType:   "aws-nitro",
		ProofSystem:       "ezkl",
		VerifiedAt:        time.Now(),
	}, nil
}

// benchComplianceProvider implements ComplianceProvider for benchmarks.
type benchComplianceProvider struct{}

func (p *benchComplianceProvider) GetComplianceEvidence(_ context.Context, _ string) (*ComplianceEvidence, error) {
	return &ComplianceEvidence{
		Frameworks:    []string{"NIST AI RMF", "SOC2"},
		ControlsMet:   18,
		ControlsTotal: 20,
		CoverageScore: 90.0,
	}, nil
}

func setupBenchFabric(b *testing.B) *AssuranceFabric {
	b.Helper()
	fabric, err := NewAssuranceFabric(FabricConfig{
		SealProvider:         &benchSealProvider{},
		AuditProvider:        &benchAuditProvider{},
		VerificationProvider: &benchVerificationProvider{},
		ComplianceProvider:   &benchComplianceProvider{},
	})
	if err != nil {
		b.Fatalf("setup: NewAssuranceFabric failed: %v", err)
	}
	return fabric
}

func BenchmarkCollectEvidence(b *testing.B) {
	fabric := setupBenchFabric(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = fabric.CollectEvidence(ctx, "job-bench-001")
	}
}

func BenchmarkAssuranceLevel(b *testing.B) {
	fabric := setupBenchFabric(b)
	ctx := context.Background()
	evidence, err := fabric.CollectEvidence(ctx, "job-bench-level")
	if err != nil {
		b.Fatalf("setup: CollectEvidence failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = evidence.AssuranceLevel
		_ = evidence.AssuranceLevel.Score()
		_ = evidence.AssuranceLevel.String()
	}
}

func BenchmarkReceiptBuilder(b *testing.B) {
	fabric := setupBenchFabric(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evidence, _ := fabric.CollectEvidence(ctx, "job-bench-receipt")
		if evidence != nil {
			builder := NewReceiptBuilder("job-bench-receipt")
			if evidence.Audit != nil {
				builder.WithAuditTrail(&ReceiptAuditTrail{
					RecordCount: evidence.Audit.RecordCount,
					ChainIntact: evidence.Audit.ChainIntact,
				})
			}
			if len(evidence.Seals) > 0 {
				builder.WithSeal(&ReceiptSeal{
					SealID:         evidence.Seals[0].SealID,
					OutputHash:     evidence.Seals[0].OutputHash,
					ValidatorCount: evidence.Seals[0].ValidatorCount,
					BlockHeight:    evidence.Seals[0].BlockHeight,
				})
			}
			builder.WithAssuranceLevel(evidence.AssuranceLevel)
			_, _ = builder.Build()
		}
	}
}

func BenchmarkExportRegulatorPackage(b *testing.B) {
	fabric := setupBenchFabric(b)
	ctx := context.Background()
	evidence, err := fabric.CollectEvidence(ctx, "job-bench-export")
	if err != nil {
		b.Fatalf("setup: CollectEvidence failed: %v", err)
	}
	builder := NewReceiptBuilder("job-bench-export")
	builder.WithAssuranceLevel(evidence.AssuranceLevel)
	if evidence.Audit != nil {
		builder.WithAuditTrail(&ReceiptAuditTrail{
			RecordCount: evidence.Audit.RecordCount,
			ChainIntact: evidence.Audit.ChainIntact,
		})
	}
	receipt, err := builder.Build()
	if err != nil {
		b.Fatalf("setup: Build failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExportRegulatorPackage(ctx, []ExecutionReceipt{*receipt}, "NIST AI RMF")
	}
}
