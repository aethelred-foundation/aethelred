package finance

import (
	"context"
	"fmt"
	"testing"
)

func BenchmarkSanctionsScreening(b *testing.B) {
	svc := NewSanctionsService(SanctionsConfig{
		BlockOnMatch: true,
	})
	ctx := context.Background()
	entity := ScreeningEntity{
		Name:       "Acme Corporation",
		EntityType: "organization",
		Country:    "US",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.ScreenEntity(ctx, entity)
	}
}

func BenchmarkRecordFinancialEvent(b *testing.B) {
	trail := NewFinancialAuditTrail()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = trail.RecordFinancialEvent(ctx, &FinancialEvent{
			Type:        EventTransaction,
			Amount:      50000.00,
			Currency:    "USD",
			Description: fmt.Sprintf("benchmark transaction %d", i),
			Regulation:  "SOX",
			Parties: []FinancialParty{
				{Name: "BenchCorp", Role: "originator", Identifier: "bench-001"},
			},
		})
	}
}

func BenchmarkGenerateSOXEvidence(b *testing.B) {
	trail := NewFinancialAuditTrail()
	ctx := context.Background()

	// Pre-populate events.
	for j := 0; j < 50; j++ {
		_ = trail.RecordFinancialEvent(ctx, &FinancialEvent{
			Type:        EventTransaction,
			Amount:      float64(j * 1000),
			Currency:    "USD",
			Description: fmt.Sprintf("pre-populate event %d", j),
			Regulation:  "SOX",
			Parties: []FinancialParty{
				{Name: "BenchCorp", Role: "originator", Identifier: "bench-001"},
			},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = trail.GenerateSOXEvidence(ctx, "2026-Q1")
	}
}
