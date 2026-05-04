package billing_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aethelred/aethelred/pkg/enterprise/billing"
)

func BenchmarkRecordUsage(b *testing.B) {
	meter := billing.NewMeteringService()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = meter.RecordUsage(ctx, billing.UsageRecord{
			ID:           fmt.Sprintf("usage-%d", i),
			CustomerID:   "cust-bench-001",
			ResourceType: billing.ResourceComputeUnit,
			Quantity:     100,
			Unit:         "compute-units",
			Timestamp:    time.Now(),
			Metadata:     map[string]string{"region": "us-east-1"},
		})
	}
}

func BenchmarkGenerateInvoice(b *testing.B) {
	meter := billing.NewMeteringService()
	reservations := billing.NewReservationManager(0.10)
	ctx := context.Background()

	// Pre-populate usage records.
	for j := 0; j < 50; j++ {
		_ = meter.RecordUsage(ctx, billing.UsageRecord{
			ID:           fmt.Sprintf("pre-usage-%d", j),
			CustomerID:   "cust-bench-invoice",
			ResourceType: billing.ResourceComputeUnit,
			Quantity:     float64(100 + j),
			Unit:         "compute-units",
			Timestamp:    time.Now().Add(-time.Duration(j) * time.Hour),
		})
	}

	invoiceMgr := billing.NewInvoiceManager(0.0, 30, reservations, meter)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = invoiceMgr.GenerateInvoice(ctx, "cust-bench-invoice", billing.Monthly)
	}
}

func BenchmarkAmountArithmetic(b *testing.B) {
	a := billing.NewAmountFromDollars(100.50)
	c := billing.NewAmountFromDollars(49.99)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sum := a.Add(c)
		diff := a.Sub(c)
		product := a.Mul(10)
		scaled := a.MulFloat(0.85)
		_ = sum.Dollars()
		_ = diff.Cents()
		_ = product.IsZero()
		_ = scaled.IsNegative()
	}
}
