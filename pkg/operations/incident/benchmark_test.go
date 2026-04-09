package incident

import (
	"context"
	"fmt"
	"testing"
)

func BenchmarkCreateIncident(b *testing.B) {
	ctrl := NewIncidentController()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ctrl.CreateIncident(ctx, &Incident{
			Type:     IncidentSecurityBreach,
			Severity: SeverityP0,
			Title:    fmt.Sprintf("Benchmark incident %d", i),
		})
	}
}

func BenchmarkTimelineEntry(b *testing.B) {
	ctrl := NewIncidentController()
	ctx := context.Background()
	inc, err := ctrl.CreateIncident(ctx, &Incident{
		Type:     IncidentSecurityBreach,
		Severity: SeverityP0,
		Title:    "Timeline benchmark incident",
	})
	if err != nil {
		b.Fatalf("setup: CreateIncident failed: %v", err)
	}

	ds := NewDisclosureService()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ds.GetDisclosureRequirements(ctx, inc)
	}
}

func BenchmarkDisclosure(b *testing.B) {
	ctrl := NewIncidentController()
	ctx := context.Background()
	inc, err := ctrl.CreateIncident(ctx, &Incident{
		Type:     IncidentSecurityBreach,
		Severity: SeverityP0,
		Title:    "Disclosure benchmark incident",
	})
	if err != nil {
		b.Fatalf("setup: CreateIncident failed: %v", err)
	}

	ds := NewDisclosureService()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ds.GenerateDisclosure(ctx, inc)
	}
}
