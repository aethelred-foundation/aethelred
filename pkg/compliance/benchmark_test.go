package compliance_test

import (
	"testing"

	"github.com/aethelred/aethelred/pkg/compliance/assessor"
	"github.com/aethelred/aethelred/pkg/compliance/exports"
	"github.com/aethelred/aethelred/pkg/compliance/frameworks"
	"github.com/aethelred/aethelred/pkg/compliance/mappings"
)

func BenchmarkFrameworkLoading(b *testing.B) {
	loaders := []func(){
		func() { frameworks.NISTAIIRMF() },
		func() { frameworks.EUAIAct() },
		func() { frameworks.CMMC() },
		func() { frameworks.HIPAA() },
		func() { frameworks.SOC2() },
		func() { frameworks.PCIDSS() },
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, load := range loaders {
			load()
		}
	}
}

func BenchmarkAssessCompliance(b *testing.B) {
	m := mappings.NewMapper()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.AssessCompliance("nist-ai-rmf")
	}
}

func BenchmarkExportJSON(b *testing.B) {
	m := mappings.NewMapper()
	a := assessor.NewAssessor(m)
	report, err := a.Assess("nist-ai-rmf")
	if err != nil {
		b.Fatalf("setup: Assess failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exports.ExportJSON(report)
	}
}

func BenchmarkExportCSV(b *testing.B) {
	m := mappings.NewMapper()
	a := assessor.NewAssessor(m)
	report, err := a.Assess("soc2")
	if err != nil {
		b.Fatalf("setup: Assess failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exports.ExportCSV(report)
	}
}

func BenchmarkExportOSCAL(b *testing.B) {
	m := mappings.NewMapper()
	a := assessor.NewAssessor(m)
	report, err := a.Assess("eu-ai-act")
	if err != nil {
		b.Fatalf("setup: Assess failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exports.ExportOSCAL(report)
	}
}
