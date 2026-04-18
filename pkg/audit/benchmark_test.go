package audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

func benchMakeChain(n int) []keeper.AuditRecord {
	records := make([]keeper.AuditRecord, 0, n)
	prevHash := "genesis"
	baseTime := time.Date(2026, 3, 28, 14, 0, 0, 0, time.UTC)

	categories := []keeper.AuditCategory{
		keeper.AuditCategoryJob,
		keeper.AuditCategoryConsensus,
		keeper.AuditCategorySecurity,
	}
	severities := []keeper.AuditSeverity{
		keeper.AuditSeverityInfo,
		keeper.AuditSeverityWarning,
		keeper.AuditSeverityCritical,
	}

	for i := 0; i < n; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		r := keeper.AuditRecord{
			Sequence:     uint64(i + 1),
			PreviousHash: prevHash,
			Category:     categories[i%len(categories)],
			Severity:     severities[i%len(severities)],
			Action:       fmt.Sprintf("action_%d", i),
			BlockHeight:  int64(1000 + i),
			Timestamp:    ts,
			Actor:        fmt.Sprintf("aethelred1actor%d", i%5),
			Details:      map[string]string{"key": fmt.Sprintf("value_%d", i)},
		}
		r.RecordHash = ComputeRecordHash(r)
		prevHash = r.RecordHash
		records = append(records, r)
	}
	return records
}

func BenchmarkChainVerification_100(b *testing.B) {
	records := benchMakeChain(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyChain(records)
	}
}

func BenchmarkChainVerification_1000(b *testing.B) {
	records := benchMakeChain(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyChain(records)
	}
}

func BenchmarkTimelineConstruction(b *testing.B) {
	records := benchMakeChain(100)
	src := &mockLogSource{records: records}
	ctx := context.Background()
	filter := NewFilter().WithLimit(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = BuildTimeline(ctx, src, filter)
	}
}

func BenchmarkBundleBuilder(b *testing.B) {
	records := benchMakeChain(20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder := NewBundleBuilder(FrameworkSOC2).
			WithID(fmt.Sprintf("bench-%d", i)).
			AddRecords(records[:10]).
			AddControlMapping("CC6.1", ControlMapping{
				ControlName:  "Logical Access",
				Description:  "Restrict access to authorized users",
				EvidenceRefs: []uint64{1, 2, 3},
				Status:       ControlSatisfied,
			})
		_, _ = builder.Build()
	}
}

func BenchmarkFilterMatching(b *testing.B) {
	records := benchMakeChain(1000)
	filter := NewFilter().
		WithCategories(keeper.AuditCategoryJob).
		WithSeverities(keeper.AuditSeverityCritical).
		WithLimit(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matched := 0
		for _, r := range records {
			if filter.Match(r) {
				matched++
			}
		}
		_ = matched
	}
}
