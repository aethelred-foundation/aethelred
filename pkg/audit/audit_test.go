package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockLogSource implements LogSource for testing with a static record set.
type mockLogSource struct {
	records []keeper.AuditRecord
}

func (m *mockLogSource) GetRecords() []keeper.AuditRecord {
	out := make([]keeper.AuditRecord, len(m.records))
	copy(out, m.records)
	return out
}

func (m *mockLogSource) GetRecordsSince(height int64) []keeper.AuditRecord {
	var out []keeper.AuditRecord
	for _, r := range m.records {
		if r.BlockHeight >= height {
			out = append(out, r)
		}
	}
	return out
}

func (m *mockLogSource) GetRecordsByCategory(cat keeper.AuditCategory) []keeper.AuditRecord {
	var out []keeper.AuditRecord
	for _, r := range m.records {
		if r.Category == cat {
			out = append(out, r)
		}
	}
	return out
}

func (m *mockLogSource) Sequence() uint64 {
	if len(m.records) == 0 {
		return 0
	}
	return m.records[len(m.records)-1].Sequence
}

func (m *mockLogSource) LastHash() string {
	if len(m.records) == 0 {
		return "genesis"
	}
	return m.records[len(m.records)-1].RecordHash
}

func (m *mockLogSource) TotalEmitted() uint64 {
	return uint64(len(m.records))
}

// makeTestRecord creates a test audit record with a valid hash chain.
func makeTestRecord(seq uint64, prevHash string, cat keeper.AuditCategory, sev keeper.AuditSeverity, action, actor string, height int64, ts string, details map[string]string) keeper.AuditRecord {
	r := keeper.AuditRecord{
		Sequence:     seq,
		PreviousHash: prevHash,
		Category:     cat,
		Severity:     sev,
		Action:       action,
		BlockHeight:  height,
		Timestamp:    ts,
		Actor:        actor,
		Details:      details,
	}
	r.RecordHash = ComputeRecordHash(r)
	return r
}

// makeTestChain builds a chain of N test records with valid hash linkage.
func makeTestChain(n int) []keeper.AuditRecord {
	records := make([]keeper.AuditRecord, 0, n)
	prevHash := "genesis"
	baseTime := time.Date(2026, 3, 28, 14, 0, 0, 0, time.UTC)

	categories := []keeper.AuditCategory{
		keeper.AuditCategoryJob,
		keeper.AuditCategoryConsensus,
		keeper.AuditCategorySecurity,
		keeper.AuditCategorySlashing,
		keeper.AuditCategoryValidator,
	}
	severities := []keeper.AuditSeverity{
		keeper.AuditSeverityInfo,
		keeper.AuditSeverityWarning,
		keeper.AuditSeverityCritical,
	}
	actions := []string{
		"job_submitted", "job_completed", "job_failed",
		"consensus_reached", "evidence_detected",
		"slashing_applied", "validator_registered",
	}
	actors := []string{
		"aethel1validator1", "aethel1validator2", "system",
	}

	for i := 0; i < n; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		cat := categories[i%len(categories)]
		sev := severities[i%len(severities)]
		action := actions[i%len(actions)]
		actor := actors[i%len(actors)]

		details := map[string]string{
			"job_id": fmt.Sprintf("job_%03d", i),
		}

		r := makeTestRecord(uint64(i+1), prevHash, cat, sev, action, actor, int64(100+i), ts, details)
		records = append(records, r)
		prevHash = r.RecordHash
	}

	return records
}

func newTestSource(n int) *mockLogSource {
	return &mockLogSource{records: makeTestChain(n)}
}

// ---------------------------------------------------------------------------
// Filter tests
// ---------------------------------------------------------------------------

func TestFilter_Match_EmptyFilter(t *testing.T) {
	f := NewFilter()
	r := makeTestRecord(1, "genesis", keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "job_submitted", "system", 100, "2026-03-28T14:00:00Z", nil)
	if !f.Match(r) {
		t.Error("empty filter should match all records")
	}
}

func TestFilter_Match_Categories(t *testing.T) {
	tests := []struct {
		name       string
		filterCats []keeper.AuditCategory
		recordCat  keeper.AuditCategory
		wantMatch  bool
	}{
		{"match_single", []keeper.AuditCategory{keeper.AuditCategoryJob}, keeper.AuditCategoryJob, true},
		{"no_match", []keeper.AuditCategory{keeper.AuditCategorySecurity}, keeper.AuditCategoryJob, false},
		{"match_multi", []keeper.AuditCategory{keeper.AuditCategoryJob, keeper.AuditCategorySecurity}, keeper.AuditCategorySecurity, true},
		{"empty_filter", nil, keeper.AuditCategoryJob, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFilter().WithCategories(tt.filterCats...)
			r := makeTestRecord(1, "genesis", tt.recordCat, keeper.AuditSeverityInfo, "test", "system", 100, "2026-03-28T14:00:00Z", nil)
			if got := f.Match(r); got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestFilter_Match_Severities(t *testing.T) {
	tests := []struct {
		name       string
		filterSevs []keeper.AuditSeverity
		recordSev  keeper.AuditSeverity
		wantMatch  bool
	}{
		{"match_info", []keeper.AuditSeverity{keeper.AuditSeverityInfo}, keeper.AuditSeverityInfo, true},
		{"match_critical", []keeper.AuditSeverity{keeper.AuditSeverityCritical}, keeper.AuditSeverityCritical, true},
		{"no_match", []keeper.AuditSeverity{keeper.AuditSeverityCritical}, keeper.AuditSeverityInfo, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFilter().WithSeverities(tt.filterSevs...)
			r := makeTestRecord(1, "genesis", keeper.AuditCategoryJob, tt.recordSev, "test", "system", 100, "2026-03-28T14:00:00Z", nil)
			if got := f.Match(r); got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestFilter_Match_TimeRange(t *testing.T) {
	from := time.Date(2026, 3, 28, 14, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 28, 15, 0, 0, 0, time.UTC)
	f := NewFilter().WithTimeRange(from, to)

	tests := []struct {
		name      string
		ts        string
		wantMatch bool
	}{
		{"within", "2026-03-28T14:30:00Z", true},
		{"at_start", "2026-03-28T14:00:00Z", true},
		{"at_end", "2026-03-28T15:00:00Z", true},
		{"before", "2026-03-28T13:59:00Z", false},
		{"after", "2026-03-28T15:01:00Z", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := makeTestRecord(1, "genesis", keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "system", 100, tt.ts, nil)
			if got := f.Match(r); got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestFilter_Match_Keywords(t *testing.T) {
	details := map[string]string{
		"job_id":    "job_123",
		"model":     "transformer_v2",
		"validator": "aethel1abc",
	}
	r := makeTestRecord(1, "genesis", keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "job_submitted", "system", 100, "2026-03-28T14:00:00Z", details)

	tests := []struct {
		name      string
		keywords  []string
		wantMatch bool
	}{
		{"match_action", []string{"submitted"}, true},
		{"match_detail_value", []string{"transformer"}, true},
		{"match_job_id", []string{"job_123"}, true},
		{"no_match", []string{"nonexistent"}, false},
		{"case_insensitive", []string{"TRANSFORMER"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFilter().WithKeywords(tt.keywords...)
			if got := f.Match(r); got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestFilter_Apply_LimitOffset(t *testing.T) {
	source := newTestSource(20)
	records := source.GetRecords()

	// Test limit.
	f := NewFilter().WithLimit(5)
	result := f.Apply(records)
	if len(result) != 5 {
		t.Errorf("expected 5 records, got %d", len(result))
	}

	// Test offset.
	f = NewFilter().WithOffset(15)
	result = f.Apply(records)
	if len(result) != 5 {
		t.Errorf("expected 5 records after offset, got %d", len(result))
	}

	// Test limit + offset.
	f = NewFilter().WithOffset(5).WithLimit(3)
	result = f.Apply(records)
	if len(result) != 3 {
		t.Errorf("expected 3 records, got %d", len(result))
	}
	if result[0].Sequence != 6 {
		t.Errorf("expected first record sequence 6, got %d", result[0].Sequence)
	}
}

// ---------------------------------------------------------------------------
// Chain verification tests
// ---------------------------------------------------------------------------

func TestVerifyChain_Valid(t *testing.T) {
	records := makeTestChain(10)
	if err := VerifyChain(records); err != nil {
		t.Errorf("valid chain should verify: %v", err)
	}
}

func TestVerifyChain_TamperedHash(t *testing.T) {
	records := makeTestChain(5)
	records[2].RecordHash = "0000000000000000000000000000000000000000000000000000000000000000"

	err := VerifyChain(records)
	if err == nil {
		t.Error("tampered hash should fail verification")
	}
}

func TestVerifyChain_BrokenLink(t *testing.T) {
	records := makeTestChain(5)
	records[3].PreviousHash = "deadbeef"
	records[3].RecordHash = ComputeRecordHash(records[3])

	err := VerifyChain(records)
	if err == nil {
		t.Error("broken chain link should fail verification")
	}
}

func TestVerifyChain_Empty(t *testing.T) {
	if err := VerifyChain(nil); err != nil {
		t.Errorf("empty chain should verify: %v", err)
	}
}

func TestComputeRecordHash_Deterministic(t *testing.T) {
	r := makeTestRecord(1, "genesis", keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "system", 100, "2026-03-28T14:00:00Z", map[string]string{"key": "value"})
	hash1 := ComputeRecordHash(r)
	hash2 := ComputeRecordHash(r)
	if hash1 != hash2 {
		t.Errorf("hash should be deterministic: %s != %s", hash1, hash2)
	}
}

// ---------------------------------------------------------------------------
// Studio tests
// ---------------------------------------------------------------------------

func TestStudio_NewStudio_NilSource(t *testing.T) {
	_, err := NewStudio(Config{})
	if err == nil {
		t.Error("NewStudio with nil source should return error")
	}
}

func TestStudio_Query(t *testing.T) {
	source := newTestSource(20)
	studio, err := NewStudio(Config{LogSource: source})
	if err != nil {
		t.Fatalf("NewStudio failed: %v", err)
	}

	ctx := context.Background()

	// Query all.
	records, err := studio.Query(ctx, nil)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(records) != 20 {
		t.Errorf("expected 20 records, got %d", len(records))
	}

	// Query with filter.
	f := NewFilter().WithCategories(keeper.AuditCategoryJob)
	records, err = studio.Query(ctx, f)
	if err != nil {
		t.Fatalf("filtered Query failed: %v", err)
	}
	for _, r := range records {
		if r.Category != keeper.AuditCategoryJob {
			t.Errorf("expected category job, got %s", r.Category)
		}
	}
}

func TestStudio_GetRecord(t *testing.T) {
	source := newTestSource(10)
	studio, _ := NewStudio(Config{LogSource: source})
	ctx := context.Background()

	r, err := studio.GetRecord(ctx, 5)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if r.Sequence != 5 {
		t.Errorf("expected sequence 5, got %d", r.Sequence)
	}

	_, err = studio.GetRecord(ctx, 999)
	if err == nil {
		t.Error("GetRecord for non-existent sequence should return error")
	}
}

func TestStudio_GetChain(t *testing.T) {
	source := newTestSource(10)
	studio, _ := NewStudio(Config{LogSource: source})
	ctx := context.Background()

	chain, err := studio.GetChain(ctx, 3, 7)
	if err != nil {
		t.Fatalf("GetChain failed: %v", err)
	}
	if len(chain) != 5 {
		t.Errorf("expected 5 records, got %d", len(chain))
	}
	if chain[0].Sequence != 3 || chain[4].Sequence != 7 {
		t.Errorf("unexpected sequence range: %d-%d", chain[0].Sequence, chain[4].Sequence)
	}
}

func TestStudio_GetStats(t *testing.T) {
	source := newTestSource(20)
	studio, _ := NewStudio(Config{LogSource: source})
	ctx := context.Background()

	stats, err := studio.GetStats(ctx, nil)
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if stats.TotalRecords != 20 {
		t.Errorf("expected 20 total records, got %d", stats.TotalRecords)
	}
	if !stats.ChainIntact {
		t.Error("chain should be intact")
	}

	// Check that all categories are represented.
	totalByCat := 0
	for _, count := range stats.ByCategory {
		totalByCat += count
	}
	if totalByCat != 20 {
		t.Errorf("expected 20 total by category, got %d", totalByCat)
	}
}

// ---------------------------------------------------------------------------
// Timeline tests
// ---------------------------------------------------------------------------

func TestBuildTimeline_Basic(t *testing.T) {
	source := newTestSource(10)
	ctx := context.Background()

	tl, err := BuildTimeline(ctx, source, nil)
	if err != nil {
		t.Fatalf("BuildTimeline failed: %v", err)
	}
	if tl.TotalEvents != 10 {
		t.Errorf("expected 10 events, got %d", tl.TotalEvents)
	}
	if tl.StartTime == nil || tl.EndTime == nil {
		t.Error("start/end time should be set")
	}
}

func TestBuildJobTimeline(t *testing.T) {
	source := newTestSource(10)
	ctx := context.Background()

	tl, err := BuildJobTimeline(ctx, source, "job_000")
	if err != nil {
		t.Fatalf("BuildJobTimeline failed: %v", err)
	}
	if tl.TotalEvents == 0 {
		t.Error("expected at least one event for job_000")
	}
	for _, e := range tl.Events {
		if e.Details["job_id"] != "job_000" {
			t.Errorf("expected job_id job_000, got %s", e.Details["job_id"])
		}
	}
}

func TestBuildActorTimeline(t *testing.T) {
	source := newTestSource(10)
	ctx := context.Background()

	tl, err := BuildActorTimeline(ctx, source, "system")
	if err != nil {
		t.Fatalf("BuildActorTimeline failed: %v", err)
	}
	for _, e := range tl.Events {
		if e.Actor != "system" {
			t.Errorf("expected actor system, got %s", e.Actor)
		}
	}
	if tl.Actor != "system" {
		t.Errorf("expected timeline actor system, got %s", tl.Actor)
	}
}

func TestMergeTimelines(t *testing.T) {
	source := newTestSource(10)
	ctx := context.Background()

	tl1, _ := BuildActorTimeline(ctx, source, "system")
	tl2, _ := BuildActorTimeline(ctx, source, "aethel1validator1")

	merged := MergeTimelines([]*Timeline{tl1, tl2})
	if merged.TotalEvents != tl1.TotalEvents+tl2.TotalEvents {
		t.Errorf("merged timeline should have %d events, got %d",
			tl1.TotalEvents+tl2.TotalEvents, merged.TotalEvents)
	}

	// Events should be sorted chronologically.
	for i := 1; i < len(merged.Events); i++ {
		if merged.Events[i].Timestamp.Before(merged.Events[i-1].Timestamp) {
			t.Error("merged events should be in chronological order")
			break
		}
	}
}

// ---------------------------------------------------------------------------
// Evidence bundle tests
// ---------------------------------------------------------------------------

func TestBundleBuilder_Build(t *testing.T) {
	records := makeTestChain(5)

	bundle, err := NewBundleBuilder(FrameworkNIST80053).
		WithID("test-bundle-001").
		AddRecords(records).
		AddSeals([]Seal{{
			SealID:     "seal-001",
			JobID:      "job_000",
			OutputHash: "abc123",
			BlockHeight: 100,
			Timestamp:  "2026-03-28T14:00:00Z",
		}}).
		AddControlMapping("AU-2", ControlMapping{
			ControlName:  "Event Logging",
			Description:  "Test evidence",
			EvidenceRefs: []uint64{1, 2, 3},
			Status:       ControlSatisfied,
		}).
		WithMetadata("assessor", "automated").
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if bundle.ID != "test-bundle-001" {
		t.Errorf("expected ID test-bundle-001, got %s", bundle.ID)
	}
	if bundle.ContentHash == "" {
		t.Error("content hash should be set")
	}
	if len(bundle.Records) != 5 {
		t.Errorf("expected 5 records, got %d", len(bundle.Records))
	}
	if len(bundle.Controls) != 1 {
		t.Errorf("expected 1 control, got %d", len(bundle.Controls))
	}
	if bundle.Framework != FrameworkNIST80053 {
		t.Errorf("expected framework NIST-800-53, got %s", bundle.Framework)
	}
}

func TestBundleBuilder_Build_NoID(t *testing.T) {
	_, err := NewBundleBuilder(FrameworkSOC2).
		AddRecords(makeTestChain(1)).
		Build()
	if err == nil {
		t.Error("Build without ID should fail")
	}
}

func TestBundleBuilder_Build_NoRecords(t *testing.T) {
	_, err := NewBundleBuilder(FrameworkSOC2).
		WithID("test").
		Build()
	if err == nil {
		t.Error("Build without records should fail")
	}
}

func TestVerifyBundle_Valid(t *testing.T) {
	records := makeTestChain(5)
	bundle, _ := NewBundleBuilder(FrameworkNIST80053).
		WithID("test-bundle-002").
		AddRecords(records).
		AddControlMapping("AU-2", ControlMapping{
			ControlName:  "Event Logging",
			EvidenceRefs: []uint64{1, 2, 3},
			Status:       ControlSatisfied,
		}).
		Build()

	if err := VerifyBundle(bundle); err != nil {
		t.Errorf("valid bundle should verify: %v", err)
	}
}

func TestVerifyBundle_TamperedContent(t *testing.T) {
	records := makeTestChain(5)
	bundle, _ := NewBundleBuilder(FrameworkNIST80053).
		WithID("test-bundle-003").
		AddRecords(records).
		Build()

	// Tamper with the bundle.
	bundle.Records = append(bundle.Records, makeTestRecord(99, "fake", keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "fake", "fake", 999, "2026-03-28T14:00:00Z", nil))

	err := VerifyBundle(bundle)
	if err == nil {
		t.Error("tampered bundle should fail verification")
	}
}

func TestVerifyBundle_InvalidControlRef(t *testing.T) {
	records := makeTestChain(3)
	bundle, _ := NewBundleBuilder(FrameworkNIST80053).
		WithID("test-bundle-004").
		AddRecords(records).
		AddControlMapping("AU-2", ControlMapping{
			ControlName:  "Event Logging",
			EvidenceRefs: []uint64{1, 999}, // 999 does not exist
			Status:       ControlSatisfied,
		}).
		Build()

	err := VerifyBundle(bundle)
	if err == nil {
		t.Error("bundle with invalid control ref should fail verification")
	}
}

func TestNIST80053ControlMappings(t *testing.T) {
	mappings := NIST80053ControlMappings()
	if len(mappings) == 0 {
		t.Error("NIST 800-53 mappings should not be empty")
	}

	// Verify key controls are present.
	controlIDs := make(map[string]bool)
	for _, m := range mappings {
		controlIDs[m.ControlID] = true
	}
	for _, id := range []string{"AU-2", "AU-3", "AU-6", "AU-9", "AU-10", "AU-11", "AU-12"} {
		if !controlIDs[id] {
			t.Errorf("expected control %s in NIST 800-53 mappings", id)
		}
	}
}

// ---------------------------------------------------------------------------
// Retention tests
// ---------------------------------------------------------------------------

func TestCheckRetention_Retained(t *testing.T) {
	// Record from 1 minute ago -- should be retained.
	ts := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)
	r := makeTestRecord(1, "genesis", keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "system", 100, ts, nil)

	policy := PolicyGDPR()
	result, err := CheckRetention(r, policy)
	if err != nil {
		t.Fatalf("CheckRetention failed: %v", err)
	}
	if !result.Retained {
		t.Error("recent record should be retained under GDPR")
	}
}

func TestCheckRetention_Expired(t *testing.T) {
	// Record from 10 years ago -- should be expired under GDPR (6yr).
	ts := time.Now().UTC().Add(-10 * 365 * 24 * time.Hour).Format(time.RFC3339)
	r := makeTestRecord(1, "genesis", keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "system", 100, ts, nil)

	policy := PolicyGDPR()
	result, err := CheckRetention(r, policy)
	if err != nil {
		t.Fatalf("CheckRetention failed: %v", err)
	}
	if result.Retained {
		t.Error("10-year-old record should be expired under GDPR (6yr policy)")
	}
}

func TestCheckRetention_CriticalBuffer(t *testing.T) {
	// Critical records get +25% retention.
	ts := time.Now().UTC().Add(-6*365*24*time.Hour - 30*24*time.Hour).Format(time.RFC3339)
	infoRecord := makeTestRecord(1, "genesis", keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "system", 100, ts, nil)
	critRecord := makeTestRecord(2, "prev", keeper.AuditCategorySecurity, keeper.AuditSeverityCritical, "test", "system", 100, ts, nil)

	policy := PolicyGDPR()

	infoResult, _ := CheckRetention(infoRecord, policy)
	critResult, _ := CheckRetention(critRecord, policy)

	if infoResult.Retained {
		t.Error("info record past 6yr should not be retained")
	}
	if !critResult.Retained {
		t.Error("critical record just past 6yr should still be retained (+25% buffer)")
	}
}

func TestMergeRetentionPolicies(t *testing.T) {
	merged := MergeRetentionPolicies(PolicyGDPR(), PolicySOX(), PolicyDefense())
	// Defense has the longest default (10yr).
	if merged.DefaultRetention.Duration != 10*365*24*time.Hour {
		t.Errorf("expected 10yr default, got %v", merged.DefaultRetention.Duration)
	}
}

func TestPolicyPresets(t *testing.T) {
	tests := []struct {
		name     string
		policy   RetentionPolicy
		minYears int
	}{
		{"GDPR", PolicyGDPR(), 6},
		{"HIPAA", PolicyHIPAA(), 6},
		{"SOX", PolicySOX(), 7},
		{"Defense", PolicyDefense(), 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := time.Duration(tt.minYears) * 365 * 24 * time.Hour
			if tt.policy.DefaultRetention.Duration < expected {
				t.Errorf("expected at least %d year retention, got %v",
					tt.minYears, tt.policy.DefaultRetention.Duration)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Chain of custody tests
// ---------------------------------------------------------------------------

func TestCustodyStore_InitAndTransfer(t *testing.T) {
	store := NewCustodyStore()

	// Initialize custody.
	_, err := store.InitCustody("bundle-001", "custodian-a", "sig-a")
	if err != nil {
		t.Fatalf("InitCustody failed: %v", err)
	}

	// Transfer to custodian B.
	_, err = store.Transfer("bundle-001", "custodian-a", "custodian-b", "sig-b")
	if err != nil {
		t.Fatalf("Transfer failed: %v", err)
	}

	// Verify current custodian.
	custodian, err := store.GetCurrentCustodian("bundle-001")
	if err != nil {
		t.Fatalf("GetCurrentCustodian failed: %v", err)
	}
	if custodian != "custodian-b" {
		t.Errorf("expected custodian-b, got %s", custodian)
	}
}

func TestCustodyStore_TransferFromWrongCustodian(t *testing.T) {
	store := NewCustodyStore()
	store.InitCustody("bundle-001", "custodian-a", "sig-a")

	_, err := store.Transfer("bundle-001", "custodian-x", "custodian-b", "sig-b")
	if err == nil {
		t.Error("transfer from wrong custodian should fail")
	}
}

func TestCustodyStore_DuplicateInit(t *testing.T) {
	store := NewCustodyStore()
	store.InitCustody("bundle-001", "custodian-a", "sig-a")

	_, err := store.InitCustody("bundle-001", "custodian-b", "sig-b")
	if err == nil {
		t.Error("duplicate init should fail")
	}
}

func TestVerifyCustody_Valid(t *testing.T) {
	store := NewCustodyStore()
	store.InitCustody("bundle-001", "custodian-a", "sig-a")
	store.Transfer("bundle-001", "custodian-a", "custodian-b", "sig-b")
	store.RecordAction("bundle-001", "custodian-b", CustodyAccess, "sig-c", "read for audit")

	chain, _ := store.GetCustodyHistory("bundle-001")
	if err := VerifyCustody(chain); err != nil {
		t.Errorf("valid custody chain should verify: %v", err)
	}
}

func TestVerifyCustody_Tampered(t *testing.T) {
	store := NewCustodyStore()
	store.InitCustody("bundle-001", "custodian-a", "sig-a")
	store.Transfer("bundle-001", "custodian-a", "custodian-b", "sig-b")

	chain, _ := store.GetCustodyHistory("bundle-001")
	chain.Records[1].Custodian = "custodian-x" // Tamper.

	if err := VerifyCustody(chain); err == nil {
		t.Error("tampered custody chain should fail verification")
	}
}

// ---------------------------------------------------------------------------
// Replay tests
// ---------------------------------------------------------------------------

func TestCompare_Identical(t *testing.T) {
	data := []byte("hello world")
	diffs := Compare(data, data)
	if len(diffs) != 0 {
		t.Errorf("identical data should produce no diffs, got %d", len(diffs))
	}
}

func TestCompare_Different(t *testing.T) {
	original := []byte("hello world")
	replayed := []byte("hello earth")
	diffs := Compare(original, replayed)
	if len(diffs) == 0 {
		t.Error("different data should produce diffs")
	}

	// Should have hash diff and byte-level diff.
	hasHashDiff := false
	hasByteDiff := false
	for _, d := range diffs {
		if d.Field == "output_hash" {
			hasHashDiff = true
		}
		if len(d.Field) > 11 && d.Field[:11] == "byte_offset" {
			hasByteDiff = true
		}
	}
	if !hasHashDiff {
		t.Error("expected hash diff")
	}
	if !hasByteDiff {
		t.Error("expected byte-level diff")
	}
}

func TestCompare_DifferentLength(t *testing.T) {
	original := []byte("short")
	replayed := []byte("much longer string")
	diffs := Compare(original, replayed)

	hasLenDiff := false
	for _, d := range diffs {
		if d.Field == "output_length" {
			hasLenDiff = true
		}
	}
	if !hasLenDiff {
		t.Error("expected length diff")
	}
}

func TestGenerateReplayEvidence(t *testing.T) {
	result := &ReplayResult{
		JobID:          "job-001",
		OriginalOutput: "hash-a",
		ReplayOutput:   "hash-b",
		Match:          false,
		Timestamp:      "2026-03-28T14:00:00Z",
	}

	evidence := GenerateReplayEvidence(result)
	if evidence == nil {
		t.Fatal("evidence should not be nil")
	}
	if evidence.ReplayHash == "" {
		t.Error("replay hash should be set")
	}
	if evidence.Match {
		t.Error("evidence should reflect non-match")
	}

	// Verify determinism.
	evidence2 := GenerateReplayEvidence(result)
	if evidence.ReplayHash != evidence2.ReplayHash {
		t.Error("evidence generation should be deterministic")
	}
}

func TestGenerateReplayEvidence_Nil(t *testing.T) {
	evidence := GenerateReplayEvidence(nil)
	if evidence != nil {
		t.Error("nil input should produce nil evidence")
	}
}

// ---------------------------------------------------------------------------
// Export format tests (basic smoke tests)
// ---------------------------------------------------------------------------

func TestExportFormats_Import(t *testing.T) {
	// Verify the export sub-package builds by importing its types.
	// Full export tests are in the export package.
	records := makeTestChain(3)
	bundle, err := NewBundleBuilder(FrameworkNIST80053).
		WithID("export-test-001").
		AddRecords(records).
		Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if bundle.SchemaVersion != "1.0.0" {
		t.Errorf("expected schema version 1.0.0, got %s", bundle.SchemaVersion)
	}
}

// ---------------------------------------------------------------------------
// Integration-style test: full audit workflow
// ---------------------------------------------------------------------------

func TestFullAuditWorkflow(t *testing.T) {
	// 1. Create a chain of records.
	records := makeTestChain(15)
	source := &mockLogSource{records: records}

	// 2. Create a studio.
	studio, err := NewStudio(Config{
		LogSource: source,
		IndexConfig: IndexConfig{
			EnableActorIndex:  true,
			EnableActionIndex: true,
		},
	})
	if err != nil {
		t.Fatalf("NewStudio failed: %v", err)
	}

	ctx := context.Background()

	// 3. Query and verify.
	allRecords, err := studio.Query(ctx, nil)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(allRecords) != 15 {
		t.Fatalf("expected 15 records, got %d", len(allRecords))
	}

	// 4. Build a timeline.
	tl, err := BuildTimeline(ctx, source, nil)
	if err != nil {
		t.Fatalf("BuildTimeline failed: %v", err)
	}
	if tl.TotalEvents != 15 {
		t.Errorf("expected 15 timeline events, got %d", tl.TotalEvents)
	}

	// 5. Build an evidence bundle.
	bundle, err := NewBundleBuilder(FrameworkNIST80053).
		WithID("workflow-bundle-001").
		AddRecords(allRecords).
		AddControlMapping("AU-2", ControlMapping{
			ControlName:  "Event Logging",
			Description:  "All audit events are recorded with structured fields.",
			EvidenceRefs: []uint64{1, 2, 3, 4, 5},
			Status:       ControlSatisfied,
		}).
		AddControlMapping("AU-9", ControlMapping{
			ControlName:  "Protection of Audit Information",
			Description:  "Hash chain provides tamper detection.",
			EvidenceRefs: []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			Status:       ControlSatisfied,
		}).
		Build()
	if err != nil {
		t.Fatalf("Bundle build failed: %v", err)
	}

	// 6. Verify bundle.
	if err := VerifyBundle(bundle); err != nil {
		t.Fatalf("Bundle verification failed: %v", err)
	}

	// 7. Check retention.
	policy := PolicyGDPR()
	retResult, err := CheckRetention(allRecords[0], policy)
	if err != nil {
		t.Fatalf("CheckRetention failed: %v", err)
	}
	if !retResult.Retained {
		t.Error("recent record should be retained")
	}

	// 8. Chain of custody.
	custodyStore := NewCustodyStore()
	_, err = custodyStore.InitCustody(bundle.ID, "auditor-001", "sig-init")
	if err != nil {
		t.Fatalf("InitCustody failed: %v", err)
	}
	_, err = custodyStore.Transfer(bundle.ID, "auditor-001", "regulator-001", "sig-transfer")
	if err != nil {
		t.Fatalf("Transfer failed: %v", err)
	}
	chain, _ := custodyStore.GetCustodyHistory(bundle.ID)
	if err := VerifyCustody(chain); err != nil {
		t.Fatalf("Custody verification failed: %v", err)
	}

	// 9. Get stats.
	stats, err := studio.GetStats(ctx, nil)
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if stats.TotalRecords != 15 {
		t.Errorf("expected 15 total records in stats, got %d", stats.TotalRecords)
	}
	if !stats.ChainIntact {
		t.Error("stats should show intact chain")
	}
}

// ---------------------------------------------------------------------------
// Hash utility test
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Edge case, error path, and concurrency tests
// ---------------------------------------------------------------------------

func TestStudio_NilLogSource_ErrorIs(t *testing.T) {
	t.Parallel()
	_, err := NewStudio(Config{})
	if err == nil {
		t.Fatal("expected error for nil log source")
	}
}

func TestStudio_GetRecordNotFound_EdgeCase(t *testing.T) {
	t.Parallel()
	source := newTestSource(5)
	studio, _ := NewStudio(Config{LogSource: source})
	ctx := context.Background()

	_, err := studio.GetRecord(ctx, 999)
	if err == nil {
		t.Error("expected error for nonexistent sequence")
	}
}

func TestStudio_GetChainInvalidRange(t *testing.T) {
	t.Parallel()
	source := newTestSource(10)
	studio, _ := NewStudio(Config{LogSource: source})
	ctx := context.Background()

	// from > to
	_, err := studio.GetChain(ctx, 8, 3)
	if err == nil {
		t.Error("expected error for from > to in GetChain")
	}
}

func TestStudio_VerifyChain_TamperedHash(t *testing.T) {
	t.Parallel()
	records := makeTestChain(5)
	records[2].RecordHash = "0000000000000000000000000000000000000000000000000000000000000000"

	err := VerifyChain(records)
	if err == nil {
		t.Error("expected error for tampered hash")
	}
}

func TestStudio_VerifyChain_BrokenLink_EdgeCase(t *testing.T) {
	t.Parallel()
	records := makeTestChain(5)
	records[3].PreviousHash = "deadbeefdeadbeef"
	records[3].RecordHash = ComputeRecordHash(records[3])

	err := VerifyChain(records)
	if err == nil {
		t.Error("expected error for broken chain link")
	}
}

func TestStudio_VerifyChain_Empty_EdgeCase(t *testing.T) {
	t.Parallel()
	if err := VerifyChain(nil); err != nil {
		t.Errorf("empty chain should verify: %v", err)
	}
	if err := VerifyChain([]keeper.AuditRecord{}); err != nil {
		t.Errorf("empty slice chain should verify: %v", err)
	}
}

func TestFilter_AllFieldsCombined(t *testing.T) {
	t.Parallel()
	from := time.Date(2026, 3, 28, 14, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 28, 14, 10, 0, 0, time.UTC)

	f := NewFilter().
		WithCategories(keeper.AuditCategoryJob).
		WithSeverities(keeper.AuditSeverityInfo).
		WithTimeRange(from, to).
		WithKeywords("job_submitted").
		WithLimit(5).
		WithOffset(0)

	records := makeTestChain(20)
	result := f.Apply(records)
	for _, r := range result {
		if r.Category != keeper.AuditCategoryJob {
			t.Errorf("expected category job, got %s", r.Category)
		}
	}
}

func TestFilter_NoMatch(t *testing.T) {
	t.Parallel()
	f := NewFilter().WithKeywords("absolutely_nonexistent_keyword_xyz")
	records := makeTestChain(10)
	result := f.Apply(records)
	if len(result) != 0 {
		t.Errorf("expected 0 matches, got %d", len(result))
	}
}

func TestTimeline_EmptyRecords(t *testing.T) {
	t.Parallel()
	source := &mockLogSource{records: nil}
	ctx := context.Background()

	tl, err := BuildTimeline(ctx, source, nil)
	if err != nil {
		t.Fatalf("BuildTimeline with empty source failed: %v", err)
	}
	if tl.TotalEvents != 0 {
		t.Errorf("expected 0 events, got %d", tl.TotalEvents)
	}
}

func TestTimeline_MergeEmpty(t *testing.T) {
	t.Parallel()
	merged := MergeTimelines(nil)
	if merged == nil {
		t.Fatal("MergeTimelines(nil) returned nil")
	}
	if merged.TotalEvents != 0 {
		t.Errorf("expected 0 events, got %d", merged.TotalEvents)
	}

	merged2 := MergeTimelines([]*Timeline{})
	if merged2 == nil {
		t.Fatal("MergeTimelines([]) returned nil")
	}
}

func TestReplay_NilResolver(t *testing.T) {
	t.Parallel()
	source := newTestSource(5)
	re := NewReplayEngine(ReplayConfig{}, source, nil)
	ctx := context.Background()

	_, err := re.Replay(ctx, "job_000")
	if err == nil {
		t.Error("expected error for nil resolver")
	}
}

func TestReplay_JobNotFound(t *testing.T) {
	t.Parallel()
	source := newTestSource(5)
	re := NewReplayEngine(ReplayConfig{}, source, nil)
	ctx := context.Background()

	_, err := re.Replay(ctx, "nonexistent-job-id")
	if err == nil {
		t.Error("expected error for unknown job ID")
	}
}

func TestBundleBuilder_NoRecords_EdgeCase(t *testing.T) {
	t.Parallel()
	_, err := NewBundleBuilder(FrameworkSOC2).
		WithID("no-records-test").
		Build()
	if err == nil {
		t.Error("Build without records should fail")
	}
}

func TestBundleBuilder_DuplicateRecords(t *testing.T) {
	t.Parallel()
	records := makeTestChain(3)
	// Add the same record twice.
	duped := append(records, records[0])

	bundle, err := NewBundleBuilder(FrameworkNIST80053).
		WithID("dup-records-test").
		AddRecords(duped).
		Build()
	// Should either succeed (dedup) or error. No panic.
	if err == nil && bundle != nil {
		// If it built, verify it has some records.
		if len(bundle.Records) == 0 {
			t.Error("expected non-empty records")
		}
	}
}

func TestBundle_VerifyTampered_EdgeCase(t *testing.T) {
	t.Parallel()
	records := makeTestChain(5)
	bundle, err := NewBundleBuilder(FrameworkNIST80053).
		WithID("tamper-test").
		AddRecords(records).
		Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Tamper with content hash.
	bundle.ContentHash = "tampered-hash-value"
	if err := VerifyBundle(bundle); err == nil {
		t.Error("expected error for tampered content hash")
	}
}

func TestRetention_ZeroDuration(t *testing.T) {
	t.Parallel()
	policy := RetentionPolicy{
		DefaultRetention: RetentionDuration{Duration: 0},
	}
	ts := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)
	r := makeTestRecord(1, "genesis", keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test", "system", 100, ts, nil)

	result, err := CheckRetention(r, policy)
	// Zero duration should mean records are never expired or always expired.
	_ = result
	_ = err
}

func TestRetention_MergePolicies(t *testing.T) {
	t.Parallel()
	merged := MergeRetentionPolicies(PolicyGDPR(), PolicySOX(), PolicyDefense())
	// Defense has the longest default (10yr).
	expected := 10 * 365 * 24 * time.Hour
	if merged.DefaultRetention.Duration != expected {
		t.Errorf("expected 10yr default, got %v", merged.DefaultRetention.Duration)
	}
}

func TestCustody_TransferToSelf(t *testing.T) {
	t.Parallel()
	store := NewCustodyStore()
	store.InitCustody("bundle-self", "custodian-a", "sig-a")

	_, err := store.Transfer("bundle-self", "custodian-a", "custodian-a", "sig-self")
	// Self-transfer may be allowed by the implementation.
	// The key test is that it doesn't panic and the chain remains valid.
	if err == nil {
		chain, _ := store.GetCustodyHistory("bundle-self")
		if chain != nil {
			if verErr := VerifyCustody(chain); verErr != nil {
				t.Errorf("custody chain invalid after self-transfer: %v", verErr)
			}
		}
	}
}

func TestCustody_DoubleInit(t *testing.T) {
	t.Parallel()
	store := NewCustodyStore()
	_, err := store.InitCustody("bundle-double", "custodian-a", "sig-a")
	if err != nil {
		t.Fatalf("first InitCustody failed: %v", err)
	}

	_, err = store.InitCustody("bundle-double", "custodian-b", "sig-b")
	if err == nil {
		t.Error("expected error for duplicate init")
	}
}

func TestCustody_VerifyTampered(t *testing.T) {
	t.Parallel()
	store := NewCustodyStore()
	store.InitCustody("bundle-tamper", "custodian-a", "sig-a")
	store.Transfer("bundle-tamper", "custodian-a", "custodian-b", "sig-b")

	chain, _ := store.GetCustodyHistory("bundle-tamper")
	chain.Records[1].Custodian = "custodian-x" // Tamper.

	if err := VerifyCustody(chain); err == nil {
		t.Error("expected error for tampered custody chain")
	}
}

func TestCustody_ConcurrentTransfers(t *testing.T) {
	t.Parallel()
	store := NewCustodyStore()

	const goroutines = 10
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			bundleID := fmt.Sprintf("bundle-concurrent-%d", idx)
			_, err := store.InitCustody(bundleID, fmt.Sprintf("custodian-%d", idx), "sig-init")
			if err != nil {
				errs <- err
				return
			}
			_, err = store.Transfer(bundleID, fmt.Sprintf("custodian-%d", idx), fmt.Sprintf("recipient-%d", idx), "sig-xfer")
			errs <- err
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent custody operation failed: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Hash utility test
// ---------------------------------------------------------------------------

func TestHashBytes(t *testing.T) {
	data := []byte("test data")
	h := hashBytes(data)
	expected := sha256.Sum256(data)
	expectedHex := hex.EncodeToString(expected[:])
	if h != expectedHex {
		t.Errorf("hashBytes mismatch: got %s, want %s", h, expectedHex)
	}

	// Empty input.
	if hashBytes(nil) != "" {
		t.Error("hashBytes of nil should return empty string")
	}
}
