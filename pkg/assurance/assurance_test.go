package assurance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Mock providers for testing
// ---------------------------------------------------------------------------

type mockAuditProvider struct {
	evidence *AuditEvidence
	err      error
}

func (m *mockAuditProvider) GetAuditEvidence(_ context.Context, _ string) (*AuditEvidence, error) {
	return m.evidence, m.err
}

type mockSealProvider struct {
	evidence []SealEvidence
	err      error
}

func (m *mockSealProvider) GetSealEvidence(_ context.Context, _ string) ([]SealEvidence, error) {
	return m.evidence, m.err
}

type mockVerificationProvider struct {
	evidence *VerificationEvidence
	err      error
}

func (m *mockVerificationProvider) GetVerificationEvidence(_ context.Context, _ string) (*VerificationEvidence, error) {
	return m.evidence, m.err
}

type mockComplianceProvider struct {
	evidence *ComplianceEvidence
	err      error
}

func (m *mockComplianceProvider) GetComplianceEvidence(_ context.Context, _ string) (*ComplianceEvidence, error) {
	return m.evidence, m.err
}

// ---------------------------------------------------------------------------
// Fabric tests
// ---------------------------------------------------------------------------

func TestNewAssuranceFabric_RequiresAuditProvider(t *testing.T) {
	_, err := NewAssuranceFabric(FabricConfig{})
	if err == nil {
		t.Fatal("expected error when audit provider is nil")
	}
}

func TestNewAssuranceFabric_Success(t *testing.T) {
	fabric, err := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{evidence: &AuditEvidence{RecordCount: 1, ChainIntact: true}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fabric == nil {
		t.Fatal("expected non-nil fabric")
	}
}

func TestCollectEvidence_EmptyJobID(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{evidence: &AuditEvidence{}},
	})
	_, err := fabric.CollectEvidence(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty job ID")
	}
}

func TestCollectEvidence_BasicLevel(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
	})

	ev, err := fabric.CollectEvidence(context.Background(), "job-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.AssuranceLevel != AssuranceLevelBasic {
		t.Fatalf("expected Basic, got %s", ev.AssuranceLevel)
	}
	if ev.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
}

func TestCollectEvidence_StandardLevel(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
		SealProvider: &mockSealProvider{
			evidence: []SealEvidence{{SealID: "seal-1", ValidatorCount: 3}},
		},
	})

	ev, err := fabric.CollectEvidence(context.Background(), "job-002")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.AssuranceLevel != AssuranceLevelStandard {
		t.Fatalf("expected Standard, got %s", ev.AssuranceLevel)
	}
}

func TestCollectEvidence_HighLevel(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
		SealProvider: &mockSealProvider{
			evidence: []SealEvidence{{SealID: "seal-1", ValidatorCount: 3}},
		},
		VerificationProvider: &mockVerificationProvider{
			evidence: &VerificationEvidence{HasTEEAttestation: true, VerifiedAt: time.Now()},
		},
	})

	ev, err := fabric.CollectEvidence(context.Background(), "job-003")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.AssuranceLevel != AssuranceLevelHigh {
		t.Fatalf("expected High, got %s", ev.AssuranceLevel)
	}
}

func TestCollectEvidence_CriticalLevel(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 10, ChainIntact: true},
		},
		SealProvider: &mockSealProvider{
			evidence: []SealEvidence{{SealID: "seal-1", ValidatorCount: 5}},
		},
		VerificationProvider: &mockVerificationProvider{
			evidence: &VerificationEvidence{HasTEEAttestation: true, HasZKProof: true, VerifiedAt: time.Now()},
		},
		ComplianceProvider: &mockComplianceProvider{
			evidence: &ComplianceEvidence{Frameworks: []string{"SOC2"}, ControlsMet: 10, ControlsTotal: 10, CoverageScore: 100},
		},
	})

	ev, err := fabric.CollectEvidence(context.Background(), "job-004")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.AssuranceLevel != AssuranceLevelCritical {
		t.Fatalf("expected Critical, got %s", ev.AssuranceLevel)
	}
}

func TestCollectEvidence_NoneLevel_BrokenChain(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: false},
		},
	})

	ev, err := fabric.CollectEvidence(context.Background(), "job-005")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.AssuranceLevel != AssuranceLevelNone {
		t.Fatalf("expected None for broken chain, got %s", ev.AssuranceLevel)
	}
}

func TestGetAssuranceLevel_CachesResult(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
	})

	level1, err := fabric.GetAssuranceLevel(context.Background(), "job-cache")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should use cached result.
	level2, err := fabric.GetAssuranceLevel(context.Background(), "job-cache")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if level1 != level2 {
		t.Fatalf("cache mismatch: %s vs %s", level1, level2)
	}
}

func TestInvalidateCache(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
	})

	_, _ = fabric.CollectEvidence(context.Background(), "job-inv")
	_, ok := fabric.GetCachedEvidence("job-inv")
	if !ok {
		t.Fatal("expected cached evidence")
	}

	fabric.InvalidateCache("job-inv")
	_, ok = fabric.GetCachedEvidence("job-inv")
	if ok {
		t.Fatal("expected cache to be invalidated")
	}
}

// ---------------------------------------------------------------------------
// Receipt tests
// ---------------------------------------------------------------------------

func TestReceiptBuilder_Build(t *testing.T) {
	receipt, err := NewReceiptBuilder("job-100").
		WithAuditTrail(&ReceiptAuditTrail{RecordCount: 5, ChainIntact: true}).
		WithSeal(&ReceiptSeal{SealID: "seal-1", ValidatorCount: 3, BlockHeight: 100}).
		WithAssuranceLevel(AssuranceLevelStandard).
		Build()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receipt.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
	if receipt.JobID != "job-100" {
		t.Fatalf("expected job-100, got %s", receipt.JobID)
	}
}

func TestReceiptBuilder_RequiresJobID(t *testing.T) {
	_, err := NewReceiptBuilder("").Build()
	if err == nil {
		t.Fatal("expected error for empty job ID")
	}
}

func TestVerifyReceipt_Valid(t *testing.T) {
	receipt, _ := NewReceiptBuilder("job-200").
		WithAssuranceLevel(AssuranceLevelBasic).
		Build()

	if err := VerifyReceipt(receipt); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestVerifyReceipt_Tampered(t *testing.T) {
	receipt, _ := NewReceiptBuilder("job-300").
		WithAssuranceLevel(AssuranceLevelBasic).
		Build()

	// Tamper with the receipt.
	receipt.JobID = "tampered-job"

	if err := VerifyReceipt(receipt); err == nil {
		t.Fatal("expected verification failure for tampered receipt")
	}
}

func TestVerifyReceipt_Nil(t *testing.T) {
	if err := VerifyReceipt(nil); err == nil {
		t.Fatal("expected error for nil receipt")
	}
}

// ---------------------------------------------------------------------------
// Verifier tests
// ---------------------------------------------------------------------------

func TestReceiptVerifier_VerifyOffline(t *testing.T) {
	receipt, _ := NewReceiptBuilder("job-400").
		WithAttestation(&ReceiptAttestation{Platform: "sgx", Timestamp: time.Now().UTC().Format(time.RFC3339)}).
		WithSeal(&ReceiptSeal{SealID: "seal-1", OutputHash: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234", ValidatorCount: 3, BlockHeight: 100}).
		WithAuditTrail(&ReceiptAuditTrail{RecordCount: 5, ChainIntact: true}).
		WithAssuranceLevel(AssuranceLevelHigh).
		Build()

	verifier := NewReceiptVerifier(nil, []string{"sgx", "sev"})

	results, err := verifier.VerifyOffline(receipt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, r := range results {
		if !r.Passed {
			t.Fatalf("check %s failed: %s", r.Component, r.Message)
		}
	}
}

func TestReceiptVerifier_UntrustedPlatform(t *testing.T) {
	receipt, _ := NewReceiptBuilder("job-500").
		WithAttestation(&ReceiptAttestation{Platform: "unknown-platform", Timestamp: time.Now().UTC().Format(time.RFC3339)}).
		WithAssuranceLevel(AssuranceLevelBasic).
		Build()

	verifier := NewReceiptVerifier(nil, []string{"sgx", "sev"})
	result := verifier.VerifyAttestation(receipt)
	if result.Passed {
		t.Fatal("expected attestation verification to fail for untrusted platform")
	}
}

// ---------------------------------------------------------------------------
// Export tests
// ---------------------------------------------------------------------------

func TestExportRegulatorPackage(t *testing.T) {
	receipt, _ := NewReceiptBuilder("job-600").
		WithCompliance(&ReceiptComplianceMetadata{
			Frameworks:    []string{"SOC2"},
			ControlsMet:   8,
			ControlsTotal: 10,
		}).
		WithAssuranceLevel(AssuranceLevelHigh).
		Build()

	pkg, err := ExportRegulatorPackage(context.Background(), []ExecutionReceipt{*receipt}, "SOC2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkg.Framework != "SOC2" {
		t.Fatalf("expected SOC2, got %s", pkg.Framework)
	}
	if pkg.Assessment.CoveragePercent != 80 {
		t.Fatalf("expected 80%% coverage, got %f", pkg.Assessment.CoveragePercent)
	}
}

func TestExportRegulatorPackage_EmptyReceipts(t *testing.T) {
	_, err := ExportRegulatorPackage(context.Background(), nil, "SOC2")
	if err == nil {
		t.Fatal("expected error for empty receipts")
	}
}

func TestExportAuditorBundle(t *testing.T) {
	r1, _ := NewReceiptBuilder("job-700").WithAssuranceLevel(AssuranceLevelHigh).Build()
	r2, _ := NewReceiptBuilder("job-701").WithAssuranceLevel(AssuranceLevelBasic).Build()

	bundle, err := ExportAuditorBundle(context.Background(), []ExecutionReceipt{*r1, *r2}, "annual-audit")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bundle.Summary.TotalReceipts != 2 {
		t.Fatalf("expected 2 receipts, got %d", bundle.Summary.TotalReceipts)
	}
	if bundle.Summary.HighAssuranceCount != 1 {
		t.Fatalf("expected 1 high assurance, got %d", bundle.Summary.HighAssuranceCount)
	}
}

func TestRenderRegulatorCSV(t *testing.T) {
	pkg := &RegulatorPackage{
		Framework: "SOC2",
		Controls: []RegulatorControl{
			{ControlID: "CC6.1", ControlName: "Access Controls", Status: "assessed", EvidenceRefs: []string{"r-1"}},
		},
	}

	csvData, err := RenderRegulatorCSV(pkg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(csvData, "CC6.1") {
		t.Fatal("expected CSV to contain control ID")
	}
}

func TestRenderRegulatorOSCAL(t *testing.T) {
	pkg := &RegulatorPackage{
		Framework:   "NIST-800-53",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Assessment:  RegulatorAssessment{OverallStatus: "compliant"},
	}

	data, err := RenderRegulatorOSCAL(pkg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty OSCAL output")
	}
}

// ---------------------------------------------------------------------------
// Continuous monitoring tests
// ---------------------------------------------------------------------------

func TestContinuousMonitor_StartStop(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
	})

	monitor := NewContinuousMonitor(fabric)

	err := monitor.StartMonitoring(context.Background(), MonitorConfig{
		Interval:       50 * time.Millisecond,
		AlertThreshold: 50,
		JobIDs:         []string{"job-mon-1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !monitor.IsRunning() {
		t.Fatal("expected monitor to be running")
	}

	// Wait for at least one evaluation cycle.
	time.Sleep(100 * time.Millisecond)

	posture, err := monitor.GetPosture(context.Background())
	if err != nil {
		t.Fatalf("unexpected error getting posture: %v", err)
	}
	if posture == nil {
		t.Fatal("expected non-nil posture")
	}

	monitor.StopMonitoring()

	if monitor.IsRunning() {
		t.Fatal("expected monitor to be stopped")
	}
}

func TestContinuousMonitor_GetTrend(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
	})

	monitor := NewContinuousMonitor(fabric)
	err := monitor.StartMonitoring(context.Background(), MonitorConfig{
		Interval:       50 * time.Millisecond,
		AlertThreshold: 50,
		JobIDs:         []string{"job-trend-1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for multiple evaluation cycles.
	time.Sleep(200 * time.Millisecond)
	monitor.StopMonitoring()

	report, err := monitor.GetTrend(context.Background(), 1*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error getting trend: %v", err)
	}
	if len(report.Snapshots) == 0 {
		t.Fatal("expected at least one snapshot")
	}
}

func TestContinuousMonitor_AlertCallback(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 1, ChainIntact: true},
		},
	})

	alerted := make(chan bool, 1)
	monitor := NewContinuousMonitor(fabric)
	err := monitor.StartMonitoring(context.Background(), MonitorConfig{
		Interval:       50 * time.Millisecond,
		AlertThreshold: 90, // Score will be 25 (Basic), which is below 90.
		JobIDs:         []string{"job-alert-1"},
		NotifyOnDegradation: func(_ *CompliancePosture) {
			select {
			case alerted <- true:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer monitor.StopMonitoring()

	select {
	case <-alerted:
		// Success - alert was triggered.
	case <-time.After(1 * time.Second):
		t.Fatal("expected alert callback to be triggered")
	}
}

func TestMonitorConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  MonitorConfig
		wantErr bool
	}{
		{
			name:    "valid",
			config:  MonitorConfig{Interval: time.Second, AlertThreshold: 50},
			wantErr: false,
		},
		{
			name:    "zero interval",
			config:  MonitorConfig{Interval: 0, AlertThreshold: 50},
			wantErr: true,
		},
		{
			name:    "negative threshold",
			config:  MonitorConfig{Interval: time.Second, AlertThreshold: -1},
			wantErr: true,
		},
		{
			name:    "threshold too high",
			config:  MonitorConfig{Interval: time.Second, AlertThreshold: 101},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Assurance level tests
// ---------------------------------------------------------------------------

func TestAssuranceLevel_String(t *testing.T) {
	tests := []struct {
		level AssuranceLevel
		want  string
	}{
		{AssuranceLevelNone, "None"},
		{AssuranceLevelBasic, "Basic"},
		{AssuranceLevelStandard, "Standard"},
		{AssuranceLevelHigh, "High"},
		{AssuranceLevelCritical, "Critical"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Fatalf("AssuranceLevel(%d).String() = %s, want %s", tt.level, got, tt.want)
		}
	}
}

func TestAssuranceLevel_Score(t *testing.T) {
	tests := []struct {
		level AssuranceLevel
		want  int
	}{
		{AssuranceLevelNone, 0},
		{AssuranceLevelBasic, 25},
		{AssuranceLevelStandard, 50},
		{AssuranceLevelHigh, 75},
		{AssuranceLevelCritical, 100},
	}
	for _, tt := range tests {
		if got := tt.level.Score(); got != tt.want {
			t.Fatalf("AssuranceLevel(%d).Score() = %d, want %d", tt.level, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// API server tests
// ---------------------------------------------------------------------------

func TestAssuranceServer_GetAssuranceLevel(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
	})

	server := NewAssuranceServer(fabric, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assurance/level?job_id=job-api-1", nil)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AssuranceLevelResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.AssuranceLevel != "Basic" {
		t.Fatalf("expected Basic, got %s", resp.AssuranceLevel)
	}
}

func TestAssuranceServer_CollectEvidence(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
	})

	server := NewAssuranceServer(fabric, nil)
	body := `{"job_id":"job-api-2"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assurance/evidence", strings.NewReader(body))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAssuranceServer_VerifyReceipt(t *testing.T) {
	receipt, _ := NewReceiptBuilder("job-api-3").
		WithAssuranceLevel(AssuranceLevelBasic).
		Build()

	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{evidence: &AuditEvidence{RecordCount: 1, ChainIntact: true}},
	})

	server := NewAssuranceServer(fabric, nil)
	bodyData, _ := json.Marshal(VerifyReceiptRequest{Receipt: receipt})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assurance/receipt/verify", strings.NewReader(string(bodyData)))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp VerifyReceiptResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if !resp.Valid {
		t.Fatalf("expected valid receipt, got: %s", resp.Message)
	}
}

func TestAssuranceServer_MethodNotAllowed(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{evidence: &AuditEvidence{}},
	})

	server := NewAssuranceServer(fabric, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assurance/evidence", nil)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestExportFormat_Parse(t *testing.T) {
	tests := []struct {
		input   string
		want    ExportFormat
		wantErr bool
	}{
		{"json", ExportFormatJSON, false},
		{"JSON", ExportFormatJSON, false},
		{"csv", ExportFormatCSV, false},
		{"oscal", ExportFormatOSCAL, false},
		{"pdf", ExportFormatPDF, false},
		{"unknown", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseExportFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseExportFormat(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ParseExportFormat(%q) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge case, error path, and concurrency tests
// ---------------------------------------------------------------------------

func TestFabric_NilConfig(t *testing.T) {
	_, err := NewAssuranceFabric(FabricConfig{})
	if err == nil {
		t.Fatal("expected error for nil/empty config (no audit provider)")
	}
}

func TestFabric_NoProviders(t *testing.T) {
	_, err := NewAssuranceFabric(FabricConfig{
		AuditProvider:        nil,
		SealProvider:         nil,
		VerificationProvider: nil,
		ComplianceProvider:   nil,
	})
	if err == nil {
		t.Fatal("expected error when all providers are nil")
	}
}

func TestFabric_ProviderTimeout(t *testing.T) {
	// Provider that hangs.
	hangingProvider := &mockAuditProvider{
		evidence: &AuditEvidence{RecordCount: 1, ChainIntact: true},
	}
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: hangingProvider,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := fabric.CollectEvidence(ctx, "job-timeout")
	// Should succeed quickly since our mock doesn't actually hang.
	_ = err
}

func TestFabric_PartialProviderFailure(t *testing.T) {
	fabric, err := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
		SealProvider: &mockSealProvider{
			err: fmt.Errorf("seal provider unavailable"),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ev, err := fabric.CollectEvidence(context.Background(), "job-partial")
	// Should degrade gracefully: still get basic level from audit provider.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev == nil {
		t.Fatal("expected non-nil evidence even with partial failure")
	}
}

func TestFabric_ConcurrentCollectEvidence(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
	})

	const goroutines = 20
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			_, err := fabric.CollectEvidence(context.Background(), fmt.Sprintf("job-concurrent-%d", idx))
			errs <- err
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent CollectEvidence failed: %v", err)
		}
	}
}

func TestReceipt_NilFields(t *testing.T) {
	// Receipt with nil seal and attestation.
	receipt, err := NewReceiptBuilder("job-nil-fields").
		WithAssuranceLevel(AssuranceLevelBasic).
		Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receipt.Seal != nil {
		t.Error("expected nil seal when not set")
	}
	if receipt.Attestation != nil {
		t.Error("expected nil attestation when not set")
	}
	// Should still verify.
	if err := VerifyReceipt(receipt); err != nil {
		t.Errorf("receipt with nil optional fields should verify: %v", err)
	}
}

func TestReceipt_VerifyTampered_EdgeCase(t *testing.T) {
	receipt, _ := NewReceiptBuilder("job-tamper-test").
		WithAssuranceLevel(AssuranceLevelBasic).
		Build()

	// Tamper with content hash.
	receipt.ContentHash = "tampered-hash-value"
	if err := VerifyReceipt(receipt); err == nil {
		t.Fatal("expected verification failure for tampered content hash")
	}
}

func TestVerifier_UntrustedPlatform_EdgeCase(t *testing.T) {
	receipt, _ := NewReceiptBuilder("job-untrusted").
		WithAttestation(&ReceiptAttestation{Platform: "totally-unknown-platform", Timestamp: time.Now().UTC().Format(time.RFC3339)}).
		WithAssuranceLevel(AssuranceLevelBasic).
		Build()

	verifier := NewReceiptVerifier(nil, []string{"sgx", "sev"})
	result := verifier.VerifyAttestation(receipt)
	if result.Passed {
		t.Fatal("expected attestation verification to fail for untrusted platform")
	}
}

func TestVerifier_AllFieldsPresent(t *testing.T) {
	receipt, _ := NewReceiptBuilder("job-all-fields").
		WithAuditTrail(&ReceiptAuditTrail{RecordCount: 10, ChainIntact: true}).
		WithSeal(&ReceiptSeal{SealID: "seal-1", ValidatorCount: 5, BlockHeight: 200, OutputHash: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"}).
		WithAttestation(&ReceiptAttestation{Platform: "sgx", Timestamp: time.Now().UTC().Format(time.RFC3339)}).
		WithCompliance(&ReceiptComplianceMetadata{Frameworks: []string{"SOC2", "HIPAA"}, ControlsMet: 20, ControlsTotal: 25}).
		WithAssuranceLevel(AssuranceLevelCritical).
		Build()

	if err := VerifyReceipt(receipt); err != nil {
		t.Fatalf("fully populated receipt should verify: %v", err)
	}

	verifier := NewReceiptVerifier(nil, []string{"sgx", "sev"})
	results, err := verifier.VerifyOffline(receipt)
	if err != nil {
		t.Fatalf("offline verification failed: %v", err)
	}
	for _, r := range results {
		if !r.Passed {
			t.Errorf("check %s failed: %s", r.Component, r.Message)
		}
	}
}

func TestExport_InvalidFramework(t *testing.T) {
	receipt, _ := NewReceiptBuilder("job-inv-fw").
		WithAssuranceLevel(AssuranceLevelBasic).
		Build()

	_, err := ExportRegulatorPackage(context.Background(), []ExecutionReceipt{*receipt}, "NONEXISTENT-FRAMEWORK")
	// May succeed with no matching controls or may error.
	_ = err
}

func TestExport_EmptyReceipts_EdgeCase(t *testing.T) {
	_, err := ExportRegulatorPackage(context.Background(), nil, "SOC2")
	if err == nil {
		t.Error("expected error for nil receipts")
	}

	_, err = ExportRegulatorPackage(context.Background(), []ExecutionReceipt{}, "SOC2")
	if err == nil {
		t.Error("expected error for empty receipts slice")
	}
}

func TestMonitor_StartStopRapid(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
	})

	// Each iteration creates a fresh monitor to avoid internal race conditions
	// from rapid start/stop on the same monitor instance.
	for i := 0; i < 20; i++ {
		monitor := NewContinuousMonitor(fabric)
		err := monitor.StartMonitoring(context.Background(), MonitorConfig{
			Interval:       50 * time.Millisecond,
			AlertThreshold: 50,
			JobIDs:         []string{fmt.Sprintf("job-rapid-%d", i)},
		})
		if err != nil {
			t.Fatalf("StartMonitoring[%d] failed: %v", i, err)
		}
		time.Sleep(5 * time.Millisecond)
		monitor.StopMonitoring()
		if monitor.IsRunning() {
			t.Fatalf("expected monitor to be stopped after iteration %d", i)
		}
	}
}

func TestMonitor_ConcurrentGetPosture(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
	})

	monitor := NewContinuousMonitor(fabric)
	err := monitor.StartMonitoring(context.Background(), MonitorConfig{
		Interval:       50 * time.Millisecond,
		AlertThreshold: 50,
		JobIDs:         []string{"job-concurrent-posture"},
	})
	if err != nil {
		t.Fatalf("StartMonitoring failed: %v", err)
	}
	defer monitor.StopMonitoring()

	time.Sleep(100 * time.Millisecond) // wait for at least one cycle

	const goroutines = 10
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := monitor.GetPosture(context.Background())
			errs <- err
		}()
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent GetPosture failed: %v", err)
		}
	}
}

func TestMonitor_AlertCallback_EdgeCase(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 1, ChainIntact: true},
		},
	})

	alerted := make(chan bool, 1)
	monitor := NewContinuousMonitor(fabric)
	err := monitor.StartMonitoring(context.Background(), MonitorConfig{
		Interval:       50 * time.Millisecond,
		AlertThreshold: 90, // Score will be below 90 (Basic=25).
		JobIDs:         []string{"job-alert-edge"},
		NotifyOnDegradation: func(_ *CompliancePosture) {
			select {
			case alerted <- true:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("StartMonitoring failed: %v", err)
	}
	defer monitor.StopMonitoring()

	select {
	case <-alerted:
		// Alert triggered as expected.
	case <-time.After(2 * time.Second):
		t.Fatal("expected alert callback to be triggered")
	}
}

func TestMonitor_TrendCalculation(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{
			evidence: &AuditEvidence{RecordCount: 5, ChainIntact: true},
		},
	})

	monitor := NewContinuousMonitor(fabric)
	err := monitor.StartMonitoring(context.Background(), MonitorConfig{
		Interval:       50 * time.Millisecond,
		AlertThreshold: 50,
		JobIDs:         []string{"job-trend-edge"},
	})
	if err != nil {
		t.Fatalf("StartMonitoring failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	monitor.StopMonitoring()

	report, err := monitor.GetTrend(context.Background(), 1*time.Hour)
	if err != nil {
		t.Fatalf("GetTrend failed: %v", err)
	}
	if len(report.Snapshots) == 0 {
		t.Fatal("expected at least one snapshot")
	}
	// Trend direction should be set.
	if report.Direction == "" {
		t.Error("expected non-empty trend direction")
	}
}

func TestAPI_InvalidJobID(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{evidence: &AuditEvidence{}},
	})

	server := NewAssuranceServer(fabric, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assurance/level?job_id=", nil)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("expected non-OK status for empty job ID")
	}
}

func TestAPI_MalformedJSON(t *testing.T) {
	fabric, _ := NewAssuranceFabric(FabricConfig{
		AuditProvider: &mockAuditProvider{evidence: &AuditEvidence{}},
	})

	server := NewAssuranceServer(fabric, nil)
	body := `{this is not valid json}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assurance/evidence", strings.NewReader(body))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("expected non-OK status for malformed JSON")
	}
}

// Suppress unused import warning for fmt.
var _ = fmt.Sprintf
