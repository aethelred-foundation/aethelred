package compliance_test

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aethelred/aethelred/pkg/compliance"
	"github.com/aethelred/aethelred/pkg/compliance/assessor"
	"github.com/aethelred/aethelred/pkg/compliance/exports"
	"github.com/aethelred/aethelred/pkg/compliance/frameworks"
	"github.com/aethelred/aethelred/pkg/compliance/mappings"
	"github.com/aethelred/aethelred/pkg/compliance/procurement"
)

// ---------------------------------------------------------------------------
// Framework loading and validation
// ---------------------------------------------------------------------------

func TestFrameworkLoading(t *testing.T) {
	tests := []struct {
		name         string
		loader       func() *compliance.Framework
		expectedID   string
		minControls  int
	}{
		{
			name:        "NIST AI RMF loads with all controls",
			loader:      frameworks.NISTAIIRMF,
			expectedID:  "nist-ai-rmf",
			minControls: 15,
		},
		{
			name:        "EU AI Act loads with all controls",
			loader:      frameworks.EUAIAct,
			expectedID:  "eu-ai-act",
			minControls: 15,
		},
		{
			name:        "CMMC loads with all controls",
			loader:      frameworks.CMMC,
			expectedID:  "cmmc-2.0",
			minControls: 15,
		},
		{
			name:        "HIPAA loads with all controls",
			loader:      frameworks.HIPAA,
			expectedID:  "hipaa",
			minControls: 14,
		},
		{
			name:        "SOC2 loads with all controls",
			loader:      frameworks.SOC2,
			expectedID:  "soc2",
			minControls: 15,
		},
		{
			name:        "PCI-DSS loads with all controls",
			loader:      frameworks.PCIDSS,
			expectedID:  "pci-dss",
			minControls: 14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := tt.loader()
			if fw == nil {
				t.Fatal("framework loader returned nil")
			}

			if fw.ID != tt.expectedID {
				t.Errorf("expected framework ID %s, got %s", tt.expectedID, fw.ID)
			}

			if fw.Name == "" {
				t.Error("framework name is empty")
			}

			if fw.Version == "" {
				t.Error("framework version is empty")
			}

			if len(fw.Controls) < tt.minControls {
				t.Errorf("expected at least %d controls, got %d", tt.minControls, len(fw.Controls))
			}
		})
	}
}

func TestFrameworkValidation(t *testing.T) {
	tests := []struct {
		name   string
		loader func() *compliance.Framework
	}{
		{"NIST AI RMF validates", frameworks.NISTAIIRMF},
		{"EU AI Act validates", frameworks.EUAIAct},
		{"CMMC validates", frameworks.CMMC},
		{"HIPAA validates", frameworks.HIPAA},
		{"SOC2 validates", frameworks.SOC2},
		{"PCI-DSS validates", frameworks.PCIDSS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := tt.loader()
			if err := fw.Validate(); err != nil {
				t.Errorf("framework validation failed: %v", err)
			}
		})
	}
}

func TestFrameworkControlUniqueness(t *testing.T) {
	tests := []struct {
		name   string
		loader func() *compliance.Framework
	}{
		{"NIST AI RMF", frameworks.NISTAIIRMF},
		{"EU AI Act", frameworks.EUAIAct},
		{"CMMC", frameworks.CMMC},
		{"HIPAA", frameworks.HIPAA},
		{"SOC2", frameworks.SOC2},
		{"PCI-DSS", frameworks.PCIDSS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := tt.loader()
			seen := make(map[string]bool)
			for _, ctrl := range fw.Controls {
				if seen[ctrl.ID] {
					t.Errorf("duplicate control ID: %s", ctrl.ID)
				}
				seen[ctrl.ID] = true
			}
		})
	}
}

func TestFrameworkControlCompleteness(t *testing.T) {
	fws := []*compliance.Framework{
		frameworks.NISTAIIRMF(),
		frameworks.EUAIAct(),
		frameworks.CMMC(),
		frameworks.HIPAA(),
		frameworks.SOC2(),
		frameworks.PCIDSS(),
	}

	for _, fw := range fws {
		t.Run(fw.ID, func(t *testing.T) {
			for _, ctrl := range fw.Controls {
				if ctrl.ID == "" {
					t.Error("control has empty ID")
				}
				if ctrl.Name == "" {
					t.Errorf("control %s has empty name", ctrl.ID)
				}
				if ctrl.Description == "" {
					t.Errorf("control %s has empty description", ctrl.ID)
				}
				if ctrl.Category == "" {
					t.Errorf("control %s has empty category", ctrl.ID)
				}
				if len(ctrl.AethelredCapabilities) == 0 {
					t.Errorf("control %s has no mapped capabilities", ctrl.ID)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Coverage level types
// ---------------------------------------------------------------------------

func TestCoverageLevel(t *testing.T) {
	tests := []struct {
		level         compliance.CoverageLevel
		expectedStr   string
		expectedScore int
	}{
		{compliance.CoverageFull, "Full", 100},
		{compliance.CoveragePartial, "Partial", 50},
		{compliance.CoveragePlanned, "Planned", 25},
		{compliance.CoverageNotApplicable, "Not Applicable", 100},
		{compliance.CoverageGap, "Gap", 0},
	}

	for _, tt := range tests {
		t.Run(tt.expectedStr, func(t *testing.T) {
			if tt.level.String() != tt.expectedStr {
				t.Errorf("expected String() = %s, got %s", tt.expectedStr, tt.level.String())
			}
			if tt.level.Score() != tt.expectedScore {
				t.Errorf("expected Score() = %d, got %d", tt.expectedScore, tt.level.Score())
			}
		})
	}
}

func TestParseCoverageLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected compliance.CoverageLevel
		wantErr  bool
	}{
		{"full", compliance.CoverageFull, false},
		{"Full", compliance.CoverageFull, false},
		{"partial", compliance.CoveragePartial, false},
		{"planned", compliance.CoveragePlanned, false},
		{"not applicable", compliance.CoverageNotApplicable, false},
		{"not_applicable", compliance.CoverageNotApplicable, false},
		{"n/a", compliance.CoverageNotApplicable, false},
		{"gap", compliance.CoverageGap, false},
		{"invalid", compliance.CoverageGap, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := compliance.ParseCoverageLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCoverageLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("ParseCoverageLevel(%q) = %v, expected %v", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Framework query methods
// ---------------------------------------------------------------------------

func TestFrameworkGetControl(t *testing.T) {
	fw := frameworks.NISTAIIRMF()

	t.Run("existing control", func(t *testing.T) {
		ctrl := fw.GetControl("GOV-1")
		if ctrl == nil {
			t.Fatal("expected control GOV-1, got nil")
		}
		if ctrl.ID != "GOV-1" {
			t.Errorf("expected control ID GOV-1, got %s", ctrl.ID)
		}
	})

	t.Run("non-existent control", func(t *testing.T) {
		ctrl := fw.GetControl("NONEXISTENT-999")
		if ctrl != nil {
			t.Error("expected nil for non-existent control")
		}
	})
}

func TestFrameworkGetControlsByCategory(t *testing.T) {
	fw := frameworks.NISTAIIRMF()
	govControls := fw.GetControlsByCategory("Govern")

	if len(govControls) == 0 {
		t.Fatal("expected at least one Govern category control")
	}

	for _, ctrl := range govControls {
		if ctrl.Category != "Govern" {
			t.Errorf("expected category Govern, got %s", ctrl.Category)
		}
	}
}

func TestFrameworkCategories(t *testing.T) {
	fw := frameworks.NISTAIIRMF()
	cats := fw.Categories()

	if len(cats) == 0 {
		t.Fatal("expected at least one category")
	}

	expectedCats := map[string]bool{
		"Govern":  false,
		"Map":     false,
		"Measure": false,
		"Manage":  false,
	}

	for _, cat := range cats {
		expectedCats[cat] = true
	}

	for cat, found := range expectedCats {
		if !found {
			t.Errorf("expected category %s not found", cat)
		}
	}
}

// ---------------------------------------------------------------------------
// Mapper tests
// ---------------------------------------------------------------------------

func TestMapperCreation(t *testing.T) {
	m := mappings.NewMapper()
	if m == nil {
		t.Fatal("NewMapper returned nil")
	}

	fws := m.ListFrameworks()
	if len(fws) != 6 {
		t.Errorf("expected 6 frameworks, got %d", len(fws))
	}
}

func TestMapperGetFramework(t *testing.T) {
	m := mappings.NewMapper()

	tests := []struct {
		id      string
		wantErr bool
	}{
		{"nist-ai-rmf", false},
		{"eu-ai-act", false},
		{"cmmc-2.0", false},
		{"hipaa", false},
		{"soc2", false},
		{"pci-dss", false},
		{"nonexistent", true},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			fw, err := m.GetFramework(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFramework(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
			if !tt.wantErr && fw == nil {
				t.Error("expected non-nil framework")
			}
		})
	}
}

func TestMapperGetMappings(t *testing.T) {
	m := mappings.NewMapper()

	ms, err := m.GetMappings("nist-ai-rmf")
	if err != nil {
		t.Fatalf("GetMappings failed: %v", err)
	}

	if len(ms) == 0 {
		t.Fatal("expected at least one mapping for nist-ai-rmf")
	}

	for _, mapping := range ms {
		if mapping.FrameworkID != "nist-ai-rmf" {
			t.Errorf("expected framework ID nist-ai-rmf, got %s", mapping.FrameworkID)
		}
		if mapping.ControlID == "" {
			t.Error("mapping has empty control ID")
		}
	}
}

func TestMapperGetMapping(t *testing.T) {
	m := mappings.NewMapper()

	ms, err := m.GetMapping("nist-ai-rmf", "GOV-1")
	if err != nil {
		t.Fatalf("GetMapping failed: %v", err)
	}

	if len(ms) == 0 {
		t.Fatal("expected at least one mapping for GOV-1")
	}

	for _, mapping := range ms {
		if mapping.ControlID != "GOV-1" {
			t.Errorf("expected control ID GOV-1, got %s", mapping.ControlID)
		}
	}
}

func TestMapperGetGaps(t *testing.T) {
	m := mappings.NewMapper()

	// Gaps may or may not exist depending on framework coverage.
	// The test just verifies the method works without error.
	for _, fwID := range m.ListFrameworkIDs() {
		gaps, err := m.GetGaps(fwID)
		if err != nil {
			t.Errorf("GetGaps(%s) failed: %v", fwID, err)
		}
		for _, g := range gaps {
			if g.CoverageLevel != compliance.CoverageGap {
				t.Errorf("expected gap coverage level, got %s", g.CoverageLevel.String())
			}
		}
	}
}

func TestMapperAssessCompliance(t *testing.T) {
	m := mappings.NewMapper()

	for _, fwID := range m.ListFrameworkIDs() {
		t.Run(fwID, func(t *testing.T) {
			summary, err := m.AssessCompliance(fwID)
			if err != nil {
				t.Fatalf("AssessCompliance(%s) failed: %v", fwID, err)
			}

			if summary.FrameworkID != fwID {
				t.Errorf("expected framework ID %s, got %s", fwID, summary.FrameworkID)
			}

			if summary.TotalControls == 0 {
				t.Error("expected non-zero total controls")
			}

			if summary.OverallScore < 0 || summary.OverallScore > 100 {
				t.Errorf("overall score %d out of range [0, 100]", summary.OverallScore)
			}

			controlSum := summary.FullCount + summary.PartialCount +
				summary.PlannedCount + summary.NACount + summary.GapCount
			if controlSum == 0 {
				t.Error("expected at least one control classification")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Assessor tests
// ---------------------------------------------------------------------------

func TestAssessorAssess(t *testing.T) {
	m := mappings.NewMapper()
	a := assessor.NewAssessor(m)

	for _, fwID := range m.ListFrameworkIDs() {
		t.Run(fwID, func(t *testing.T) {
			report, err := a.Assess(fwID)
			if err != nil {
				t.Fatalf("Assess(%s) failed: %v", fwID, err)
			}

			if report.FrameworkID != fwID {
				t.Errorf("expected framework ID %s, got %s", fwID, report.FrameworkID)
			}

			if report.TotalControls == 0 {
				t.Error("expected non-zero total controls")
			}

			if len(report.ControlResults) != report.TotalControls {
				t.Errorf("expected %d control results, got %d",
					report.TotalControls, len(report.ControlResults))
			}

			if report.OverallScore < 0 || report.OverallScore > 100 {
				t.Errorf("overall score %d out of range [0, 100]", report.OverallScore)
			}

			// Verify evidence inventory has entries.
			if len(report.EvidenceInventory) == 0 {
				t.Error("expected non-empty evidence inventory")
			}

			// Verify assessed timestamp is set.
			if report.AssessedAt.IsZero() {
				t.Error("assessed_at timestamp is zero")
			}
		})
	}
}

func TestAssessorAssessAll(t *testing.T) {
	m := mappings.NewMapper()
	a := assessor.NewAssessor(m)

	reports, err := a.AssessAll()
	if err != nil {
		t.Fatalf("AssessAll failed: %v", err)
	}

	if len(reports) != 6 {
		t.Errorf("expected 6 reports, got %d", len(reports))
	}
}

func TestAssessorInvalidFramework(t *testing.T) {
	m := mappings.NewMapper()
	a := assessor.NewAssessor(m)

	_, err := a.Assess("nonexistent-framework")
	if err == nil {
		t.Error("expected error for nonexistent framework")
	}
}

// ---------------------------------------------------------------------------
// Export tests
// ---------------------------------------------------------------------------

func TestExportJSON(t *testing.T) {
	m := mappings.NewMapper()
	a := assessor.NewAssessor(m)
	report, err := a.Assess("nist-ai-rmf")
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	data, err := exports.ExportJSON(report)
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("ExportJSON returned empty data")
	}

	// Verify it is valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("ExportJSON output is not valid JSON: %v", err)
	}

	// Verify key fields are present.
	if _, ok := parsed["framework_id"]; !ok {
		t.Error("JSON missing framework_id field")
	}
	if _, ok := parsed["overall_score"]; !ok {
		t.Error("JSON missing overall_score field")
	}
	if _, ok := parsed["control_results"]; !ok {
		t.Error("JSON missing control_results field")
	}
}

func TestExportJSONNilReport(t *testing.T) {
	_, err := exports.ExportJSON(nil)
	if err == nil {
		t.Error("expected error for nil report")
	}
}

func TestExportCSV(t *testing.T) {
	m := mappings.NewMapper()
	a := assessor.NewAssessor(m)
	report, err := a.Assess("soc2")
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	data, err := exports.ExportCSV(report)
	if err != nil {
		t.Fatalf("ExportCSV failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("ExportCSV returned empty data")
	}

	// Parse the CSV and verify structure.
	reader := csv.NewReader(strings.NewReader(string(data)))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("CSV parsing failed: %v", err)
	}

	// Header + at least one data row.
	if len(records) < 2 {
		t.Fatalf("expected at least 2 CSV rows (header + data), got %d", len(records))
	}

	// Verify header columns.
	expectedHeaders := []string{
		"Framework", "Control ID", "Control Name", "Category",
		"Coverage Level", "Capabilities", "Evidence",
		"Gap Description", "Recommendation",
	}
	for i, expected := range expectedHeaders {
		if i >= len(records[0]) {
			t.Errorf("missing header column %d: %s", i, expected)
			continue
		}
		if records[0][i] != expected {
			t.Errorf("header column %d: expected %s, got %s", i, expected, records[0][i])
		}
	}

	// Verify row count matches control count (header + controls).
	if len(records) != report.TotalControls+1 {
		t.Errorf("expected %d CSV rows, got %d", report.TotalControls+1, len(records))
	}
}

func TestExportCSVNilReport(t *testing.T) {
	_, err := exports.ExportCSV(nil)
	if err == nil {
		t.Error("expected error for nil report")
	}
}

func TestExportOSCAL(t *testing.T) {
	m := mappings.NewMapper()
	a := assessor.NewAssessor(m)
	report, err := a.Assess("eu-ai-act")
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	data, err := exports.ExportOSCAL(report)
	if err != nil {
		t.Fatalf("ExportOSCAL failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("ExportOSCAL returned empty data")
	}

	// Verify it is valid JSON.
	var parsed exports.OSCALAssessmentResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("ExportOSCAL output is not valid JSON: %v", err)
	}

	// Verify OSCAL structure.
	if parsed.UUID == "" {
		t.Error("OSCAL UUID is empty")
	}
	if parsed.Metadata.OSCALVersion == "" {
		t.Error("OSCAL version is empty")
	}
	if len(parsed.Results) == 0 {
		t.Fatal("expected at least one OSCAL result")
	}
	if len(parsed.Results[0].Findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Verify findings have proper target structure.
	for _, finding := range parsed.Results[0].Findings {
		if finding.Target.Type != "control" {
			t.Errorf("expected target type 'control', got '%s'", finding.Target.Type)
		}
		if finding.Target.TargetID == "" {
			t.Error("finding target ID is empty")
		}
		validStatuses := map[string]bool{
			"satisfied": true, "not-satisfied": true,
			"other": true, "not-applicable": true,
		}
		if !validStatuses[finding.Target.Status] {
			t.Errorf("invalid OSCAL status: %s", finding.Target.Status)
		}
	}
}

func TestExportOSCALNilReport(t *testing.T) {
	_, err := exports.ExportOSCAL(nil)
	if err == nil {
		t.Error("expected error for nil report")
	}
}

// ---------------------------------------------------------------------------
// Procurement template tests
// ---------------------------------------------------------------------------

func TestSecurityQuestionnaire(t *testing.T) {
	sq := procurement.StandardSecurityQuestionnaire()
	if sq == nil {
		t.Fatal("StandardSecurityQuestionnaire returned nil")
	}

	if sq.Name == "" {
		t.Error("questionnaire name is empty")
	}

	if len(sq.Questions) == 0 {
		t.Fatal("expected at least one security question")
	}

	for _, q := range sq.Questions {
		if q.ID == "" {
			t.Error("question has empty ID")
		}
		if q.Category == "" {
			t.Errorf("question %s has empty category", q.ID)
		}
		if q.Question == "" {
			t.Errorf("question %s has empty question text", q.ID)
		}
		if q.Response == "" {
			t.Errorf("question %s has empty response", q.ID)
		}
		if len(q.Capabilities) == 0 {
			t.Errorf("question %s has no capabilities", q.ID)
		}
	}
}

func TestSecurityQuestionnaireCategories(t *testing.T) {
	sq := procurement.StandardSecurityQuestionnaire()

	expectedCategories := map[string]bool{
		"Encryption":          false,
		"Access Control":      false,
		"Audit and Logging":   false,
		"Incident Response":   false,
		"Data Integrity":      false,
		"Business Continuity": false,
		"Compliance":          false,
	}

	for _, q := range sq.Questions {
		expectedCategories[q.Category] = true
	}

	for cat, found := range expectedCategories {
		if !found {
			t.Errorf("expected category %s not found in questionnaire", cat)
		}
	}
}

func TestRFPResponse(t *testing.T) {
	rfp := procurement.StandardRFPResponse()
	if rfp == nil {
		t.Fatal("StandardRFPResponse returned nil")
	}

	if rfp.Name == "" {
		t.Error("RFP response name is empty")
	}

	if len(rfp.Sections) == 0 {
		t.Fatal("expected at least one RFP section")
	}

	for _, section := range rfp.Sections {
		if section.Title == "" {
			t.Error("section has empty title")
		}
		if section.Content == "" {
			t.Errorf("section %s has empty content", section.Title)
		}
		if len(section.Capabilities) == 0 {
			t.Errorf("section %s has no capabilities", section.Title)
		}
	}
}

func TestVendorAssessment(t *testing.T) {
	va := procurement.StandardVendorAssessment()
	if va == nil {
		t.Fatal("StandardVendorAssessment returned nil")
	}

	if va.Name == "" {
		t.Error("vendor assessment name is empty")
	}

	if len(va.Fields) == 0 {
		t.Fatal("expected at least one vendor assessment field")
	}

	for _, field := range va.Fields {
		if field.Field == "" {
			t.Error("field name is empty")
		}
		if field.Value == "" {
			t.Errorf("field %s has empty value", field.Field)
		}
	}
}

// ---------------------------------------------------------------------------
// Capability description tests
// ---------------------------------------------------------------------------

func TestCapabilityDescriptions(t *testing.T) {
	capabilities := []string{
		compliance.CapDigitalSeal,
		compliance.CapTEEAttestation,
		compliance.CapPoUWConsensus,
		compliance.CapAuditTrail,
		compliance.CapPQCCrypto,
		compliance.CapModelProvenance,
		compliance.CapImmutableLedger,
		compliance.CapRBACGovernance,
		compliance.CapVerifiableCompute,
		compliance.CapSlashingEnforcement,
	}

	for _, cap := range capabilities {
		t.Run(cap, func(t *testing.T) {
			desc := compliance.CapabilityDescription(cap)
			if desc == "" {
				t.Errorf("capability %s has empty description", cap)
			}
			if desc == "Platform capability" {
				t.Errorf("capability %s has generic description", cap)
			}
		})
	}
}

func TestCapabilityDescriptionUnknown(t *testing.T) {
	desc := compliance.CapabilityDescription("nonexistent-capability")
	if desc != "Platform capability" {
		t.Errorf("expected generic description for unknown capability, got %s", desc)
	}
}

// ---------------------------------------------------------------------------
// Control validation tests
// ---------------------------------------------------------------------------

func TestControlValidation(t *testing.T) {
	tests := []struct {
		name    string
		control compliance.Control
		wantErr bool
	}{
		{
			name: "valid control",
			control: compliance.Control{
				ID: "TEST-1", Name: "Test Control",
				Description: "A test control", Category: "Test",
			},
			wantErr: false,
		},
		{
			name:    "missing ID",
			control: compliance.Control{Name: "Test", Description: "Desc", Category: "Cat"},
			wantErr: true,
		},
		{
			name:    "missing name",
			control: compliance.Control{ID: "T-1", Description: "Desc", Category: "Cat"},
			wantErr: true,
		},
		{
			name:    "missing description",
			control: compliance.Control{ID: "T-1", Name: "Test", Category: "Cat"},
			wantErr: true,
		},
		{
			name:    "missing category",
			control: compliance.Control{ID: "T-1", Name: "Test", Description: "Desc"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.control.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestControlMappingValidation(t *testing.T) {
	tests := []struct {
		name    string
		mapping compliance.ControlMapping
		wantErr bool
	}{
		{
			name: "valid full mapping",
			mapping: compliance.ControlMapping{
				FrameworkID: "test", ControlID: "T-1",
				AethelredCapability: "audit-trail", CoverageLevel: compliance.CoverageFull,
			},
			wantErr: false,
		},
		{
			name: "valid gap mapping",
			mapping: compliance.ControlMapping{
				FrameworkID: "test", ControlID: "T-1",
				CoverageLevel: compliance.CoverageGap,
			},
			wantErr: false,
		},
		{
			name: "missing framework ID",
			mapping: compliance.ControlMapping{
				ControlID: "T-1", AethelredCapability: "audit-trail",
			},
			wantErr: true,
		},
		{
			name: "missing control ID",
			mapping: compliance.ControlMapping{
				FrameworkID: "test", AethelredCapability: "audit-trail",
			},
			wantErr: true,
		},
		{
			name: "missing capability for non-gap",
			mapping: compliance.ControlMapping{
				FrameworkID: "test", ControlID: "T-1",
				CoverageLevel: compliance.CoverageFull,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mapping.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration test: end-to-end flow
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Edge case, error path, and concurrency tests
// ---------------------------------------------------------------------------

func TestFrameworkValidate_NilControls(t *testing.T) {
	t.Parallel()
	fw := &compliance.Framework{
		ID:      "test-nil",
		Name:    "Nil Controls Framework",
		Version: "1.0",
	}
	// nil controls
	if err := fw.Validate(); err == nil {
		t.Error("expected validation error for nil controls")
	}

	// empty controls slice
	fw.Controls = []compliance.Control{}
	if err := fw.Validate(); err == nil {
		t.Error("expected validation error for empty controls slice")
	}
}

func TestFrameworkValidate_DuplicateControlIDs(t *testing.T) {
	t.Parallel()
	fw := &compliance.Framework{
		ID:      "test-dup",
		Name:    "Duplicate IDs",
		Version: "1.0",
		Controls: []compliance.Control{
			{ID: "C-1", Name: "Control 1", Description: "Desc", Category: "Cat"},
			{ID: "C-1", Name: "Control 1 dup", Description: "Desc", Category: "Cat"},
		},
	}
	if err := fw.Validate(); err == nil {
		t.Error("expected validation error for duplicate control IDs")
	}
}

func TestFrameworkValidate_EmptyID(t *testing.T) {
	t.Parallel()
	fw := &compliance.Framework{
		ID:      "",
		Name:    "No ID",
		Version: "1.0",
		Controls: []compliance.Control{
			{ID: "C-1", Name: "C", Description: "D", Category: "Cat"},
		},
	}
	if err := fw.Validate(); err == nil {
		t.Error("expected validation error for empty framework ID")
	}
}

func TestControlValidate_EmptyFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		control compliance.Control
	}{
		{"all empty", compliance.Control{}},
		{"only ID", compliance.Control{ID: "X"}},
		{"no description", compliance.Control{ID: "X", Name: "Y"}},
		{"no category", compliance.Control{ID: "X", Name: "Y", Description: "Z"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.control.Validate(); err == nil {
				t.Errorf("expected validation error for control with missing fields: %+v", tt.control)
			}
		})
	}
}

func TestParseCoverageLevel_EdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty string", "", true},
		{"unicode whitespace", "\u00a0full\u00a0", false}, // parser strips unicode whitespace
		{"mixed case FULL", "FULL", false},
		{"mixed case pArTiAl", "pArTiAl", false},
		{"very long string", strings.Repeat("a", 10000), true},
		{"whitespace only", "   ", true},
		{"tab and newline", "\tfull\n", false}, // parser trims whitespace
		{"numeric", "123", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := compliance.ParseCoverageLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCoverageLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestMapperGetFramework_NotFound(t *testing.T) {
	t.Parallel()
	m := mappings.NewMapper()
	_, err := m.GetFramework("nonexistent-framework-xyz")
	if err == nil {
		t.Fatal("expected error for nonexistent framework")
	}
	// The error should wrap or be ErrFrameworkNotFound.
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestMapperGetMapping_InvalidIDs(t *testing.T) {
	t.Parallel()
	m := mappings.NewMapper()

	// Empty framework ID.
	_, err := m.GetMapping("", "GOV-1")
	if err == nil {
		t.Error("expected error for empty framework ID")
	}

	// Empty control ID.
	_, err = m.GetMapping("nist-ai-rmf", "")
	if err == nil {
		t.Error("expected error for empty control ID")
	}

	// Both empty.
	_, err = m.GetMapping("", "")
	if err == nil {
		t.Error("expected error for both empty IDs")
	}
}

func TestMapperAssessCompliance_EmptyFramework(t *testing.T) {
	t.Parallel()
	m := mappings.NewMapper()
	// Use a nonexistent framework to trigger an error path.
	_, err := m.AssessCompliance("nonexistent-framework")
	if err == nil {
		t.Error("expected error for nonexistent framework in AssessCompliance")
	}
}

func TestAssessorAssess_ConcurrentAssessments(t *testing.T) {
	t.Parallel()
	m := mappings.NewMapper()
	a := assessor.NewAssessor(m)

	const goroutines = 10
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := a.Assess("nist-ai-rmf")
			errs <- err
		}()
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Assess failed: %v", err)
		}
	}
}

func TestExportJSON_NilReport_EdgeCase(t *testing.T) {
	t.Parallel()
	_, err := exports.ExportJSON(nil)
	if err == nil {
		t.Error("expected error for nil report")
	}
}

func TestExportCSV_EmptyControls(t *testing.T) {
	t.Parallel()
	// Create an assessment report with no control results.
	report := &assessor.AssessmentReport{
		FrameworkID:    "test-empty",
		TotalControls:  0,
		ControlResults: nil,
	}
	_, err := exports.ExportCSV(report)
	// Depending on implementation, this may return an error or a CSV with just headers.
	// Either behavior is acceptable; we just verify it doesn't panic.
	_ = err
}

func TestExportOSCAL_LargeDataset(t *testing.T) {
	t.Parallel()
	m := mappings.NewMapper()
	a := assessor.NewAssessor(m)

	// Assess all frameworks and export each (testing with the full dataset).
	reports, err := a.AssessAll()
	if err != nil {
		t.Fatalf("AssessAll failed: %v", err)
	}

	for _, report := range reports {
		data, err := exports.ExportOSCAL(report)
		if err != nil {
			t.Errorf("ExportOSCAL(%s) failed: %v", report.FrameworkID, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("ExportOSCAL(%s) returned empty data", report.FrameworkID)
		}
		// Verify it's valid JSON.
		var parsed map[string]interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Errorf("ExportOSCAL(%s) output is not valid JSON: %v", report.FrameworkID, err)
		}
	}
}

func TestProcurementTemplates_AllFieldsPopulated(t *testing.T) {
	t.Parallel()
	// Security Questionnaire: verify no empty answers.
	sq := procurement.StandardSecurityQuestionnaire()
	for _, q := range sq.Questions {
		if q.Response == "" {
			t.Errorf("question %s has empty response", q.ID)
		}
		if q.Question == "" {
			t.Errorf("question %s has empty question text", q.ID)
		}
	}

	// RFP Response: verify no empty content.
	rfp := procurement.StandardRFPResponse()
	for _, section := range rfp.Sections {
		if section.Content == "" {
			t.Errorf("RFP section %s has empty content", section.Title)
		}
		if section.Title == "" {
			t.Error("RFP section has empty title")
		}
	}

	// Vendor Assessment: verify no empty values.
	va := procurement.StandardVendorAssessment()
	for _, field := range va.Fields {
		if field.Value == "" {
			t.Errorf("vendor assessment field %s has empty value", field.Field)
		}
		if field.Field == "" {
			t.Error("vendor assessment has empty field name")
		}
	}
}

func TestFullWorkflow_Concurrent(t *testing.T) {
	t.Parallel()
	const goroutines = 5
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			m := mappings.NewMapper()
			a := assessor.NewAssessor(m)
			reports, err := a.AssessAll()
			if err != nil {
				errs <- err
				return
			}
			for _, report := range reports {
				if _, err := exports.ExportJSON(report); err != nil {
					errs <- err
					return
				}
				if _, err := exports.ExportCSV(report); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		}()
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent workflow failed: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration test: end-to-end flow
// ---------------------------------------------------------------------------

func TestEndToEndAssessmentFlow(t *testing.T) {
	// 1. Create mapper with all frameworks.
	m := mappings.NewMapper()

	// 2. Verify all frameworks loaded.
	fwIDs := m.ListFrameworkIDs()
	if len(fwIDs) != 6 {
		t.Fatalf("expected 6 frameworks, got %d", len(fwIDs))
	}

	// 3. Create assessor.
	a := assessor.NewAssessor(m)

	// 4. Assess all frameworks.
	reports, err := a.AssessAll()
	if err != nil {
		t.Fatalf("AssessAll failed: %v", err)
	}

	for _, report := range reports {
		// 5. Export each report in all formats.
		jsonData, err := exports.ExportJSON(report)
		if err != nil {
			t.Errorf("ExportJSON(%s) failed: %v", report.FrameworkID, err)
		}
		if len(jsonData) == 0 {
			t.Errorf("ExportJSON(%s) returned empty data", report.FrameworkID)
		}

		csvData, err := exports.ExportCSV(report)
		if err != nil {
			t.Errorf("ExportCSV(%s) failed: %v", report.FrameworkID, err)
		}
		if len(csvData) == 0 {
			t.Errorf("ExportCSV(%s) returned empty data", report.FrameworkID)
		}

		oscalData, err := exports.ExportOSCAL(report)
		if err != nil {
			t.Errorf("ExportOSCAL(%s) failed: %v", report.FrameworkID, err)
		}
		if len(oscalData) == 0 {
			t.Errorf("ExportOSCAL(%s) returned empty data", report.FrameworkID)
		}
	}

	// 6. Verify procurement templates load.
	sq := procurement.StandardSecurityQuestionnaire()
	if sq == nil || len(sq.Questions) == 0 {
		t.Error("security questionnaire is empty")
	}

	rfp := procurement.StandardRFPResponse()
	if rfp == nil || len(rfp.Sections) == 0 {
		t.Error("RFP response is empty")
	}

	va := procurement.StandardVendorAssessment()
	if va == nil || len(va.Fields) == 0 {
		t.Error("vendor assessment is empty")
	}
}
