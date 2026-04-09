// Package assessor provides the gap assessment engine that produces
// structured compliance assessment reports with remediation recommendations.
package assessor

import (
	"fmt"
	"time"

	"github.com/aethelred/aethelred/pkg/compliance"
	"github.com/aethelred/aethelred/pkg/compliance/mappings"
)

// Assessor evaluates compliance posture against registered regulatory
// frameworks and produces structured assessment reports.
type Assessor struct {
	mapper *mappings.Mapper
}

// NewAssessor creates a new Assessor backed by the given Mapper.
func NewAssessor(m *mappings.Mapper) *Assessor {
	if m == nil {
		return &Assessor{}
	}
	return &Assessor{mapper: m}
}

// ---------------------------------------------------------------------------
// Assessment report types
// ---------------------------------------------------------------------------

// AssessmentReport is the structured output of a compliance assessment for
// a single regulatory framework.
type AssessmentReport struct {
	// Metadata
	FrameworkID   string    `json:"framework_id"`
	FrameworkName string    `json:"framework_name"`
	Version       string    `json:"framework_version"`
	AssessedAt    time.Time `json:"assessed_at"`

	// Scores
	OverallScore     int     `json:"overall_score"`      // 0-100
	FullPercent      float64 `json:"full_percent"`        // Percentage of controls with full coverage
	PartialPercent   float64 `json:"partial_percent"`     // Percentage with partial coverage
	GapPercent       float64 `json:"gap_percent"`         // Percentage with gaps

	// Control-level results
	ControlResults []ControlResult `json:"control_results"`

	// Gaps requiring attention
	Gaps []GapItem `json:"gaps"`

	// Evidence inventory
	EvidenceInventory []EvidenceItem `json:"evidence_inventory"`

	// Summary statistics
	TotalControls     int `json:"total_controls"`
	FullCount         int `json:"full_count"`
	PartialCount      int `json:"partial_count"`
	PlannedCount      int `json:"planned_count"`
	NotApplicableCount int `json:"not_applicable_count"`
	GapCount          int `json:"gap_count"`
}

// ControlResult captures the assessment outcome for a single control.
type ControlResult struct {
	ControlID       string                  `json:"control_id"`
	ControlName     string                  `json:"control_name"`
	Category        string                  `json:"category"`
	CoverageLevel   compliance.CoverageLevel `json:"coverage_level"`
	CoverageName    string                  `json:"coverage_name"`
	Capabilities    []string                `json:"capabilities"`
	Evidence        string                  `json:"evidence"`
	GapDescription  string                  `json:"gap_description,omitempty"`
	Recommendation  string                  `json:"recommendation,omitempty"`
}

// GapItem describes a specific compliance gap with remediation guidance.
type GapItem struct {
	ControlID        string `json:"control_id"`
	ControlName      string `json:"control_name"`
	Category         string `json:"category"`
	Description      string `json:"description"`
	Impact           string `json:"impact"`
	Recommendation   string `json:"recommendation"`
	Priority         string `json:"priority"` // "critical", "high", "medium", "low"
	EstimatedEffort  string `json:"estimated_effort"`
}

// EvidenceItem describes a piece of evidence in the compliance inventory.
type EvidenceItem struct {
	ControlID   string                      `json:"control_id"`
	Type        compliance.EvidenceType     `json:"type"`
	Description string                      `json:"description"`
	Source      string                      `json:"source"`
	Automated   bool                        `json:"automated"`
	Available   bool                        `json:"available"`
}

// ---------------------------------------------------------------------------
// Assessment engine
// ---------------------------------------------------------------------------

// Assess performs a full compliance assessment for the specified framework
// and returns a structured report.
func (a *Assessor) Assess(frameworkID string) (*AssessmentReport, error) {
	if frameworkID == "" {
		return nil, fmt.Errorf("Assessor.Assess: %w: framework ID is required", compliance.ErrInvalidInput)
	}

	fw, err := a.mapper.GetFramework(frameworkID)
	if err != nil {
		return nil, fmt.Errorf("Assessor.Assess: %w: %v", compliance.ErrAssessmentFailed, err)
	}

	allMappings, err := a.mapper.GetMappings(frameworkID)
	if err != nil {
		return nil, fmt.Errorf("Assessor.Assess: %w: %v", compliance.ErrAssessmentFailed, err)
	}

	// Build per-control mapping index (best coverage per control).
	type controlInfo struct {
		level        compliance.CoverageLevel
		capabilities []string
		evidence     string
		gap          string
		remediation  string
	}
	controlIndex := make(map[string]*controlInfo)

	for _, m := range allMappings {
		ci, ok := controlIndex[m.ControlID]
		if !ok {
			ci = &controlInfo{
				level: m.CoverageLevel,
			}
			controlIndex[m.ControlID] = ci
		}
		// Use best (lowest enum) coverage level.
		if m.CoverageLevel < ci.level {
			ci.level = m.CoverageLevel
		}
		if m.AethelredCapability != "" {
			ci.capabilities = appendUnique(ci.capabilities, m.AethelredCapability)
		}
		if m.Evidence != "" {
			ci.evidence = m.Evidence
		}
		if m.GapDescription != "" {
			ci.gap = m.GapDescription
		}
		if m.RemediationSteps != "" {
			ci.remediation = m.RemediationSteps
		}
	}

	// Build control results and collect gaps and evidence.
	report := &AssessmentReport{
		FrameworkID:   fw.ID,
		FrameworkName: fw.Name,
		Version:       fw.Version,
		AssessedAt:    time.Now().UTC(),
		TotalControls: len(fw.Controls),
	}

	totalScore := 0

	for _, ctrl := range fw.Controls {
		ci, ok := controlIndex[ctrl.ID]
		if !ok {
			ci = &controlInfo{level: compliance.CoverageGap}
		}

		cr := ControlResult{
			ControlID:     ctrl.ID,
			ControlName:   ctrl.Name,
			Category:      ctrl.Category,
			CoverageLevel: ci.level,
			CoverageName:  ci.level.String(),
			Capabilities:  ci.capabilities,
			Evidence:      ci.evidence,
		}

		totalScore += ci.level.Score()

		switch ci.level {
		case compliance.CoverageFull:
			report.FullCount++
		case compliance.CoveragePartial:
			report.PartialCount++
			cr.GapDescription = "Partial coverage — additional organizational controls may be needed"
			cr.Recommendation = generatePartialRecommendation(ctrl)
		case compliance.CoveragePlanned:
			report.PlannedCount++
			cr.GapDescription = "Capability is on the platform roadmap"
			cr.Recommendation = "Monitor roadmap for general availability; implement interim manual controls"
		case compliance.CoverageNotApplicable:
			report.NotApplicableCount++
		case compliance.CoverageGap:
			report.GapCount++
			cr.GapDescription = ci.gap
			cr.Recommendation = ci.remediation

			// Add to gap list.
			report.Gaps = append(report.Gaps, GapItem{
				ControlID:       ctrl.ID,
				ControlName:     ctrl.Name,
				Category:        ctrl.Category,
				Description:     ci.gap,
				Impact:          assessGapImpact(ctrl),
				Recommendation:  ci.remediation,
				Priority:        assessGapPriority(ctrl),
				EstimatedEffort: assessEffort(ctrl),
			})
		}

		report.ControlResults = append(report.ControlResults, cr)

		// Build evidence inventory.
		for _, ev := range ctrl.EvidenceRequirements {
			report.EvidenceInventory = append(report.EvidenceInventory, EvidenceItem{
				ControlID:   ctrl.ID,
				Type:        ev.Type,
				Description: ev.Description,
				Source:      ev.Source,
				Automated:   ev.Automated,
				Available:   ci.level != compliance.CoverageGap,
			})
		}
	}

	// Compute aggregate scores.
	if report.TotalControls > 0 {
		report.OverallScore = totalScore / report.TotalControls
		applicable := float64(report.TotalControls - report.NotApplicableCount)
		if applicable > 0 {
			report.FullPercent = float64(report.FullCount) / applicable * 100
			report.PartialPercent = float64(report.PartialCount) / applicable * 100
			report.GapPercent = float64(report.GapCount) / applicable * 100
		}
	}

	return report, nil
}

// AssessAll performs assessments across all registered frameworks.
func (a *Assessor) AssessAll() ([]*AssessmentReport, error) {
	fwIDs := a.mapper.ListFrameworkIDs()
	reports := make([]*AssessmentReport, 0, len(fwIDs))
	for _, id := range fwIDs {
		report, err := a.Assess(id)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}
	return reports, nil
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func generatePartialRecommendation(ctrl compliance.Control) string {
	manualCount := 0
	for _, ev := range ctrl.EvidenceRequirements {
		if !ev.Automated {
			manualCount++
		}
	}
	if manualCount > 0 {
		return fmt.Sprintf(
			"Supplement automated platform controls with organizational processes for %d manual evidence requirement(s)",
			manualCount,
		)
	}
	return "Review control coverage and supplement with organizational procedures as needed"
}

func assessGapImpact(ctrl compliance.Control) string {
	switch ctrl.Category {
	case "Security", "Technical Safeguards", "System and Communications Protection",
		"Access Control", "Accuracy and Security":
		return "Potential security exposure affecting data protection and system integrity"
	case "Privacy", "Privacy Rule":
		return "Risk of non-compliance with data subject rights and privacy obligations"
	case "Govern", "Risk Management", "Risk Classification":
		return "Incomplete governance framework affecting organizational risk posture"
	default:
		return "Gap in regulatory compliance coverage requiring attention"
	}
}

func assessGapPriority(ctrl compliance.Control) string {
	criticalCategories := map[string]bool{
		"Security": true, "Technical Safeguards": true,
		"Accuracy and Security": true, "Access Control": true,
		"Data Protection": true, "Transmission Security": true,
	}
	highCategories := map[string]bool{
		"Risk Management": true, "Logging": true,
		"Audit and Accountability": true, "Human Oversight": true,
		"Incident Response": true,
	}

	if criticalCategories[ctrl.Category] {
		return "critical"
	}
	if highCategories[ctrl.Category] {
		return "high"
	}
	return "medium"
}

func assessEffort(ctrl compliance.Control) string {
	if len(ctrl.EvidenceRequirements) > 3 {
		return "high"
	}
	if len(ctrl.EvidenceRequirements) > 1 {
		return "medium"
	}
	return "low"
}
