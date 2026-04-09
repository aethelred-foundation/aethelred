// Package mappings provides the control mapping engine that connects
// regulatory framework controls to Aethelred platform capabilities.
package mappings

import (
	"fmt"
	"sync"

	"github.com/aethelred/aethelred/pkg/compliance"
	"github.com/aethelred/aethelred/pkg/compliance/frameworks"
)

// Mapper holds the registry of frameworks and their control mappings to
// Aethelred platform capabilities. It is safe for concurrent read access
// after initialization.
type Mapper struct {
	mu         sync.RWMutex
	frameworks map[string]*compliance.Framework
	mappings   map[string][]compliance.ControlMapping // key: frameworkID
	logger     compliance.Logger
	metrics    compliance.MetricsCollector
}

// NewMapper creates a Mapper pre-loaded with all supported regulatory
// frameworks and their control mappings.
func NewMapper() *Mapper {
	m := &Mapper{
		frameworks: make(map[string]*compliance.Framework),
		mappings:   make(map[string][]compliance.ControlMapping),
		logger:     compliance.NoopLogger{},
		metrics:    compliance.NoopMetrics{},
	}

	m.registerFramework(frameworks.NISTAIIRMF())
	m.registerFramework(frameworks.EUAIAct())
	m.registerFramework(frameworks.CMMC())
	m.registerFramework(frameworks.HIPAA())
	m.registerFramework(frameworks.SOC2())
	m.registerFramework(frameworks.PCIDSS())

	return m
}

// registerFramework adds a framework and generates control mappings from
// each control's declared Aethelred capabilities.
func (m *Mapper) registerFramework(fw *compliance.Framework) {
	m.frameworks[fw.ID] = fw

	var fwMappings []compliance.ControlMapping
	for _, ctrl := range fw.Controls {
		if len(ctrl.AethelredCapabilities) == 0 {
			// Control has no mapped capabilities — record as a gap.
			fwMappings = append(fwMappings, compliance.ControlMapping{
				FrameworkID:         fw.ID,
				ControlID:           ctrl.ID,
				AethelredCapability: "",
				CoverageLevel:       compliance.CoverageGap,
				Evidence:            "",
				GapDescription:      "No platform capabilities currently address this control",
				RemediationSteps:    "Evaluate organizational process controls or roadmap platform features",
			})
			continue
		}

		// Determine coverage level based on the number of capabilities and
		// whether evidence collection is automated.
		level := determineCoverage(ctrl)

		for _, cap := range ctrl.AethelredCapabilities {
			fwMappings = append(fwMappings, compliance.ControlMapping{
				FrameworkID:         fw.ID,
				ControlID:           ctrl.ID,
				AethelredCapability: cap,
				CoverageLevel:       level,
				Evidence:            buildEvidenceSummary(ctrl),
				ImplementationNotes: compliance.CapabilityDescription(cap),
			})
		}
	}

	m.mappings[fw.ID] = fwMappings
}

// determineCoverage assesses the coverage level of a control based on its
// evidence requirements and mapped capabilities.
func determineCoverage(ctrl compliance.Control) compliance.CoverageLevel {
	if len(ctrl.AethelredCapabilities) == 0 {
		return compliance.CoverageGap
	}

	// Count automated vs. manual evidence requirements.
	automatedCount := 0
	for _, ev := range ctrl.EvidenceRequirements {
		if ev.Automated {
			automatedCount++
		}
	}

	totalEvidence := len(ctrl.EvidenceRequirements)
	if totalEvidence == 0 {
		return compliance.CoveragePartial
	}

	automatedRatio := float64(automatedCount) / float64(totalEvidence)

	// Full coverage: majority of evidence is automated and multiple
	// capabilities address the control.
	if automatedRatio >= 0.5 && len(ctrl.AethelredCapabilities) >= 2 {
		return compliance.CoverageFull
	}

	// Partial coverage: some automated evidence or fewer capabilities.
	if automatedRatio > 0 || len(ctrl.AethelredCapabilities) >= 1 {
		return compliance.CoveragePartial
	}

	return compliance.CoverageGap
}

// buildEvidenceSummary creates a human-readable evidence description from
// a control's evidence requirements.
func buildEvidenceSummary(ctrl compliance.Control) string {
	if len(ctrl.EvidenceRequirements) == 0 {
		return "No evidence requirements defined"
	}

	summary := ""
	for i, ev := range ctrl.EvidenceRequirements {
		if i > 0 {
			summary += "; "
		}
		auto := "manual"
		if ev.Automated {
			auto = "automated"
		}
		summary += fmt.Sprintf("%s (%s, %s)", ev.Description, ev.Type, auto)
	}
	return summary
}

// ---------------------------------------------------------------------------
// Query methods
// ---------------------------------------------------------------------------

// GetFramework returns the framework with the given ID, or an error if
// not found.
func (m *Mapper) GetFramework(id string) (*compliance.Framework, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fw, ok := m.frameworks[id]
	if !ok {
		return nil, fmt.Errorf("Mapper.GetFramework: %w: %s", compliance.ErrFrameworkNotFound, id)
	}
	return fw, nil
}

// ListFrameworks returns all registered framework definitions.
func (m *Mapper) ListFrameworks() []*compliance.Framework {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*compliance.Framework, 0, len(m.frameworks))
	for _, fw := range m.frameworks {
		result = append(result, fw)
	}
	return result
}

// ListFrameworkIDs returns the IDs of all registered frameworks.
func (m *Mapper) ListFrameworkIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.frameworks))
	for id := range m.frameworks {
		ids = append(ids, id)
	}
	return ids
}

// GetMappings returns all control mappings for a given framework.
func (m *Mapper) GetMappings(frameworkID string) ([]compliance.ControlMapping, error) {
	if frameworkID == "" {
		return nil, fmt.Errorf("Mapper.GetMappings: %w: framework ID is required", compliance.ErrInvalidInput)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	mappings, ok := m.mappings[frameworkID]
	if !ok {
		return nil, fmt.Errorf("Mapper.GetMappings: %w: %s", compliance.ErrMappingNotFound, frameworkID)
	}

	result := make([]compliance.ControlMapping, len(mappings))
	copy(result, mappings)
	return result, nil
}

// GetMapping returns the mappings for a specific control within a framework.
func (m *Mapper) GetMapping(frameworkID, controlID string) ([]compliance.ControlMapping, error) {
	if frameworkID == "" {
		return nil, fmt.Errorf("Mapper.GetMapping: %w: framework ID is required", compliance.ErrInvalidInput)
	}
	if controlID == "" {
		return nil, fmt.Errorf("Mapper.GetMapping: %w: control ID is required", compliance.ErrInvalidInput)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	mappings, ok := m.mappings[frameworkID]
	if !ok {
		return nil, fmt.Errorf("Mapper.GetMapping: %w: %s", compliance.ErrMappingNotFound, frameworkID)
	}

	var result []compliance.ControlMapping
	for _, mapping := range mappings {
		if mapping.ControlID == controlID {
			result = append(result, mapping)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("Mapper.GetMapping: %w: control %s in framework %s", compliance.ErrMappingNotFound, controlID, frameworkID)
	}
	return result, nil
}

// GetGaps returns all control mappings with a Gap coverage level for a
// given framework.
func (m *Mapper) GetGaps(frameworkID string) ([]compliance.ControlMapping, error) {
	if frameworkID == "" {
		return nil, fmt.Errorf("Mapper.GetGaps: %w: framework ID is required", compliance.ErrInvalidInput)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	mappings, ok := m.mappings[frameworkID]
	if !ok {
		return nil, fmt.Errorf("Mapper.GetGaps: %w: %s", compliance.ErrMappingNotFound, frameworkID)
	}

	var gaps []compliance.ControlMapping
	for _, mapping := range mappings {
		if mapping.CoverageLevel == compliance.CoverageGap {
			gaps = append(gaps, mapping)
		}
	}
	return gaps, nil
}

// AssessCompliance returns a summary of compliance coverage for a framework
// including the overall score and per-control breakdown.
func (m *Mapper) AssessCompliance(frameworkID string) (*ComplianceSummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fw, ok := m.frameworks[frameworkID]
	if !ok {
		return nil, fmt.Errorf("Mapper.AssessCompliance: %w: %s", compliance.ErrFrameworkNotFound, frameworkID)
	}

	mappings, ok := m.mappings[frameworkID]
	if !ok {
		return nil, fmt.Errorf("Mapper.AssessCompliance: %w: %s", compliance.ErrMappingNotFound, frameworkID)
	}

	// Aggregate per-control coverage (use best coverage per control).
	controlCoverage := make(map[string]compliance.CoverageLevel)
	for _, mapping := range mappings {
		existing, ok := controlCoverage[mapping.ControlID]
		if !ok || mapping.CoverageLevel < existing {
			// Lower enum value = better coverage (Full=0, Gap=4)
			controlCoverage[mapping.ControlID] = mapping.CoverageLevel
		}
	}

	// Compute scores.
	totalScore := 0
	applicableCount := 0
	var fullCount, partialCount, plannedCount, naCount, gapCount int

	for _, level := range controlCoverage {
		switch level {
		case compliance.CoverageFull:
			fullCount++
		case compliance.CoveragePartial:
			partialCount++
		case compliance.CoveragePlanned:
			plannedCount++
		case compliance.CoverageNotApplicable:
			naCount++
		case compliance.CoverageGap:
			gapCount++
		}

		if level != compliance.CoverageNotApplicable {
			applicableCount++
		}
		totalScore += level.Score()
	}

	overallScore := 0
	if len(controlCoverage) > 0 {
		overallScore = totalScore / len(controlCoverage)
	}

	return &ComplianceSummary{
		FrameworkID:   frameworkID,
		FrameworkName: fw.Name,
		TotalControls: len(fw.Controls),
		OverallScore:  overallScore,
		FullCount:     fullCount,
		PartialCount:  partialCount,
		PlannedCount:  plannedCount,
		NACount:       naCount,
		GapCount:      gapCount,
	}, nil
}

// ComplianceSummary provides an aggregate view of compliance posture for
// a single regulatory framework.
type ComplianceSummary struct {
	// FrameworkID is the framework being assessed.
	FrameworkID string `json:"framework_id"`

	// FrameworkName is the display name.
	FrameworkName string `json:"framework_name"`

	// TotalControls is the number of controls in the framework.
	TotalControls int `json:"total_controls"`

	// OverallScore is the aggregate compliance score (0-100).
	OverallScore int `json:"overall_score"`

	// Coverage breakdown by level.
	FullCount    int `json:"full_count"`
	PartialCount int `json:"partial_count"`
	PlannedCount int `json:"planned_count"`
	NACount      int `json:"na_count"`
	GapCount     int `json:"gap_count"`
}
