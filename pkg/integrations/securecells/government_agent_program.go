package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentProgramFilter narrows national or enterprise
// program views across government-agent-ready secure cells.
type SecureCellGovernmentAgentProgramFilter struct {
	CellID              string
	Jurisdiction        string
	ServiceCode         string
	ServiceTier         string
	ReadinessLevel      SecureCellGovernmentAgentReadinessLevel
	MinimumOverallScore int
	Limit               int
}

// SecureCellGovernmentAgentProgramStage is the rollout posture an operator can
// use when sequencing service automation cohorts.
type SecureCellGovernmentAgentProgramStage string

const (
	SecureCellGovernmentAgentProgramStageMapTacitWork       SecureCellGovernmentAgentProgramStage = "map_tacit_work"
	SecureCellGovernmentAgentProgramStageEvidenceHardening  SecureCellGovernmentAgentProgramStage = "evidence_hardening"
	SecureCellGovernmentAgentProgramStageSupervisedPilot    SecureCellGovernmentAgentProgramStage = "supervised_pilot"
	SecureCellGovernmentAgentProgramStageAutonomyRamp       SecureCellGovernmentAgentProgramStage = "autonomy_ramp"
	SecureCellGovernmentAgentProgramStageAutonomousEligible SecureCellGovernmentAgentProgramStage = "autonomous_eligible"
)

// SecureCellGovernmentAgentProgramService is the per-service row behind a
// program summary.
type SecureCellGovernmentAgentProgramService struct {
	CellID                 string                                  `json:"cell_id"`
	Name                   string                                  `json:"name"`
	Purpose                string                                  `json:"purpose,omitempty"`
	Resource               string                                  `json:"resource,omitempty"`
	Jurisdiction           string                                  `json:"jurisdiction,omitempty"`
	ServiceCode            string                                  `json:"service_code,omitempty"`
	ServiceTier            string                                  `json:"service_tier,omitempty"`
	ReadinessLevel         SecureCellGovernmentAgentReadinessLevel `json:"readiness_level"`
	RecommendedStage       SecureCellGovernmentAgentProgramStage   `json:"recommended_stage"`
	ReadyForSupervisedRun  bool                                    `json:"ready_for_supervised_run"`
	ReadyForAutonomousRun  bool                                    `json:"ready_for_autonomous_run"`
	LegibleForAgent        bool                                    `json:"legible_for_agent"`
	EvidenceReady          bool                                    `json:"evidence_ready"`
	SLAReady               bool                                    `json:"sla_ready"`
	IdentityReady          bool                                    `json:"identity_ready"`
	LocalizationReady      bool                                    `json:"localization_ready"`
	OverallScore           int                                     `json:"overall_score"`
	BlueprintCoverageScore int                                     `json:"blueprint_coverage_score"`
	BlueprintCriticalGaps  int                                     `json:"blueprint_critical_gaps"`
	BlueprintWarningGaps   int                                     `json:"blueprint_warning_gaps"`
	CriticalFindingCount   int                                     `json:"critical_finding_count"`
	WarningFindingCount    int                                     `json:"warning_finding_count"`
	NextActionCount        int                                     `json:"next_action_count"`
	WorkflowBlueprintID    string                                  `json:"workflow_blueprint_id,omitempty"`
	WorkflowDigest         string                                  `json:"workflow_digest"`
	TopBlockerCodes        []string                                `json:"top_blocker_codes,omitempty"`
	UpdatedAt              time.Time                               `json:"updated_at"`
}

// SecureCellGovernmentAgentProgramBlocker groups repeated readiness blockers
// across a program.
type SecureCellGovernmentAgentProgramBlocker struct {
	Code           string                                     `json:"code"`
	Category       string                                     `json:"category,omitempty"`
	Severity       SecureCellGovernmentAgentReadinessSeverity `json:"severity"`
	Count          int                                        `json:"count"`
	ServiceCellIDs []string                                   `json:"service_cell_ids,omitempty"`
	Recommendation string                                     `json:"recommendation,omitempty"`
}

// SecureCellGovernmentAgentProgramSummary is a portfolio-level rollup for the
// workflow-legibility metric that government-agent programs need to manage.
type SecureCellGovernmentAgentProgramSummary struct {
	ProgramID                     string                                    `json:"program_id"`
	Jurisdiction                  string                                    `json:"jurisdiction,omitempty"`
	ServiceCode                   string                                    `json:"service_code,omitempty"`
	ServiceTier                   string                                    `json:"service_tier,omitempty"`
	ServiceCount                  int                                       `json:"service_count"`
	LegibleServiceCount           int                                       `json:"legible_service_count"`
	EvidenceReadyServiceCount     int                                       `json:"evidence_ready_service_count"`
	SLAReadyServiceCount          int                                       `json:"sla_ready_service_count"`
	IdentityReadyServiceCount     int                                       `json:"identity_ready_service_count"`
	LocalizationReadyServiceCount int                                       `json:"localization_ready_service_count"`
	BlockedCount                  int                                       `json:"blocked_count"`
	FoundationReadyCount          int                                       `json:"foundation_ready_count"`
	SupervisedReadyCount          int                                       `json:"supervised_ready_count"`
	AutonomyReadyCount            int                                       `json:"autonomy_ready_count"`
	AverageOverallScore           int                                       `json:"average_overall_score"`
	AverageBlueprintCoverageScore int                                       `json:"average_blueprint_coverage_score"`
	LegibilityRate                int                                       `json:"legibility_rate"`
	SupervisedReadyRate           int                                       `json:"supervised_ready_rate"`
	AutonomyReadyRate             int                                       `json:"autonomy_ready_rate"`
	CriticalFindingCount          int                                       `json:"critical_finding_count"`
	WarningFindingCount           int                                       `json:"warning_finding_count"`
	TopBlockers                   []SecureCellGovernmentAgentProgramBlocker `json:"top_blockers,omitempty"`
	Services                      []SecureCellGovernmentAgentProgramService `json:"services"`
	ProgramDigest                 string                                    `json:"program_digest"`
	GeneratedAt                   time.Time                                 `json:"generated_at"`
}

// GetGovernmentAgentProgramSummary returns a live portfolio rollup of services
// that are ready, blocked, or approaching agent-executable workflow posture.
func (s *Service) GetGovernmentAgentProgramSummary(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) (*SecureCellGovernmentAgentProgramSummary, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-program: service is required")
	}

	readinessFilter := SecureCellGovernmentAgentReadinessFilter{
		CellID:              strings.TrimSpace(filter.CellID),
		Jurisdiction:        strings.TrimSpace(filter.Jurisdiction),
		ReadinessLevel:      filter.ReadinessLevel,
		MinimumOverallScore: filter.MinimumOverallScore,
	}
	assessments, err := s.ListGovernmentAgentReadinessAssessments(ctx, readinessFilter)
	if err != nil {
		return nil, err
	}
	blueprints, err := s.ListGovernmentAgentWorkflowBlueprints(ctx, SecureCellGovernmentAgentReadinessFilter{
		CellID:       readinessFilter.CellID,
		Jurisdiction: readinessFilter.Jurisdiction,
	})
	if err != nil {
		return nil, err
	}
	blueprintByCellID := make(map[string]SecureCellGovernmentAgentWorkflowBlueprint, len(blueprints))
	for _, blueprint := range blueprints {
		blueprintByCellID[blueprint.CellID] = blueprint
	}

	serviceCode := strings.TrimSpace(filter.ServiceCode)
	serviceTier := strings.TrimSpace(filter.ServiceTier)
	services := make([]SecureCellGovernmentAgentProgramService, 0, len(assessments))
	findingsByCellID := make(map[string][]SecureCellGovernmentAgentReadinessFinding, len(assessments))
	for _, assessment := range assessments {
		if serviceCode != "" && !strings.EqualFold(assessment.ServiceCode, serviceCode) {
			continue
		}
		if serviceTier != "" && !strings.EqualFold(assessment.ServiceTier, serviceTier) {
			continue
		}
		blueprint := blueprintByCellID[assessment.CellID]
		service := secureCellGovernmentAgentProgramService(assessment, blueprint)
		services = append(services, service)
		findingsByCellID[assessment.CellID] = append([]SecureCellGovernmentAgentReadinessFinding(nil), assessment.Findings...)
	}

	sort.SliceStable(services, func(i, j int) bool {
		if services[i].RecommendedStage == services[j].RecommendedStage {
			if services[i].OverallScore == services[j].OverallScore {
				return services[i].CellID < services[j].CellID
			}
			return services[i].OverallScore < services[j].OverallScore
		}
		return secureCellGovernmentAgentProgramStageRank(services[i].RecommendedStage) < secureCellGovernmentAgentProgramStageRank(services[j].RecommendedStage)
	})
	if filter.Limit > 0 && len(services) > filter.Limit {
		services = services[:filter.Limit]
	}

	blockers := map[string]*SecureCellGovernmentAgentProgramBlocker{}
	for _, service := range services {
		for _, finding := range findingsByCellID[service.CellID] {
			if finding.Severity == SecureCellGovernmentAgentReadinessSeverityInfo {
				continue
			}
			key := strings.TrimSpace(finding.Code)
			if key == "" {
				continue
			}
			blocker, ok := blockers[key]
			if !ok {
				blocker = &SecureCellGovernmentAgentProgramBlocker{
					Code:           key,
					Category:       finding.Category,
					Severity:       finding.Severity,
					Recommendation: finding.Recommendation,
				}
				blockers[key] = blocker
			}
			blocker.Count++
			blocker.ServiceCellIDs = append(blocker.ServiceCellIDs, service.CellID)
		}
	}
	topBlockers := make([]SecureCellGovernmentAgentProgramBlocker, 0, len(blockers))
	for _, blocker := range blockers {
		blocker.ServiceCellIDs = uniqueTrimmedStrings(blocker.ServiceCellIDs)
		topBlockers = append(topBlockers, *blocker)
	}
	sort.SliceStable(topBlockers, func(i, j int) bool {
		if topBlockers[i].Count == topBlockers[j].Count {
			if topBlockers[i].Severity == topBlockers[j].Severity {
				return topBlockers[i].Code < topBlockers[j].Code
			}
			return secureCellGovernmentAgentReadinessSeverityRank(topBlockers[i].Severity) < secureCellGovernmentAgentReadinessSeverityRank(topBlockers[j].Severity)
		}
		return topBlockers[i].Count > topBlockers[j].Count
	})
	if len(topBlockers) > 10 {
		topBlockers = topBlockers[:10]
	}

	now := time.Now().UTC()
	summary := secureCellGovernmentAgentProgramSummary(filter, services, topBlockers, now)
	return &summary, nil
}

func secureCellGovernmentAgentProgramService(assessment SecureCellGovernmentAgentReadinessAssessment, blueprint SecureCellGovernmentAgentWorkflowBlueprint) SecureCellGovernmentAgentProgramService {
	critical, warning := secureCellGovernmentAgentReadinessFindingCountsForProgram(assessment.Findings)
	identityReady := len(assessment.IdentityProviders) > 0
	if strings.EqualFold(strings.TrimSpace(assessment.Jurisdiction), "UAE") {
		identityReady = metadataListContainsIdentityProvider(assessment.IdentityProviders, "uae_pass")
	}
	localizationReady := len(assessment.Languages) > 0
	if strings.EqualFold(strings.TrimSpace(assessment.Jurisdiction), "UAE") {
		localizationReady = metadataListContainsLanguage(assessment.Languages, "ar") && metadataListContainsLanguage(assessment.Languages, "en")
	}
	evidenceReady := assessment.Evidence.PolicyReceiptChainHash != "" &&
		assessment.Evidence.ControlLedgerHash != "" &&
		assessment.Evidence.PortablePackageHash != "" &&
		assessment.Evidence.PortablePackageSigned &&
		assessment.Evidence.PortablePackageAnchored
	slaReady := assessment.Scorecard.SLAAutomation >= 75 &&
		assessment.Signals.TimedDecisionCount > 0 &&
		assessment.Signals.EscalationLadderCount > 0
	legible := assessment.BlueprintCoverageScore >= 75 &&
		assessment.BlueprintCriticalGaps == 0 &&
		assessment.Signals.GovernedDecisionCount > 0 &&
		evidenceReady
	if blueprint.BlueprintID != "" {
		legible = blueprint.CoverageScore >= 75 &&
			blueprint.CriticalGapCount == 0 &&
			assessment.Signals.GovernedDecisionCount > 0 &&
			evidenceReady
	}
	return SecureCellGovernmentAgentProgramService{
		CellID:                 assessment.CellID,
		Name:                   assessment.Name,
		Purpose:                assessment.Purpose,
		Resource:               assessment.Resource,
		Jurisdiction:           assessment.Jurisdiction,
		ServiceCode:            assessment.ServiceCode,
		ServiceTier:            assessment.ServiceTier,
		ReadinessLevel:         assessment.ReadinessLevel,
		RecommendedStage:       secureCellGovernmentAgentProgramStage(assessment, blueprint, legible, evidenceReady, slaReady),
		ReadyForSupervisedRun:  assessment.ReadyForSupervisedRun,
		ReadyForAutonomousRun:  assessment.ReadyForAutonomousRun,
		LegibleForAgent:        legible,
		EvidenceReady:          evidenceReady,
		SLAReady:               slaReady,
		IdentityReady:          identityReady,
		LocalizationReady:      localizationReady,
		OverallScore:           assessment.Scorecard.Overall,
		BlueprintCoverageScore: assessment.BlueprintCoverageScore,
		BlueprintCriticalGaps:  assessment.BlueprintCriticalGaps,
		BlueprintWarningGaps:   blueprint.WarningGapCount,
		CriticalFindingCount:   critical,
		WarningFindingCount:    warning,
		NextActionCount:        len(assessment.NextActions),
		WorkflowBlueprintID:    assessment.WorkflowBlueprintID,
		WorkflowDigest:         assessment.WorkflowDigest,
		TopBlockerCodes:        secureCellGovernmentAgentProgramTopBlockerCodes(assessment.Findings),
		UpdatedAt:              assessment.UpdatedAt.UTC(),
	}
}

func secureCellGovernmentAgentProgramSummary(
	filter SecureCellGovernmentAgentProgramFilter,
	services []SecureCellGovernmentAgentProgramService,
	topBlockers []SecureCellGovernmentAgentProgramBlocker,
	generatedAt time.Time,
) SecureCellGovernmentAgentProgramSummary {
	summary := SecureCellGovernmentAgentProgramSummary{
		Jurisdiction: strings.TrimSpace(filter.Jurisdiction),
		ServiceCode:  strings.TrimSpace(filter.ServiceCode),
		ServiceTier:  strings.TrimSpace(filter.ServiceTier),
		Services:     services,
		TopBlockers:  topBlockers,
		GeneratedAt:  generatedAt.UTC(),
	}
	totalOverall := 0
	totalCoverage := 0
	for _, service := range services {
		summary.ServiceCount++
		totalOverall += service.OverallScore
		totalCoverage += service.BlueprintCoverageScore
		if service.LegibleForAgent {
			summary.LegibleServiceCount++
		}
		if service.EvidenceReady {
			summary.EvidenceReadyServiceCount++
		}
		if service.SLAReady {
			summary.SLAReadyServiceCount++
		}
		if service.IdentityReady {
			summary.IdentityReadyServiceCount++
		}
		if service.LocalizationReady {
			summary.LocalizationReadyServiceCount++
		}
		summary.CriticalFindingCount += service.CriticalFindingCount
		summary.WarningFindingCount += service.WarningFindingCount
		switch service.ReadinessLevel {
		case SecureCellGovernmentAgentReadinessBlocked:
			summary.BlockedCount++
		case SecureCellGovernmentAgentReadinessFoundationReady:
			summary.FoundationReadyCount++
		case SecureCellGovernmentAgentReadinessSupervisedReady:
			summary.SupervisedReadyCount++
		case SecureCellGovernmentAgentReadinessAutonomyReady:
			summary.AutonomyReadyCount++
		}
	}
	if summary.ServiceCount > 0 {
		summary.AverageOverallScore = totalOverall / summary.ServiceCount
		summary.AverageBlueprintCoverageScore = totalCoverage / summary.ServiceCount
		summary.LegibilityRate = summary.LegibleServiceCount * 100 / summary.ServiceCount
		summary.SupervisedReadyRate = (summary.SupervisedReadyCount + summary.AutonomyReadyCount) * 100 / summary.ServiceCount
		summary.AutonomyReadyRate = summary.AutonomyReadyCount * 100 / summary.ServiceCount
	}
	core := struct {
		Jurisdiction string                                    `json:"jurisdiction,omitempty"`
		ServiceCode  string                                    `json:"service_code,omitempty"`
		ServiceTier  string                                    `json:"service_tier,omitempty"`
		Services     []SecureCellGovernmentAgentProgramService `json:"services"`
		TopBlockers  []SecureCellGovernmentAgentProgramBlocker `json:"top_blockers,omitempty"`
	}{
		Jurisdiction: summary.Jurisdiction,
		ServiceCode:  summary.ServiceCode,
		ServiceTier:  summary.ServiceTier,
		Services:     summary.Services,
		TopBlockers:  summary.TopBlockers,
	}
	summary.ProgramDigest = EvidenceHash(core)
	summary.ProgramID = "government-agent-program:" + firstNonEmpty(summary.Jurisdiction, "all") + ":" + summary.ProgramDigest[:12]
	return summary
}

func secureCellGovernmentAgentProgramStage(
	assessment SecureCellGovernmentAgentReadinessAssessment,
	blueprint SecureCellGovernmentAgentWorkflowBlueprint,
	legible bool,
	evidenceReady bool,
	slaReady bool,
) SecureCellGovernmentAgentProgramStage {
	if assessment.ReadyForAutonomousRun && legible && slaReady {
		return SecureCellGovernmentAgentProgramStageAutonomousEligible
	}
	if assessment.ReadyForSupervisedRun && legible {
		return SecureCellGovernmentAgentProgramStageAutonomyRamp
	}
	if evidenceReady && assessment.Signals.GovernedDecisionCount > 0 && blueprint.CriticalGapCount == 0 {
		return SecureCellGovernmentAgentProgramStageSupervisedPilot
	}
	if evidenceReady {
		return SecureCellGovernmentAgentProgramStageEvidenceHardening
	}
	return SecureCellGovernmentAgentProgramStageMapTacitWork
}

func secureCellGovernmentAgentProgramTopBlockerCodes(findings []SecureCellGovernmentAgentReadinessFinding) []string {
	candidates := make([]SecureCellGovernmentAgentReadinessFinding, 0, len(findings))
	for _, finding := range findings {
		if finding.Severity == SecureCellGovernmentAgentReadinessSeverityInfo || strings.TrimSpace(finding.Code) == "" {
			continue
		}
		candidates = append(candidates, finding)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Severity == candidates[j].Severity {
			return candidates[i].Code < candidates[j].Code
		}
		return secureCellGovernmentAgentReadinessSeverityRank(candidates[i].Severity) < secureCellGovernmentAgentReadinessSeverityRank(candidates[j].Severity)
	})
	seen := map[string]struct{}{}
	codes := make([]string, 0, len(candidates))
	for _, finding := range candidates {
		code := strings.TrimSpace(finding.Code)
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, code)
	}
	if len(codes) > 5 {
		return codes[:5]
	}
	return codes
}

func secureCellGovernmentAgentReadinessFindingCountsForProgram(findings []SecureCellGovernmentAgentReadinessFinding) (critical int, warning int) {
	for _, finding := range findings {
		switch finding.Severity {
		case SecureCellGovernmentAgentReadinessSeverityCritical:
			critical++
		case SecureCellGovernmentAgentReadinessSeverityWarning:
			warning++
		}
	}
	return critical, warning
}

func secureCellGovernmentAgentProgramStageRank(stage SecureCellGovernmentAgentProgramStage) int {
	switch stage {
	case SecureCellGovernmentAgentProgramStageMapTacitWork:
		return 0
	case SecureCellGovernmentAgentProgramStageEvidenceHardening:
		return 1
	case SecureCellGovernmentAgentProgramStageSupervisedPilot:
		return 2
	case SecureCellGovernmentAgentProgramStageAutonomyRamp:
		return 3
	case SecureCellGovernmentAgentProgramStageAutonomousEligible:
		return 4
	default:
		return 5
	}
}

func secureCellGovernmentAgentReadinessSeverityRank(severity SecureCellGovernmentAgentReadinessSeverity) int {
	switch severity {
	case SecureCellGovernmentAgentReadinessSeverityCritical:
		return 0
	case SecureCellGovernmentAgentReadinessSeverityWarning:
		return 1
	default:
		return 2
	}
}
