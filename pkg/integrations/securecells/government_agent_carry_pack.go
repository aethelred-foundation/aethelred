package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentCarryMode describes whether a workflow can be
// carried by supervised execution, autonomous execution, or neither.
type SecureCellGovernmentAgentCarryMode string

const (
	SecureCellGovernmentAgentCarryModeBlocked    SecureCellGovernmentAgentCarryMode = "blocked"
	SecureCellGovernmentAgentCarryModeSupervised SecureCellGovernmentAgentCarryMode = "supervised"
	SecureCellGovernmentAgentCarryModeAutonomous SecureCellGovernmentAgentCarryMode = "autonomous"
)

// SecureCellGovernmentAgentCarryLane tells an executor which control lane a
// step belongs to.
type SecureCellGovernmentAgentCarryLane string

const (
	SecureCellGovernmentAgentCarryLaneBlocked          SecureCellGovernmentAgentCarryLane = "blocked"
	SecureCellGovernmentAgentCarryLaneOperatorControl  SecureCellGovernmentAgentCarryLane = "operator_control"
	SecureCellGovernmentAgentCarryLaneHumanApproval    SecureCellGovernmentAgentCarryLane = "human_approval"
	SecureCellGovernmentAgentCarryLaneAgentAutomated   SecureCellGovernmentAgentCarryLane = "agent_automated"
	SecureCellGovernmentAgentCarryLaneEvidenceFinalize SecureCellGovernmentAgentCarryLane = "evidence_finalize"
)

// SecureCellGovernmentAgentCarryPackStep is a blueprint step normalized into a
// preflightable execution contract.
type SecureCellGovernmentAgentCarryPackStep struct {
	Sequence              int                                       `json:"sequence"`
	StepID                string                                    `json:"step_id"`
	Kind                  SecureCellGovernmentAgentWorkflowStepKind `json:"kind"`
	Lane                  SecureCellGovernmentAgentCarryLane        `json:"lane"`
	Name                  string                                    `json:"name"`
	Description           string                                    `json:"description,omitempty"`
	Source                string                                    `json:"source,omitempty"`
	Action                string                                    `json:"action,omitempty"`
	SessionID             string                                    `json:"session_id,omitempty"`
	ThreadID              string                                    `json:"thread_id,omitempty"`
	DecisionID            string                                    `json:"decision_id,omitempty"`
	OwnerRole             string                                    `json:"owner_role,omitempty"`
	OwnerDID              string                                    `json:"owner_did,omitempty"`
	DataClasses           []string                                  `json:"data_classes,omitempty"`
	AllowedTools          []string                                  `json:"allowed_tools,omitempty"`
	RequiredEvidence      []string                                  `json:"required_evidence,omitempty"`
	Preconditions         []string                                  `json:"preconditions,omitempty"`
	RequiresHumanApproval bool                                      `json:"requires_human_approval"`
	Automatable           bool                                      `json:"automatable"`
	Blocked               bool                                      `json:"blocked"`
	BlockerCodes          []string                                  `json:"blocker_codes,omitempty"`
	SLATemplate           string                                    `json:"sla_template,omitempty"`
	DueAt                 *time.Time                                `json:"due_at,omitempty"`
	EscalationTargets     []string                                  `json:"escalation_targets,omitempty"`
	Status                string                                    `json:"status,omitempty"`
}

// SecureCellGovernmentAgentCarryPack is the evidence-bearing execution bundle
// an operator can use to hand a service workflow to a supervised executor
// without leaving tacit gaps.
type SecureCellGovernmentAgentCarryPack struct {
	CarryPackID             string                                     `json:"carry_pack_id"`
	CellID                  string                                     `json:"cell_id"`
	Name                    string                                     `json:"name"`
	Purpose                 string                                     `json:"purpose,omitempty"`
	Resource                string                                     `json:"resource,omitempty"`
	Jurisdiction            string                                     `json:"jurisdiction,omitempty"`
	ServiceCode             string                                     `json:"service_code,omitempty"`
	ServiceTier             string                                     `json:"service_tier,omitempty"`
	CarryMode               SecureCellGovernmentAgentCarryMode         `json:"carry_mode"`
	ProgramStage            SecureCellGovernmentAgentProgramStage      `json:"program_stage"`
	ReadinessLevel          SecureCellGovernmentAgentReadinessLevel    `json:"readiness_level"`
	ReadyForAgentCarry      bool                                       `json:"ready_for_agent_carry"`
	ReadyForAutonomousCarry bool                                       `json:"ready_for_autonomous_carry"`
	OverallScore            int                                        `json:"overall_score"`
	BlueprintCoverageScore  int                                        `json:"blueprint_coverage_score"`
	StepCount               int                                        `json:"step_count"`
	AutomatableStepCount    int                                        `json:"automatable_step_count"`
	HumanApprovalStepCount  int                                        `json:"human_approval_step_count"`
	EvidenceBoundStepCount  int                                        `json:"evidence_bound_step_count"`
	SLAProtectedStepCount   int                                        `json:"sla_protected_step_count"`
	EscalationStepCount     int                                        `json:"escalation_step_count"`
	BlockedStepCount        int                                        `json:"blocked_step_count"`
	CriticalFindingCount    int                                        `json:"critical_finding_count"`
	WarningFindingCount     int                                        `json:"warning_finding_count"`
	Preconditions           []string                                   `json:"preconditions,omitempty"`
	RequiredEvidence        []string                                   `json:"required_evidence,omitempty"`
	TopBlockerCodes         []string                                   `json:"top_blocker_codes,omitempty"`
	Steps                   []SecureCellGovernmentAgentCarryPackStep   `json:"steps"`
	Handoffs                []SecureCellGovernmentAgentWorkflowHandoff `json:"handoffs,omitempty"`
	Evidence                SecureCellGovernmentAgentEvidenceState     `json:"evidence"`
	WorkflowBlueprintID     string                                     `json:"workflow_blueprint_id,omitempty"`
	WorkflowDigest          string                                     `json:"workflow_digest"`
	CarryPackDigest         string                                     `json:"carry_pack_digest"`
	GeneratedAt             time.Time                                  `json:"generated_at"`
	UpdatedAt               time.Time                                  `json:"updated_at"`
}

// GetGovernmentAgentCarryPack returns the execution carry pack for one secure
// cell.
func (s *Service) GetGovernmentAgentCarryPack(ctx context.Context, cellID string) (*SecureCellGovernmentAgentCarryPack, error) {
	items, err := s.ListGovernmentAgentCarryPacks(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-carry-pack: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentCarryPacks returns executable handoff packs for matching
// government-agent secure cells.
func (s *Service) ListGovernmentAgentCarryPacks(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentCarryPack, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-carry-pack: service is required")
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
	packs := make([]SecureCellGovernmentAgentCarryPack, 0, len(assessments))
	for _, assessment := range assessments {
		if serviceCode != "" && !strings.EqualFold(assessment.ServiceCode, serviceCode) {
			continue
		}
		if serviceTier != "" && !strings.EqualFold(assessment.ServiceTier, serviceTier) {
			continue
		}
		blueprint := blueprintByCellID[assessment.CellID]
		packs = append(packs, secureCellGovernmentAgentCarryPack(assessment, blueprint, time.Now().UTC()))
	}

	sort.SliceStable(packs, func(i, j int) bool {
		if packs[i].CarryMode == packs[j].CarryMode {
			if packs[i].OverallScore == packs[j].OverallScore {
				return packs[i].CellID < packs[j].CellID
			}
			return packs[i].OverallScore < packs[j].OverallScore
		}
		return secureCellGovernmentAgentCarryModeRank(packs[i].CarryMode) < secureCellGovernmentAgentCarryModeRank(packs[j].CarryMode)
	})
	if filter.Limit > 0 && len(packs) > filter.Limit {
		packs = packs[:filter.Limit]
	}
	return packs, nil
}

func secureCellGovernmentAgentCarryPack(
	assessment SecureCellGovernmentAgentReadinessAssessment,
	blueprint SecureCellGovernmentAgentWorkflowBlueprint,
	generatedAt time.Time,
) SecureCellGovernmentAgentCarryPack {
	critical, warning := secureCellGovernmentAgentReadinessFindingCountsForProgram(assessment.Findings)
	programService := secureCellGovernmentAgentProgramService(assessment, blueprint)
	steps := make([]SecureCellGovernmentAgentCarryPackStep, 0, len(blueprint.Steps))
	requiredEvidence := make([]string, 0)
	preconditions := secureCellGovernmentAgentCarryPackPreconditions(assessment, blueprint, programService)
	for _, step := range blueprint.Steps {
		packStep := secureCellGovernmentAgentCarryPackStep(step)
		requiredEvidence = append(requiredEvidence, packStep.RequiredEvidence...)
		steps = append(steps, packStep)
	}
	requiredEvidence = uniqueTrimmedStrings(requiredEvidence)
	sort.Strings(requiredEvidence)

	pack := SecureCellGovernmentAgentCarryPack{
		CellID:                 assessment.CellID,
		Name:                   assessment.Name,
		Purpose:                assessment.Purpose,
		Resource:               assessment.Resource,
		Jurisdiction:           assessment.Jurisdiction,
		ServiceCode:            assessment.ServiceCode,
		ServiceTier:            assessment.ServiceTier,
		CarryMode:              secureCellGovernmentAgentCarryMode(assessment, blueprint, programService),
		ProgramStage:           programService.RecommendedStage,
		ReadinessLevel:         assessment.ReadinessLevel,
		OverallScore:           assessment.Scorecard.Overall,
		BlueprintCoverageScore: assessment.BlueprintCoverageScore,
		CriticalFindingCount:   critical,
		WarningFindingCount:    warning,
		Preconditions:          preconditions,
		RequiredEvidence:       requiredEvidence,
		TopBlockerCodes:        secureCellGovernmentAgentProgramTopBlockerCodes(assessment.Findings),
		Steps:                  steps,
		Handoffs:               append([]SecureCellGovernmentAgentWorkflowHandoff(nil), blueprint.Handoffs...),
		Evidence:               assessment.Evidence,
		WorkflowBlueprintID:    assessment.WorkflowBlueprintID,
		WorkflowDigest:         assessment.WorkflowDigest,
		GeneratedAt:            generatedAt.UTC(),
		UpdatedAt:              assessment.UpdatedAt.UTC(),
	}
	pack.ReadyForAgentCarry = pack.CarryMode == SecureCellGovernmentAgentCarryModeSupervised || pack.CarryMode == SecureCellGovernmentAgentCarryModeAutonomous
	pack.ReadyForAutonomousCarry = pack.CarryMode == SecureCellGovernmentAgentCarryModeAutonomous
	for _, step := range pack.Steps {
		pack.StepCount++
		if step.Automatable {
			pack.AutomatableStepCount++
		}
		if step.RequiresHumanApproval {
			pack.HumanApprovalStepCount++
		}
		if len(step.RequiredEvidence) > 0 && !step.Blocked {
			pack.EvidenceBoundStepCount++
		}
		if strings.TrimSpace(step.SLATemplate) != "" || step.DueAt != nil {
			pack.SLAProtectedStepCount++
		}
		if step.Kind == SecureCellGovernmentAgentWorkflowStepEscalation {
			pack.EscalationStepCount++
		}
		if step.Blocked {
			pack.BlockedStepCount++
		}
	}
	core := struct {
		CellID              string                                   `json:"cell_id"`
		CarryMode           SecureCellGovernmentAgentCarryMode       `json:"carry_mode"`
		ProgramStage        SecureCellGovernmentAgentProgramStage    `json:"program_stage"`
		Preconditions       []string                                 `json:"preconditions,omitempty"`
		RequiredEvidence    []string                                 `json:"required_evidence,omitempty"`
		TopBlockerCodes     []string                                 `json:"top_blocker_codes,omitempty"`
		Steps               []SecureCellGovernmentAgentCarryPackStep `json:"steps"`
		WorkflowDigest      string                                   `json:"workflow_digest"`
		WorkflowBlueprintID string                                   `json:"workflow_blueprint_id,omitempty"`
	}{
		CellID:              pack.CellID,
		CarryMode:           pack.CarryMode,
		ProgramStage:        pack.ProgramStage,
		Preconditions:       pack.Preconditions,
		RequiredEvidence:    pack.RequiredEvidence,
		TopBlockerCodes:     pack.TopBlockerCodes,
		Steps:               pack.Steps,
		WorkflowDigest:      pack.WorkflowDigest,
		WorkflowBlueprintID: pack.WorkflowBlueprintID,
	}
	pack.CarryPackDigest = EvidenceHash(core)
	pack.CarryPackID = "government-agent-carry-pack:" + pack.CellID + ":" + pack.CarryPackDigest[:12]
	return pack
}

func secureCellGovernmentAgentCarryPackStep(step SecureCellGovernmentAgentWorkflowStep) SecureCellGovernmentAgentCarryPackStep {
	blockerCodes := secureCellGovernmentAgentWorkflowGapCodes(step.Gaps)
	blocked := len(blockerCodes) > 0 && secureCellGovernmentAgentWorkflowHasCriticalGap(step.Gaps)
	lane := secureCellGovernmentAgentCarryLane(step, blocked)
	preconditions := secureCellGovernmentAgentCarryStepPreconditions(step, blocked)
	requiredEvidence := uniqueTrimmedStrings(step.EvidenceArtifacts)
	sort.Strings(requiredEvidence)
	return SecureCellGovernmentAgentCarryPackStep{
		Sequence:              step.Sequence,
		StepID:                step.StepID,
		Kind:                  step.Kind,
		Lane:                  lane,
		Name:                  step.Name,
		Description:           step.Description,
		Source:                step.Source,
		Action:                step.Action,
		SessionID:             step.SessionID,
		ThreadID:              step.ThreadID,
		DecisionID:            step.DecisionID,
		OwnerRole:             step.OwnerRole,
		OwnerDID:              step.OwnerDID,
		DataClasses:           uniqueTrimmedStrings(step.DataClasses),
		AllowedTools:          uniqueTrimmedStrings(step.AllowedTools),
		RequiredEvidence:      requiredEvidence,
		Preconditions:         preconditions,
		RequiresHumanApproval: step.RequiresHumanApproval,
		Automatable:           step.Automatable && !blocked,
		Blocked:               blocked,
		BlockerCodes:          blockerCodes,
		SLATemplate:           step.SLATemplate,
		DueAt:                 cloneTimePtr(step.DueAt),
		EscalationTargets:     uniqueTrimmedStrings(step.EscalationTargets),
		Status:                step.Status,
	}
}

func secureCellGovernmentAgentCarryPackPreconditions(
	assessment SecureCellGovernmentAgentReadinessAssessment,
	blueprint SecureCellGovernmentAgentWorkflowBlueprint,
	programService SecureCellGovernmentAgentProgramService,
) []string {
	preconditions := make([]string, 0)
	add := func(condition string, ok bool) {
		if ok {
			preconditions = append(preconditions, condition)
		} else {
			preconditions = append(preconditions, "missing:"+condition)
		}
	}
	add("policy_receipt_chain", assessment.Evidence.PolicyReceiptChainHash != "")
	add("control_ledger", assessment.Evidence.ControlLedgerHash != "")
	add("portable_package_signed_and_anchored", assessment.Evidence.PortablePackageSigned && assessment.Evidence.PortablePackageAnchored)
	add("governed_decisions", assessment.Signals.GovernedDecisionCount > 0)
	add("approval_boundary", assessment.Signals.ApprovalGateCount > 0)
	add("sla_timer", assessment.Signals.TimedDecisionCount > 0)
	add("escalation_ladder", assessment.Signals.EscalationLadderCount > 0)
	add("service_code", strings.TrimSpace(assessment.ServiceCode) != "")
	add("identity_boundary", programService.IdentityReady)
	add("localization_surface", programService.LocalizationReady)
	add("workflow_blueprint", blueprint.BlueprintID != "" && blueprint.CriticalGapCount == 0)
	return uniqueTrimmedStrings(preconditions)
}

func secureCellGovernmentAgentCarryStepPreconditions(step SecureCellGovernmentAgentWorkflowStep, blocked bool) []string {
	preconditions := make([]string, 0, 4)
	if blocked {
		preconditions = append(preconditions, "resolve_step_blockers")
	}
	if step.RequiresHumanApproval {
		preconditions = append(preconditions, "human_approval_before_execution")
	}
	if strings.TrimSpace(step.SLATemplate) != "" || step.DueAt != nil {
		preconditions = append(preconditions, "sla_timer_active")
	}
	if len(step.EscalationTargets) > 0 {
		preconditions = append(preconditions, "escalation_target_available")
	}
	if len(step.EvidenceArtifacts) > 0 {
		preconditions = append(preconditions, "evidence_artifacts_available")
	}
	if len(step.AllowedTools) > 0 {
		preconditions = append(preconditions, "tool_scope_bound")
	}
	return uniqueTrimmedStrings(preconditions)
}

func secureCellGovernmentAgentCarryMode(
	assessment SecureCellGovernmentAgentReadinessAssessment,
	blueprint SecureCellGovernmentAgentWorkflowBlueprint,
	programService SecureCellGovernmentAgentProgramService,
) SecureCellGovernmentAgentCarryMode {
	if assessment.ReadyForAutonomousRun &&
		programService.LegibleForAgent &&
		programService.SLAReady &&
		blueprint.CriticalGapCount == 0 &&
		blueprint.WarningGapCount == 0 {
		return SecureCellGovernmentAgentCarryModeAutonomous
	}
	if assessment.ReadyForSupervisedRun &&
		programService.LegibleForAgent &&
		blueprint.CriticalGapCount == 0 {
		return SecureCellGovernmentAgentCarryModeSupervised
	}
	return SecureCellGovernmentAgentCarryModeBlocked
}

func secureCellGovernmentAgentCarryLane(step SecureCellGovernmentAgentWorkflowStep, blocked bool) SecureCellGovernmentAgentCarryLane {
	if blocked {
		return SecureCellGovernmentAgentCarryLaneBlocked
	}
	if step.RequiresHumanApproval {
		return SecureCellGovernmentAgentCarryLaneHumanApproval
	}
	if step.Kind == SecureCellGovernmentAgentWorkflowStepEvidence {
		return SecureCellGovernmentAgentCarryLaneEvidenceFinalize
	}
	if step.Automatable {
		return SecureCellGovernmentAgentCarryLaneAgentAutomated
	}
	return SecureCellGovernmentAgentCarryLaneOperatorControl
}

func secureCellGovernmentAgentWorkflowGapCodes(gaps []SecureCellGovernmentAgentWorkflowGap) []string {
	codes := make([]string, 0, len(gaps))
	for _, gap := range gaps {
		if strings.TrimSpace(gap.Code) != "" {
			codes = append(codes, gap.Code)
		}
	}
	codes = uniqueTrimmedStrings(codes)
	sort.Strings(codes)
	return codes
}

func secureCellGovernmentAgentWorkflowHasCriticalGap(gaps []SecureCellGovernmentAgentWorkflowGap) bool {
	for _, gap := range gaps {
		if gap.Severity == SecureCellGovernmentAgentWorkflowGapCritical {
			return true
		}
	}
	return false
}

func secureCellGovernmentAgentCarryModeRank(mode SecureCellGovernmentAgentCarryMode) int {
	switch mode {
	case SecureCellGovernmentAgentCarryModeBlocked:
		return 0
	case SecureCellGovernmentAgentCarryModeSupervised:
		return 1
	case SecureCellGovernmentAgentCarryModeAutonomous:
		return 2
	default:
		return 3
	}
}
