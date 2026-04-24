package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentRehearsalStatus describes the result of a live
// preflight rehearsal against an agent carry pack.
type SecureCellGovernmentAgentRehearsalStatus string

const (
	SecureCellGovernmentAgentRehearsalStatusBlocked              SecureCellGovernmentAgentRehearsalStatus = "blocked"
	SecureCellGovernmentAgentRehearsalStatusOperatorReviewNeeded SecureCellGovernmentAgentRehearsalStatus = "operator_review_needed"
	SecureCellGovernmentAgentRehearsalStatusSupervisedReady      SecureCellGovernmentAgentRehearsalStatus = "supervised_ready"
	SecureCellGovernmentAgentRehearsalStatusAutonomousReady      SecureCellGovernmentAgentRehearsalStatus = "autonomous_ready"
)

// SecureCellGovernmentAgentRehearsalOutcome captures one check or step result.
type SecureCellGovernmentAgentRehearsalOutcome string

const (
	SecureCellGovernmentAgentRehearsalOutcomePass  SecureCellGovernmentAgentRehearsalOutcome = "pass"
	SecureCellGovernmentAgentRehearsalOutcomeWarn  SecureCellGovernmentAgentRehearsalOutcome = "warn"
	SecureCellGovernmentAgentRehearsalOutcomeBlock SecureCellGovernmentAgentRehearsalOutcome = "block"
)

// SecureCellGovernmentAgentRehearsalCheck is one preflight assertion.
type SecureCellGovernmentAgentRehearsalCheck struct {
	Code           string                                    `json:"code"`
	Outcome        SecureCellGovernmentAgentRehearsalOutcome `json:"outcome"`
	Detail         string                                    `json:"detail,omitempty"`
	Recommendation string                                    `json:"recommendation,omitempty"`
}

// SecureCellGovernmentAgentRehearsalStep is a carry-pack step with preflight
// checks and an execution result.
type SecureCellGovernmentAgentRehearsalStep struct {
	Sequence          int                                       `json:"sequence"`
	StepID            string                                    `json:"step_id"`
	Kind              SecureCellGovernmentAgentWorkflowStepKind `json:"kind"`
	Lane              SecureCellGovernmentAgentCarryLane        `json:"lane"`
	Name              string                                    `json:"name"`
	Action            string                                    `json:"action,omitempty"`
	Outcome           SecureCellGovernmentAgentRehearsalOutcome `json:"outcome"`
	CanExecute        bool                                      `json:"can_execute"`
	RequiresOperator  bool                                      `json:"requires_operator"`
	RequiresApproval  bool                                      `json:"requires_approval"`
	RequiredEvidence  []string                                  `json:"required_evidence,omitempty"`
	AllowedTools      []string                                  `json:"allowed_tools,omitempty"`
	Preconditions     []string                                  `json:"preconditions,omitempty"`
	BlockerCodes      []string                                  `json:"blocker_codes,omitempty"`
	Checks            []SecureCellGovernmentAgentRehearsalCheck `json:"checks,omitempty"`
	DueAt             *time.Time                                `json:"due_at,omitempty"`
	EscalationTargets []string                                  `json:"escalation_targets,omitempty"`
}

// SecureCellGovernmentAgentRehearsalReport is the operator-facing dry-run proof
// that a workflow can or cannot be carried by an agent executor.
type SecureCellGovernmentAgentRehearsalReport struct {
	RehearsalID              string                                   `json:"rehearsal_id"`
	CellID                   string                                   `json:"cell_id"`
	CarryPackID              string                                   `json:"carry_pack_id"`
	Name                     string                                   `json:"name"`
	Jurisdiction             string                                   `json:"jurisdiction,omitempty"`
	ServiceCode              string                                   `json:"service_code,omitempty"`
	ServiceTier              string                                   `json:"service_tier,omitempty"`
	Status                   SecureCellGovernmentAgentRehearsalStatus `json:"status"`
	CarryMode                SecureCellGovernmentAgentCarryMode       `json:"carry_mode"`
	ProgramStage             SecureCellGovernmentAgentProgramStage    `json:"program_stage"`
	ReadyForAgentCarry       bool                                     `json:"ready_for_agent_carry"`
	ReadyForAutonomousCarry  bool                                     `json:"ready_for_autonomous_carry"`
	RehearsalScore           int                                      `json:"rehearsal_score"`
	StepCount                int                                      `json:"step_count"`
	PassStepCount            int                                      `json:"pass_step_count"`
	WarnStepCount            int                                      `json:"warn_step_count"`
	BlockStepCount           int                                      `json:"block_step_count"`
	GlobalPreconditionCount  int                                      `json:"global_precondition_count"`
	MissingPreconditionCount int                                      `json:"missing_precondition_count"`
	EvidenceBoundStepCount   int                                      `json:"evidence_bound_step_count"`
	HumanApprovalStepCount   int                                      `json:"human_approval_step_count"`
	SLAProtectedStepCount    int                                      `json:"sla_protected_step_count"`
	EscalationStepCount      int                                      `json:"escalation_step_count"`
	TopBlockerCodes          []string                                 `json:"top_blocker_codes,omitempty"`
	MissingPreconditions     []string                                 `json:"missing_preconditions,omitempty"`
	OperatorInstructions     []string                                 `json:"operator_instructions,omitempty"`
	Steps                    []SecureCellGovernmentAgentRehearsalStep `json:"steps"`
	CarryPackDigest          string                                   `json:"carry_pack_digest"`
	RehearsalDigest          string                                   `json:"rehearsal_digest"`
	GeneratedAt              time.Time                                `json:"generated_at"`
	UpdatedAt                time.Time                                `json:"updated_at"`
}

// GetGovernmentAgentRehearsalReport returns the preflight rehearsal report for
// one secure cell.
func (s *Service) GetGovernmentAgentRehearsalReport(ctx context.Context, cellID string) (*SecureCellGovernmentAgentRehearsalReport, error) {
	items, err := s.ListGovernmentAgentRehearsalReports(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-rehearsal: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentRehearsalReports returns preflight execution reports for
// all matching carry packs.
func (s *Service) ListGovernmentAgentRehearsalReports(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentRehearsalReport, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-rehearsal: service is required")
	}
	packs, err := s.ListGovernmentAgentCarryPacks(ctx, filter)
	if err != nil {
		return nil, err
	}
	reports := make([]SecureCellGovernmentAgentRehearsalReport, 0, len(packs))
	now := time.Now().UTC()
	for _, pack := range packs {
		reports = append(reports, secureCellGovernmentAgentRehearsalReport(pack, now))
	}
	sort.SliceStable(reports, func(i, j int) bool {
		if reports[i].Status == reports[j].Status {
			if reports[i].RehearsalScore == reports[j].RehearsalScore {
				return reports[i].CellID < reports[j].CellID
			}
			return reports[i].RehearsalScore < reports[j].RehearsalScore
		}
		return secureCellGovernmentAgentRehearsalStatusRank(reports[i].Status) < secureCellGovernmentAgentRehearsalStatusRank(reports[j].Status)
	})
	return reports, nil
}

func secureCellGovernmentAgentRehearsalReport(pack SecureCellGovernmentAgentCarryPack, generatedAt time.Time) SecureCellGovernmentAgentRehearsalReport {
	steps := make([]SecureCellGovernmentAgentRehearsalStep, 0, len(pack.Steps))
	for _, step := range pack.Steps {
		steps = append(steps, secureCellGovernmentAgentRehearsalStep(step))
	}
	missingPreconditions := secureCellGovernmentAgentMissingPreconditions(pack.Preconditions)
	report := SecureCellGovernmentAgentRehearsalReport{
		CellID:                   pack.CellID,
		CarryPackID:              pack.CarryPackID,
		Name:                     pack.Name,
		Jurisdiction:             pack.Jurisdiction,
		ServiceCode:              pack.ServiceCode,
		ServiceTier:              pack.ServiceTier,
		CarryMode:                pack.CarryMode,
		ProgramStage:             pack.ProgramStage,
		ReadyForAgentCarry:       pack.ReadyForAgentCarry,
		ReadyForAutonomousCarry:  pack.ReadyForAutonomousCarry,
		GlobalPreconditionCount:  len(pack.Preconditions),
		MissingPreconditions:     missingPreconditions,
		MissingPreconditionCount: len(missingPreconditions),
		EvidenceBoundStepCount:   pack.EvidenceBoundStepCount,
		HumanApprovalStepCount:   pack.HumanApprovalStepCount,
		SLAProtectedStepCount:    pack.SLAProtectedStepCount,
		EscalationStepCount:      pack.EscalationStepCount,
		TopBlockerCodes:          append([]string(nil), pack.TopBlockerCodes...),
		OperatorInstructions:     secureCellGovernmentAgentRehearsalInstructions(pack, missingPreconditions),
		Steps:                    steps,
		CarryPackDigest:          pack.CarryPackDigest,
		GeneratedAt:              generatedAt.UTC(),
		UpdatedAt:                pack.UpdatedAt.UTC(),
	}
	for _, step := range report.Steps {
		report.StepCount++
		switch step.Outcome {
		case SecureCellGovernmentAgentRehearsalOutcomeBlock:
			report.BlockStepCount++
		case SecureCellGovernmentAgentRehearsalOutcomeWarn:
			report.WarnStepCount++
		default:
			report.PassStepCount++
		}
	}
	report.Status = secureCellGovernmentAgentRehearsalStatus(pack, report)
	report.RehearsalScore = secureCellGovernmentAgentRehearsalScore(report)
	core := struct {
		CellID               string                                   `json:"cell_id"`
		CarryPackID          string                                   `json:"carry_pack_id"`
		Status               SecureCellGovernmentAgentRehearsalStatus `json:"status"`
		RehearsalScore       int                                      `json:"rehearsal_score"`
		MissingPreconditions []string                                 `json:"missing_preconditions,omitempty"`
		TopBlockerCodes      []string                                 `json:"top_blocker_codes,omitempty"`
		Steps                []SecureCellGovernmentAgentRehearsalStep `json:"steps"`
		CarryPackDigest      string                                   `json:"carry_pack_digest"`
	}{
		CellID:               report.CellID,
		CarryPackID:          report.CarryPackID,
		Status:               report.Status,
		RehearsalScore:       report.RehearsalScore,
		MissingPreconditions: report.MissingPreconditions,
		TopBlockerCodes:      report.TopBlockerCodes,
		Steps:                report.Steps,
		CarryPackDigest:      report.CarryPackDigest,
	}
	report.RehearsalDigest = EvidenceHash(core)
	report.RehearsalID = "government-agent-rehearsal:" + report.CellID + ":" + report.RehearsalDigest[:12]
	return report
}

func secureCellGovernmentAgentRehearsalStep(step SecureCellGovernmentAgentCarryPackStep) SecureCellGovernmentAgentRehearsalStep {
	checks := make([]SecureCellGovernmentAgentRehearsalCheck, 0, 6)
	addCheck := func(code string, outcome SecureCellGovernmentAgentRehearsalOutcome, detail string, recommendation string) {
		checks = append(checks, SecureCellGovernmentAgentRehearsalCheck{
			Code:           code,
			Outcome:        outcome,
			Detail:         detail,
			Recommendation: recommendation,
		})
	}
	if step.Blocked {
		addCheck("STEP_BLOCKERS_CLEAR", SecureCellGovernmentAgentRehearsalOutcomeBlock, "Step has unresolved critical blockers.", "Resolve the step blocker codes before execution.")
	} else {
		addCheck("STEP_BLOCKERS_CLEAR", SecureCellGovernmentAgentRehearsalOutcomePass, "No critical step blockers are present.", "")
	}
	if len(step.RequiredEvidence) > 0 {
		addCheck("STEP_EVIDENCE_BOUND", SecureCellGovernmentAgentRehearsalOutcomePass, "Required evidence artifacts are attached.", "")
	} else if step.Lane == SecureCellGovernmentAgentCarryLaneAgentAutomated || step.Lane == SecureCellGovernmentAgentCarryLaneHumanApproval {
		addCheck("STEP_EVIDENCE_BOUND", SecureCellGovernmentAgentRehearsalOutcomeWarn, "No step-level evidence artifact is attached.", "Bind policy receipts, trace links, or decision receipts to this step.")
	}
	if step.RequiresHumanApproval {
		addCheck("STEP_APPROVAL_BOUNDARY", SecureCellGovernmentAgentRehearsalOutcomePass, "Human approval is explicit before execution.", "")
	} else if step.Lane == SecureCellGovernmentAgentCarryLaneAgentAutomated {
		addCheck("STEP_APPROVAL_BOUNDARY", SecureCellGovernmentAgentRehearsalOutcomePass, "Step is scoped for automated execution.", "")
	}
	if strings.TrimSpace(step.SLATemplate) != "" || step.DueAt != nil {
		addCheck("STEP_SLA_BOUNDARY", SecureCellGovernmentAgentRehearsalOutcomePass, "SLA timer or deadline is attached.", "")
	} else if step.Lane == SecureCellGovernmentAgentCarryLaneHumanApproval {
		addCheck("STEP_SLA_BOUNDARY", SecureCellGovernmentAgentRehearsalOutcomeWarn, "Human approval step has no SLA timer.", "Attach a decision SLA template or explicit due time.")
	}
	if len(step.EscalationTargets) > 0 {
		addCheck("STEP_ESCALATION_TARGET", SecureCellGovernmentAgentRehearsalOutcomePass, "Escalation target is explicit.", "")
	} else if step.Lane == SecureCellGovernmentAgentCarryLaneHumanApproval {
		addCheck("STEP_ESCALATION_TARGET", SecureCellGovernmentAgentRehearsalOutcomeWarn, "No escalation target is available for this approval step.", "Attach a deterministic escalation target.")
	}
	if len(step.AllowedTools) > 0 || step.Lane == SecureCellGovernmentAgentCarryLaneOperatorControl || step.Lane == SecureCellGovernmentAgentCarryLaneEvidenceFinalize {
		addCheck("STEP_TOOL_SCOPE", SecureCellGovernmentAgentRehearsalOutcomePass, "Tool scope is explicit or the step is operator-controlled.", "")
	} else {
		addCheck("STEP_TOOL_SCOPE", SecureCellGovernmentAgentRehearsalOutcomeWarn, "No allowed tool scope is attached.", "Declare the tool or adapter scope before agent execution.")
	}

	outcome := secureCellGovernmentAgentRehearsalChecksOutcome(checks)
	return SecureCellGovernmentAgentRehearsalStep{
		Sequence:          step.Sequence,
		StepID:            step.StepID,
		Kind:              step.Kind,
		Lane:              step.Lane,
		Name:              step.Name,
		Action:            step.Action,
		Outcome:           outcome,
		CanExecute:        outcome != SecureCellGovernmentAgentRehearsalOutcomeBlock,
		RequiresOperator:  step.Lane == SecureCellGovernmentAgentCarryLaneOperatorControl || step.Lane == SecureCellGovernmentAgentCarryLaneEvidenceFinalize,
		RequiresApproval:  step.RequiresHumanApproval,
		RequiredEvidence:  append([]string(nil), step.RequiredEvidence...),
		AllowedTools:      append([]string(nil), step.AllowedTools...),
		Preconditions:     append([]string(nil), step.Preconditions...),
		BlockerCodes:      append([]string(nil), step.BlockerCodes...),
		Checks:            checks,
		DueAt:             cloneTimePtr(step.DueAt),
		EscalationTargets: append([]string(nil), step.EscalationTargets...),
	}
}

func secureCellGovernmentAgentRehearsalChecksOutcome(checks []SecureCellGovernmentAgentRehearsalCheck) SecureCellGovernmentAgentRehearsalOutcome {
	outcome := SecureCellGovernmentAgentRehearsalOutcomePass
	for _, check := range checks {
		if check.Outcome == SecureCellGovernmentAgentRehearsalOutcomeBlock {
			return SecureCellGovernmentAgentRehearsalOutcomeBlock
		}
		if check.Outcome == SecureCellGovernmentAgentRehearsalOutcomeWarn {
			outcome = SecureCellGovernmentAgentRehearsalOutcomeWarn
		}
	}
	return outcome
}

func secureCellGovernmentAgentRehearsalStatus(pack SecureCellGovernmentAgentCarryPack, report SecureCellGovernmentAgentRehearsalReport) SecureCellGovernmentAgentRehearsalStatus {
	if pack.CarryMode == SecureCellGovernmentAgentCarryModeBlocked || report.BlockStepCount > 0 || report.MissingPreconditionCount > 0 {
		return SecureCellGovernmentAgentRehearsalStatusBlocked
	}
	if report.WarnStepCount > 0 {
		return SecureCellGovernmentAgentRehearsalStatusOperatorReviewNeeded
	}
	if pack.ReadyForAutonomousCarry {
		return SecureCellGovernmentAgentRehearsalStatusAutonomousReady
	}
	return SecureCellGovernmentAgentRehearsalStatusSupervisedReady
}

func secureCellGovernmentAgentRehearsalScore(report SecureCellGovernmentAgentRehearsalReport) int {
	score := 100
	score -= report.BlockStepCount * 18
	score -= report.MissingPreconditionCount * 8
	score -= report.WarnStepCount * 4
	if report.StepCount == 0 {
		score = 0
	}
	return clampSecureCellGovernmentAgentScore(score)
}

func secureCellGovernmentAgentMissingPreconditions(preconditions []string) []string {
	missing := make([]string, 0)
	for _, precondition := range preconditions {
		if strings.HasPrefix(strings.TrimSpace(precondition), "missing:") {
			missing = append(missing, precondition)
		}
	}
	missing = uniqueTrimmedStrings(missing)
	sort.Strings(missing)
	return missing
}

func secureCellGovernmentAgentRehearsalInstructions(pack SecureCellGovernmentAgentCarryPack, missing []string) []string {
	instructions := make([]string, 0, len(missing)+len(pack.TopBlockerCodes)+2)
	for _, item := range missing {
		instructions = append(instructions, "Resolve precondition "+strings.TrimPrefix(item, "missing:"))
	}
	for _, code := range pack.TopBlockerCodes {
		instructions = append(instructions, "Clear blocker "+code)
	}
	if pack.CarryMode == SecureCellGovernmentAgentCarryModeSupervised {
		instructions = append(instructions, "Run under supervised operator control until warning checks are clear")
	}
	if pack.CarryMode == SecureCellGovernmentAgentCarryModeAutonomous {
		instructions = append(instructions, "Preserve post-run evidence receipts for each automated step")
	}
	return uniqueTrimmedStrings(instructions)
}

func secureCellGovernmentAgentRehearsalStatusRank(status SecureCellGovernmentAgentRehearsalStatus) int {
	switch status {
	case SecureCellGovernmentAgentRehearsalStatusBlocked:
		return 0
	case SecureCellGovernmentAgentRehearsalStatusOperatorReviewNeeded:
		return 1
	case SecureCellGovernmentAgentRehearsalStatusSupervisedReady:
		return 2
	case SecureCellGovernmentAgentRehearsalStatusAutonomousReady:
		return 3
	default:
		return 4
	}
}
