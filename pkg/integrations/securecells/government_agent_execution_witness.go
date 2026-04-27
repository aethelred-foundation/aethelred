package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionWitnessStatus is the handoff posture after
// rehearsal has produced a concrete execution witness.
type SecureCellGovernmentAgentExecutionWitnessStatus string

const (
	SecureCellGovernmentAgentExecutionWitnessBlocked                     SecureCellGovernmentAgentExecutionWitnessStatus = "blocked"
	SecureCellGovernmentAgentExecutionWitnessOperatorAttestationRequired SecureCellGovernmentAgentExecutionWitnessStatus = "operator_attestation_required"
	SecureCellGovernmentAgentExecutionWitnessSupervisedReady             SecureCellGovernmentAgentExecutionWitnessStatus = "supervised_witness_ready"
	SecureCellGovernmentAgentExecutionWitnessAutonomousReady             SecureCellGovernmentAgentExecutionWitnessStatus = "autonomous_witness_ready"
)

// SecureCellGovernmentAgentExecutionWitnessStep records the evidence a carried
// step must return after execution.
type SecureCellGovernmentAgentExecutionWitnessStep struct {
	Sequence                int                                       `json:"sequence"`
	StepID                  string                                    `json:"step_id"`
	Kind                    SecureCellGovernmentAgentWorkflowStepKind `json:"kind"`
	Lane                    SecureCellGovernmentAgentCarryLane        `json:"lane"`
	Name                    string                                    `json:"name"`
	Action                  string                                    `json:"action,omitempty"`
	CanExecute              bool                                      `json:"can_execute"`
	ReleaseGate             bool                                      `json:"release_gate"`
	ReleaseGateReasons      []string                                  `json:"release_gate_reasons,omitempty"`
	ReturnRequired          bool                                      `json:"return_required"`
	RequiresOperator        bool                                      `json:"requires_operator"`
	RequiresApproval        bool                                      `json:"requires_approval"`
	ExpectedStateTransition string                                    `json:"expected_state_transition,omitempty"`
	RequiredInputEvidence   []string                                  `json:"required_input_evidence,omitempty"`
	ExpectedReturnReceipts  []string                                  `json:"expected_return_receipts,omitempty"`
	AllowedTools            []string                                  `json:"allowed_tools,omitempty"`
	BlockerCodes            []string                                  `json:"blocker_codes,omitempty"`
	Outcome                 SecureCellGovernmentAgentRehearsalOutcome `json:"outcome"`
	DueAt                   *time.Time                                `json:"due_at,omitempty"`
	EscalationTargets       []string                                  `json:"escalation_targets,omitempty"`
}

// SecureCellGovernmentAgentExecutionWitness binds the preflight rehearsal to
// the receipts expected from a real supervised or autonomous execution handoff.
type SecureCellGovernmentAgentExecutionWitness struct {
	WitnessID                  string                                          `json:"witness_id"`
	CellID                     string                                          `json:"cell_id"`
	CarryPackID                string                                          `json:"carry_pack_id"`
	RehearsalID                string                                          `json:"rehearsal_id"`
	Name                       string                                          `json:"name"`
	Jurisdiction               string                                          `json:"jurisdiction,omitempty"`
	ServiceCode                string                                          `json:"service_code,omitempty"`
	ServiceTier                string                                          `json:"service_tier,omitempty"`
	Status                     SecureCellGovernmentAgentExecutionWitnessStatus `json:"status"`
	CarryMode                  SecureCellGovernmentAgentCarryMode              `json:"carry_mode"`
	RehearsalStatus            SecureCellGovernmentAgentRehearsalStatus        `json:"rehearsal_status"`
	ReadyForExecutionHandoff   bool                                            `json:"ready_for_execution_handoff"`
	ReadyForSupervisedHandoff  bool                                            `json:"ready_for_supervised_handoff"`
	ReadyForAutonomousHandoff  bool                                            `json:"ready_for_autonomous_handoff"`
	ExecutionWitnessScore      int                                             `json:"execution_witness_score"`
	StepCount                  int                                             `json:"step_count"`
	ExecutableStepCount        int                                             `json:"executable_step_count"`
	ReleaseGateCount           int                                             `json:"release_gate_count"`
	ExpectedReturnReceiptCount int                                             `json:"expected_return_receipt_count"`
	BlockedStepCount           int                                             `json:"blocked_step_count"`
	HandoffBlockerCount        int                                             `json:"handoff_blocker_count"`
	OperatorInstructionCount   int                                             `json:"operator_instruction_count"`
	OperatorAttestationCount   int                                             `json:"operator_attestation_count"`
	MissingPreconditionCount   int                                             `json:"missing_precondition_count"`
	TopBlockerCodes            []string                                        `json:"top_blocker_codes,omitempty"`
	MissingPreconditions       []string                                        `json:"missing_preconditions,omitempty"`
	OperatorInstructions       []string                                        `json:"operator_instructions,omitempty"`
	OperatorAttestations       []string                                        `json:"operator_attestations,omitempty"`
	IngressEvidence            []string                                        `json:"ingress_evidence,omitempty"`
	EgressReceipts             []string                                        `json:"egress_receipts,omitempty"`
	RequiredInputEvidence      []string                                        `json:"required_input_evidence,omitempty"`
	ExpectedReturnReceipts     []string                                        `json:"expected_return_receipts,omitempty"`
	Steps                      []SecureCellGovernmentAgentExecutionWitnessStep `json:"steps"`
	CarryPackDigest            string                                          `json:"carry_pack_digest"`
	RehearsalDigest            string                                          `json:"rehearsal_digest"`
	WitnessDigest              string                                          `json:"witness_digest"`
	GeneratedAt                time.Time                                       `json:"generated_at"`
	UpdatedAt                  time.Time                                       `json:"updated_at"`
}

// GetGovernmentAgentExecutionWitness returns the execution handoff witness for
// one secure cell.
func (s *Service) GetGovernmentAgentExecutionWitness(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionWitness, error) {
	items, err := s.ListGovernmentAgentExecutionWitnesses(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-witness: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionWitnesses returns evidence-return manifests for
// matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionWitnesses(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionWitness, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-witness: service is required")
	}
	reports, err := s.ListGovernmentAgentRehearsalReports(ctx, filter)
	if err != nil {
		return nil, err
	}
	witnesses := make([]SecureCellGovernmentAgentExecutionWitness, 0, len(reports))
	now := time.Now().UTC()
	for _, report := range reports {
		witnesses = append(witnesses, secureCellGovernmentAgentExecutionWitness(report, now))
	}
	sort.SliceStable(witnesses, func(i, j int) bool {
		if witnesses[i].Status == witnesses[j].Status {
			if witnesses[i].ExecutableStepCount == witnesses[j].ExecutableStepCount {
				return witnesses[i].CellID < witnesses[j].CellID
			}
			return witnesses[i].ExecutableStepCount < witnesses[j].ExecutableStepCount
		}
		return secureCellGovernmentAgentExecutionWitnessStatusRank(witnesses[i].Status) < secureCellGovernmentAgentExecutionWitnessStatusRank(witnesses[j].Status)
	})
	return witnesses, nil
}

func secureCellGovernmentAgentExecutionWitness(report SecureCellGovernmentAgentRehearsalReport, generatedAt time.Time) SecureCellGovernmentAgentExecutionWitness {
	steps := make([]SecureCellGovernmentAgentExecutionWitnessStep, 0, len(report.Steps))
	requiredInputEvidence := make([]string, 0)
	expectedReceipts := make([]string, 0)
	operatorAttestations := make([]string, 0)
	for _, step := range report.Steps {
		witnessStep := secureCellGovernmentAgentExecutionWitnessStep(step)
		requiredInputEvidence = append(requiredInputEvidence, witnessStep.RequiredInputEvidence...)
		expectedReceipts = append(expectedReceipts, witnessStep.ExpectedReturnReceipts...)
		operatorAttestations = append(operatorAttestations, secureCellGovernmentAgentOperatorAttestationsForStep(witnessStep)...)
		steps = append(steps, witnessStep)
	}
	if secureCellGovernmentAgentExecutionWitnessStatus(report) == SecureCellGovernmentAgentExecutionWitnessBlocked {
		expectedReceipts = append(expectedReceipts, "blocker_resolution_receipt")
	}
	requiredInputEvidence = uniqueSortedStrings(requiredInputEvidence)
	expectedReceipts = uniqueSortedStrings(expectedReceipts)
	operatorAttestations = append(operatorAttestations, secureCellGovernmentAgentOperatorAttestationsForReport(report)...)
	operatorAttestations = uniqueSortedStrings(operatorAttestations)

	witness := SecureCellGovernmentAgentExecutionWitness{
		CellID:                   report.CellID,
		CarryPackID:              report.CarryPackID,
		RehearsalID:              report.RehearsalID,
		Name:                     report.Name,
		Jurisdiction:             report.Jurisdiction,
		ServiceCode:              report.ServiceCode,
		ServiceTier:              report.ServiceTier,
		Status:                   secureCellGovernmentAgentExecutionWitnessStatus(report),
		CarryMode:                report.CarryMode,
		RehearsalStatus:          report.Status,
		MissingPreconditionCount: report.MissingPreconditionCount,
		TopBlockerCodes:          append([]string(nil), report.TopBlockerCodes...),
		MissingPreconditions:     append([]string(nil), report.MissingPreconditions...),
		OperatorInstructions:     append([]string(nil), report.OperatorInstructions...),
		OperatorInstructionCount: len(report.OperatorInstructions),
		OperatorAttestations:     operatorAttestations,
		OperatorAttestationCount: len(operatorAttestations),
		IngressEvidence:          requiredInputEvidence,
		EgressReceipts:           expectedReceipts,
		RequiredInputEvidence:    requiredInputEvidence,
		ExpectedReturnReceipts:   expectedReceipts,
		Steps:                    steps,
		CarryPackDigest:          report.CarryPackDigest,
		RehearsalDigest:          report.RehearsalDigest,
		GeneratedAt:              generatedAt.UTC(),
		UpdatedAt:                report.UpdatedAt.UTC(),
	}
	witness.ReadyForExecutionHandoff = witness.Status == SecureCellGovernmentAgentExecutionWitnessSupervisedReady || witness.Status == SecureCellGovernmentAgentExecutionWitnessAutonomousReady
	witness.ReadyForSupervisedHandoff = witness.ReadyForExecutionHandoff
	witness.ReadyForAutonomousHandoff = witness.Status == SecureCellGovernmentAgentExecutionWitnessAutonomousReady
	for _, step := range witness.Steps {
		witness.StepCount++
		if step.CanExecute {
			witness.ExecutableStepCount++
		}
		if step.ReleaseGate {
			witness.ReleaseGateCount++
		}
		if !step.CanExecute {
			witness.BlockedStepCount++
		}
		witness.ExpectedReturnReceiptCount += len(step.ExpectedReturnReceipts)
	}
	witness.HandoffBlockerCount = witness.BlockedStepCount + witness.MissingPreconditionCount + len(witness.TopBlockerCodes)
	witness.ExecutionWitnessScore = secureCellGovernmentAgentExecutionWitnessScore(report.RehearsalScore, witness)
	witness.WitnessDigest = secureCellGovernmentAgentExecutionWitnessDigest(witness)
	witness.WitnessID = "government-agent-execution-witness:" + witness.CellID + ":" + witness.WitnessDigest[:12]
	return witness
}

func secureCellGovernmentAgentExecutionWitnessStep(step SecureCellGovernmentAgentRehearsalStep) SecureCellGovernmentAgentExecutionWitnessStep {
	expectedReceipts := secureCellGovernmentAgentExpectedReturnReceipts(step)
	releaseGateReasons := secureCellGovernmentAgentExecutionReleaseGateReasons(step)
	return SecureCellGovernmentAgentExecutionWitnessStep{
		Sequence:                step.Sequence,
		StepID:                  step.StepID,
		Kind:                    step.Kind,
		Lane:                    step.Lane,
		Name:                    step.Name,
		Action:                  step.Action,
		CanExecute:              step.CanExecute,
		ReleaseGate:             len(releaseGateReasons) > 0,
		ReleaseGateReasons:      releaseGateReasons,
		ReturnRequired:          len(expectedReceipts) > 0,
		RequiresOperator:        step.RequiresOperator,
		RequiresApproval:        step.RequiresApproval,
		ExpectedStateTransition: secureCellGovernmentAgentExpectedStateTransition(step),
		RequiredInputEvidence:   uniqueSortedStrings(step.RequiredEvidence),
		ExpectedReturnReceipts:  expectedReceipts,
		AllowedTools:            secureCellGovernmentAgentWitnessAllowedTools(step),
		BlockerCodes:            uniqueSortedStrings(step.BlockerCodes),
		Outcome:                 step.Outcome,
		DueAt:                   cloneTimePtr(step.DueAt),
		EscalationTargets:       uniqueSortedStrings(step.EscalationTargets),
	}
}

func secureCellGovernmentAgentExecutionWitnessStatus(report SecureCellGovernmentAgentRehearsalReport) SecureCellGovernmentAgentExecutionWitnessStatus {
	switch report.Status {
	case SecureCellGovernmentAgentRehearsalStatusAutonomousReady:
		return SecureCellGovernmentAgentExecutionWitnessAutonomousReady
	case SecureCellGovernmentAgentRehearsalStatusSupervisedReady:
		return SecureCellGovernmentAgentExecutionWitnessSupervisedReady
	case SecureCellGovernmentAgentRehearsalStatusOperatorReviewNeeded:
		return SecureCellGovernmentAgentExecutionWitnessOperatorAttestationRequired
	default:
		return SecureCellGovernmentAgentExecutionWitnessBlocked
	}
}

func secureCellGovernmentAgentExpectedReturnReceipts(step SecureCellGovernmentAgentRehearsalStep) []string {
	receipts := []string{"step_outcome_receipt", "trace_link"}
	if step.Lane == SecureCellGovernmentAgentCarryLaneAgentAutomated {
		receipts = append(receipts, "tool_invocation_receipt", "policy_receipt")
	}
	if step.RequiresApproval {
		receipts = append(receipts, "human_approval_receipt", "decision_receipt")
	}
	if step.RequiresOperator {
		receipts = append(receipts, "operator_attestation_receipt")
	}
	if step.Lane == SecureCellGovernmentAgentCarryLaneEvidenceFinalize {
		receipts = append(receipts, "portable_package_receipt", "audit_anchor_receipt")
	}
	if step.DueAt != nil {
		receipts = append(receipts, "sla_timer_receipt")
	}
	if len(step.EscalationTargets) > 0 {
		receipts = append(receipts, "escalation_path_receipt")
	}
	if step.Outcome == SecureCellGovernmentAgentRehearsalOutcomeBlock {
		receipts = append(receipts, "blocker_resolution_receipt")
	}
	return uniqueSortedStrings(receipts)
}

func secureCellGovernmentAgentExecutionReleaseGateReasons(step SecureCellGovernmentAgentRehearsalStep) []string {
	reasons := make([]string, 0, 4)
	if step.RequiresApproval {
		reasons = append(reasons, "human_approval_required")
	}
	if step.RequiresOperator {
		reasons = append(reasons, "operator_attestation_required")
	}
	switch step.Outcome {
	case SecureCellGovernmentAgentRehearsalOutcomeWarn:
		reasons = append(reasons, "warning_review_required")
	case SecureCellGovernmentAgentRehearsalOutcomeBlock:
		reasons = append(reasons, "blocker_resolution_required")
	}
	return uniqueSortedStrings(reasons)
}

func secureCellGovernmentAgentExpectedStateTransition(step SecureCellGovernmentAgentRehearsalStep) string {
	if step.Outcome == SecureCellGovernmentAgentRehearsalOutcomeBlock {
		return "blocked_to_ready_after_resolution"
	}
	switch step.Lane {
	case SecureCellGovernmentAgentCarryLaneHumanApproval:
		return "pending_approval_to_approved_or_rejected"
	case SecureCellGovernmentAgentCarryLaneAgentAutomated:
		return "ready_to_executed_with_policy_receipt"
	case SecureCellGovernmentAgentCarryLaneEvidenceFinalize:
		return "executed_to_evidence_anchored"
	case SecureCellGovernmentAgentCarryLaneOperatorControl:
		return "operator_attestation_to_ready"
	default:
		return "observed_to_recorded"
	}
}

func secureCellGovernmentAgentWitnessAllowedTools(step SecureCellGovernmentAgentRehearsalStep) []string {
	if tools := uniqueSortedStrings(step.AllowedTools); len(tools) > 0 {
		return tools
	}
	switch step.Lane {
	case SecureCellGovernmentAgentCarryLaneAgentAutomated:
		return []string{"secure_cells", "policy_receipts", "trace_link"}
	case SecureCellGovernmentAgentCarryLaneHumanApproval:
		return []string{"secure_cells", "approval_receipts", "decision_registry"}
	case SecureCellGovernmentAgentCarryLaneEvidenceFinalize:
		return []string{"secure_cells", "evidence_package", "audit_anchor"}
	default:
		return []string{"secure_cells", "operator_attestation"}
	}
}

func secureCellGovernmentAgentOperatorAttestationsForStep(step SecureCellGovernmentAgentExecutionWitnessStep) []string {
	items := make([]string, 0, len(step.ReleaseGateReasons))
	for _, reason := range step.ReleaseGateReasons {
		if reason == "human_approval_required" || reason == "operator_attestation_required" || reason == "warning_review_required" || reason == "blocker_resolution_required" {
			items = append(items, step.StepID+":"+reason)
		}
	}
	return items
}

func secureCellGovernmentAgentOperatorAttestationsForReport(report SecureCellGovernmentAgentRehearsalReport) []string {
	items := make([]string, 0, len(report.MissingPreconditions)+1)
	if report.Status == SecureCellGovernmentAgentRehearsalStatusOperatorReviewNeeded {
		items = append(items, "rehearsal_warning_acceptance")
	}
	for _, precondition := range report.MissingPreconditions {
		items = append(items, "missing_precondition:"+precondition)
	}
	return items
}

func secureCellGovernmentAgentExecutionWitnessScore(rehearsalScore int, witness SecureCellGovernmentAgentExecutionWitness) int {
	score := rehearsalScore
	score -= witness.BlockedStepCount * 12
	score -= witness.MissingPreconditionCount * 8
	score -= len(witness.TopBlockerCodes) * 4
	if witness.Status == SecureCellGovernmentAgentExecutionWitnessOperatorAttestationRequired {
		score -= 6
	}
	if witness.Status == SecureCellGovernmentAgentExecutionWitnessAutonomousReady {
		score += 3
	}
	return clampSecureCellGovernmentAgentScore(score)
}

func secureCellGovernmentAgentExecutionWitnessStatusRank(status SecureCellGovernmentAgentExecutionWitnessStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionWitnessBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionWitnessOperatorAttestationRequired:
		return 1
	case SecureCellGovernmentAgentExecutionWitnessSupervisedReady:
		return 2
	case SecureCellGovernmentAgentExecutionWitnessAutonomousReady:
		return 3
	default:
		return 4
	}
}

func uniqueSortedStrings(items []string) []string {
	out := uniqueTrimmedStrings(items)
	sort.Strings(out)
	return out
}
