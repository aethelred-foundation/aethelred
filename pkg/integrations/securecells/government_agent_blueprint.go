package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentWorkflowStepKind classifies one operator-readable
// step in an agent-executable government service workflow.
type SecureCellGovernmentAgentWorkflowStepKind string

const (
	SecureCellGovernmentAgentWorkflowStepContext          SecureCellGovernmentAgentWorkflowStepKind = "context"
	SecureCellGovernmentAgentWorkflowStepOperatorDeclared SecureCellGovernmentAgentWorkflowStepKind = "operator_declared"
	SecureCellGovernmentAgentWorkflowStepIntegration      SecureCellGovernmentAgentWorkflowStepKind = "integration"
	SecureCellGovernmentAgentWorkflowStepAgentAction      SecureCellGovernmentAgentWorkflowStepKind = "agent_action"
	SecureCellGovernmentAgentWorkflowStepSession          SecureCellGovernmentAgentWorkflowStepKind = "session"
	SecureCellGovernmentAgentWorkflowStepThread           SecureCellGovernmentAgentWorkflowStepKind = "thread"
	SecureCellGovernmentAgentWorkflowStepDecisionGate     SecureCellGovernmentAgentWorkflowStepKind = "decision_gate"
	SecureCellGovernmentAgentWorkflowStepEscalation       SecureCellGovernmentAgentWorkflowStepKind = "escalation"
	SecureCellGovernmentAgentWorkflowStepEvidence         SecureCellGovernmentAgentWorkflowStepKind = "evidence"
	SecureCellGovernmentAgentWorkflowStepExceptionControl SecureCellGovernmentAgentWorkflowStepKind = "exception_control"
)

// SecureCellGovernmentAgentWorkflowGapSeverity describes whether a blueprint
// gap blocks autonomous execution or only needs operator cleanup.
type SecureCellGovernmentAgentWorkflowGapSeverity string

const (
	SecureCellGovernmentAgentWorkflowGapCritical SecureCellGovernmentAgentWorkflowGapSeverity = "critical"
	SecureCellGovernmentAgentWorkflowGapWarning  SecureCellGovernmentAgentWorkflowGapSeverity = "warning"
	SecureCellGovernmentAgentWorkflowGapInfo     SecureCellGovernmentAgentWorkflowGapSeverity = "info"
)

// SecureCellGovernmentAgentWorkflowGap is a concrete missing artifact or
// control that prevents a government service workflow from being agent-legible.
type SecureCellGovernmentAgentWorkflowGap struct {
	Severity       SecureCellGovernmentAgentWorkflowGapSeverity `json:"severity"`
	Code           string                                       `json:"code"`
	Category       string                                       `json:"category"`
	Detail         string                                       `json:"detail,omitempty"`
	Recommendation string                                       `json:"recommendation,omitempty"`
}

// SecureCellGovernmentAgentWorkflowStep is one executable, auditable workflow
// node an operator can hand to a supervised or autonomous government-service
// agent.
type SecureCellGovernmentAgentWorkflowStep struct {
	Sequence              int                                       `json:"sequence"`
	StepID                string                                    `json:"step_id"`
	Kind                  SecureCellGovernmentAgentWorkflowStepKind `json:"kind"`
	Name                  string                                    `json:"name"`
	Description           string                                    `json:"description,omitempty"`
	Source                string                                    `json:"source"`
	SessionID             string                                    `json:"session_id,omitempty"`
	ThreadID              string                                    `json:"thread_id,omitempty"`
	DecisionID            string                                    `json:"decision_id,omitempty"`
	Action                string                                    `json:"action,omitempty"`
	OwnerRole             string                                    `json:"owner_role,omitempty"`
	OwnerDID              string                                    `json:"owner_did,omitempty"`
	DataClasses           []string                                  `json:"data_classes,omitempty"`
	AllowedTools          []string                                  `json:"allowed_tools,omitempty"`
	EvidenceArtifacts     []string                                  `json:"evidence_artifacts,omitempty"`
	RequiresHumanApproval bool                                      `json:"requires_human_approval"`
	Automatable           bool                                      `json:"automatable"`
	SLATemplate           string                                    `json:"sla_template,omitempty"`
	DueAt                 *time.Time                                `json:"due_at,omitempty"`
	EscalationTargets     []string                                  `json:"escalation_targets,omitempty"`
	Status                string                                    `json:"status,omitempty"`
	Gaps                  []SecureCellGovernmentAgentWorkflowGap    `json:"gaps,omitempty"`
}

// SecureCellGovernmentAgentWorkflowHandoff captures one explicit handoff edge
// between steps, owners, or escalation stages.
type SecureCellGovernmentAgentWorkflowHandoff struct {
	FromStepID       string   `json:"from_step_id"`
	ToStepID         string   `json:"to_step_id"`
	Reason           string   `json:"reason,omitempty"`
	RequiredEvidence []string `json:"required_evidence,omitempty"`
}

// SecureCellGovernmentAgentWorkflowBlueprint makes a government-service
// workflow legible enough for an AI agent to carry without inventing missing
// approvals, handoffs, or evidence.
type SecureCellGovernmentAgentWorkflowBlueprint struct {
	BlueprintID            string                                     `json:"blueprint_id"`
	CellID                 string                                     `json:"cell_id"`
	Name                   string                                     `json:"name"`
	Purpose                string                                     `json:"purpose"`
	Resource               string                                     `json:"resource,omitempty"`
	Jurisdiction           string                                     `json:"jurisdiction,omitempty"`
	ServiceCode            string                                     `json:"service_code,omitempty"`
	ServiceTier            string                                     `json:"service_tier,omitempty"`
	CoverageScore          int                                        `json:"coverage_score"`
	ReadinessLevel         SecureCellGovernmentAgentReadinessLevel    `json:"readiness_level"`
	StepCount              int                                        `json:"step_count"`
	OperatorDeclaredSteps  int                                        `json:"operator_declared_steps"`
	EvidenceBoundSteps     int                                        `json:"evidence_bound_steps"`
	HumanApprovalGateCount int                                        `json:"human_approval_gate_count"`
	SLAProtectedStepCount  int                                        `json:"sla_protected_step_count"`
	EscalationStepCount    int                                        `json:"escalation_step_count"`
	AutomatableStepCount   int                                        `json:"automatable_step_count"`
	CriticalGapCount       int                                        `json:"critical_gap_count"`
	WarningGapCount        int                                        `json:"warning_gap_count"`
	Steps                  []SecureCellGovernmentAgentWorkflowStep    `json:"steps"`
	Handoffs               []SecureCellGovernmentAgentWorkflowHandoff `json:"handoffs,omitempty"`
	Gaps                   []SecureCellGovernmentAgentWorkflowGap     `json:"gaps,omitempty"`
	Evidence               SecureCellGovernmentAgentEvidenceState     `json:"evidence"`
	WorkflowDigest         string                                     `json:"workflow_digest"`
	GeneratedAt            time.Time                                  `json:"generated_at"`
	UpdatedAt              time.Time                                  `json:"updated_at"`
}

// GetGovernmentAgentWorkflowBlueprint returns the executable blueprint for one
// secure cell.
func (s *Service) GetGovernmentAgentWorkflowBlueprint(ctx context.Context, cellID string) (*SecureCellGovernmentAgentWorkflowBlueprint, error) {
	items, err := s.ListGovernmentAgentWorkflowBlueprints(ctx, SecureCellGovernmentAgentReadinessFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-blueprint: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentWorkflowBlueprints returns operator-facing workflow maps
// for all matching government-agent secure cells.
func (s *Service) ListGovernmentAgentWorkflowBlueprints(_ context.Context, filter SecureCellGovernmentAgentReadinessFilter) ([]SecureCellGovernmentAgentWorkflowBlueprint, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-blueprint: service is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cellID := strings.TrimSpace(filter.CellID)
	jurisdiction := strings.TrimSpace(filter.Jurisdiction)
	items := make([]SecureCellGovernmentAgentWorkflowBlueprint, 0, len(s.runs))
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		if jurisdiction != "" && !strings.EqualFold(strings.TrimSpace(run.request.Jurisdiction), jurisdiction) {
			continue
		}
		blueprint := secureCellGovernmentAgentWorkflowBlueprint(run, len(s.decisionSLATemplates))
		if filter.ReadinessLevel != "" && blueprint.ReadinessLevel != filter.ReadinessLevel {
			continue
		}
		if filter.MinimumOverallScore > 0 && blueprint.CoverageScore < filter.MinimumOverallScore {
			continue
		}
		items = append(items, blueprint)
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].CoverageScore == items[j].CoverageScore {
			if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
				return items[i].CellID < items[j].CellID
			}
			return items[i].UpdatedAt.After(items[j].UpdatedAt)
		}
		return items[i].CoverageScore < items[j].CoverageScore
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func secureCellGovernmentAgentWorkflowBlueprint(run *secureCellRun, configuredSLATemplateCount int) SecureCellGovernmentAgentWorkflowBlueprint {
	now := time.Now().UTC()
	result := run.result
	metadata := mergeStringMaps(run.request.Metadata, secureCellGovernmentAgentPolicyMetadata(result))
	serviceCode := firstNonEmpty(
		metadataValue(metadata, "government_service_code"),
		metadataValue(metadata, "service_code"),
		metadataValue(metadata, "service_catalog_id"),
	)
	serviceTier := firstNonEmpty(
		metadataValue(metadata, "service_tier"),
		metadataValue(metadata, "sla_tier"),
		metadataValue(metadata, "priority_tier"),
	)
	identityProviders := normalizedMetadataList(metadata, "identity_provider", "identity_providers", "digital_identity_provider")
	languages := normalizedMetadataList(metadata, "languages", "supported_languages", "locales", "locale")
	signals := secureCellGovernmentAgentWorkflowSignals(result)
	evidenceState := secureCellGovernmentAgentEvidenceState(result)

	steps := make([]SecureCellGovernmentAgentWorkflowStep, 0)
	handoffs := make([]SecureCellGovernmentAgentWorkflowHandoff, 0)
	gaps := make([]SecureCellGovernmentAgentWorkflowGap, 0)
	sequence := 1

	addGap := func(severity SecureCellGovernmentAgentWorkflowGapSeverity, code, category, detail, recommendation string) SecureCellGovernmentAgentWorkflowGap {
		gap := SecureCellGovernmentAgentWorkflowGap{
			Severity:       severity,
			Code:           code,
			Category:       category,
			Detail:         detail,
			Recommendation: recommendation,
		}
		gaps = append(gaps, gap)
		return gap
	}
	addStep := func(step SecureCellGovernmentAgentWorkflowStep) string {
		step.Sequence = sequence
		sequence++
		step.StepID = secureCellGovernmentAgentStepID(result.CellID, step.Source, step.Kind, step.Sequence, step.SessionID, step.ThreadID, step.DecisionID, step.Action)
		step.DataClasses = uniqueTrimmedStrings(step.DataClasses)
		step.AllowedTools = uniqueTrimmedStrings(step.AllowedTools)
		step.EvidenceArtifacts = uniqueTrimmedStrings(step.EvidenceArtifacts)
		step.EscalationTargets = uniqueTrimmedStrings(step.EscalationTargets)
		steps = append(steps, step)
		return step.StepID
	}
	addHandoff := func(from, to, reason string, evidence ...string) {
		if strings.TrimSpace(from) == "" || strings.TrimSpace(to) == "" {
			return
		}
		handoffs = append(handoffs, SecureCellGovernmentAgentWorkflowHandoff{
			FromStepID:       from,
			ToStepID:         to,
			Reason:           strings.TrimSpace(reason),
			RequiredEvidence: uniqueTrimmedStrings(evidence),
		})
	}

	contextStep := addStep(SecureCellGovernmentAgentWorkflowStep{
		Kind:              SecureCellGovernmentAgentWorkflowStepContext,
		Name:              "Service execution contract",
		Description:       firstNonEmpty(result.Purpose, "Government-service secure-cell execution context"),
		Source:            "secure_cell",
		Action:            "secure_cells.create",
		OwnerRole:         "service_owner",
		DataClasses:       result.Policy.DataClasses,
		AllowedTools:      result.Policy.AllowedTools,
		EvidenceArtifacts: secureCellGovernmentAgentEvidenceArtifacts(evidenceState, "policy_receipt_chain", "control_ledger", "portable_package"),
		Automatable:       false,
		Status:            string(result.Status),
	})

	operatorDeclaredStepIDs := make([]string, 0)
	for _, declared := range secureCellGovernmentAgentDeclaredWorkflowSteps(metadata) {
		stepID := addStep(SecureCellGovernmentAgentWorkflowStep{
			Kind:              SecureCellGovernmentAgentWorkflowStepOperatorDeclared,
			Name:              declared,
			Description:       "Operator-declared end-to-end workflow step.",
			Source:            "metadata.workflow_steps",
			DataClasses:       result.Policy.DataClasses,
			AllowedTools:      result.Policy.AllowedTools,
			EvidenceArtifacts: secureCellGovernmentAgentEvidenceArtifacts(evidenceState, "policy_receipt_chain"),
			Automatable:       true,
			Status:            "declared",
		})
		addHandoff(contextStep, stepID, "operator-declared workflow sequence", "policy_receipt_chain")
		if len(operatorDeclaredStepIDs) > 0 {
			addHandoff(operatorDeclaredStepIDs[len(operatorDeclaredStepIDs)-1], stepID, "declared workflow order", "policy_receipt_chain")
		}
		operatorDeclaredStepIDs = append(operatorDeclaredStepIDs, stepID)
	}
	if len(operatorDeclaredStepIDs) == 0 {
		addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_STEPS_NOT_DECLARED", "workflow", "No explicit workflow_steps metadata is present, so the blueprint is inferred from runtime artifacts.", "Declare the end-to-end workflow_steps metadata in service order before autonomous rollout.")
	}

	integrationGaps := make([]SecureCellGovernmentAgentWorkflowGap, 0)
	if len(result.Policy.DataClasses) == 0 {
		integrationGaps = append(integrationGaps, addGap(SecureCellGovernmentAgentWorkflowGapCritical, "GOVAGENT_BLUEPRINT_DATA_CLASSES_MISSING", "integration", "No data classes are attached to the workflow.", "Map each service step to the data classes an agent may read or write."))
	}
	if len(result.Policy.AllowedTools) == 0 {
		integrationGaps = append(integrationGaps, addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_TOOLS_MISSING", "authority", "No allowed tools are attached to the workflow.", "Declare each tool or integration adapter the agent may invoke."))
	}
	if len(identityProviders) == 0 {
		integrationGaps = append(integrationGaps, addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_IDENTITY_PROVIDER_MISSING", "integration", "No digital identity provider is declared.", "Attach identity_provider metadata such as UAE Pass or the applicable national eID."))
	}
	integrationStep := addStep(SecureCellGovernmentAgentWorkflowStep{
		Kind:              SecureCellGovernmentAgentWorkflowStepIntegration,
		Name:              "Identity, records, and system-of-record binding",
		Description:       "Declares the authoritative identity, record, data-sharing, and system integration boundaries the agent may use.",
		Source:            "policy+metadata",
		Action:            "integration.bind",
		OwnerRole:         "platform_integration_owner",
		DataClasses:       result.Policy.DataClasses,
		AllowedTools:      result.Policy.AllowedTools,
		EvidenceArtifacts: secureCellGovernmentAgentEvidenceArtifacts(evidenceState, "control_ledger", "portable_package"),
		Automatable:       false,
		Status:            "mapped",
		Gaps:              integrationGaps,
	})
	addHandoff(contextStep, integrationStep, "bind service context to authoritative records", "control_ledger", "portable_package")

	for _, action := range result.Policy.AllowedActions {
		addHandoff(integrationStep, addStep(SecureCellGovernmentAgentWorkflowStep{
			Kind:              SecureCellGovernmentAgentWorkflowStepAgentAction,
			Name:              "Agent action: " + action,
			Description:       "Policy-scoped action available to the government-service agent.",
			Source:            "policy.allowed_actions",
			Action:            action,
			OwnerRole:         "workflow_owner",
			DataClasses:       result.Policy.DataClasses,
			AllowedTools:      result.Policy.AllowedTools,
			EvidenceArtifacts: secureCellGovernmentAgentEvidenceArtifacts(evidenceState, "policy_receipt_chain", "execution_seal"),
			Automatable:       true,
			Status:            "allowed",
		}), "policy-scoped agent action", "policy_receipt_chain", "execution_seal")
	}

	sessionStepByID := map[string]string{}
	for _, session := range result.Sessions {
		stepID := addStep(SecureCellGovernmentAgentWorkflowStep{
			Kind:              SecureCellGovernmentAgentWorkflowStepSession,
			Name:              session.Name,
			Description:       session.Purpose,
			Source:            "secure_cell_session",
			SessionID:         session.ID,
			Action:            "secure_cells.session.start",
			OwnerDID:          session.StartedBy,
			DataClasses:       session.DataClasses,
			AllowedTools:      result.Policy.AllowedTools,
			EvidenceArtifacts: secureCellGovernmentAgentEvidenceArtifacts(evidenceState, "policy_receipt_chain", "trace_link"),
			Automatable:       true,
			Status:            string(session.Status),
		})
		sessionStepByID[session.ID] = stepID
		addHandoff(contextStep, stepID, "session scopes workflow execution", "policy_receipt_chain")
	}

	threadStepByID := map[string]string{}
	for _, thread := range result.Threads {
		stepID := addStep(SecureCellGovernmentAgentWorkflowStep{
			Kind:              SecureCellGovernmentAgentWorkflowStepThread,
			Name:              thread.Name,
			Description:       thread.Purpose,
			Source:            "secure_cell_thread",
			SessionID:         thread.SessionID,
			ThreadID:          thread.ID,
			Action:            "secure_cells.session.thread.start",
			OwnerDID:          thread.StartedBy,
			DataClasses:       thread.DataClasses,
			AllowedTools:      result.Policy.AllowedTools,
			EvidenceArtifacts: secureCellGovernmentAgentEvidenceArtifacts(evidenceState, "policy_receipt_chain", "trace_link"),
			Automatable:       true,
			Status:            string(thread.Status),
		})
		threadStepByID[thread.ID] = stepID
		addHandoff(firstNonEmpty(sessionStepByID[thread.SessionID], contextStep), stepID, "thread narrows collaboration scope", "policy_receipt_chain")
	}

	for _, decision := range result.Decisions {
		decisionGaps := make([]SecureCellGovernmentAgentWorkflowGap, 0)
		if decision.ApprovalThreshold <= 0 && len(decision.RequiredApproverRoles) == 0 && len(decision.EligibleApproverDIDs) == 0 {
			decisionGaps = append(decisionGaps, addGap(SecureCellGovernmentAgentWorkflowGapCritical, "GOVAGENT_BLUEPRINT_DECISION_AUTHORITY_MISSING", "authority", "A governed decision does not define approver roles, approver DIDs, or a threshold.", "Attach approval_threshold, required_approver_roles, or eligible_approver_dids to each non-delegable service decision."))
		}
		if strings.TrimSpace(decision.SLATemplate) == "" && decision.EscalationDueAt == nil && decision.ResolutionDueAt == nil {
			decisionGaps = append(decisionGaps, addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_DECISION_TIMER_MISSING", "sla", "A governed decision does not carry a deadline or SLA template.", "Attach a decision SLA template, escalation_due_at, or resolution_due_at."))
		}
		if len(decision.EscalationLadder) == 0 && strings.TrimSpace(decision.AutoEscalateToDID) == "" {
			decisionGaps = append(decisionGaps, addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_DECISION_ESCALATION_MISSING", "sla", "A governed decision has no escalation ladder.", "Add deterministic escalation tiers so overdue decisions do not rely on informal follow-up."))
		}
		stepID := addStep(SecureCellGovernmentAgentWorkflowStep{
			Kind:                  SecureCellGovernmentAgentWorkflowStepDecisionGate,
			Name:                  decision.Title,
			Description:           decision.Summary,
			Source:                "secure_cell_decision",
			SessionID:             decision.SessionID,
			ThreadID:              decision.ThreadID,
			DecisionID:            decision.ID,
			Action:                "secure_cells.session.thread.decision.create",
			OwnerDID:              decision.ProposedBy,
			OwnerRole:             firstNonEmpty(strings.Join(decision.RequiredApproverRoles, ","), "decision_owner"),
			DataClasses:           uniqueTrimmedStrings([]string{decision.Classification}),
			AllowedTools:          result.Policy.AllowedTools,
			EvidenceArtifacts:     secureCellGovernmentAgentEvidenceArtifacts(evidenceState, "policy_receipt_chain", "decision_receipt", "approval_vote_receipts", "trace_link"),
			RequiresHumanApproval: decision.ApprovalThreshold > 0 || len(decision.RequiredApproverRoles) > 0 || len(decision.EligibleApproverDIDs) > 0,
			Automatable:           false,
			SLATemplate:           decision.SLATemplate,
			DueAt:                 secureCellGovernmentAgentDecisionDueAt(decision),
			EscalationTargets:     secureCellGovernmentAgentDecisionEscalationTargets(decision),
			Status:                string(decision.Status),
			Gaps:                  decisionGaps,
		})
		addHandoff(firstNonEmpty(threadStepByID[decision.ThreadID], sessionStepByID[decision.SessionID], contextStep), stepID, "human-governed decision gate", "decision_receipt", "approval_vote_receipts")
		for _, tier := range decision.EscalationLadder {
			escalationID := addStep(SecureCellGovernmentAgentWorkflowStep{
				Kind:                  SecureCellGovernmentAgentWorkflowStepEscalation,
				Name:                  firstNonEmpty(tier.TierID, "decision escalation"),
				Description:           tier.Reason,
				Source:                "decision_escalation_ladder",
				SessionID:             decision.SessionID,
				ThreadID:              decision.ThreadID,
				DecisionID:            decision.ID,
				Action:                "secure_cells.session.thread.decision.escalate",
				OwnerDID:              tier.TargetDID,
				DataClasses:           uniqueTrimmedStrings([]string{decision.Classification}),
				EvidenceArtifacts:     secureCellGovernmentAgentEvidenceArtifacts(evidenceState, "policy_receipt_chain", "trace_link"),
				RequiresHumanApproval: true,
				Automatable:           strings.TrimSpace(tier.TargetDID) != "",
				DueAt:                 cloneTimePtr(tier.DueAt),
				EscalationTargets:     []string{tier.TargetDID},
				Status:                "pending_if_overdue",
			})
			addHandoff(stepID, escalationID, "timed escalation ladder", "policy_receipt_chain", "trace_link")
		}
	}

	evidenceGaps := make([]SecureCellGovernmentAgentWorkflowGap, 0)
	if evidenceState.PolicyReceiptChainHash == "" || evidenceState.ControlLedgerHash == "" || evidenceState.PortablePackageHash == "" {
		evidenceGaps = append(evidenceGaps, addGap(SecureCellGovernmentAgentWorkflowGapCritical, "GOVAGENT_BLUEPRINT_EVIDENCE_PACKAGE_INCOMPLETE", "evidence", "The workflow does not yet have a complete receipt-chain, ledger, and portable package.", "Regenerate the secure-cell artifact package before agent execution."))
	}
	evidenceStep := addStep(SecureCellGovernmentAgentWorkflowStep{
		Kind:              SecureCellGovernmentAgentWorkflowStepEvidence,
		Name:              "Evidence package and audit anchor",
		Description:       "Portable artifact bundle that proves policy receipts, sealed transitions, and audit anchoring.",
		Source:            "evidence_fabric",
		Action:            "secure_cells.artifacts.package",
		OwnerRole:         "trust_kernel_operator",
		EvidenceArtifacts: secureCellGovernmentAgentEvidenceArtifacts(evidenceState, "policy_receipt_chain", "control_ledger", "portable_package", "execution_seal"),
		Automatable:       true,
		Status:            "packaged",
		Gaps:              evidenceGaps,
	})
	if len(steps) > 1 {
		addHandoff(steps[len(steps)-2].StepID, evidenceStep, "finalize evidence package", "control_ledger", "portable_package")
	}

	exceptionGaps := make([]SecureCellGovernmentAgentWorkflowGap, 0)
	if !metadataTruth(metadata, "human_override", "human_in_the_loop", "emergency_stop", "operator_override") {
		exceptionGaps = append(exceptionGaps, addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_HUMAN_OVERRIDE_MISSING", "oversight", "No human override or emergency stop metadata is declared.", "Declare human_override, human_in_the_loop, emergency_stop, or operator_override metadata."))
	}
	addHandoff(evidenceStep, addStep(SecureCellGovernmentAgentWorkflowStep{
		Kind:                  SecureCellGovernmentAgentWorkflowStepExceptionControl,
		Name:                  "Human override and exception control",
		Description:           "Non-delegable operator control for exceptions, pauses, quarantines, and emergency stops.",
		Source:                "metadata+transitions",
		Action:                "secure_cells.exception_control",
		OwnerRole:             "risk_and_policy_owner",
		EvidenceArtifacts:     secureCellGovernmentAgentEvidenceArtifacts(evidenceState, "policy_receipt_chain", "trace_link"),
		RequiresHumanApproval: true,
		Automatable:           false,
		Status:                "declared",
		Gaps:                  exceptionGaps,
	}), "operator retains non-delegable override", "policy_receipt_chain", "trace_link")

	if strings.TrimSpace(serviceCode) == "" {
		addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_SERVICE_CODE_MISSING", "workflow", "No stable government service catalog code is attached.", "Add government_service_code or service_catalog_id metadata.")
	}
	if configuredSLATemplateCount == 0 || signals.TimedDecisionCount == 0 {
		addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_SLA_COVERAGE_MISSING", "sla", "No configured SLA template or timed decision is visible in this cell.", "Attach per-tier decision timers and escalation ladders before autonomous operation.")
	}
	if signals.DecisionCount == 0 {
		addGap(SecureCellGovernmentAgentWorkflowGapCritical, "GOVAGENT_BLUEPRINT_DECISION_GATES_MISSING", "workflow", "No governed decision gates are modeled.", "Model every approval, denial, exception, and handoff as a governed decision.")
	}
	if signals.ApprovalGateCount == 0 {
		addGap(SecureCellGovernmentAgentWorkflowGapCritical, "GOVAGENT_BLUEPRINT_APPROVAL_GATES_MISSING", "authority", "No human approval boundary is modeled.", "Attach approval thresholds, required approver roles, or eligible approver DIDs.")
	}
	if strings.EqualFold(strings.TrimSpace(run.request.Jurisdiction), "UAE") {
		if !metadataListContainsIdentityProvider(identityProviders, "uae_pass") {
			addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_UAE_PASS_MISSING", "integration", "UAE Pass is not declared as an identity boundary.", "Set identity_provider metadata to UAE Pass or attach the equivalent eID adapter.")
		}
		if !metadataListContainsLanguage(languages, "ar") || !metadataListContainsLanguage(languages, "en") {
			addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_BILINGUAL_SURFACE_MISSING", "localization", "Arabic and English service surfaces are not both declared.", "Set supported languages to Arabic and English for the workflow pack.")
		}
		if !metadataTruth(metadata, "digital_records_policy", "government_services_digital_records_policy") {
			addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_DIGITAL_RECORDS_POLICY_MISSING", "integration", "Official digital-records policy is not attached.", "Attach the official digital-records policy reference for the service workflow.")
		}
		if !metadataTruth(metadata, "data_sharing_policy", "government_services_data_sharing_policy") {
			addGap(SecureCellGovernmentAgentWorkflowGapWarning, "GOVAGENT_BLUEPRINT_DATA_SHARING_POLICY_MISSING", "integration", "Collect-once/data-sharing policy is not attached.", "Attach data-sharing constraints for cross-entity reuse.")
		}
	}

	coverage := secureCellGovernmentAgentBlueprintCoverageScore(signals, evidenceState, metadata, serviceCode, identityProviders, languages, result, run.request.Jurisdiction, len(operatorDeclaredStepIDs), configuredSLATemplateCount)
	critical, warning := secureCellGovernmentAgentWorkflowGapCounts(gaps)
	level := secureCellGovernmentAgentBlueprintReadinessLevel(coverage, critical, warning)
	sort.SliceStable(gaps, func(i, j int) bool {
		if gaps[i].Severity == gaps[j].Severity {
			return gaps[i].Code < gaps[j].Code
		}
		return secureCellGovernmentAgentGapSeverityRank(gaps[i].Severity) < secureCellGovernmentAgentGapSeverityRank(gaps[j].Severity)
	})

	blueprintCore := struct {
		CellID        string                                     `json:"cell_id"`
		ServiceCode   string                                     `json:"service_code,omitempty"`
		ServiceTier   string                                     `json:"service_tier,omitempty"`
		CoverageScore int                                        `json:"coverage_score"`
		Steps         []SecureCellGovernmentAgentWorkflowStep    `json:"steps"`
		Handoffs      []SecureCellGovernmentAgentWorkflowHandoff `json:"handoffs,omitempty"`
		Gaps          []SecureCellGovernmentAgentWorkflowGap     `json:"gaps,omitempty"`
		Evidence      SecureCellGovernmentAgentEvidenceState     `json:"evidence"`
	}{
		CellID:        result.CellID,
		ServiceCode:   serviceCode,
		ServiceTier:   serviceTier,
		CoverageScore: coverage,
		Steps:         steps,
		Handoffs:      handoffs,
		Gaps:          gaps,
		Evidence:      evidenceState,
	}
	digest := EvidenceHash(blueprintCore)
	blueprint := SecureCellGovernmentAgentWorkflowBlueprint{
		BlueprintID:           "government-agent-blueprint:" + result.CellID + ":" + digest[:12],
		CellID:                result.CellID,
		Name:                  result.Name,
		Purpose:               result.Purpose,
		Resource:              run.request.Resource,
		Jurisdiction:          run.request.Jurisdiction,
		ServiceCode:           serviceCode,
		ServiceTier:           serviceTier,
		CoverageScore:         coverage,
		ReadinessLevel:        level,
		StepCount:             len(steps),
		OperatorDeclaredSteps: len(operatorDeclaredStepIDs),
		CriticalGapCount:      critical,
		WarningGapCount:       warning,
		Steps:                 steps,
		Handoffs:              handoffs,
		Gaps:                  gaps,
		Evidence:              evidenceState,
		WorkflowDigest:        digest,
		GeneratedAt:           now,
		UpdatedAt:             result.UpdatedAt.UTC(),
	}
	for _, step := range steps {
		if len(step.EvidenceArtifacts) > 0 && len(step.Gaps) == 0 {
			blueprint.EvidenceBoundSteps++
		}
		if step.RequiresHumanApproval {
			blueprint.HumanApprovalGateCount++
		}
		if strings.TrimSpace(step.SLATemplate) != "" || step.DueAt != nil {
			blueprint.SLAProtectedStepCount++
		}
		if step.Kind == SecureCellGovernmentAgentWorkflowStepEscalation {
			blueprint.EscalationStepCount++
		}
		if step.Automatable {
			blueprint.AutomatableStepCount++
		}
	}
	return blueprint
}

func secureCellGovernmentAgentDeclaredWorkflowSteps(metadata map[string]string) []string {
	raw := firstNonEmpty(
		metadataValue(metadata, "workflow_steps"),
		metadataValue(metadata, "service_workflow_steps"),
		metadataValue(metadata, "agent_workflow_steps"),
	)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '>' || r == '|' || r == ';' || r == '\n' || r == '\t' || r == ','
	})
	steps := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := strings.TrimSpace(part)
		if normalized != "" {
			steps = append(steps, normalized)
		}
	}
	return uniqueTrimmedStrings(steps)
}

func secureCellGovernmentAgentEvidenceArtifacts(state SecureCellGovernmentAgentEvidenceState, requested ...string) []string {
	artifacts := make([]string, 0, len(requested))
	for _, item := range requested {
		switch item {
		case "policy_receipt_chain":
			if state.PolicyReceiptChainHash != "" {
				artifacts = append(artifacts, item)
			}
		case "control_ledger":
			if state.ControlLedgerHash != "" {
				artifacts = append(artifacts, item)
			}
		case "portable_package":
			if state.PortablePackageHash != "" && state.PortablePackageSigned && state.PortablePackageAnchored {
				artifacts = append(artifacts, item)
			}
		case "execution_seal":
			if state.ExecutionSealID != "" || state.SealedTransitionCount > 0 {
				artifacts = append(artifacts, item)
			}
		case "trace_link":
			if state.TraceLinkedTransitionCount > 0 {
				artifacts = append(artifacts, item)
			}
		default:
			artifacts = append(artifacts, item)
		}
	}
	return uniqueTrimmedStrings(artifacts)
}

func secureCellGovernmentAgentDecisionDueAt(decision SecureCellThreadDecision) *time.Time {
	if decision.ResolutionDueAt != nil {
		return cloneTimePtr(decision.ResolutionDueAt)
	}
	if decision.EscalationDueAt != nil {
		return cloneTimePtr(decision.EscalationDueAt)
	}
	return nil
}

func secureCellGovernmentAgentDecisionEscalationTargets(decision SecureCellThreadDecision) []string {
	targets := make([]string, 0, len(decision.EscalationLadder)+1)
	if strings.TrimSpace(decision.AutoEscalateToDID) != "" {
		targets = append(targets, decision.AutoEscalateToDID)
	}
	for _, tier := range decision.EscalationLadder {
		if strings.TrimSpace(tier.TargetDID) != "" {
			targets = append(targets, tier.TargetDID)
		}
	}
	return uniqueTrimmedStrings(targets)
}

func secureCellGovernmentAgentStepID(cellID, source string, kind SecureCellGovernmentAgentWorkflowStepKind, sequence int, refs ...string) string {
	parts := []string{cellID, source, string(kind), fmt.Sprintf("%03d", sequence)}
	parts = append(parts, refs...)
	digest := EvidenceHash(uniqueTrimmedStrings(parts))
	return "govagent-step:" + digest[:16]
}

func secureCellGovernmentAgentBlueprintCoverageScore(
	signals SecureCellGovernmentAgentWorkflowSignals,
	evidence SecureCellGovernmentAgentEvidenceState,
	metadata map[string]string,
	serviceCode string,
	identityProviders []string,
	languages []string,
	result *SecureCellResult,
	jurisdiction string,
	operatorDeclaredSteps int,
	configuredSLATemplateCount int,
) int {
	total := 0
	passed := 0
	check := func(ok bool, weight int) {
		total += weight
		if ok {
			passed += weight
		}
	}
	check(strings.TrimSpace(serviceCode) != "", 6)
	check(operatorDeclaredSteps > 0, 8)
	check(strings.TrimSpace(result.Purpose) != "" && len(result.Policy.AllowedActions) > 0, 8)
	check(len(result.Policy.DataClasses) > 0, 8)
	check(len(result.Policy.AllowedTools) > 0, 6)
	check(len(identityProviders) > 0, 6)
	check(signals.SessionCount > 0, 6)
	check(signals.ThreadCount > 0, 6)
	check(signals.GovernedDecisionCount > 0, 10)
	check(signals.ApprovalGateCount > 0, 8)
	check(configuredSLATemplateCount > 0 && signals.TimedDecisionCount > 0, 8)
	check(signals.EscalationLadderCount > 0, 6)
	check(evidence.PolicyReceiptChainHash != "" && evidence.ControlLedgerHash != "" && evidence.PortablePackageHash != "", 10)
	check(evidence.PortablePackageSigned && evidence.PortablePackageAnchored, 6)
	if strings.EqualFold(strings.TrimSpace(string(result.Status)), string(SecureCellStatusActive)) {
		check(true, 2)
	} else {
		check(false, 2)
	}
	if strings.EqualFold(strings.TrimSpace(jurisdiction), "uae") || strings.EqualFold(strings.TrimSpace(metadataValue(metadata, "jurisdiction")), "uae") || strings.EqualFold(strings.TrimSpace(metadataValue(metadata, "market")), "uae") {
		check(metadataListContainsLanguage(languages, "ar") && metadataListContainsLanguage(languages, "en"), 4)
		check(metadataListContainsIdentityProvider(identityProviders, "uae_pass"), 4)
	} else {
		check(len(languages) > 0 || len(identityProviders) > 0, 4)
		check(metadataTruth(metadata, "digital_records_policy", "data_sharing_policy", "government_services_digital_records_policy", "government_services_data_sharing_policy"), 4)
	}
	if total == 0 {
		return 0
	}
	return clampSecureCellGovernmentAgentScore(passed * 100 / total)
}

func secureCellGovernmentAgentWorkflowGapCounts(gaps []SecureCellGovernmentAgentWorkflowGap) (critical int, warning int) {
	for _, gap := range gaps {
		switch gap.Severity {
		case SecureCellGovernmentAgentWorkflowGapCritical:
			critical++
		case SecureCellGovernmentAgentWorkflowGapWarning:
			warning++
		}
	}
	return critical, warning
}

func secureCellGovernmentAgentBlueprintReadinessLevel(score int, critical int, warning int) SecureCellGovernmentAgentReadinessLevel {
	switch {
	case critical > 0 || score < 60:
		return SecureCellGovernmentAgentReadinessBlocked
	case score >= 90 && warning == 0:
		return SecureCellGovernmentAgentReadinessAutonomyReady
	case score >= 75:
		return SecureCellGovernmentAgentReadinessSupervisedReady
	default:
		return SecureCellGovernmentAgentReadinessFoundationReady
	}
}

func secureCellGovernmentAgentGapSeverityRank(severity SecureCellGovernmentAgentWorkflowGapSeverity) int {
	switch severity {
	case SecureCellGovernmentAgentWorkflowGapCritical:
		return 0
	case SecureCellGovernmentAgentWorkflowGapWarning:
		return 1
	default:
		return 2
	}
}
