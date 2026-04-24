package securecells

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestService_GovernmentAgentReadinessScoresUAEWorkflowCell(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)
	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federal Permit Renewal Agent Cell",
		Purpose:       "make a UAE federal permit renewal workflow executable by a supervised government AI agent",
		Resource:      "uae:federal-services:permit-renewal",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "service_owner"},
			{Identity: participantB, Role: "risk_reviewer"},
		},
		Policy: SecureCellPolicy{
			AllowedActions:             []string{"records.read", "eligibility.evaluate", "decision.recommend", "notice.send"},
			AllowedTools:               []string{"secure_cells", "uae_pass", "service_registry"},
			DataClasses:                []string{"identity", "permit_record", "payment_status"},
			ComputeZones:               []string{"uae-enclave"},
			RetentionPolicy:            "UAE federal services records retention",
			RequireConfidentialCompute: boolPtr(true),
		},
		Metadata: map[string]string{
			"government_service_code": "MOHRE-PERMIT-RENEWAL",
			"service_tier":            "tier_1",
			"identity_provider":       "UAE Pass",
			"languages":               "ar,en",
			"digital_records_policy":  "official",
			"data_sharing_policy":     "collect_once",
			"system_of_record":        "federal-permit-registry",
			"human_override":          "enabled",
			"workflow_steps":          "identity intake > eligibility evaluation > governed approval > bilingual notice",
			"cell_id":                 "gov-agent-readiness-uae",
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Permit renewal execution session",
		Purpose:         "run the explicit service workflow under operator supervision",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		DataClasses:     []string{"identity", "permit_record", "payment_status"},
		Reason:          "model the service end to end before agent execution",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	sessionID := started.Sessions[0].ID

	threaded, err := service.StartThread(ctx, created.CellID, SecureCellSessionThreadStartRequest{
		ActorDID:        owner.AgentID(),
		SessionID:       sessionID,
		Name:            "Eligibility and approval path",
		Purpose:         "convert tacit eligibility handoffs into governed steps",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		DataClasses:     []string{"identity", "permit_record", "payment_status"},
		Reason:          "prepare agent-legible workflow thread",
	})
	if err != nil {
		t.Fatalf("StartThread failed: %v", err)
	}
	threadID := threaded.Threads[0].ID
	escalationDueAt := time.Now().UTC().Add(2 * time.Hour)
	resolutionDueAt := time.Now().UTC().Add(8 * time.Hour)
	if _, err := service.CreateThreadDecision(ctx, created.CellID, SecureCellThreadDecisionRequest{
		ActorDID:              owner.AgentID(),
		SessionID:             sessionID,
		ThreadID:              threadID,
		Title:                 "Approve agent-recommended permit renewal",
		Summary:               "The agent may recommend the renewal, but a service owner and risk reviewer must approve execution.",
		Classification:        "permit_record",
		GovernanceTemplate:    "standard_review",
		ApprovalThreshold:     2,
		EligibleApproverDIDs:  []string{participantA.AgentID(), participantB.AgentID()},
		RequiredApproverRoles: []string{"service_owner", "risk_reviewer"},
		EscalationDueAt:       &escalationDueAt,
		ResolutionDueAt:       &resolutionDueAt,
		EscalationLadder: []SecureCellDecisionEscalationTier{
			{
				TierID:    "tier-1-director",
				TargetDID: participantB.AgentID(),
				Mode:      SecureCellThreadDecisionDelegationModeEscalate,
				DueAt:     &resolutionDueAt,
				Reason:    "director review for overdue government-service decision",
			},
		},
		Reason: "bind decision authority before agent execution",
		Metadata: map[string]string{
			"non_delegable_human_approval": "true",
			"evidence_requirement":         "identity,eligibility,approval,notice",
		},
	}); err != nil {
		t.Fatalf("CreateThreadDecision failed: %v", err)
	}

	assessment, err := service.GetGovernmentAgentReadinessAssessment(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentReadinessAssessment failed: %v", err)
	}
	if assessment.Scorecard.Overall < 75 {
		t.Fatalf("expected supervised readiness score, got %+v", assessment.Scorecard)
	}
	if assessment.ReadinessLevel != SecureCellGovernmentAgentReadinessSupervisedReady && assessment.ReadinessLevel != SecureCellGovernmentAgentReadinessAutonomyReady {
		t.Fatalf("expected supervised/autonomy readiness, got %+v", assessment)
	}
	if !assessment.ReadyForSupervisedRun {
		t.Fatalf("expected supervised run readiness, got %+v", assessment)
	}
	if assessment.ServiceCode != "MOHRE-PERMIT-RENEWAL" {
		t.Fatalf("expected service code to be surfaced, got %q", assessment.ServiceCode)
	}
	if assessment.Signals.ApprovalGateCount != 1 || assessment.Signals.TimedDecisionCount != 1 || assessment.Signals.EscalationLadderCount != 1 {
		t.Fatalf("expected governed timed decision signals, got %+v", assessment.Signals)
	}
	if !assessment.Evidence.PortablePackageSigned || !assessment.Evidence.PortablePackageAnchored || assessment.Evidence.PolicyReceiptChainHash == "" {
		t.Fatalf("expected signed anchored evidence state, got %+v", assessment.Evidence)
	}
	if assessment.WorkflowBlueprintID == "" || assessment.BlueprintCoverageScore < 75 || assessment.BlueprintStepCount == 0 {
		t.Fatalf("expected readiness to reference an executable workflow blueprint, got %+v", assessment)
	}
	if hasGovernmentAgentReadinessFinding(assessment.Findings, "GOVAGENT_NO_GOVERNED_DECISIONS") {
		t.Fatalf("did not expect governed-decision blocker, got %+v", assessment.Findings)
	}

	blueprint, err := service.GetGovernmentAgentWorkflowBlueprint(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentWorkflowBlueprint failed: %v", err)
	}
	if blueprint.OperatorDeclaredSteps != 4 {
		t.Fatalf("expected four operator-declared workflow steps, got %+v", blueprint)
	}
	if blueprint.CoverageScore < 75 || blueprint.ReadinessLevel == SecureCellGovernmentAgentReadinessBlocked {
		t.Fatalf("expected executable blueprint coverage, got %+v", blueprint)
	}
	if blueprint.CriticalGapCount != 0 {
		t.Fatalf("expected no critical blueprint gaps, got %+v", blueprint.Gaps)
	}
	if blueprint.HumanApprovalGateCount == 0 || blueprint.EscalationStepCount == 0 || blueprint.EvidenceBoundSteps == 0 {
		t.Fatalf("expected approval, escalation, and evidence-bound blueprint steps, got %+v", blueprint)
	}
	if !hasGovernmentAgentBlueprintStepKind(blueprint.Steps, SecureCellGovernmentAgentWorkflowStepDecisionGate) {
		t.Fatalf("expected governed decision gate step, got %+v", blueprint.Steps)
	}
	if blueprint.WorkflowDigest == "" || !strings.Contains(blueprint.BlueprintID, blueprint.WorkflowDigest[:12]) {
		t.Fatalf("expected digest-bound blueprint ID, got %+v", blueprint)
	}

	program, err := service.GetGovernmentAgentProgramSummary(ctx, SecureCellGovernmentAgentProgramFilter{
		Jurisdiction: "UAE",
		ServiceTier:  "tier_1",
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentProgramSummary failed: %v", err)
	}
	if program.ServiceCount != 1 || program.LegibleServiceCount != 1 || program.EvidenceReadyServiceCount != 1 {
		t.Fatalf("expected one legible evidence-ready service, got %+v", program)
	}
	if program.SupervisedReadyCount+program.AutonomyReadyCount != 1 || program.SupervisedReadyRate != 100 {
		t.Fatalf("expected supervised-ready program rollup, got %+v", program)
	}
	if len(program.Services) != 1 || program.Services[0].RecommendedStage == SecureCellGovernmentAgentProgramStageMapTacitWork {
		t.Fatalf("expected service rollout stage beyond tacit mapping, got %+v", program.Services)
	}
	if program.ProgramDigest == "" || !strings.Contains(program.ProgramID, program.ProgramDigest[:12]) {
		t.Fatalf("expected digest-bound program ID, got %+v", program)
	}
}

func TestService_GovernmentAgentReadinessFindsTacitWorkflowGaps(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, _ := newTestSecureCellService(t)
	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Tacit Service Cell",
		Purpose:       "informal service discussion without explicit agent workflow",
		Resource:      "uae:federal-services:tacit",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
		Metadata: map[string]string{
			"cell_id": "gov-agent-readiness-tacit",
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	assessment, err := service.GetGovernmentAgentReadinessAssessment(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentReadinessAssessment failed: %v", err)
	}
	if assessment.ReadinessLevel != SecureCellGovernmentAgentReadinessBlocked {
		t.Fatalf("expected blocked readiness, got %+v", assessment)
	}
	if !hasGovernmentAgentReadinessFinding(assessment.Findings, "GOVAGENT_NO_GOVERNED_DECISIONS") {
		t.Fatalf("expected governed-decision blocker, got %+v", assessment.Findings)
	}
	if !hasGovernmentAgentReadinessFinding(assessment.Findings, "GOVAGENT_UAE_PASS_MISSING") {
		t.Fatalf("expected UAE Pass warning, got %+v", assessment.Findings)
	}
	if len(assessment.NextActions) == 0 {
		t.Fatalf("expected next actions, got %+v", assessment)
	}
	for _, action := range assessment.NextActions {
		if strings.TrimSpace(action.Action) == "" {
			t.Fatalf("expected actionable recommendation, got %+v", assessment.NextActions)
		}
	}

	blueprint, err := service.GetGovernmentAgentWorkflowBlueprint(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentWorkflowBlueprint failed: %v", err)
	}
	if blueprint.ReadinessLevel != SecureCellGovernmentAgentReadinessBlocked || blueprint.CriticalGapCount == 0 {
		t.Fatalf("expected blocked blueprint with critical gaps, got %+v", blueprint)
	}
	if !hasGovernmentAgentBlueprintGap(blueprint.Gaps, "GOVAGENT_BLUEPRINT_DECISION_GATES_MISSING") {
		t.Fatalf("expected missing decision-gate blueprint gap, got %+v", blueprint.Gaps)
	}
	if !hasGovernmentAgentBlueprintGap(blueprint.Gaps, "GOVAGENT_BLUEPRINT_UAE_PASS_MISSING") {
		t.Fatalf("expected UAE Pass blueprint gap, got %+v", blueprint.Gaps)
	}

	program, err := service.GetGovernmentAgentProgramSummary(ctx, SecureCellGovernmentAgentProgramFilter{
		Jurisdiction: "UAE",
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentProgramSummary failed: %v", err)
	}
	if program.ServiceCount != 1 || program.BlockedCount != 1 || program.LegibleServiceCount != 0 {
		t.Fatalf("expected blocked non-legible program rollup, got %+v", program)
	}
	if len(program.TopBlockers) == 0 || !hasGovernmentAgentProgramBlocker(program.TopBlockers, "GOVAGENT_NO_GOVERNED_DECISIONS") {
		t.Fatalf("expected governed-decision blocker in program rollup, got %+v", program.TopBlockers)
	}
	if len(program.Services) != 1 || program.Services[0].RecommendedStage != SecureCellGovernmentAgentProgramStageEvidenceHardening {
		t.Fatalf("expected evidence-hardening stage for tacit workflow with artifacts, got %+v", program.Services)
	}
}

func hasGovernmentAgentReadinessFinding(findings []SecureCellGovernmentAgentReadinessFinding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func hasGovernmentAgentBlueprintGap(gaps []SecureCellGovernmentAgentWorkflowGap, code string) bool {
	for _, gap := range gaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}

func hasGovernmentAgentBlueprintStepKind(steps []SecureCellGovernmentAgentWorkflowStep, kind SecureCellGovernmentAgentWorkflowStepKind) bool {
	for _, step := range steps {
		if step.Kind == kind {
			return true
		}
	}
	return false
}

func hasGovernmentAgentProgramBlocker(blockers []SecureCellGovernmentAgentProgramBlocker, code string) bool {
	for _, blocker := range blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}
