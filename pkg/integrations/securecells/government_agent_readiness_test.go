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

	carryPack, err := service.GetGovernmentAgentCarryPack(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentCarryPack failed: %v", err)
	}
	if carryPack.CarryMode == SecureCellGovernmentAgentCarryModeBlocked || !carryPack.ReadyForAgentCarry {
		t.Fatalf("expected carry-ready supervised pack, got %+v", carryPack)
	}
	if carryPack.StepCount == 0 || carryPack.HumanApprovalStepCount == 0 || carryPack.AutomatableStepCount == 0 {
		t.Fatalf("expected executable carry-pack steps, got %+v", carryPack)
	}
	if !hasGovernmentAgentCarryPackStepLane(carryPack.Steps, SecureCellGovernmentAgentCarryLaneHumanApproval) {
		t.Fatalf("expected human approval lane in carry pack, got %+v", carryPack.Steps)
	}
	if !hasString(carryPack.RequiredEvidence, "policy_receipt_chain") || !hasString(carryPack.Preconditions, "approval_boundary") {
		t.Fatalf("expected evidence and approval preconditions, got %+v", carryPack)
	}
	if carryPack.CarryPackDigest == "" || !strings.Contains(carryPack.CarryPackID, carryPack.CarryPackDigest[:12]) {
		t.Fatalf("expected digest-bound carry pack, got %+v", carryPack)
	}

	rehearsal, err := service.GetGovernmentAgentRehearsalReport(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentRehearsalReport failed: %v", err)
	}
	if rehearsal.Status == SecureCellGovernmentAgentRehearsalStatusBlocked || !rehearsal.ReadyForAgentCarry {
		t.Fatalf("expected non-blocked rehearsal for carry-ready workflow, got %+v", rehearsal)
	}
	if rehearsal.StepCount == 0 || rehearsal.PassStepCount == 0 || rehearsal.BlockStepCount != 0 {
		t.Fatalf("expected passing rehearsal steps without blocks, got %+v", rehearsal)
	}
	if rehearsal.RehearsalScore <= 0 || rehearsal.RehearsalDigest == "" || !strings.Contains(rehearsal.RehearsalID, rehearsal.RehearsalDigest[:12]) {
		t.Fatalf("expected scored digest-bound rehearsal, got %+v", rehearsal)
	}
	if !hasGovernmentAgentRehearsalStepOutcome(rehearsal.Steps, SecureCellGovernmentAgentRehearsalOutcomePass) {
		t.Fatalf("expected at least one passing rehearsal step, got %+v", rehearsal.Steps)
	}

	witness, err := service.GetGovernmentAgentExecutionWitness(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionWitness failed: %v", err)
	}
	if witness.Status == SecureCellGovernmentAgentExecutionWitnessBlocked {
		t.Fatalf("expected non-blocked execution witness, got %+v", witness)
	}
	if witness.ExecutionWitnessScore <= 0 || witness.WitnessDigest == "" || !strings.Contains(witness.WitnessID, witness.WitnessDigest[:12]) {
		t.Fatalf("expected scored digest-bound execution witness, got %+v", witness)
	}
	if witness.StepCount == 0 || witness.ExpectedReturnReceiptCount == 0 || len(witness.EgressReceipts) == 0 {
		t.Fatalf("expected evidence-return witness steps, got %+v", witness)
	}
	if !hasGovernmentAgentExecutionWitnessStepReceipt(witness.Steps, "human_approval_receipt") {
		t.Fatalf("expected human approval receipt obligation in execution witness, got %+v", witness.Steps)
	}
	if !hasGovernmentAgentExecutionWitnessReleaseGate(witness.Steps, "human_approval_required") {
		t.Fatalf("expected human approval release gate in execution witness, got %+v", witness.Steps)
	}

	receiptLedger, err := service.GetGovernmentAgentExecutionReceiptLedger(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionReceiptLedger failed: %v", err)
	}
	if receiptLedger.Status == SecureCellGovernmentAgentExecutionReceiptLedgerBlocked || receiptLedger.LedgerDigest == "" || !strings.Contains(receiptLedger.LedgerID, receiptLedger.LedgerDigest[:12]) {
		t.Fatalf("expected digest-bound non-blocked receipt ledger, got %+v", receiptLedger)
	}
	if receiptLedger.WitnessID != witness.WitnessID || receiptLedger.ReceiptObligationCount == 0 || len(receiptLedger.Obligations) == 0 {
		t.Fatalf("expected receipt ledger tied to execution witness obligations, got %+v", receiptLedger)
	}
	if !hasGovernmentAgentExecutionReceiptObligation(receiptLedger.Obligations, "human_approval_receipt") || !hasGovernmentAgentExecutionReceiptObligation(receiptLedger.Obligations, "tool_invocation_receipt") {
		t.Fatalf("expected approval and tool receipt obligations, got %+v", receiptLedger.Obligations)
	}
	if !hasGovernmentAgentExecutionReceiptObligationStatus(receiptLedger.Obligations, "human_approval_receipt", SecureCellGovernmentAgentExecutionReceiptObligationReleaseGateDue) {
		t.Fatalf("expected human approval receipt to wait on a release gate, got %+v", receiptLedger.Obligations)
	}

	actionQueue, err := service.GetGovernmentAgentExecutionActionQueue(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionActionQueue failed: %v", err)
	}
	if actionQueue.Status == SecureCellGovernmentAgentExecutionActionQueueBlocked || actionQueue.QueueDigest == "" || !strings.Contains(actionQueue.QueueID, actionQueue.QueueDigest[:12]) {
		t.Fatalf("expected digest-bound non-blocked execution action queue, got %+v", actionQueue)
	}
	if actionQueue.LedgerID != receiptLedger.LedgerID || actionQueue.ActionCount == 0 || len(actionQueue.Actions) == 0 {
		t.Fatalf("expected action queue tied to receipt ledger actions, got %+v", actionQueue)
	}
	if !hasGovernmentAgentExecutionActionKind(actionQueue.Actions, SecureCellGovernmentAgentExecutionActionApproveReleaseGate) || !hasGovernmentAgentExecutionActionKind(actionQueue.Actions, SecureCellGovernmentAgentExecutionActionCollectReceipt) {
		t.Fatalf("expected release-gate and receipt-collection actions, got %+v", actionQueue.Actions)
	}
	if !hasGovernmentAgentExecutionActionReceipt(actionQueue.Actions, "human_approval_receipt") {
		t.Fatalf("expected human approval receipt action, got %+v", actionQueue.Actions)
	}

	handoffBundle, err := service.GetGovernmentAgentExecutionHandoffBundle(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionHandoffBundle failed: %v", err)
	}
	if handoffBundle.Status == SecureCellGovernmentAgentExecutionHandoffBundleBlocked || handoffBundle.BundleDigest == "" || !strings.Contains(handoffBundle.BundleID, handoffBundle.BundleDigest[:12]) {
		t.Fatalf("expected digest-bound non-blocked handoff bundle, got %+v", handoffBundle)
	}
	if handoffBundle.Witness.WitnessID != witness.WitnessID || handoffBundle.ReceiptLedger.LedgerID != receiptLedger.LedgerID || handoffBundle.ActionQueue.QueueID != actionQueue.QueueID {
		t.Fatalf("expected handoff bundle to bind witness, ledger, and queue, got %+v", handoffBundle)
	}
	if len(handoffBundle.OperatorInstructions) == 0 || !hasString(handoffBundle.RequiredReceiptTypes, "human_approval_receipt") {
		t.Fatalf("expected handoff instructions and required receipt types, got %+v", handoffBundle)
	}

	verification, err := service.GetGovernmentAgentExecutionHandoffVerification(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionHandoffVerification failed: %v", err)
	}
	if verification.Status != SecureCellGovernmentAgentExecutionHandoffVerificationVerified || verification.FailCount != 0 {
		t.Fatalf("expected verified handoff verification without failures, got %+v", verification)
	}
	if verification.VerificationDigest == "" || !strings.Contains(verification.VerificationID, verification.VerificationDigest[:12]) {
		t.Fatalf("expected digest-bound handoff verification, got %+v", verification)
	}
	if verification.BundleID != handoffBundle.BundleID || verification.ExpectedBundleDigest != handoffBundle.BundleDigest || verification.ExpectedQueueDigest != actionQueue.QueueDigest {
		t.Fatalf("expected handoff verification to recompute bundle and queue digests, got %+v", verification)
	}
	if !hasGovernmentAgentExecutionHandoffVerificationCheck(verification.Checks, "BUNDLE_DIGEST_BOUND", SecureCellGovernmentAgentExecutionHandoffVerificationPass) {
		t.Fatalf("expected passing bundle digest verification check, got %+v", verification.Checks)
	}

	authorization, err := service.GetGovernmentAgentExecutionLaunchAuthorization(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchAuthorization failed: %v", err)
	}
	if authorization.Status != SecureCellGovernmentAgentExecutionLaunchAuthorizationOperatorReviewRequired || authorization.CanLaunchNow {
		t.Fatalf("expected operator-review launch hold, got %+v", authorization)
	}
	if !authorization.CanLaunchAfterOperatorReview || authorization.RequiredOperatorAcknowledgementCount == 0 {
		t.Fatalf("expected launch after operator acknowledgement, got %+v", authorization)
	}
	if authorization.BlockGateCount != 0 || authorization.HoldGateCount == 0 || authorization.LaunchDigest == "" || !strings.Contains(authorization.AuthorizationID, authorization.LaunchDigest[:12]) {
		t.Fatalf("expected digest-bound launch authorization with review hold, got %+v", authorization)
	}
	if authorization.VerificationID != verification.VerificationID || !hasGovernmentAgentExecutionLaunchGate(authorization.Gates, "OPERATOR_REVIEW_COMPLETE", SecureCellGovernmentAgentExecutionLaunchGateHold) {
		t.Fatalf("expected launch authorization to bind verification and review gate, got %+v", authorization)
	}

	clearance, err := service.GetGovernmentAgentExecutionLaunchClearance(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClearance failed: %v", err)
	}
	if clearance.Status != SecureCellGovernmentAgentExecutionLaunchClearanceHeldForReview || clearance.CanLaunchNow {
		t.Fatalf("expected held launch clearance register, got %+v", clearance)
	}
	if clearance.AcknowledgementItemCount == 0 || clearance.RemediationItemCount != 0 || clearance.RegisterDigest == "" || !strings.Contains(clearance.RegisterID, clearance.RegisterDigest[:12]) {
		t.Fatalf("expected digest-bound launch clearance register with acknowledgement items, got %+v", clearance)
	}
	if clearance.AuthorizationID != authorization.AuthorizationID || !hasGovernmentAgentExecutionLaunchClearanceItem(clearance.Items, "OPERATOR_REVIEW_COMPLETE", SecureCellGovernmentAgentExecutionLaunchClearanceItemAcknowledgementRequired) {
		t.Fatalf("expected launch clearance to bind authorization and review acknowledgement item, got %+v", clearance)
	}

	launchReceiptManifest, err := service.GetGovernmentAgentExecutionLaunchReceiptManifest(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchReceiptManifest failed: %v", err)
	}
	if launchReceiptManifest.Status != SecureCellGovernmentAgentExecutionLaunchReceiptManifestAwaitingAcknowledgements || launchReceiptManifest.PendingAcknowledgementReceiptCount == 0 {
		t.Fatalf("expected launch receipt manifest awaiting acknowledgements, got %+v", launchReceiptManifest)
	}
	if !launchReceiptManifest.CanAcceptReceipts || !launchReceiptManifest.CanLaunchAfterReceipts || launchReceiptManifest.ManifestDigest == "" || !strings.Contains(launchReceiptManifest.ManifestID, launchReceiptManifest.ManifestDigest[:12]) {
		t.Fatalf("expected digest-bound launch receipt manifest accepting receipts, got %+v", launchReceiptManifest)
	}
	if launchReceiptManifest.RegisterID != clearance.RegisterID || !hasGovernmentAgentExecutionLaunchReceiptRequirement(launchReceiptManifest.Requirements, "operator_acknowledgement_receipt", SecureCellGovernmentAgentExecutionLaunchReceiptRequirementPendingAcknowledgement) {
		t.Fatalf("expected launch receipt manifest to bind clearance and acknowledgement receipt, got %+v", launchReceiptManifest)
	}

	launchReceiptValidation, err := service.GetGovernmentAgentExecutionLaunchReceiptValidation(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchReceiptValidation failed: %v", err)
	}
	if launchReceiptValidation.Status != SecureCellGovernmentAgentExecutionLaunchReceiptValidationReady || launchReceiptValidation.FailCount != 0 {
		t.Fatalf("expected launch receipt validation ready without failures, got %+v", launchReceiptValidation)
	}
	if launchReceiptValidation.ValidationDigest == "" || !strings.Contains(launchReceiptValidation.ValidationID, launchReceiptValidation.ValidationDigest[:12]) {
		t.Fatalf("expected digest-bound launch receipt validation, got %+v", launchReceiptValidation)
	}
	if launchReceiptValidation.ManifestID != launchReceiptManifest.ManifestID || !hasGovernmentAgentExecutionLaunchReceiptValidationCheck(launchReceiptValidation.Checks, "REQUIREMENT_DIGEST_BOUND", SecureCellGovernmentAgentExecutionLaunchReceiptValidationPass) {
		t.Fatalf("expected receipt validation to bind manifest and requirement digest checks, got %+v", launchReceiptValidation)
	}

	launchPackage, err := service.GetGovernmentAgentExecutionLaunchPackage(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchPackage failed: %v", err)
	}
	if launchPackage.Status != SecureCellGovernmentAgentExecutionLaunchPackageReviewRequired || launchPackage.ValidationFailCount != 0 || launchPackage.CanLaunchNow {
		t.Fatalf("expected launch package held for operator review without validation failures, got %+v", launchPackage)
	}
	if launchPackage.PackageDigest == "" || !strings.Contains(launchPackage.PackageID, launchPackage.PackageDigest[:12]) {
		t.Fatalf("expected digest-bound launch package, got %+v", launchPackage)
	}
	if launchPackage.ReceiptValidationID != launchReceiptValidation.ValidationID || len(launchPackage.OperatorInstructions) == 0 {
		t.Fatalf("expected launch package to bind receipt validation and operator instructions, got %+v", launchPackage)
	}

	launchCustody, err := service.GetGovernmentAgentExecutionLaunchCustody(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchCustody failed: %v", err)
	}
	if launchCustody.Status != SecureCellGovernmentAgentExecutionLaunchCustodyAwaitingReceipt || launchCustody.CanIssueNow || !launchCustody.CanIssueAfterOperatorReceipts {
		t.Fatalf("expected launch custody to await operator receipts, got %+v", launchCustody)
	}
	if launchCustody.CustodyDigest == "" || !strings.Contains(launchCustody.CustodyID, launchCustody.CustodyDigest[:12]) || launchCustody.PackageID != launchPackage.PackageID {
		t.Fatalf("expected digest-bound launch custody tied to package, got %+v", launchCustody)
	}
	if launchCustody.PendingActionCount == 0 || !hasGovernmentAgentExecutionLaunchCustodyAction(launchCustody.Actions, "collect_operator_acknowledgement", SecureCellGovernmentAgentExecutionLaunchCustodyActionPending) {
		t.Fatalf("expected pending acknowledgement custody action, got %+v", launchCustody.Actions)
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

	carryPack, err := service.GetGovernmentAgentCarryPack(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentCarryPack failed: %v", err)
	}
	if carryPack.CarryMode != SecureCellGovernmentAgentCarryModeBlocked || carryPack.ReadyForAgentCarry {
		t.Fatalf("expected blocked carry pack for tacit workflow, got %+v", carryPack)
	}
	if !hasString(carryPack.TopBlockerCodes, "GOVAGENT_NO_GOVERNED_DECISIONS") || !hasString(carryPack.Preconditions, "missing:governed_decisions") {
		t.Fatalf("expected governed-decision blocker and missing precondition, got %+v", carryPack)
	}

	rehearsal, err := service.GetGovernmentAgentRehearsalReport(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentRehearsalReport failed: %v", err)
	}
	if rehearsal.Status != SecureCellGovernmentAgentRehearsalStatusBlocked || rehearsal.ReadyForAgentCarry {
		t.Fatalf("expected blocked rehearsal for tacit workflow, got %+v", rehearsal)
	}
	if !hasString(rehearsal.MissingPreconditions, "missing:governed_decisions") || !hasString(rehearsal.TopBlockerCodes, "GOVAGENT_NO_GOVERNED_DECISIONS") {
		t.Fatalf("expected governed-decision rehearsal blockers, got %+v", rehearsal)
	}
	if len(rehearsal.OperatorInstructions) == 0 || rehearsal.RehearsalDigest == "" {
		t.Fatalf("expected actionable digest-bound rehearsal, got %+v", rehearsal)
	}

	witness, err := service.GetGovernmentAgentExecutionWitness(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionWitness failed: %v", err)
	}
	if witness.Status != SecureCellGovernmentAgentExecutionWitnessBlocked || witness.ReadyForExecutionHandoff {
		t.Fatalf("expected blocked execution witness for tacit workflow, got %+v", witness)
	}
	if witness.HandoffBlockerCount == 0 || !hasString(witness.MissingPreconditions, "missing:governed_decisions") {
		t.Fatalf("expected blocker-counted witness with missing governed decisions, got %+v", witness)
	}
	if len(witness.OperatorAttestations) == 0 || !hasString(witness.EgressReceipts, "blocker_resolution_receipt") {
		t.Fatalf("expected operator attestations and blocker-resolution receipts, got %+v", witness)
	}

	receiptLedger, err := service.GetGovernmentAgentExecutionReceiptLedger(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionReceiptLedger failed: %v", err)
	}
	if receiptLedger.Status != SecureCellGovernmentAgentExecutionReceiptLedgerBlocked || receiptLedger.BlockedReceiptCount == 0 {
		t.Fatalf("expected blocked receipt ledger for tacit workflow, got %+v", receiptLedger)
	}
	if !hasGovernmentAgentExecutionReceiptObligation(receiptLedger.Obligations, "blocker_resolution_receipt") || !hasString(receiptLedger.MissingPreconditions, "missing:governed_decisions") {
		t.Fatalf("expected blocker-resolution receipt obligation with missing governed decisions, got %+v", receiptLedger)
	}
	if receiptLedger.LedgerDigest == "" || receiptLedger.WitnessID != witness.WitnessID {
		t.Fatalf("expected digest-bound receipt ledger tied to witness, got %+v", receiptLedger)
	}

	actionQueue, err := service.GetGovernmentAgentExecutionActionQueue(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionActionQueue failed: %v", err)
	}
	if actionQueue.Status != SecureCellGovernmentAgentExecutionActionQueueBlocked || actionQueue.BlockedActionCount == 0 {
		t.Fatalf("expected blocked execution action queue for tacit workflow, got %+v", actionQueue)
	}
	if actionQueue.QueueDigest == "" || actionQueue.LedgerID != receiptLedger.LedgerID {
		t.Fatalf("expected digest-bound action queue tied to receipt ledger, got %+v", actionQueue)
	}
	if !hasGovernmentAgentExecutionActionKind(actionQueue.Actions, SecureCellGovernmentAgentExecutionActionResolveBlocker) || !hasGovernmentAgentExecutionActionReceipt(actionQueue.Actions, "blocker_resolution_receipt") {
		t.Fatalf("expected blocker-resolution action, got %+v", actionQueue.Actions)
	}

	handoffBundle, err := service.GetGovernmentAgentExecutionHandoffBundle(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionHandoffBundle failed: %v", err)
	}
	if handoffBundle.Status != SecureCellGovernmentAgentExecutionHandoffBundleBlocked || handoffBundle.CanHandoff {
		t.Fatalf("expected blocked handoff bundle for tacit workflow, got %+v", handoffBundle)
	}
	if handoffBundle.BundleDigest == "" || handoffBundle.ActionQueue.QueueID != actionQueue.QueueID || !hasString(handoffBundle.MissingPreconditions, "missing:governed_decisions") {
		t.Fatalf("expected digest-bound handoff bundle tied to blocked action queue, got %+v", handoffBundle)
	}

	verification, err := service.GetGovernmentAgentExecutionHandoffVerification(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionHandoffVerification failed: %v", err)
	}
	if verification.Status != SecureCellGovernmentAgentExecutionHandoffVerificationWithBlockers || verification.FailCount != 0 || verification.BlockedActionCount == 0 {
		t.Fatalf("expected blocker-marked handoff verification without digest failures, got %+v", verification)
	}
	if verification.BundleID != handoffBundle.BundleID || verification.ExpectedBundleDigest != handoffBundle.BundleDigest {
		t.Fatalf("expected handoff verification to bind blocked bundle digest, got %+v", verification)
	}
	if !hasGovernmentAgentExecutionHandoffVerificationCheck(verification.Checks, "BLOCKER_STATUS_CONSISTENCY", SecureCellGovernmentAgentExecutionHandoffVerificationPass) {
		t.Fatalf("expected passing blocker consistency verification check, got %+v", verification.Checks)
	}

	authorization, err := service.GetGovernmentAgentExecutionLaunchAuthorization(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchAuthorization failed: %v", err)
	}
	if authorization.Status != SecureCellGovernmentAgentExecutionLaunchAuthorizationBlocked || authorization.CanLaunchNow || authorization.CanLaunchAfterOperatorReview {
		t.Fatalf("expected blocked launch authorization for tacit workflow, got %+v", authorization)
	}
	if authorization.BlockGateCount == 0 || authorization.LaunchDigest == "" || authorization.VerificationID != verification.VerificationID {
		t.Fatalf("expected digest-bound launch authorization tied to blocked verification, got %+v", authorization)
	}
	if !hasGovernmentAgentExecutionLaunchGate(authorization.Gates, "BLOCKERS_CLEARED", SecureCellGovernmentAgentExecutionLaunchGateBlock) {
		t.Fatalf("expected blocker launch gate, got %+v", authorization.Gates)
	}

	clearance, err := service.GetGovernmentAgentExecutionLaunchClearance(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClearance failed: %v", err)
	}
	if clearance.Status != SecureCellGovernmentAgentExecutionLaunchClearanceBlocked || clearance.CanLaunchNow || clearance.CanLaunchAfterOperatorReview {
		t.Fatalf("expected blocked launch clearance register, got %+v", clearance)
	}
	if clearance.RemediationItemCount == 0 || clearance.CriticalItemCount == 0 || clearance.RegisterDigest == "" || clearance.AuthorizationID != authorization.AuthorizationID {
		t.Fatalf("expected digest-bound launch clearance register with remediation items, got %+v", clearance)
	}
	if !hasGovernmentAgentExecutionLaunchClearanceItem(clearance.Items, "BLOCKERS_CLEARED", SecureCellGovernmentAgentExecutionLaunchClearanceItemRemediationRequired) {
		t.Fatalf("expected blocker remediation clearance item, got %+v", clearance.Items)
	}

	launchReceiptManifest, err := service.GetGovernmentAgentExecutionLaunchReceiptManifest(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchReceiptManifest failed: %v", err)
	}
	if launchReceiptManifest.Status != SecureCellGovernmentAgentExecutionLaunchReceiptManifestBlocked || launchReceiptManifest.BlockedReceiptCount == 0 || launchReceiptManifest.CanLaunchAfterReceipts {
		t.Fatalf("expected blocked launch receipt manifest for tacit workflow, got %+v", launchReceiptManifest)
	}
	if launchReceiptManifest.ManifestDigest == "" || launchReceiptManifest.RegisterID != clearance.RegisterID {
		t.Fatalf("expected digest-bound launch receipt manifest tied to clearance, got %+v", launchReceiptManifest)
	}
	if !hasGovernmentAgentExecutionLaunchReceiptRequirement(launchReceiptManifest.Requirements, "remediation_receipt", SecureCellGovernmentAgentExecutionLaunchReceiptRequirementBlocked) {
		t.Fatalf("expected remediation receipt requirement, got %+v", launchReceiptManifest.Requirements)
	}

	launchReceiptValidation, err := service.GetGovernmentAgentExecutionLaunchReceiptValidation(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchReceiptValidation failed: %v", err)
	}
	if launchReceiptValidation.Status != SecureCellGovernmentAgentExecutionLaunchReceiptValidationBlocked || launchReceiptValidation.FailCount != 0 || launchReceiptValidation.BlockedReceiptCount == 0 {
		t.Fatalf("expected blocked launch receipt validation without contract failures, got %+v", launchReceiptValidation)
	}
	if launchReceiptValidation.ManifestID != launchReceiptManifest.ManifestID || launchReceiptValidation.ValidationDigest == "" {
		t.Fatalf("expected digest-bound receipt validation tied to manifest, got %+v", launchReceiptValidation)
	}
	if !hasGovernmentAgentExecutionLaunchReceiptValidationCheck(launchReceiptValidation.Checks, "MANIFEST_REQUIREMENTS_PRESENT", SecureCellGovernmentAgentExecutionLaunchReceiptValidationPass) {
		t.Fatalf("expected manifest requirement presence check, got %+v", launchReceiptValidation.Checks)
	}

	launchPackage, err := service.GetGovernmentAgentExecutionLaunchPackage(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchPackage failed: %v", err)
	}
	if launchPackage.Status != SecureCellGovernmentAgentExecutionLaunchPackageBlocked || launchPackage.CanLaunchNow || launchPackage.CanLaunchAfterOperatorReview {
		t.Fatalf("expected blocked launch package for tacit workflow, got %+v", launchPackage)
	}
	if launchPackage.BlockedReceiptCount == 0 || launchPackage.PackageDigest == "" || launchPackage.ReceiptValidationID != launchReceiptValidation.ValidationID {
		t.Fatalf("expected digest-bound blocked launch package tied to receipt validation, got %+v", launchPackage)
	}

	launchCustody, err := service.GetGovernmentAgentExecutionLaunchCustody(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchCustody failed: %v", err)
	}
	if launchCustody.Status != SecureCellGovernmentAgentExecutionLaunchCustodyBlocked || launchCustody.CanIssueNow || launchCustody.CanIssueAfterOperatorReceipts {
		t.Fatalf("expected blocked launch custody for tacit workflow, got %+v", launchCustody)
	}
	if launchCustody.BlockedActionCount == 0 || launchCustody.CustodyDigest == "" || launchCustody.PackageID != launchPackage.PackageID {
		t.Fatalf("expected digest-bound blocked launch custody tied to package, got %+v", launchCustody)
	}
	if !hasGovernmentAgentExecutionLaunchCustodyAction(launchCustody.Actions, "resolve_blocked_receipts", SecureCellGovernmentAgentExecutionLaunchCustodyActionBlocked) {
		t.Fatalf("expected blocked remediation custody action, got %+v", launchCustody.Actions)
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

func hasGovernmentAgentCarryPackStepLane(steps []SecureCellGovernmentAgentCarryPackStep, lane SecureCellGovernmentAgentCarryLane) bool {
	for _, step := range steps {
		if step.Lane == lane {
			return true
		}
	}
	return false
}

func hasGovernmentAgentRehearsalStepOutcome(steps []SecureCellGovernmentAgentRehearsalStep, outcome SecureCellGovernmentAgentRehearsalOutcome) bool {
	for _, step := range steps {
		if step.Outcome == outcome {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionWitnessStepReceipt(steps []SecureCellGovernmentAgentExecutionWitnessStep, receipt string) bool {
	for _, step := range steps {
		if hasString(step.ExpectedReturnReceipts, receipt) {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionWitnessReleaseGate(steps []SecureCellGovernmentAgentExecutionWitnessStep, reason string) bool {
	for _, step := range steps {
		if hasString(step.ReleaseGateReasons, reason) {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionReceiptObligation(obligations []SecureCellGovernmentAgentExecutionReceiptObligation, receiptType string) bool {
	for _, obligation := range obligations {
		if obligation.ReceiptType == receiptType {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionReceiptObligationStatus(
	obligations []SecureCellGovernmentAgentExecutionReceiptObligation,
	receiptType string,
	status SecureCellGovernmentAgentExecutionReceiptObligationStatus,
) bool {
	for _, obligation := range obligations {
		if obligation.ReceiptType == receiptType && obligation.Status == status {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionActionKind(actions []SecureCellGovernmentAgentExecutionAction, kind SecureCellGovernmentAgentExecutionActionKind) bool {
	for _, action := range actions {
		if action.Kind == kind {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionActionReceipt(actions []SecureCellGovernmentAgentExecutionAction, receiptType string) bool {
	for _, action := range actions {
		if action.ReceiptType == receiptType {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionHandoffVerificationCheck(
	checks []SecureCellGovernmentAgentExecutionHandoffVerificationCheck,
	code string,
	outcome SecureCellGovernmentAgentExecutionHandoffVerificationOutcome,
) bool {
	for _, check := range checks {
		if check.Code == code && check.Outcome == outcome {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchGate(
	gates []SecureCellGovernmentAgentExecutionLaunchGate,
	code string,
	status SecureCellGovernmentAgentExecutionLaunchGateStatus,
) bool {
	for _, gate := range gates {
		if gate.Code == code && gate.Status == status {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchClearanceItem(
	items []SecureCellGovernmentAgentExecutionLaunchClearanceItem,
	gateCode string,
	status SecureCellGovernmentAgentExecutionLaunchClearanceItemStatus,
) bool {
	for _, item := range items {
		if item.GateCode == gateCode && item.Status == status {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchReceiptRequirement(
	requirements []SecureCellGovernmentAgentExecutionLaunchReceiptRequirement,
	receiptType string,
	status SecureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus,
) bool {
	for _, requirement := range requirements {
		if requirement.ReceiptType == receiptType && requirement.Status == status {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchReceiptValidationCheck(
	checks []SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck,
	code string,
	outcome SecureCellGovernmentAgentExecutionLaunchReceiptValidationOutcome,
) bool {
	for _, check := range checks {
		if check.Code == code && check.Outcome == outcome {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchCustodyAction(
	actions []SecureCellGovernmentAgentExecutionLaunchCustodyAction,
	actionType string,
	status SecureCellGovernmentAgentExecutionLaunchCustodyActionStatus,
) bool {
	for _, action := range actions {
		if action.ActionType == actionType && action.Status == status {
			return true
		}
	}
	return false
}

func hasString(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}
