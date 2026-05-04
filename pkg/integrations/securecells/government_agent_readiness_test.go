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

	launchActivation, err := service.GetGovernmentAgentExecutionLaunchActivation(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchActivation failed: %v", err)
	}
	if launchActivation.Status != SecureCellGovernmentAgentExecutionLaunchActivationOperatorReceiptsRequired || launchActivation.CanExecuteNow || !launchActivation.CanExecuteAfterOperatorReceipts {
		t.Fatalf("expected activation to require operator receipts, got %+v", launchActivation)
	}
	if launchActivation.ActivationDigest == "" || !strings.Contains(launchActivation.ActivationID, launchActivation.ActivationDigest[:12]) || launchActivation.CustodyID != launchCustody.CustodyID {
		t.Fatalf("expected digest-bound activation tied to custody, got %+v", launchActivation)
	}
	if launchActivation.WarnCount == 0 || launchActivation.FailCount != 0 || !hasGovernmentAgentExecutionLaunchActivationCheck(launchActivation.Checks, "PACKAGE_DIGEST_BOUND", SecureCellGovernmentAgentExecutionLaunchActivationCheckPass) {
		t.Fatalf("expected warning-only launch activation with package digest check, got %+v", launchActivation.Checks)
	}

	launchOrder, err := service.GetGovernmentAgentExecutionLaunchOrder(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchOrder failed: %v", err)
	}
	if launchOrder.Status != SecureCellGovernmentAgentExecutionLaunchOrderWaitingOperatorReceipts || launchOrder.CanStartNow || !launchOrder.CanStartAfterOperatorReceipts {
		t.Fatalf("expected launch order waiting for operator receipts, got %+v", launchOrder)
	}
	if launchOrder.OrderDigest == "" || !strings.Contains(launchOrder.OrderID, launchOrder.OrderDigest[:12]) || launchOrder.ActivationID != launchActivation.ActivationID {
		t.Fatalf("expected digest-bound launch order tied to activation, got %+v", launchOrder)
	}
	if launchOrder.ReturnReceiptCount == 0 || !hasGovernmentAgentExecutionLaunchOrderStopCondition(launchOrder.StopConditions, "OPERATOR_RECEIPTS_MISSING", SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityHigh) {
		t.Fatalf("expected operator receipt stop condition and return receipts, got %+v", launchOrder)
	}

	launchMonitor, err := service.GetGovernmentAgentExecutionLaunchMonitor(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchMonitor failed: %v", err)
	}
	if launchMonitor.Status != SecureCellGovernmentAgentExecutionLaunchMonitorWaitingOperatorReceipts || launchMonitor.CanMonitorNow || !launchMonitor.CanMonitorAfterOperatorReceipts {
		t.Fatalf("expected launch monitor waiting for operator receipts, got %+v", launchMonitor)
	}
	if launchMonitor.MonitorDigest == "" || !strings.Contains(launchMonitor.MonitorID, launchMonitor.MonitorDigest[:12]) || launchMonitor.OrderID != launchOrder.OrderID {
		t.Fatalf("expected digest-bound launch monitor tied to order, got %+v", launchMonitor)
	}
	if launchMonitor.PendingCheckpointCount == 0 || !hasGovernmentAgentExecutionLaunchMonitorCheckpoint(launchMonitor.Checkpoints, "return_receipt", "operator_acknowledgement_receipt", SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointPending) {
		t.Fatalf("expected pending operator acknowledgement checkpoint, got %+v", launchMonitor.Checkpoints)
	}

	launchReceiptIntake, err := service.GetGovernmentAgentExecutionLaunchReceiptIntake(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchReceiptIntake failed: %v", err)
	}
	if launchReceiptIntake.Status != SecureCellGovernmentAgentExecutionLaunchReceiptIntakeAwaitingOperatorReceipts || launchReceiptIntake.CanCollectNow || !launchReceiptIntake.CanCollectAfterOperatorReceipts {
		t.Fatalf("expected launch receipt intake waiting for operator receipts, got %+v", launchReceiptIntake)
	}
	if launchReceiptIntake.LedgerDigest == "" || !strings.Contains(launchReceiptIntake.LedgerID, launchReceiptIntake.LedgerDigest[:12]) || launchReceiptIntake.MonitorID != launchMonitor.MonitorID {
		t.Fatalf("expected digest-bound launch receipt intake tied to monitor, got %+v", launchReceiptIntake)
	}
	if launchReceiptIntake.PendingReceiptItemCount == 0 || !hasGovernmentAgentExecutionLaunchReceiptIntakeItem(launchReceiptIntake.Items, "operator_acknowledgement_receipt", SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemPending) {
		t.Fatalf("expected pending operator acknowledgement intake item, got %+v", launchReceiptIntake.Items)
	}

	launchCloseout, err := service.GetGovernmentAgentExecutionLaunchCloseout(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchCloseout failed: %v", err)
	}
	if launchCloseout.Status != SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingOperatorReceipts || launchCloseout.CanCloseNow || launchCloseout.CanCloseAfterRuntimeReceipts {
		t.Fatalf("expected launch closeout waiting for operator receipts, got %+v", launchCloseout)
	}
	if launchCloseout.RegisterDigest == "" || !strings.Contains(launchCloseout.RegisterID, launchCloseout.RegisterDigest[:12]) || launchCloseout.LedgerID != launchReceiptIntake.LedgerID {
		t.Fatalf("expected digest-bound launch closeout tied to receipt intake, got %+v", launchCloseout)
	}
	if launchCloseout.OperatorReceiptGateCount == 0 || !hasGovernmentAgentExecutionLaunchCloseoutGate(launchCloseout.Gates, "operator_acknowledgement_receipt", SecureCellGovernmentAgentExecutionLaunchCloseoutGateAwaitingOperatorReceipt) {
		t.Fatalf("expected operator acknowledgement closeout gate, got %+v", launchCloseout.Gates)
	}

	launchSettlement, err := service.GetGovernmentAgentExecutionLaunchSettlement(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchSettlement failed: %v", err)
	}
	if launchSettlement.Status != SecureCellGovernmentAgentExecutionLaunchSettlementAwaitingPreservation || launchSettlement.CanSettleNow || !launchSettlement.CanSettleAfterPreservation {
		t.Fatalf("expected launch settlement awaiting preservation, got %+v", launchSettlement)
	}
	if launchSettlement.SettlementRegisterDigest == "" || !strings.Contains(launchSettlement.RegisterID, launchSettlement.SettlementRegisterDigest[:12]) || launchSettlement.CloseoutRegisterID != launchCloseout.RegisterID {
		t.Fatalf("expected digest-bound launch settlement tied to closeout, got %+v", launchSettlement)
	}
	if launchSettlement.PendingSettlementItemCount == 0 || !hasGovernmentAgentExecutionLaunchSettlementItem(launchSettlement.Items, "operator_acknowledgement_receipt", SecureCellGovernmentAgentExecutionLaunchSettlementItemAwaitingPreservation) {
		t.Fatalf("expected awaiting-preservation settlement item, got %+v", launchSettlement.Items)
	}

	launchArchiveCertificate, err := service.GetGovernmentAgentExecutionLaunchArchiveCertificate(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchArchiveCertificate failed: %v", err)
	}
	if launchArchiveCertificate.Status != SecureCellGovernmentAgentExecutionLaunchArchiveCertificateAwaitingPreservation || launchArchiveCertificate.CanIssueNow || !launchArchiveCertificate.CanIssueAfterPreservation {
		t.Fatalf("expected launch archive certificate awaiting preservation, got %+v", launchArchiveCertificate)
	}
	if launchArchiveCertificate.CertificateDigest == "" || !strings.Contains(launchArchiveCertificate.CertificateID, launchArchiveCertificate.CertificateDigest[:12]) || launchArchiveCertificate.SettlementRegisterID != launchSettlement.RegisterID {
		t.Fatalf("expected digest-bound launch archive certificate tied to settlement, got %+v", launchArchiveCertificate)
	}
	if launchArchiveCertificate.PendingArchiveItemCount == 0 || !hasGovernmentAgentExecutionLaunchArchiveCertificateItem(launchArchiveCertificate.Items, "operator_acknowledgement_receipt", SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemAwaitingPreservation) {
		t.Fatalf("expected awaiting-preservation archive certificate item, got %+v", launchArchiveCertificate.Items)
	}

	launchClosureRegistry, err := service.GetGovernmentAgentExecutionLaunchClosureRegistry(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureRegistry failed: %v", err)
	}
	if launchClosureRegistry.Status != SecureCellGovernmentAgentExecutionLaunchClosureRegistryAwaitingArchiveIssue || launchClosureRegistry.CanCloseRecordNow || !launchClosureRegistry.CanCloseAfterArchiveIssue {
		t.Fatalf("expected launch closure registry awaiting archive issue, got %+v", launchClosureRegistry)
	}
	if launchClosureRegistry.RegistryDigest == "" || !strings.Contains(launchClosureRegistry.RegistryID, launchClosureRegistry.RegistryDigest[:12]) || launchClosureRegistry.CertificateID != launchArchiveCertificate.CertificateID {
		t.Fatalf("expected digest-bound launch closure registry tied to archive certificate, got %+v", launchClosureRegistry)
	}
	if launchClosureRegistry.PendingClosureItemCount == 0 || !hasGovernmentAgentExecutionLaunchClosureItem(launchClosureRegistry.Items, "operator_acknowledgement_receipt", SecureCellGovernmentAgentExecutionLaunchClosureItemAwaitingArchiveIssue) {
		t.Fatalf("expected awaiting-archive-issue closure item, got %+v", launchClosureRegistry.Items)
	}

	launchClosureBoard, err := service.GetGovernmentAgentExecutionLaunchClosureBoard(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureBoard failed: %v", err)
	}
	if launchClosureBoard.Status != SecureCellGovernmentAgentExecutionLaunchClosureBoardAwaitingArchiveIssue || launchClosureBoard.CanCloseNow || !launchClosureBoard.CanCloseAfterArchiveIssue {
		t.Fatalf("expected launch closure board awaiting archive issue, got %+v", launchClosureBoard)
	}
	if launchClosureBoard.BoardDigest == "" || !strings.Contains(launchClosureBoard.BoardID, launchClosureBoard.BoardDigest[:12]) || launchClosureBoard.RegistryID != launchClosureRegistry.RegistryID {
		t.Fatalf("expected digest-bound launch closure board tied to closure registry, got %+v", launchClosureBoard)
	}
	if launchClosureBoard.PendingItemCount == 0 || !hasGovernmentAgentExecutionLaunchClosureBoardItem(launchClosureBoard.Items, "operator_acknowledgement_receipt", SecureCellGovernmentAgentExecutionLaunchClosureBoardItemAwaitingArchiveIssue) {
		t.Fatalf("expected awaiting-archive-issue closure board item, got %+v", launchClosureBoard.Items)
	}

	launchClosureCommandCenter, err := service.GetGovernmentAgentExecutionLaunchClosureCommandCenter(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureCommandCenter failed: %v", err)
	}
	if launchClosureCommandCenter.Status != SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterAwaitingArchiveIssue || launchClosureCommandCenter.CanCloseNow || !launchClosureCommandCenter.CanCloseAfterArchiveIssue {
		t.Fatalf("expected launch closure command center awaiting archive issue, got %+v", launchClosureCommandCenter)
	}
	if launchClosureCommandCenter.CenterDigest == "" || !strings.Contains(launchClosureCommandCenter.CenterID, launchClosureCommandCenter.CenterDigest[:12]) || launchClosureCommandCenter.BoardID != launchClosureBoard.BoardID {
		t.Fatalf("expected digest-bound launch closure command center tied to closure board, got %+v", launchClosureCommandCenter)
	}
	if launchClosureCommandCenter.PrimaryAction != "issue_archive_certificate" || launchClosureCommandCenter.PendingItemCount == 0 {
		t.Fatalf("expected archive-issue primary action, got %+v", launchClosureCommandCenter)
	}

	launchClosureDashboard, err := service.GetGovernmentAgentExecutionLaunchClosureDashboard(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureDashboard failed: %v", err)
	}
	if launchClosureDashboard.Status != SecureCellGovernmentAgentExecutionLaunchClosureDashboardAwaitingArchiveIssue || launchClosureDashboard.CanCloseNow || !launchClosureDashboard.CanCloseAfterArchiveIssue {
		t.Fatalf("expected launch closure dashboard awaiting archive issue, got %+v", launchClosureDashboard)
	}
	if launchClosureDashboard.DashboardDigest == "" || !strings.Contains(launchClosureDashboard.DashboardID, launchClosureDashboard.DashboardDigest[:12]) || launchClosureDashboard.CenterID != launchClosureCommandCenter.CenterID {
		t.Fatalf("expected digest-bound launch closure dashboard tied to command center, got %+v", launchClosureDashboard)
	}
	if launchClosureDashboard.PrimaryAction != "issue_archive_certificate" || launchClosureDashboard.PendingItemCount == 0 {
		t.Fatalf("expected archive-issue dashboard action, got %+v", launchClosureDashboard)
	}

	launchClosurePortfolio, err := service.GetGovernmentAgentExecutionLaunchClosurePortfolio(ctx, SecureCellGovernmentAgentProgramFilter{
		Jurisdiction: "UAE",
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosurePortfolio failed: %v", err)
	}
	if launchClosurePortfolio.CellCount == 0 || launchClosurePortfolio.AwaitingArchiveIssueCount == 0 || launchClosurePortfolio.CanCloseAfterArchiveCount == 0 {
		t.Fatalf("expected awaiting-archive closure portfolio counts, got %+v", launchClosurePortfolio)
	}
	if launchClosurePortfolio.PortfolioDigest == "" || !strings.Contains(launchClosurePortfolio.PortfolioID, launchClosurePortfolio.PortfolioDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure portfolio, got %+v", launchClosurePortfolio)
	}
	launchClosurePortfolioAgain, err := service.GetGovernmentAgentExecutionLaunchClosurePortfolio(ctx, SecureCellGovernmentAgentProgramFilter{
		Jurisdiction: "UAE",
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosurePortfolio repeat failed: %v", err)
	}
	if launchClosurePortfolioAgain.PortfolioDigest != launchClosurePortfolio.PortfolioDigest {
		t.Fatalf("expected stable launch closure portfolio digest, got %q then %q", launchClosurePortfolio.PortfolioDigest, launchClosurePortfolioAgain.PortfolioDigest)
	}
	if len(launchClosurePortfolio.PrimaryActions) == 0 || launchClosurePortfolio.PrimaryActions[0].Action != "issue_archive_certificate" || launchClosurePortfolio.PrimaryActions[0].Count == 0 {
		t.Fatalf("expected archive-issue portfolio action, got %+v", launchClosurePortfolio)
	}
	if len(launchClosurePortfolio.Dashboards) == 0 || launchClosurePortfolio.Dashboards[0].DashboardID != launchClosureDashboard.DashboardID {
		t.Fatalf("expected launch closure portfolio to include dashboard rows, got %+v", launchClosurePortfolio)
	}

	launchClosureActionQueue, err := service.GetGovernmentAgentExecutionLaunchClosureActionQueue(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureActionQueue failed: %v", err)
	}
	if launchClosureActionQueue.Status != SecureCellGovernmentAgentExecutionLaunchClosureActionQueueDue || launchClosureActionQueue.DashboardID != launchClosureDashboard.DashboardID {
		t.Fatalf("expected due launch closure action queue tied to dashboard, got %+v", launchClosureActionQueue)
	}
	if launchClosureActionQueue.ActionCount != 1 || len(launchClosureActionQueue.Actions) != 1 {
		t.Fatalf("expected single launch closure action queue item, got %+v", launchClosureActionQueue)
	}
	if launchClosureActionQueue.QueueDigest == "" || !strings.Contains(launchClosureActionQueue.QueueID, launchClosureActionQueue.QueueDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure action queue, got %+v", launchClosureActionQueue)
	}
	action := launchClosureActionQueue.Actions[0]
	if action.Kind != SecureCellGovernmentAgentExecutionLaunchClosureActionIssueArchive || action.Status != SecureCellGovernmentAgentExecutionLaunchClosureActionQueueDue || action.Priority != SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityHigh {
		t.Fatalf("expected due archive-issue action, got %+v", action)
	}
	if action.DueAt == nil || action.OverdueSeconds != 0 || action.ActionDigest == "" {
		t.Fatalf("expected timed launch closure action, got %+v", action)
	}

	launchClosureAutomationAction, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAction(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAction failed: %v", err)
	}
	if launchClosureAutomationAction.QueueID != launchClosureActionQueue.QueueID || launchClosureAutomationAction.PendingAction != "issue_archive_certificate" {
		t.Fatalf("expected launch closure automation action tied to queue, got %+v", launchClosureAutomationAction)
	}
	if launchClosureAutomationAction.AutomationAction != "secure_cell.government_agent_execution_launch_archive_issue_pending" || launchClosureAutomationAction.ActionKind != SecureCellGovernmentAgentExecutionLaunchClosureActionIssueArchive {
		t.Fatalf("expected archive-issue automation action, got %+v", launchClosureAutomationAction)
	}
	if launchClosureAutomationAction.ActionDigest == "" || launchClosureAutomationAction.RecordID == "" || launchClosureAutomationAction.DueAt == nil {
		t.Fatalf("expected digest-bound timed launch closure automation action, got %+v", launchClosureAutomationAction)
	}
	overdueAt := launchClosureAutomationAction.DueAt.UTC().Add(time.Minute)
	launchClosureOverdueActions, err := service.ListGovernmentAgentExecutionLaunchClosureOverdueActions(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("ListGovernmentAgentExecutionLaunchClosureOverdueActions failed: %v", err)
	}
	if len(launchClosureOverdueActions) != 1 || launchClosureOverdueActions[0].CellID != created.CellID {
		t.Fatalf("expected one overdue launch closure action, got %+v", launchClosureOverdueActions)
	}
	if launchClosureOverdueActions[0].PendingAction != "issue_archive_certificate" || launchClosureOverdueActions[0].AutomationAction != "secure_cell.government_agent_execution_launch_archive_issue_pending" || launchClosureOverdueActions[0].OverdueSeconds <= 0 {
		t.Fatalf("expected overdue archive-issue action record, got %+v", launchClosureOverdueActions[0])
	}
	if !strings.HasPrefix(launchClosureOverdueActions[0].RecordID, "government-agent-execution-launch-closure-overdue-action:"+created.CellID+":") {
		t.Fatalf("expected overdue-action record id, got %q", launchClosureOverdueActions[0].RecordID)
	}
	launchClosureAutomationSummary, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationSummary(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationSummary failed: %v", err)
	}
	if launchClosureAutomationSummary.ActionCount == 0 || launchClosureAutomationSummary.OverdueCount == 0 || launchClosureAutomationSummary.MaxOverdueSeconds <= 0 {
		t.Fatalf("expected overdue launch closure automation summary, got %+v", launchClosureAutomationSummary)
	}
	if launchClosureAutomationSummary.SummaryDigest == "" || len(launchClosureAutomationSummary.TopActions) == 0 || launchClosureAutomationSummary.TopActions[0].PendingAction != "issue_archive_certificate" {
		t.Fatalf("expected digest-bound archive-issue automation summary, got %+v", launchClosureAutomationSummary)
	}
	launchClosureAutomationBoard, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationBoard(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationBoard failed: %v", err)
	}
	if launchClosureAutomationBoard.RecommendedLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue || launchClosureAutomationBoard.RecommendedAction != "drain_overdue_closure_actions" {
		t.Fatalf("expected overdue launch closure automation board recommendation, got %+v", launchClosureAutomationBoard)
	}
	if len(launchClosureAutomationBoard.Items) == 0 || launchClosureAutomationBoard.Items[0].Lane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue {
		t.Fatalf("expected overdue launch closure automation board items, got %+v", launchClosureAutomationBoard)
	}
	if launchClosureAutomationBoard.BoardDigest == "" || !strings.Contains(launchClosureAutomationBoard.BoardID, launchClosureAutomationBoard.BoardDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure automation board, got %+v", launchClosureAutomationBoard)
	}
	launchClosureAutomationPacket, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationPacket(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationPacket failed: %v", err)
	}
	if launchClosureAutomationPacket.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue || launchClosureAutomationPacket.FocusAction != "drain_overdue_closure_actions" {
		t.Fatalf("expected overdue launch closure automation packet focus, got %+v", launchClosureAutomationPacket)
	}
	if launchClosureAutomationPacket.ItemCount != 1 || len(launchClosureAutomationPacket.Steps) == 0 || launchClosureAutomationPacket.Steps[0].PendingAction != "issue_archive_certificate" {
		t.Fatalf("expected overdue launch closure automation packet steps, got %+v", launchClosureAutomationPacket)
	}
	if launchClosureAutomationPacket.BoardID == "" || launchClosureAutomationPacket.BoardDigest == "" || !hasString(launchClosureAutomationPacket.Steps[0].CellIDs, created.CellID) {
		t.Fatalf("expected packet tied to board and cell, got %+v", launchClosureAutomationPacket)
	}
	if launchClosureAutomationPacket.PacketDigest == "" || !strings.Contains(launchClosureAutomationPacket.PacketID, launchClosureAutomationPacket.PacketDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure automation packet, got %+v", launchClosureAutomationPacket)
	}
	launchClosureAutomationRunbook, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationRunbook(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationRunbook failed: %v", err)
	}
	if launchClosureAutomationRunbook.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue || launchClosureAutomationRunbook.FocusAction != "drain_overdue_closure_actions" {
		t.Fatalf("expected overdue launch closure automation runbook focus, got %+v", launchClosureAutomationRunbook)
	}
	if launchClosureAutomationRunbook.ItemCount != 1 || len(launchClosureAutomationRunbook.Steps) < 2 || launchClosureAutomationRunbook.Steps[1].PendingAction != "issue_archive_certificate" {
		t.Fatalf("expected overdue launch closure automation runbook steps, got %+v", launchClosureAutomationRunbook)
	}
	if launchClosureAutomationRunbook.PacketID == "" || launchClosureAutomationRunbook.PacketDigest == "" || !hasString(launchClosureAutomationRunbook.Steps[0].CellIDs, created.CellID) {
		t.Fatalf("expected runbook tied to packet and cell, got %+v", launchClosureAutomationRunbook)
	}
	if launchClosureAutomationRunbook.RunbookDigest == "" || !strings.Contains(launchClosureAutomationRunbook.RunbookID, launchClosureAutomationRunbook.RunbookDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure automation runbook, got %+v", launchClosureAutomationRunbook)
	}
	launchClosureAutomationBrief, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationBrief(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationBrief failed: %v", err)
	}
	if launchClosureAutomationBrief.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue || launchClosureAutomationBrief.FocusAction != "drain_overdue_closure_actions" {
		t.Fatalf("expected overdue launch closure automation brief focus, got %+v", launchClosureAutomationBrief)
	}
	if launchClosureAutomationBrief.Severity != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityHigh || launchClosureAutomationBrief.TopCheckpoint != "Issue archive certificates" {
		t.Fatalf("expected overdue launch closure automation brief severity/checkpoint, got %+v", launchClosureAutomationBrief)
	}
	if len(launchClosureAutomationBrief.UniquePendingAction) != 1 || launchClosureAutomationBrief.UniquePendingAction[0] != "issue_archive_certificate" {
		t.Fatalf("expected overdue launch closure automation brief pending actions, got %+v", launchClosureAutomationBrief)
	}
	if launchClosureAutomationBrief.RunbookID == "" || launchClosureAutomationBrief.BriefDigest == "" || !hasString(launchClosureAutomationBrief.Steps[0].CellIDs, created.CellID) {
		t.Fatalf("expected brief tied to runbook and cell, got %+v", launchClosureAutomationBrief)
	}
	if !strings.Contains(launchClosureAutomationBrief.BriefID, launchClosureAutomationBrief.BriefDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure automation brief, got %+v", launchClosureAutomationBrief)
	}
	launchClosureAutomationDispatch, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationDispatch(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationDispatch failed: %v", err)
	}
	if launchClosureAutomationDispatch.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue || launchClosureAutomationDispatch.FocusAction != "drain_overdue_closure_actions" {
		t.Fatalf("expected overdue launch closure automation dispatch focus, got %+v", launchClosureAutomationDispatch)
	}
	if launchClosureAutomationDispatch.Severity != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityHigh || launchClosureAutomationDispatch.LeadRole != "operations_lead" {
		t.Fatalf("expected overdue launch closure automation dispatch severity/lead, got %+v", launchClosureAutomationDispatch)
	}
	if launchClosureAutomationDispatch.AssignmentCount != 1 || len(launchClosureAutomationDispatch.Assignments) != 1 || launchClosureAutomationDispatch.Assignments[0].PendingAction != "issue_archive_certificate" {
		t.Fatalf("expected overdue launch closure automation dispatch assignments, got %+v", launchClosureAutomationDispatch)
	}
	if launchClosureAutomationDispatch.BriefID == "" || launchClosureAutomationDispatch.DispatchDigest == "" || !hasString(launchClosureAutomationDispatch.Assignments[0].CellIDs, created.CellID) {
		t.Fatalf("expected dispatch tied to brief and cell, got %+v", launchClosureAutomationDispatch)
	}
	if !strings.Contains(launchClosureAutomationDispatch.DispatchID, launchClosureAutomationDispatch.DispatchDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure automation dispatch, got %+v", launchClosureAutomationDispatch)
	}
	launchClosureAutomationDirective, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationDirective(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationDirective failed: %v", err)
	}
	if launchClosureAutomationDirective.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue || launchClosureAutomationDirective.FocusAction != "drain_overdue_closure_actions" {
		t.Fatalf("expected overdue launch closure automation directive focus, got %+v", launchClosureAutomationDirective)
	}
	if launchClosureAutomationDirective.Severity != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityHigh || launchClosureAutomationDirective.ExecutionWindow != "within_15_minutes" || !launchClosureAutomationDirective.AckRequired {
		t.Fatalf("expected overdue launch closure automation directive severity/window/ack, got %+v", launchClosureAutomationDirective)
	}
	if launchClosureAutomationDirective.AssignmentCount != 1 || len(launchClosureAutomationDirective.Assignments) != 1 || launchClosureAutomationDirective.Assignments[0].PendingAction != "issue_archive_certificate" {
		t.Fatalf("expected overdue launch closure automation directive assignments, got %+v", launchClosureAutomationDirective)
	}
	if launchClosureAutomationDirective.DispatchID == "" || launchClosureAutomationDirective.DirectiveDigest == "" || !hasString(launchClosureAutomationDirective.Assignments[0].CellIDs, created.CellID) {
		t.Fatalf("expected directive tied to dispatch and cell, got %+v", launchClosureAutomationDirective)
	}
	if !strings.Contains(launchClosureAutomationDirective.DirectiveID, launchClosureAutomationDirective.DirectiveDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure automation directive, got %+v", launchClosureAutomationDirective)
	}
	launchClosureAutomationAcknowledgement, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement failed: %v", err)
	}
	if launchClosureAutomationAcknowledgement.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue || launchClosureAutomationAcknowledgement.FocusAction != "drain_overdue_closure_actions" {
		t.Fatalf("expected overdue launch closure automation acknowledgement focus, got %+v", launchClosureAutomationAcknowledgement)
	}
	if launchClosureAutomationAcknowledgement.AckStatus != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatusOverdue || launchClosureAutomationAcknowledgement.AckOverdueSeconds <= 0 {
		t.Fatalf("expected overdue launch closure automation acknowledgement timer, got %+v", launchClosureAutomationAcknowledgement)
	}
	if launchClosureAutomationAcknowledgement.AckAction != "recover_launch_closure_acknowledgement" || len(launchClosureAutomationAcknowledgement.RequiredRoles) != 1 || launchClosureAutomationAcknowledgement.RequiredRoles[0] != "archive_officer" {
		t.Fatalf("expected overdue launch closure automation acknowledgement action/role, got %+v", launchClosureAutomationAcknowledgement)
	}
	if launchClosureAutomationAcknowledgement.DirectiveID == "" || launchClosureAutomationAcknowledgement.AcknowledgementDigest == "" || !hasString(launchClosureAutomationAcknowledgement.Assignments[0].CellIDs, created.CellID) {
		t.Fatalf("expected acknowledgement tied to directive and cell, got %+v", launchClosureAutomationAcknowledgement)
	}
	if !strings.Contains(launchClosureAutomationAcknowledgement.AcknowledgementID, launchClosureAutomationAcknowledgement.AcknowledgementDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure automation acknowledgement, got %+v", launchClosureAutomationAcknowledgement)
	}
	launchClosureAutomationAcknowledgementReceipt, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceipt.ReceiptStatus != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatusOverdue || launchClosureAutomationAcknowledgementReceipt.ReceiptOverdueSeconds <= 0 {
		t.Fatalf("expected overdue launch closure automation acknowledgement receipt, got %+v", launchClosureAutomationAcknowledgementReceipt)
	}
	if launchClosureAutomationAcknowledgementReceipt.ReceiptAction != "recover_missing_launch_closure_ack_receipt" || !hasString(launchClosureAutomationAcknowledgementReceipt.ReceiptEvidence, "overdue_acknowledgement_explanation") {
		t.Fatalf("expected recoverable acknowledgement receipt evidence, got %+v", launchClosureAutomationAcknowledgementReceipt)
	}
	if launchClosureAutomationAcknowledgementReceipt.AcknowledgementID == "" || launchClosureAutomationAcknowledgementReceipt.ReceiptDigest == "" || !hasString(launchClosureAutomationAcknowledgementReceipt.Assignments[0].CellIDs, created.CellID) {
		t.Fatalf("expected acknowledgement receipt tied to acknowledgement and cell, got %+v", launchClosureAutomationAcknowledgementReceipt)
	}
	if !strings.Contains(launchClosureAutomationAcknowledgementReceipt.AcknowledgementReceiptID, launchClosureAutomationAcknowledgementReceipt.ReceiptDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure automation acknowledgement receipt, got %+v", launchClosureAutomationAcknowledgementReceipt)
	}
	launchClosureAutomationAcknowledgementReceiptManifest, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceiptManifest.ReceiptStatus != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatusOverdue || launchClosureAutomationAcknowledgementReceiptManifest.OverdueEvidenceCount == 0 {
		t.Fatalf("expected overdue launch closure automation acknowledgement receipt manifest, got %+v", launchClosureAutomationAcknowledgementReceiptManifest)
	}
	if launchClosureAutomationAcknowledgementReceiptManifest.EscalationEvidenceCount != 0 || !hasLaunchClosureAutomationAckReceiptManifestEvidence(launchClosureAutomationAcknowledgementReceiptManifest.Items, "overdue_acknowledgement_explanation") {
		t.Fatalf("expected recoverable acknowledgement receipt manifest evidence, got %+v", launchClosureAutomationAcknowledgementReceiptManifest)
	}
	if launchClosureAutomationAcknowledgementReceiptManifest.AcknowledgementReceiptID == "" || launchClosureAutomationAcknowledgementReceiptManifest.ManifestDigest == "" || !hasString(launchClosureAutomationAcknowledgementReceiptManifest.Items[0].CellIDs, created.CellID) {
		t.Fatalf("expected acknowledgement receipt manifest tied to receipt and cell, got %+v", launchClosureAutomationAcknowledgementReceiptManifest)
	}
	if !strings.Contains(launchClosureAutomationAcknowledgementReceiptManifest.ManifestID, launchClosureAutomationAcknowledgementReceiptManifest.ManifestDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure automation acknowledgement receipt manifest, got %+v", launchClosureAutomationAcknowledgementReceiptManifest)
	}
	launchClosureAutomationAcknowledgementReceiptEvidenceQueue, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceQueue.Status != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusOverdue || launchClosureAutomationAcknowledgementReceiptEvidenceQueue.OverdueCount == 0 {
		t.Fatalf("expected overdue launch closure automation acknowledgement receipt evidence queue, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceQueue)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceQueue.EscalationCount != 0 || !hasLaunchClosureAutomationAckReceiptEvidenceQueueEvidence(launchClosureAutomationAcknowledgementReceiptEvidenceQueue.Items, "overdue_acknowledgement_explanation") {
		t.Fatalf("expected recoverable acknowledgement receipt evidence queue, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceQueue)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceQueue.ManifestID == "" || launchClosureAutomationAcknowledgementReceiptEvidenceQueue.QueueDigest == "" || !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceQueue.Items[0].CellIDs, created.CellID) {
		t.Fatalf("expected acknowledgement receipt evidence queue tied to manifest and cell, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceQueue)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceQueue.Items[0].ItemDigest == "" || !strings.Contains(launchClosureAutomationAcknowledgementReceiptEvidenceQueue.QueueID, launchClosureAutomationAcknowledgementReceiptEvidenceQueue.QueueDigest[:12]) {
		t.Fatalf("expected digest-bound launch closure automation acknowledgement receipt evidence queue, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceQueue)
	}
	launchClosureAutomationAcknowledgementReceiptEvidenceDispatch, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Status != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusOverdue || launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.OverdueDispatchCount == 0 {
		t.Fatalf("expected overdue launch closure automation acknowledgement receipt evidence dispatch, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatch)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.EscalationDispatchCount != 0 || !hasLaunchClosureAutomationAckReceiptEvidenceDispatchEvidence(launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Items, "overdue_acknowledgement_explanation") {
		t.Fatalf("expected recoverable acknowledgement receipt evidence dispatch, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatch)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.QueueID == "" || launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.DispatchDigest == "" || !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Items[0].CellIDs, created.CellID) {
		t.Fatalf("expected acknowledgement receipt evidence dispatch tied to queue and cell, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatch)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Items[0].DispatchItemDigest == "" || launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Items[0].DispatchChannel != "operator_recovery_channel" {
		t.Fatalf("expected digest-bound recovery evidence dispatch item, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Items[0])
	}
	launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Status != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusOverdueRequired || launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.OverdueAcceptanceCount == 0 {
		t.Fatalf("expected overdue launch closure automation acknowledgement receipt evidence dispatch acceptance, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.EscalationAcceptanceCount != 0 || !hasLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceEvidence(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Items, "overdue_acknowledgement_explanation") {
		t.Fatalf("expected recoverable acknowledgement receipt evidence dispatch acceptance, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.DispatchID == "" || launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.AcceptanceDigest == "" || !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Items[0].CellIDs, created.CellID) {
		t.Fatalf("expected acknowledgement receipt evidence dispatch acceptance tied to dispatch and cell, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance)
	}
	if !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Items[0].AcceptanceEvidence, "overdue_dispatch_acceptance_explanation") || launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Items[0].AcceptanceChannel != "operator_recovery_acceptance" {
		t.Fatalf("expected overdue evidence dispatch acceptance proof requirements, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Items[0])
	}
	launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		Jurisdiction: "UAE",
		Before:       &overdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Status != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusOverdue || launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.OverdueReceiptCount == 0 {
		t.Fatalf("expected overdue launch closure automation acknowledgement receipt evidence dispatch acceptance receipt, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.EscalationReceiptCount != 0 || !hasLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptEvidence(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Items, "overdue_acknowledgement_explanation") {
		t.Fatalf("expected recoverable acknowledgement receipt evidence dispatch acceptance receipt, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.AcceptanceID == "" || launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.AcceptanceReceiptDigest == "" || !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Items[0].CellIDs, created.CellID) {
		t.Fatalf("expected acknowledgement receipt evidence dispatch acceptance receipt tied to acceptance and cell, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt)
	}
	if !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Items[0].ReceiptEvidence, "overdue_acceptance_receipt_reason") || !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Items[0].ReceiptEvidence, "custody_timestamp") {
		t.Fatalf("expected overdue custody receipt evidence requirements, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Items[0])
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

	launchActivation, err := service.GetGovernmentAgentExecutionLaunchActivation(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchActivation failed: %v", err)
	}
	if launchActivation.Status != SecureCellGovernmentAgentExecutionLaunchActivationDenied || launchActivation.CanExecuteNow || launchActivation.CanExecuteAfterOperatorReceipts {
		t.Fatalf("expected denied launch activation for tacit workflow, got %+v", launchActivation)
	}
	if launchActivation.FailCount == 0 || launchActivation.ActivationDigest == "" || launchActivation.CustodyID != launchCustody.CustodyID {
		t.Fatalf("expected digest-bound denied launch activation tied to custody, got %+v", launchActivation)
	}
	if !hasGovernmentAgentExecutionLaunchActivationCheck(launchActivation.Checks, "CUSTODY_ACTIONS_CLEARED", SecureCellGovernmentAgentExecutionLaunchActivationCheckFail) {
		t.Fatalf("expected failed custody action activation check, got %+v", launchActivation.Checks)
	}

	launchOrder, err := service.GetGovernmentAgentExecutionLaunchOrder(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchOrder failed: %v", err)
	}
	if launchOrder.Status != SecureCellGovernmentAgentExecutionLaunchOrderDenied || launchOrder.CanStartNow || launchOrder.CanStartAfterOperatorReceipts {
		t.Fatalf("expected denied launch order for tacit workflow, got %+v", launchOrder)
	}
	if launchOrder.CriticalStopConditionCount == 0 || launchOrder.OrderDigest == "" || launchOrder.ActivationID != launchActivation.ActivationID {
		t.Fatalf("expected digest-bound denied launch order tied to activation, got %+v", launchOrder)
	}
	if !hasGovernmentAgentExecutionLaunchOrderStopCondition(launchOrder.StopConditions, "ACTIVATION_CHECK_FAILED", SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityCritical) {
		t.Fatalf("expected critical activation failure stop condition, got %+v", launchOrder.StopConditions)
	}

	launchMonitor, err := service.GetGovernmentAgentExecutionLaunchMonitor(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchMonitor failed: %v", err)
	}
	if launchMonitor.Status != SecureCellGovernmentAgentExecutionLaunchMonitorDenied || launchMonitor.CanMonitorNow || launchMonitor.CanMonitorAfterOperatorReceipts {
		t.Fatalf("expected denied launch monitor for tacit workflow, got %+v", launchMonitor)
	}
	if launchMonitor.BlockedCheckpointCount == 0 || launchMonitor.MonitorDigest == "" || launchMonitor.OrderID != launchOrder.OrderID {
		t.Fatalf("expected digest-bound denied launch monitor tied to order, got %+v", launchMonitor)
	}
	if !hasGovernmentAgentExecutionLaunchMonitorCheckpoint(launchMonitor.Checkpoints, "stop_condition_watch", "", SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointBlocked) {
		t.Fatalf("expected blocked stop-condition watch checkpoint, got %+v", launchMonitor.Checkpoints)
	}

	launchReceiptIntake, err := service.GetGovernmentAgentExecutionLaunchReceiptIntake(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchReceiptIntake failed: %v", err)
	}
	if launchReceiptIntake.Status != SecureCellGovernmentAgentExecutionLaunchReceiptIntakeBlocked || launchReceiptIntake.CanCollectNow || launchReceiptIntake.CanCollectAfterOperatorReceipts {
		t.Fatalf("expected blocked launch receipt intake for tacit workflow, got %+v", launchReceiptIntake)
	}
	if launchReceiptIntake.BlockedReceiptItemCount == 0 || launchReceiptIntake.LedgerDigest == "" || launchReceiptIntake.MonitorID != launchMonitor.MonitorID {
		t.Fatalf("expected digest-bound blocked launch receipt intake tied to monitor, got %+v", launchReceiptIntake)
	}
	if !hasGovernmentAgentExecutionLaunchReceiptIntakeItem(launchReceiptIntake.Items, "stop_condition_watch_receipt", SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemBlocked) {
		t.Fatalf("expected blocked stop-condition watch receipt intake item, got %+v", launchReceiptIntake.Items)
	}

	launchCloseout, err := service.GetGovernmentAgentExecutionLaunchCloseout(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchCloseout failed: %v", err)
	}
	if launchCloseout.Status != SecureCellGovernmentAgentExecutionLaunchCloseoutBlocked || launchCloseout.CanCloseNow || launchCloseout.CanCloseAfterRuntimeReceipts {
		t.Fatalf("expected blocked launch closeout for tacit workflow, got %+v", launchCloseout)
	}
	if launchCloseout.BlockedGateCount == 0 || launchCloseout.RegisterDigest == "" || launchCloseout.LedgerID != launchReceiptIntake.LedgerID {
		t.Fatalf("expected digest-bound blocked launch closeout tied to receipt intake, got %+v", launchCloseout)
	}
	if !hasGovernmentAgentExecutionLaunchCloseoutGate(launchCloseout.Gates, "stop_condition_watch_receipt", SecureCellGovernmentAgentExecutionLaunchCloseoutGateBlocked) {
		t.Fatalf("expected blocked stop-condition watch closeout gate, got %+v", launchCloseout.Gates)
	}

	launchSettlement, err := service.GetGovernmentAgentExecutionLaunchSettlement(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchSettlement failed: %v", err)
	}
	if launchSettlement.Status != SecureCellGovernmentAgentExecutionLaunchSettlementBlocked || launchSettlement.CanSettleNow || launchSettlement.CanSettleAfterPreservation {
		t.Fatalf("expected blocked launch settlement for tacit workflow, got %+v", launchSettlement)
	}
	if launchSettlement.BlockedSettlementItemCount == 0 || launchSettlement.SettlementRegisterDigest == "" || launchSettlement.CloseoutRegisterID != launchCloseout.RegisterID {
		t.Fatalf("expected digest-bound blocked launch settlement tied to closeout, got %+v", launchSettlement)
	}
	if !hasGovernmentAgentExecutionLaunchSettlementItem(launchSettlement.Items, "stop_condition_watch_receipt", SecureCellGovernmentAgentExecutionLaunchSettlementItemBlocked) {
		t.Fatalf("expected blocked stop-condition watch settlement item, got %+v", launchSettlement.Items)
	}

	launchArchiveCertificate, err := service.GetGovernmentAgentExecutionLaunchArchiveCertificate(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchArchiveCertificate failed: %v", err)
	}
	if launchArchiveCertificate.Status != SecureCellGovernmentAgentExecutionLaunchArchiveCertificateBlocked || launchArchiveCertificate.CanIssueNow || launchArchiveCertificate.CanIssueAfterPreservation {
		t.Fatalf("expected blocked launch archive certificate for tacit workflow, got %+v", launchArchiveCertificate)
	}
	if launchArchiveCertificate.BlockedArchiveItemCount == 0 || launchArchiveCertificate.CertificateDigest == "" || launchArchiveCertificate.SettlementRegisterID != launchSettlement.RegisterID {
		t.Fatalf("expected digest-bound blocked launch archive certificate tied to settlement, got %+v", launchArchiveCertificate)
	}
	if !hasGovernmentAgentExecutionLaunchArchiveCertificateItem(launchArchiveCertificate.Items, "stop_condition_watch_receipt", SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemBlocked) {
		t.Fatalf("expected blocked stop-condition watch archive certificate item, got %+v", launchArchiveCertificate.Items)
	}

	launchClosureRegistry, err := service.GetGovernmentAgentExecutionLaunchClosureRegistry(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureRegistry failed: %v", err)
	}
	if launchClosureRegistry.Status != SecureCellGovernmentAgentExecutionLaunchClosureRegistryBlocked || launchClosureRegistry.CanCloseRecordNow || launchClosureRegistry.CanCloseAfterArchiveIssue {
		t.Fatalf("expected blocked launch closure registry for tacit workflow, got %+v", launchClosureRegistry)
	}
	if launchClosureRegistry.BlockedClosureItemCount == 0 || launchClosureRegistry.RegistryDigest == "" || launchClosureRegistry.CertificateID != launchArchiveCertificate.CertificateID {
		t.Fatalf("expected digest-bound blocked launch closure registry tied to archive certificate, got %+v", launchClosureRegistry)
	}
	if !hasGovernmentAgentExecutionLaunchClosureItem(launchClosureRegistry.Items, "stop_condition_watch_receipt", SecureCellGovernmentAgentExecutionLaunchClosureItemBlocked) {
		t.Fatalf("expected blocked stop-condition watch closure item, got %+v", launchClosureRegistry.Items)
	}

	launchClosureBoard, err := service.GetGovernmentAgentExecutionLaunchClosureBoard(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureBoard failed: %v", err)
	}
	if launchClosureBoard.Status != SecureCellGovernmentAgentExecutionLaunchClosureBoardBlocked || launchClosureBoard.CanCloseNow || launchClosureBoard.CanCloseAfterArchiveIssue {
		t.Fatalf("expected blocked launch closure board for tacit workflow, got %+v", launchClosureBoard)
	}
	if launchClosureBoard.BlockedItemCount == 0 || launchClosureBoard.BoardDigest == "" || launchClosureBoard.RegistryID != launchClosureRegistry.RegistryID {
		t.Fatalf("expected digest-bound blocked launch closure board tied to closure registry, got %+v", launchClosureBoard)
	}
	if !hasGovernmentAgentExecutionLaunchClosureBoardItem(launchClosureBoard.Items, "stop_condition_watch_receipt", SecureCellGovernmentAgentExecutionLaunchClosureBoardItemBlocked) {
		t.Fatalf("expected blocked stop-condition watch closure board item, got %+v", launchClosureBoard.Items)
	}

	launchClosureCommandCenter, err := service.GetGovernmentAgentExecutionLaunchClosureCommandCenter(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureCommandCenter failed: %v", err)
	}
	if launchClosureCommandCenter.Status != SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterBlocked || launchClosureCommandCenter.CanCloseNow || launchClosureCommandCenter.CanCloseAfterArchiveIssue {
		t.Fatalf("expected blocked launch closure command center for tacit workflow, got %+v", launchClosureCommandCenter)
	}
	if launchClosureCommandCenter.BlockedItemCount == 0 || launchClosureCommandCenter.CenterDigest == "" || launchClosureCommandCenter.BoardID != launchClosureBoard.BoardID {
		t.Fatalf("expected digest-bound blocked launch closure command center tied to closure board, got %+v", launchClosureCommandCenter)
	}
	if launchClosureCommandCenter.PrimaryAction != "escalate_blocked_closure" {
		t.Fatalf("expected blocked-closure primary action, got %+v", launchClosureCommandCenter)
	}

	launchClosureDashboard, err := service.GetGovernmentAgentExecutionLaunchClosureDashboard(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureDashboard failed: %v", err)
	}
	if launchClosureDashboard.Status != SecureCellGovernmentAgentExecutionLaunchClosureDashboardBlocked || launchClosureDashboard.CanCloseNow || launchClosureDashboard.CanCloseAfterArchiveIssue {
		t.Fatalf("expected blocked launch closure dashboard for tacit workflow, got %+v", launchClosureDashboard)
	}
	if launchClosureDashboard.BlockedItemCount == 0 || launchClosureDashboard.DashboardDigest == "" || launchClosureDashboard.CenterID != launchClosureCommandCenter.CenterID {
		t.Fatalf("expected digest-bound blocked launch closure dashboard tied to command center, got %+v", launchClosureDashboard)
	}
	if launchClosureDashboard.PrimaryAction != "escalate_blocked_closure" {
		t.Fatalf("expected blocked dashboard action, got %+v", launchClosureDashboard)
	}

	launchClosurePortfolio, err := service.GetGovernmentAgentExecutionLaunchClosurePortfolio(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: created.CellID,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosurePortfolio failed: %v", err)
	}
	if launchClosurePortfolio.CellCount != 1 || launchClosurePortfolio.BlockedCount != 1 || launchClosurePortfolio.EscalationRequiredCount != 1 {
		t.Fatalf("expected blocked launch closure portfolio counts, got %+v", launchClosurePortfolio)
	}
	if launchClosurePortfolio.PortfolioDigest == "" || len(launchClosurePortfolio.PrimaryActions) == 0 || launchClosurePortfolio.PrimaryActions[0].Action != "escalate_blocked_closure" {
		t.Fatalf("expected blocked launch closure portfolio action, got %+v", launchClosurePortfolio)
	}

	launchClosureActionQueue, err := service.GetGovernmentAgentExecutionLaunchClosureActionQueue(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureActionQueue failed: %v", err)
	}
	if launchClosureActionQueue.Status != SecureCellGovernmentAgentExecutionLaunchClosureActionQueueBlocked || launchClosureActionQueue.BlockedActionCount != 1 {
		t.Fatalf("expected blocked launch closure action queue, got %+v", launchClosureActionQueue)
	}
	if len(launchClosureActionQueue.Actions) != 1 {
		t.Fatalf("expected one blocked launch closure action, got %+v", launchClosureActionQueue)
	}
	action := launchClosureActionQueue.Actions[0]
	if action.Kind != SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked || action.Status != SecureCellGovernmentAgentExecutionLaunchClosureActionQueueBlocked || !action.EscalationRecommended {
		t.Fatalf("expected blocked escalation action, got %+v", action)
	}
	if action.Priority != SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityCritical || action.ActionDigest == "" {
		t.Fatalf("expected critical blocked launch closure action, got %+v", action)
	}

	launchClosureAutomationAction, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAction(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAction failed: %v", err)
	}
	if launchClosureAutomationAction.AutomationAction != "secure_cell.government_agent_execution_launch_closure_escalated" || launchClosureAutomationAction.PendingAction != "escalate_blocked_closure" {
		t.Fatalf("expected blocked launch closure automation action, got %+v", launchClosureAutomationAction)
	}
	if launchClosureAutomationAction.ActionPriority != SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityCritical || !launchClosureAutomationAction.EscalationRecommended {
		t.Fatalf("expected critical escalation automation action, got %+v", launchClosureAutomationAction)
	}
	blockedOverdueAt := launchClosureAutomationAction.DueAt.UTC().Add(time.Minute)
	blockedOverdueActions, err := service.ListGovernmentAgentExecutionLaunchClosureOverdueActions(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
		Limit:  1,
	})
	if err != nil {
		t.Fatalf("ListGovernmentAgentExecutionLaunchClosureOverdueActions failed: %v", err)
	}
	if len(blockedOverdueActions) != 1 || blockedOverdueActions[0].PendingAction != "escalate_blocked_closure" || blockedOverdueActions[0].AutomationAction != "secure_cell.government_agent_execution_launch_closure_escalated" {
		t.Fatalf("expected blocked overdue launch closure action, got %+v", blockedOverdueActions)
	}
	if blockedOverdueActions[0].OverdueSeconds <= 0 || blockedOverdueActions[0].ActionPriority != SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityCritical {
		t.Fatalf("expected timed critical blocked overdue action, got %+v", blockedOverdueActions[0])
	}
	if !strings.HasPrefix(blockedOverdueActions[0].RecordID, "government-agent-execution-launch-closure-overdue-action:"+created.CellID+":") {
		t.Fatalf("expected blocked overdue-action record id, got %q", blockedOverdueActions[0].RecordID)
	}
	launchClosureAutomationSummary, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationSummary(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationSummary failed: %v", err)
	}
	if launchClosureAutomationSummary.ActionCount != 1 || launchClosureAutomationSummary.OverdueCount != 1 || launchClosureAutomationSummary.EscalationRecommendedCount != 1 {
		t.Fatalf("expected blocked launch closure automation summary counts, got %+v", launchClosureAutomationSummary)
	}
	if len(launchClosureAutomationSummary.TopActions) == 0 || launchClosureAutomationSummary.TopActions[0].PendingAction != "escalate_blocked_closure" {
		t.Fatalf("expected blocked launch closure automation summary action, got %+v", launchClosureAutomationSummary)
	}
	launchClosureAutomationBoard, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationBoard(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationBoard failed: %v", err)
	}
	if launchClosureAutomationBoard.RecommendedLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked || launchClosureAutomationBoard.RecommendedAction != "clear_blocked_closure_path" {
		t.Fatalf("expected blocked launch closure automation board recommendation, got %+v", launchClosureAutomationBoard)
	}
	if len(launchClosureAutomationBoard.Items) != 1 || launchClosureAutomationBoard.Items[0].Lane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked {
		t.Fatalf("expected blocked launch closure automation board item, got %+v", launchClosureAutomationBoard)
	}
	launchClosureAutomationPacket, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationPacket(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationPacket failed: %v", err)
	}
	if launchClosureAutomationPacket.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked || launchClosureAutomationPacket.FocusAction != "clear_blocked_closure_path" {
		t.Fatalf("expected blocked launch closure automation packet focus, got %+v", launchClosureAutomationPacket)
	}
	if launchClosureAutomationPacket.ItemCount != 1 || len(launchClosureAutomationPacket.Steps) == 0 || launchClosureAutomationPacket.Steps[0].PendingAction != "escalate_blocked_closure" {
		t.Fatalf("expected blocked launch closure automation packet steps, got %+v", launchClosureAutomationPacket)
	}
	if launchClosureAutomationPacket.BoardID == "" || launchClosureAutomationPacket.BoardDigest == "" || !hasString(launchClosureAutomationPacket.Steps[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked packet tied to board and cell, got %+v", launchClosureAutomationPacket)
	}
	launchClosureAutomationRunbook, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationRunbook(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationRunbook failed: %v", err)
	}
	if launchClosureAutomationRunbook.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked || launchClosureAutomationRunbook.FocusAction != "clear_blocked_closure_path" {
		t.Fatalf("expected blocked launch closure automation runbook focus, got %+v", launchClosureAutomationRunbook)
	}
	if launchClosureAutomationRunbook.ItemCount != 1 || len(launchClosureAutomationRunbook.Steps) < 2 || launchClosureAutomationRunbook.Steps[1].PendingAction != "escalate_blocked_closure" {
		t.Fatalf("expected blocked launch closure automation runbook steps, got %+v", launchClosureAutomationRunbook)
	}
	if launchClosureAutomationRunbook.PacketID == "" || launchClosureAutomationRunbook.RunbookDigest == "" || !hasString(launchClosureAutomationRunbook.Steps[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked runbook tied to packet and cell, got %+v", launchClosureAutomationRunbook)
	}
	launchClosureAutomationBrief, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationBrief(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationBrief failed: %v", err)
	}
	if launchClosureAutomationBrief.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked || launchClosureAutomationBrief.FocusAction != "clear_blocked_closure_path" {
		t.Fatalf("expected blocked launch closure automation brief focus, got %+v", launchClosureAutomationBrief)
	}
	if launchClosureAutomationBrief.Severity != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityCritical || launchClosureAutomationBrief.TopCheckpoint != "Escalate blocked closure records" {
		t.Fatalf("expected blocked launch closure automation brief severity/checkpoint, got %+v", launchClosureAutomationBrief)
	}
	if len(launchClosureAutomationBrief.UniquePendingAction) != 1 || launchClosureAutomationBrief.UniquePendingAction[0] != "escalate_blocked_closure" {
		t.Fatalf("expected blocked launch closure automation brief pending actions, got %+v", launchClosureAutomationBrief)
	}
	if launchClosureAutomationBrief.RunbookID == "" || launchClosureAutomationBrief.BriefDigest == "" || !hasString(launchClosureAutomationBrief.Steps[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked brief tied to runbook and cell, got %+v", launchClosureAutomationBrief)
	}
	launchClosureAutomationDispatch, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationDispatch(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationDispatch failed: %v", err)
	}
	if launchClosureAutomationDispatch.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked || launchClosureAutomationDispatch.FocusAction != "clear_blocked_closure_path" {
		t.Fatalf("expected blocked launch closure automation dispatch focus, got %+v", launchClosureAutomationDispatch)
	}
	if launchClosureAutomationDispatch.Severity != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityCritical || launchClosureAutomationDispatch.LeadRole != "incident_commander" || !launchClosureAutomationDispatch.EscalationRequired {
		t.Fatalf("expected blocked launch closure automation dispatch severity/lead/escalation, got %+v", launchClosureAutomationDispatch)
	}
	if launchClosureAutomationDispatch.AssignmentCount != 1 || len(launchClosureAutomationDispatch.Assignments) != 1 || launchClosureAutomationDispatch.Assignments[0].PendingAction != "escalate_blocked_closure" {
		t.Fatalf("expected blocked launch closure automation dispatch assignments, got %+v", launchClosureAutomationDispatch)
	}
	if launchClosureAutomationDispatch.BriefID == "" || launchClosureAutomationDispatch.DispatchDigest == "" || !hasString(launchClosureAutomationDispatch.Assignments[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked dispatch tied to brief and cell, got %+v", launchClosureAutomationDispatch)
	}
	launchClosureAutomationDirective, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationDirective(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationDirective failed: %v", err)
	}
	if launchClosureAutomationDirective.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked || launchClosureAutomationDirective.FocusAction != "clear_blocked_closure_path" {
		t.Fatalf("expected blocked launch closure automation directive focus, got %+v", launchClosureAutomationDirective)
	}
	if launchClosureAutomationDirective.Severity != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityCritical || launchClosureAutomationDirective.ExecutionWindow != "immediate" || !launchClosureAutomationDirective.EscalationRequired {
		t.Fatalf("expected blocked launch closure automation directive severity/window/escalation, got %+v", launchClosureAutomationDirective)
	}
	if launchClosureAutomationDirective.AssignmentCount != 1 || len(launchClosureAutomationDirective.Assignments) != 1 || launchClosureAutomationDirective.Assignments[0].PendingAction != "escalate_blocked_closure" {
		t.Fatalf("expected blocked launch closure automation directive assignments, got %+v", launchClosureAutomationDirective)
	}
	if launchClosureAutomationDirective.DispatchID == "" || launchClosureAutomationDirective.DirectiveDigest == "" || !hasString(launchClosureAutomationDirective.Assignments[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked directive tied to dispatch and cell, got %+v", launchClosureAutomationDirective)
	}
	launchClosureAutomationAcknowledgement, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement failed: %v", err)
	}
	if launchClosureAutomationAcknowledgement.FocusLane != SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked || launchClosureAutomationAcknowledgement.FocusAction != "clear_blocked_closure_path" {
		t.Fatalf("expected blocked launch closure automation acknowledgement focus, got %+v", launchClosureAutomationAcknowledgement)
	}
	if launchClosureAutomationAcknowledgement.AckStatus != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatusOverdue || launchClosureAutomationAcknowledgement.AckAction != "escalate_launch_closure_acknowledgement" {
		t.Fatalf("expected blocked launch closure automation acknowledgement status/action, got %+v", launchClosureAutomationAcknowledgement)
	}
	if len(launchClosureAutomationAcknowledgement.RequiredRoles) != 1 || launchClosureAutomationAcknowledgement.RequiredRoles[0] != "incident_commander" || !launchClosureAutomationAcknowledgement.EscalationRequired {
		t.Fatalf("expected blocked launch closure automation acknowledgement role/escalation, got %+v", launchClosureAutomationAcknowledgement)
	}
	if launchClosureAutomationAcknowledgement.DirectiveID == "" || launchClosureAutomationAcknowledgement.AcknowledgementDigest == "" || !hasString(launchClosureAutomationAcknowledgement.Assignments[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked acknowledgement tied to directive and cell, got %+v", launchClosureAutomationAcknowledgement)
	}
	launchClosureAutomationAcknowledgementReceipt, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceipt.ReceiptStatus != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatusOverdue || launchClosureAutomationAcknowledgementReceipt.ReceiptAction != "escalate_missing_launch_closure_ack_receipt" {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt status/action, got %+v", launchClosureAutomationAcknowledgementReceipt)
	}
	if !hasString(launchClosureAutomationAcknowledgementReceipt.ReceiptEvidence, "escalation_owner_confirmation") || !launchClosureAutomationAcknowledgementReceipt.EscalationRequired {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt escalation evidence, got %+v", launchClosureAutomationAcknowledgementReceipt)
	}
	if launchClosureAutomationAcknowledgementReceipt.AcknowledgementID == "" || launchClosureAutomationAcknowledgementReceipt.ReceiptDigest == "" || !hasString(launchClosureAutomationAcknowledgementReceipt.Assignments[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked acknowledgement receipt tied to acknowledgement and cell, got %+v", launchClosureAutomationAcknowledgementReceipt)
	}
	launchClosureAutomationAcknowledgementReceiptManifest, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceiptManifest.ReceiptStatus != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatusOverdue || launchClosureAutomationAcknowledgementReceiptManifest.EscalationEvidenceCount == 0 {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt manifest status/evidence counts, got %+v", launchClosureAutomationAcknowledgementReceiptManifest)
	}
	if !hasLaunchClosureAutomationAckReceiptManifestEvidence(launchClosureAutomationAcknowledgementReceiptManifest.Items, "escalation_owner_confirmation") || !hasString(launchClosureAutomationAcknowledgementReceiptManifest.Items[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt manifest evidence and cell, got %+v", launchClosureAutomationAcknowledgementReceiptManifest)
	}
	if launchClosureAutomationAcknowledgementReceiptManifest.AcknowledgementReceiptID == "" || launchClosureAutomationAcknowledgementReceiptManifest.ManifestDigest == "" {
		t.Fatalf("expected blocked acknowledgement receipt manifest tied to receipt, got %+v", launchClosureAutomationAcknowledgementReceiptManifest)
	}
	launchClosureAutomationAcknowledgementReceiptEvidenceQueue, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceQueue.Status != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusEscalation || launchClosureAutomationAcknowledgementReceiptEvidenceQueue.EscalationCount == 0 {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt evidence queue status/counts, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceQueue)
	}
	if !hasLaunchClosureAutomationAckReceiptEvidenceQueueEvidence(launchClosureAutomationAcknowledgementReceiptEvidenceQueue.Items, "escalation_owner_confirmation") || !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceQueue.Items[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt evidence queue evidence and cell, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceQueue)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceQueue.Items[0].Priority != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityCritical || launchClosureAutomationAcknowledgementReceiptEvidenceQueue.Items[0].Action != "collect_escalation_ack_receipt_evidence" {
		t.Fatalf("expected critical blocked acknowledgement receipt evidence queue item, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceQueue.Items[0])
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceQueue.ManifestID == "" || launchClosureAutomationAcknowledgementReceiptEvidenceQueue.QueueDigest == "" {
		t.Fatalf("expected blocked acknowledgement receipt evidence queue tied to manifest, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceQueue)
	}
	launchClosureAutomationAcknowledgementReceiptEvidenceDispatch, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Status != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusEscalation || launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.EscalationDispatchCount == 0 {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt evidence dispatch status/counts, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatch)
	}
	if !hasLaunchClosureAutomationAckReceiptEvidenceDispatchEvidence(launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Items, "escalation_owner_confirmation") || !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Items[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt evidence dispatch evidence and cell, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatch)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Items[0].DispatchChannel != "incident_command_channel" || launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Items[0].EscalationTarget != "incident_commander" {
		t.Fatalf("expected incident command dispatch for blocked acknowledgement receipt evidence, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.Items[0])
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.QueueID == "" || launchClosureAutomationAcknowledgementReceiptEvidenceDispatch.DispatchDigest == "" {
		t.Fatalf("expected blocked acknowledgement receipt evidence dispatch tied to queue, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatch)
	}
	launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Status != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusEscalationRequired || launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.EscalationAcceptanceCount == 0 {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt evidence dispatch acceptance status/counts, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance)
	}
	if !hasLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceEvidence(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Items, "escalation_owner_confirmation") || !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Items[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt evidence dispatch acceptance evidence and cell, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Items[0].AcceptanceChannel != "incident_command_acceptance" || !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Items[0].AcceptanceEvidence, "incident_command_acceptance_authorization") {
		t.Fatalf("expected incident command acceptance for blocked acknowledgement receipt evidence dispatch, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.Items[0])
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.DispatchID == "" || launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance.AcceptanceDigest == "" {
		t.Fatalf("expected blocked acknowledgement receipt evidence dispatch acceptance tied to dispatch, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance)
	}
	launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt, err := service.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: created.CellID,
		Before: &blockedOverdueAt,
	})
	if err != nil {
		t.Fatalf("GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt failed: %v", err)
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Status != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusEscalation || launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.EscalationReceiptCount == 0 {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt evidence dispatch acceptance receipt status/counts, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt)
	}
	if !hasLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptEvidence(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Items, "escalation_owner_confirmation") || !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Items[0].CellIDs, created.CellID) {
		t.Fatalf("expected blocked launch closure automation acknowledgement receipt evidence dispatch acceptance receipt evidence and cell, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt)
	}
	if !hasString(launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Items[0].ReceiptEvidence, "incident_command_receipt_authorization") || launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Items[0].ReceiptAction != "issue_escalated_ack_receipt_evidence_dispatch_acceptance_receipt" {
		t.Fatalf("expected incident command custody receipt for blocked acknowledgement receipt evidence dispatch, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.Items[0])
	}
	if launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.AcceptanceID == "" || launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt.AcceptanceReceiptDigest == "" {
		t.Fatalf("expected blocked acknowledgement receipt evidence dispatch acceptance receipt tied to acceptance, got %+v", launchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt)
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

func hasLaunchClosureAutomationAckReceiptManifestEvidence(items []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem, evidence string) bool {
	for _, item := range items {
		if item.Evidence == evidence {
			return true
		}
	}
	return false
}

func hasLaunchClosureAutomationAckReceiptEvidenceQueueEvidence(items []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem, evidence string) bool {
	for _, item := range items {
		if item.Evidence == evidence {
			return true
		}
	}
	return false
}

func hasLaunchClosureAutomationAckReceiptEvidenceDispatchEvidence(items []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem, evidence string) bool {
	for _, item := range items {
		if item.Evidence == evidence {
			return true
		}
	}
	return false
}

func hasLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceEvidence(items []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem, evidence string) bool {
	for _, item := range items {
		if item.Evidence == evidence {
			return true
		}
	}
	return false
}

func hasLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptEvidence(items []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem, evidence string) bool {
	for _, item := range items {
		if item.Evidence == evidence {
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

func hasGovernmentAgentExecutionLaunchActivationCheck(
	checks []SecureCellGovernmentAgentExecutionLaunchActivationCheck,
	code string,
	status SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus,
) bool {
	for _, check := range checks {
		if check.Code == code && check.Status == status {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchOrderStopCondition(
	conditions []SecureCellGovernmentAgentExecutionLaunchOrderStopCondition,
	code string,
	priority SecureCellGovernmentAgentExecutionLaunchOrderStopPriority,
) bool {
	for _, condition := range conditions {
		if condition.Code == code && condition.Priority == priority {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchMonitorCheckpoint(
	checkpoints []SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint,
	kind string,
	receiptType string,
	status SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus,
) bool {
	for _, checkpoint := range checkpoints {
		if checkpoint.Kind == kind && checkpoint.Status == status && (receiptType == "" || checkpoint.ReceiptType == receiptType) {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchReceiptIntakeItem(
	items []SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItem,
	receiptType string,
	status SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus,
) bool {
	for _, item := range items {
		if item.ReceiptType == receiptType && item.Status == status {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchCloseoutGate(
	gates []SecureCellGovernmentAgentExecutionLaunchCloseoutGate,
	receiptType string,
	status SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus,
) bool {
	for _, gate := range gates {
		if gate.ReceiptType == receiptType && gate.Status == status {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchSettlementItem(
	items []SecureCellGovernmentAgentExecutionLaunchSettlementItem,
	receiptType string,
	status SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus,
) bool {
	for _, item := range items {
		if item.ReceiptType == receiptType && item.Status == status {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchArchiveCertificateItem(
	items []SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItem,
	receiptType string,
	status SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus,
) bool {
	for _, item := range items {
		if item.ReceiptType == receiptType && item.Status == status {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchClosureItem(
	items []SecureCellGovernmentAgentExecutionLaunchClosureItem,
	receiptType string,
	status SecureCellGovernmentAgentExecutionLaunchClosureItemStatus,
) bool {
	for _, item := range items {
		if item.ReceiptType == receiptType && item.Status == status {
			return true
		}
	}
	return false
}

func hasGovernmentAgentExecutionLaunchClosureBoardItem(
	items []SecureCellGovernmentAgentExecutionLaunchClosureBoardItem,
	receiptType string,
	status SecureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus,
) bool {
	for _, item := range items {
		if item.ReceiptType == receiptType && item.Status == status {
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
