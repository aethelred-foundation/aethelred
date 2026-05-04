package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionHandoffVerificationStatus describes
// whether a handoff bundle and all of its bound components verified cleanly.
type SecureCellGovernmentAgentExecutionHandoffVerificationStatus string

const (
	SecureCellGovernmentAgentExecutionHandoffVerificationFailed       SecureCellGovernmentAgentExecutionHandoffVerificationStatus = "verification_failed"
	SecureCellGovernmentAgentExecutionHandoffVerificationWithBlockers SecureCellGovernmentAgentExecutionHandoffVerificationStatus = "verified_with_blockers"
	SecureCellGovernmentAgentExecutionHandoffVerificationVerified     SecureCellGovernmentAgentExecutionHandoffVerificationStatus = "verified"
)

// SecureCellGovernmentAgentExecutionHandoffVerificationOutcome records one
// deterministic verifier result.
type SecureCellGovernmentAgentExecutionHandoffVerificationOutcome string

const (
	SecureCellGovernmentAgentExecutionHandoffVerificationPass SecureCellGovernmentAgentExecutionHandoffVerificationOutcome = "pass"
	SecureCellGovernmentAgentExecutionHandoffVerificationWarn SecureCellGovernmentAgentExecutionHandoffVerificationOutcome = "warn"
	SecureCellGovernmentAgentExecutionHandoffVerificationFail SecureCellGovernmentAgentExecutionHandoffVerificationOutcome = "fail"
)

// SecureCellGovernmentAgentExecutionHandoffVerificationCheck is one evidence
// check over a handoff bundle and its component links.
type SecureCellGovernmentAgentExecutionHandoffVerificationCheck struct {
	CheckID        string                                                       `json:"check_id"`
	Code           string                                                       `json:"code"`
	Outcome        SecureCellGovernmentAgentExecutionHandoffVerificationOutcome `json:"outcome"`
	Detail         string                                                       `json:"detail"`
	Recommendation string                                                       `json:"recommendation,omitempty"`
	GeneratedAt    time.Time                                                    `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionHandoffVerification is the operator-facing
// proof that a handoff bundle is internally consistent before execution.
type SecureCellGovernmentAgentExecutionHandoffVerification struct {
	VerificationID         string                                                       `json:"verification_id"`
	BundleID               string                                                       `json:"bundle_id"`
	CellID                 string                                                       `json:"cell_id"`
	Name                   string                                                       `json:"name"`
	Jurisdiction           string                                                       `json:"jurisdiction,omitempty"`
	ServiceCode            string                                                       `json:"service_code,omitempty"`
	ServiceTier            string                                                       `json:"service_tier,omitempty"`
	Status                 SecureCellGovernmentAgentExecutionHandoffVerificationStatus  `json:"status"`
	BundleStatus           SecureCellGovernmentAgentExecutionHandoffBundleStatus        `json:"bundle_status"`
	CarryMode              SecureCellGovernmentAgentCarryMode                           `json:"carry_mode"`
	CanHandoff             bool                                                         `json:"can_handoff"`
	CanAutonomousHandoff   bool                                                         `json:"can_autonomous_handoff"`
	RequiresOperatorReview bool                                                         `json:"requires_operator_review"`
	CheckCount             int                                                          `json:"check_count"`
	PassCount              int                                                          `json:"pass_count"`
	WarnCount              int                                                          `json:"warn_count"`
	FailCount              int                                                          `json:"fail_count"`
	BlockedActionCount     int                                                          `json:"blocked_action_count"`
	ReleaseGateActionCount int                                                          `json:"release_gate_action_count"`
	ReceiptCollectionCount int                                                          `json:"receipt_collection_count"`
	RequiredReceiptTypes   []string                                                     `json:"required_receipt_types,omitempty"`
	TopBlockerCodes        []string                                                     `json:"top_blocker_codes,omitempty"`
	MissingPreconditions   []string                                                     `json:"missing_preconditions,omitempty"`
	WitnessID              string                                                       `json:"witness_id"`
	LedgerID               string                                                       `json:"ledger_id"`
	QueueID                string                                                       `json:"queue_id"`
	WitnessDigest          string                                                       `json:"witness_digest"`
	ExpectedWitnessDigest  string                                                       `json:"expected_witness_digest"`
	LedgerDigest           string                                                       `json:"ledger_digest"`
	ExpectedLedgerDigest   string                                                       `json:"expected_ledger_digest"`
	QueueDigest            string                                                       `json:"queue_digest"`
	ExpectedQueueDigest    string                                                       `json:"expected_queue_digest"`
	BundleDigest           string                                                       `json:"bundle_digest"`
	ExpectedBundleDigest   string                                                       `json:"expected_bundle_digest"`
	Checks                 []SecureCellGovernmentAgentExecutionHandoffVerificationCheck `json:"checks"`
	VerificationDigest     string                                                       `json:"verification_digest"`
	GeneratedAt            time.Time                                                    `json:"generated_at"`
	UpdatedAt              time.Time                                                    `json:"updated_at"`
}

// GetGovernmentAgentExecutionHandoffVerification returns the bundle verifier
// result for one secure cell.
func (s *Service) GetGovernmentAgentExecutionHandoffVerification(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionHandoffVerification, error) {
	items, err := s.ListGovernmentAgentExecutionHandoffVerifications(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-handoff-verification: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionHandoffVerifications returns verifier results
// for matching government-service execution handoff bundles.
func (s *Service) ListGovernmentAgentExecutionHandoffVerifications(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionHandoffVerification, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-handoff-verification: service is required")
	}
	bundles, err := s.ListGovernmentAgentExecutionHandoffBundles(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	verifications := make([]SecureCellGovernmentAgentExecutionHandoffVerification, 0, len(bundles))
	for _, bundle := range bundles {
		verifications = append(verifications, secureCellGovernmentAgentExecutionHandoffVerification(bundle, now))
	}
	sort.SliceStable(verifications, func(i, j int) bool {
		if verifications[i].Status == verifications[j].Status {
			if verifications[i].FailCount == verifications[j].FailCount {
				if verifications[i].WarnCount == verifications[j].WarnCount {
					return verifications[i].CellID < verifications[j].CellID
				}
				return verifications[i].WarnCount > verifications[j].WarnCount
			}
			return verifications[i].FailCount > verifications[j].FailCount
		}
		return secureCellGovernmentAgentExecutionHandoffVerificationStatusRank(verifications[i].Status) < secureCellGovernmentAgentExecutionHandoffVerificationStatusRank(verifications[j].Status)
	})
	return verifications, nil
}

func secureCellGovernmentAgentExecutionHandoffVerification(
	bundle SecureCellGovernmentAgentExecutionHandoffBundle,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionHandoffVerification {
	expectedWitnessDigest := secureCellGovernmentAgentExecutionWitnessDigest(bundle.Witness)
	expectedLedgerDigest := secureCellGovernmentAgentExecutionReceiptLedgerDigest(bundle.ReceiptLedger)
	expectedQueueDigest := secureCellGovernmentAgentExecutionActionQueueDigest(bundle.ActionQueue)
	expectedBundleDigest := secureCellGovernmentAgentExecutionHandoffBundleDigest(bundle)

	checks := []SecureCellGovernmentAgentExecutionHandoffVerificationCheck{
		secureCellGovernmentAgentExecutionHandoffVerificationDigestCheck("WITNESS_DIGEST_BOUND", "execution witness", bundle.Witness.WitnessID, bundle.WitnessDigest, expectedWitnessDigest, generatedAt),
		secureCellGovernmentAgentExecutionHandoffVerificationDigestCheck("LEDGER_DIGEST_BOUND", "receipt ledger", bundle.ReceiptLedger.LedgerID, bundle.LedgerDigest, expectedLedgerDigest, generatedAt),
		secureCellGovernmentAgentExecutionHandoffVerificationDigestCheck("QUEUE_DIGEST_BOUND", "action queue", bundle.ActionQueue.QueueID, bundle.QueueDigest, expectedQueueDigest, generatedAt),
		secureCellGovernmentAgentExecutionHandoffVerificationDigestCheck("BUNDLE_DIGEST_BOUND", "handoff bundle", bundle.BundleID, bundle.BundleDigest, expectedBundleDigest, generatedAt),
		secureCellGovernmentAgentExecutionHandoffVerificationLinkCheck("LEDGER_WITNESS_LINK", bundle.ReceiptLedger.WitnessID == bundle.Witness.WitnessID, "Receipt ledger links to the execution witness.", "Regenerate the receipt ledger from the current execution witness.", generatedAt),
		secureCellGovernmentAgentExecutionHandoffVerificationLinkCheck("QUEUE_LEDGER_LINK", bundle.ActionQueue.LedgerID == bundle.ReceiptLedger.LedgerID, "Action queue links to the receipt ledger.", "Regenerate the action queue from the current receipt ledger.", generatedAt),
		secureCellGovernmentAgentExecutionHandoffVerificationLinkCheck("QUEUE_WITNESS_LINK", bundle.ActionQueue.WitnessID == bundle.Witness.WitnessID, "Action queue links to the execution witness.", "Regenerate the action queue from the current receipt ledger.", generatedAt),
		secureCellGovernmentAgentExecutionHandoffVerificationLinkCheck("BUNDLE_COMPONENT_DIGESTS", bundle.WitnessDigest == bundle.Witness.WitnessDigest && bundle.LedgerDigest == bundle.ReceiptLedger.LedgerDigest && bundle.QueueDigest == bundle.ActionQueue.QueueDigest, "Bundle component digests match the nested artifacts.", "Regenerate the handoff bundle from the current witness, receipt ledger, and action queue.", generatedAt),
		secureCellGovernmentAgentExecutionHandoffVerificationGateCheck(bundle, generatedAt),
		secureCellGovernmentAgentExecutionHandoffVerificationReviewCheck(bundle, generatedAt),
		secureCellGovernmentAgentExecutionHandoffVerificationReceiptCheck(bundle, generatedAt),
		secureCellGovernmentAgentExecutionHandoffVerificationInstructionCheck(bundle, generatedAt),
	}

	verification := SecureCellGovernmentAgentExecutionHandoffVerification{
		BundleID:               bundle.BundleID,
		CellID:                 bundle.CellID,
		Name:                   bundle.Name,
		Jurisdiction:           bundle.Jurisdiction,
		ServiceCode:            bundle.ServiceCode,
		ServiceTier:            bundle.ServiceTier,
		BundleStatus:           bundle.Status,
		CarryMode:              bundle.CarryMode,
		CanHandoff:             bundle.CanHandoff,
		CanAutonomousHandoff:   bundle.CanAutonomousHandoff,
		RequiresOperatorReview: bundle.RequiresOperatorReview,
		BlockedActionCount:     bundle.BlockedActionCount,
		ReleaseGateActionCount: bundle.ReleaseGateActionCount,
		ReceiptCollectionCount: bundle.ReceiptCollectionCount,
		RequiredReceiptTypes:   append([]string(nil), bundle.RequiredReceiptTypes...),
		TopBlockerCodes:        append([]string(nil), bundle.TopBlockerCodes...),
		MissingPreconditions:   append([]string(nil), bundle.MissingPreconditions...),
		WitnessID:              bundle.Witness.WitnessID,
		LedgerID:               bundle.ReceiptLedger.LedgerID,
		QueueID:                bundle.ActionQueue.QueueID,
		WitnessDigest:          bundle.WitnessDigest,
		ExpectedWitnessDigest:  expectedWitnessDigest,
		LedgerDigest:           bundle.LedgerDigest,
		ExpectedLedgerDigest:   expectedLedgerDigest,
		QueueDigest:            bundle.QueueDigest,
		ExpectedQueueDigest:    expectedQueueDigest,
		BundleDigest:           bundle.BundleDigest,
		ExpectedBundleDigest:   expectedBundleDigest,
		Checks:                 checks,
		GeneratedAt:            generatedAt.UTC(),
		UpdatedAt:              bundle.UpdatedAt.UTC(),
	}
	for _, check := range verification.Checks {
		verification.CheckCount++
		switch check.Outcome {
		case SecureCellGovernmentAgentExecutionHandoffVerificationFail:
			verification.FailCount++
		case SecureCellGovernmentAgentExecutionHandoffVerificationWarn:
			verification.WarnCount++
		default:
			verification.PassCount++
		}
	}
	verification.Status = secureCellGovernmentAgentExecutionHandoffVerificationStatus(verification)
	verification.VerificationDigest = secureCellGovernmentAgentExecutionHandoffVerificationDigest(verification)
	verification.VerificationID = "government-agent-execution-handoff-verification:" + verification.CellID + ":" + verification.VerificationDigest[:12]
	return verification
}

func secureCellGovernmentAgentExecutionHandoffVerificationDigestCheck(
	code string,
	label string,
	artifactID string,
	actualDigest string,
	expectedDigest string,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionHandoffVerificationCheck {
	outcome := SecureCellGovernmentAgentExecutionHandoffVerificationPass
	displayLabel := secureCellGovernmentAgentVerificationLabel(label)
	detail := displayLabel + " digest matches its recomputed evidence hash and bound ID."
	recommendation := ""
	if strings.TrimSpace(actualDigest) == "" {
		outcome = SecureCellGovernmentAgentExecutionHandoffVerificationFail
		detail = displayLabel + " digest is missing."
		recommendation = "Regenerate the " + label + " before handoff."
	} else if actualDigest != expectedDigest {
		outcome = SecureCellGovernmentAgentExecutionHandoffVerificationFail
		detail = displayLabel + " digest does not match its recomputed evidence hash."
		recommendation = "Regenerate the " + label + " from current upstream artifacts."
	} else if !strings.Contains(artifactID, secureCellGovernmentAgentDigestPrefix(actualDigest)) {
		outcome = SecureCellGovernmentAgentExecutionHandoffVerificationFail
		detail = displayLabel + " ID is not bound to the digest prefix."
		recommendation = "Regenerate the " + label + " so its ID carries the digest prefix."
	}
	return secureCellGovernmentAgentExecutionHandoffVerificationCheck(code, outcome, detail, recommendation, generatedAt)
}

func secureCellGovernmentAgentExecutionHandoffVerificationLinkCheck(
	code string,
	condition bool,
	passDetail string,
	recommendation string,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionHandoffVerificationCheck {
	outcome := SecureCellGovernmentAgentExecutionHandoffVerificationPass
	detail := passDetail
	if !condition {
		outcome = SecureCellGovernmentAgentExecutionHandoffVerificationFail
		detail = strings.TrimSuffix(passDetail, ".") + " check failed."
	}
	return secureCellGovernmentAgentExecutionHandoffVerificationCheck(code, outcome, detail, recommendation, generatedAt)
}

func secureCellGovernmentAgentExecutionHandoffVerificationGateCheck(
	bundle SecureCellGovernmentAgentExecutionHandoffBundle,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionHandoffVerificationCheck {
	condition := true
	if bundle.BlockedActionCount > 0 {
		condition = bundle.Status == SecureCellGovernmentAgentExecutionHandoffBundleBlocked && !bundle.CanHandoff && !bundle.CanAutonomousHandoff
	}
	return secureCellGovernmentAgentExecutionHandoffVerificationLinkCheck(
		"BLOCKER_STATUS_CONSISTENCY",
		condition,
		"Blocked actions force blocked handoff status and disable execution handoff.",
		"Resolve blocked actions and regenerate the handoff bundle.",
		generatedAt,
	)
}

func secureCellGovernmentAgentExecutionHandoffVerificationReviewCheck(
	bundle SecureCellGovernmentAgentExecutionHandoffBundle,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionHandoffVerificationCheck {
	condition := true
	if bundle.ReleaseGateActionCount > 0 {
		condition = bundle.RequiresOperatorReview && !bundle.CanAutonomousHandoff
	}
	return secureCellGovernmentAgentExecutionHandoffVerificationLinkCheck(
		"RELEASE_GATE_REVIEW_CONSISTENCY",
		condition,
		"Release gates require operator review and disable autonomous handoff.",
		"Complete release-gate approval or regenerate the action queue.",
		generatedAt,
	)
}

func secureCellGovernmentAgentExecutionHandoffVerificationReceiptCheck(
	bundle SecureCellGovernmentAgentExecutionHandoffBundle,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionHandoffVerificationCheck {
	condition := len(bundle.RequiredReceiptTypes) > 0 && bundle.ReceiptObligationCount > 0 && len(bundle.ReceiptLedger.Obligations) > 0
	return secureCellGovernmentAgentExecutionHandoffVerificationLinkCheck(
		"RECEIPT_REQUIREMENTS_PRESENT",
		condition,
		"Required receipt types and ledger obligations are present.",
		"Regenerate the receipt ledger from the execution witness.",
		generatedAt,
	)
}

func secureCellGovernmentAgentExecutionHandoffVerificationInstructionCheck(
	bundle SecureCellGovernmentAgentExecutionHandoffBundle,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionHandoffVerificationCheck {
	return secureCellGovernmentAgentExecutionHandoffVerificationLinkCheck(
		"OPERATOR_INSTRUCTIONS_PRESENT",
		len(bundle.OperatorInstructions) > 0,
		"Operator instructions are present for the handoff.",
		"Regenerate the handoff bundle to produce operator instructions.",
		generatedAt,
	)
}

func secureCellGovernmentAgentExecutionHandoffVerificationCheck(
	code string,
	outcome SecureCellGovernmentAgentExecutionHandoffVerificationOutcome,
	detail string,
	recommendation string,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionHandoffVerificationCheck {
	check := SecureCellGovernmentAgentExecutionHandoffVerificationCheck{
		Code:           strings.TrimSpace(code),
		Outcome:        outcome,
		Detail:         strings.TrimSpace(detail),
		Recommendation: strings.TrimSpace(recommendation),
		GeneratedAt:    generatedAt.UTC(),
	}
	core := struct {
		Code           string                                                       `json:"code"`
		Outcome        SecureCellGovernmentAgentExecutionHandoffVerificationOutcome `json:"outcome"`
		Detail         string                                                       `json:"detail"`
		Recommendation string                                                       `json:"recommendation,omitempty"`
	}{
		Code:           check.Code,
		Outcome:        check.Outcome,
		Detail:         check.Detail,
		Recommendation: check.Recommendation,
	}
	check.CheckID = "government-agent-execution-handoff-check:" + EvidenceHash(core)[:12]
	return check
}

func secureCellGovernmentAgentExecutionHandoffVerificationStatus(verification SecureCellGovernmentAgentExecutionHandoffVerification) SecureCellGovernmentAgentExecutionHandoffVerificationStatus {
	if verification.FailCount > 0 {
		return SecureCellGovernmentAgentExecutionHandoffVerificationFailed
	}
	if verification.BundleStatus == SecureCellGovernmentAgentExecutionHandoffBundleBlocked || verification.BlockedActionCount > 0 {
		return SecureCellGovernmentAgentExecutionHandoffVerificationWithBlockers
	}
	return SecureCellGovernmentAgentExecutionHandoffVerificationVerified
}

func secureCellGovernmentAgentExecutionHandoffVerificationStatusRank(status SecureCellGovernmentAgentExecutionHandoffVerificationStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionHandoffVerificationFailed:
		return 0
	case SecureCellGovernmentAgentExecutionHandoffVerificationWithBlockers:
		return 1
	case SecureCellGovernmentAgentExecutionHandoffVerificationVerified:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentDigestPrefix(digest string) string {
	digest = strings.TrimSpace(digest)
	if len(digest) <= 12 {
		return digest
	}
	return digest[:12]
}

func secureCellGovernmentAgentVerificationLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return label
	}
	return strings.ToUpper(label[:1]) + label[1:]
}

func secureCellGovernmentAgentExecutionWitnessDigest(witness SecureCellGovernmentAgentExecutionWitness) string {
	core := struct {
		CellID                 string                                          `json:"cell_id"`
		CarryPackID            string                                          `json:"carry_pack_id"`
		RehearsalID            string                                          `json:"rehearsal_id"`
		Status                 SecureCellGovernmentAgentExecutionWitnessStatus `json:"status"`
		ExecutionWitnessScore  int                                             `json:"execution_witness_score"`
		RequiredInputEvidence  []string                                        `json:"required_input_evidence,omitempty"`
		ExpectedReturnReceipts []string                                        `json:"expected_return_receipts,omitempty"`
		OperatorAttestations   []string                                        `json:"operator_attestations,omitempty"`
		TopBlockerCodes        []string                                        `json:"top_blocker_codes,omitempty"`
		MissingPreconditions   []string                                        `json:"missing_preconditions,omitempty"`
		Steps                  []SecureCellGovernmentAgentExecutionWitnessStep `json:"steps"`
		CarryPackDigest        string                                          `json:"carry_pack_digest"`
		RehearsalDigest        string                                          `json:"rehearsal_digest"`
	}{
		CellID:                 witness.CellID,
		CarryPackID:            witness.CarryPackID,
		RehearsalID:            witness.RehearsalID,
		Status:                 witness.Status,
		ExecutionWitnessScore:  witness.ExecutionWitnessScore,
		RequiredInputEvidence:  witness.RequiredInputEvidence,
		ExpectedReturnReceipts: witness.ExpectedReturnReceipts,
		OperatorAttestations:   witness.OperatorAttestations,
		TopBlockerCodes:        witness.TopBlockerCodes,
		MissingPreconditions:   witness.MissingPreconditions,
		Steps:                  witness.Steps,
		CarryPackDigest:        witness.CarryPackDigest,
		RehearsalDigest:        witness.RehearsalDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionReceiptLedgerDigest(ledger SecureCellGovernmentAgentExecutionReceiptLedger) string {
	obligationDigests := make([]string, 0, len(ledger.Obligations))
	for _, obligation := range ledger.Obligations {
		obligationDigests = append(obligationDigests, obligation.ObligationDigest)
	}
	core := struct {
		CellID               string                                                `json:"cell_id"`
		WitnessID            string                                                `json:"witness_id"`
		Status               SecureCellGovernmentAgentExecutionReceiptLedgerStatus `json:"status"`
		ReceiptTypes         []string                                              `json:"receipt_types,omitempty"`
		TopBlockerCodes      []string                                              `json:"top_blocker_codes,omitempty"`
		MissingPreconditions []string                                              `json:"missing_preconditions,omitempty"`
		ObligationDigests    []string                                              `json:"obligation_digests"`
		WitnessDigest        string                                                `json:"witness_digest"`
	}{
		CellID:               ledger.CellID,
		WitnessID:            ledger.WitnessID,
		Status:               ledger.Status,
		ReceiptTypes:         ledger.ReceiptTypes,
		TopBlockerCodes:      ledger.TopBlockerCodes,
		MissingPreconditions: ledger.MissingPreconditions,
		ObligationDigests:    obligationDigests,
		WitnessDigest:        ledger.WitnessDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionActionQueueDigest(queue SecureCellGovernmentAgentExecutionActionQueue) string {
	actionDigests := make([]string, 0, len(queue.Actions))
	for _, action := range queue.Actions {
		actionDigests = append(actionDigests, action.ActionDigest)
	}
	core := struct {
		CellID               string                                              `json:"cell_id"`
		LedgerID             string                                              `json:"ledger_id"`
		Status               SecureCellGovernmentAgentExecutionActionQueueStatus `json:"status"`
		TopBlockerCodes      []string                                            `json:"top_blocker_codes,omitempty"`
		MissingPreconditions []string                                            `json:"missing_preconditions,omitempty"`
		ActionDigests        []string                                            `json:"action_digests"`
		LedgerDigest         string                                              `json:"ledger_digest"`
	}{
		CellID:               queue.CellID,
		LedgerID:             queue.LedgerID,
		Status:               queue.Status,
		TopBlockerCodes:      queue.TopBlockerCodes,
		MissingPreconditions: queue.MissingPreconditions,
		ActionDigests:        actionDigests,
		LedgerDigest:         queue.LedgerDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionHandoffBundleDigest(bundle SecureCellGovernmentAgentExecutionHandoffBundle) string {
	core := struct {
		BundleVersion              string                                                `json:"bundle_version"`
		CellID                     string                                                `json:"cell_id"`
		Status                     SecureCellGovernmentAgentExecutionHandoffBundleStatus `json:"status"`
		CanHandoff                 bool                                                  `json:"can_handoff"`
		CanAutonomousHandoff       bool                                                  `json:"can_autonomous_handoff"`
		BlockedActionCount         int                                                   `json:"blocked_action_count"`
		ReleaseGateActionCount     int                                                   `json:"release_gate_action_count"`
		ReceiptCollectionCount     int                                                   `json:"receipt_collection_count"`
		EscalationRecommendedCount int                                                   `json:"escalation_recommended_count"`
		RequiredReceiptTypes       []string                                              `json:"required_receipt_types,omitempty"`
		TopBlockerCodes            []string                                              `json:"top_blocker_codes,omitempty"`
		MissingPreconditions       []string                                              `json:"missing_preconditions,omitempty"`
		OperatorInstructions       []string                                              `json:"operator_instructions,omitempty"`
		WitnessDigest              string                                                `json:"witness_digest"`
		LedgerDigest               string                                                `json:"ledger_digest"`
		QueueDigest                string                                                `json:"queue_digest"`
	}{
		BundleVersion:              bundle.BundleVersion,
		CellID:                     bundle.CellID,
		Status:                     bundle.Status,
		CanHandoff:                 bundle.CanHandoff,
		CanAutonomousHandoff:       bundle.CanAutonomousHandoff,
		BlockedActionCount:         bundle.BlockedActionCount,
		ReleaseGateActionCount:     bundle.ReleaseGateActionCount,
		ReceiptCollectionCount:     bundle.ReceiptCollectionCount,
		EscalationRecommendedCount: bundle.EscalationRecommendedCount,
		RequiredReceiptTypes:       bundle.RequiredReceiptTypes,
		TopBlockerCodes:            bundle.TopBlockerCodes,
		MissingPreconditions:       bundle.MissingPreconditions,
		OperatorInstructions:       bundle.OperatorInstructions,
		WitnessDigest:              bundle.WitnessDigest,
		LedgerDigest:               bundle.LedgerDigest,
		QueueDigest:                bundle.QueueDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionHandoffVerificationDigest(verification SecureCellGovernmentAgentExecutionHandoffVerification) string {
	checkIDs := make([]string, 0, len(verification.Checks))
	for _, check := range verification.Checks {
		checkIDs = append(checkIDs, check.CheckID)
	}
	core := struct {
		BundleID              string                                                      `json:"bundle_id"`
		CellID                string                                                      `json:"cell_id"`
		Status                SecureCellGovernmentAgentExecutionHandoffVerificationStatus `json:"status"`
		BundleStatus          SecureCellGovernmentAgentExecutionHandoffBundleStatus       `json:"bundle_status"`
		CanHandoff            bool                                                        `json:"can_handoff"`
		CanAutonomousHandoff  bool                                                        `json:"can_autonomous_handoff"`
		CheckIDs              []string                                                    `json:"check_ids"`
		WitnessDigest         string                                                      `json:"witness_digest"`
		ExpectedWitnessDigest string                                                      `json:"expected_witness_digest"`
		LedgerDigest          string                                                      `json:"ledger_digest"`
		ExpectedLedgerDigest  string                                                      `json:"expected_ledger_digest"`
		QueueDigest           string                                                      `json:"queue_digest"`
		ExpectedQueueDigest   string                                                      `json:"expected_queue_digest"`
		BundleDigest          string                                                      `json:"bundle_digest"`
		ExpectedBundleDigest  string                                                      `json:"expected_bundle_digest"`
	}{
		BundleID:              verification.BundleID,
		CellID:                verification.CellID,
		Status:                verification.Status,
		BundleStatus:          verification.BundleStatus,
		CanHandoff:            verification.CanHandoff,
		CanAutonomousHandoff:  verification.CanAutonomousHandoff,
		CheckIDs:              checkIDs,
		WitnessDigest:         verification.WitnessDigest,
		ExpectedWitnessDigest: verification.ExpectedWitnessDigest,
		LedgerDigest:          verification.LedgerDigest,
		ExpectedLedgerDigest:  verification.ExpectedLedgerDigest,
		QueueDigest:           verification.QueueDigest,
		ExpectedQueueDigest:   verification.ExpectedQueueDigest,
		BundleDigest:          verification.BundleDigest,
		ExpectedBundleDigest:  verification.ExpectedBundleDigest,
	}
	return EvidenceHash(core)
}
