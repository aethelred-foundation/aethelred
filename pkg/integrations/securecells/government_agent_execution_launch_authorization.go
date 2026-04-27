package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus is the launch
// posture after a verified handoff bundle is checked against runtime gates.
type SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchAuthorizationBlocked                SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchAuthorizationOperatorReviewRequired SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus = "operator_review_required"
	SecureCellGovernmentAgentExecutionLaunchAuthorizationSupervised             SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus = "authorized_supervised"
	SecureCellGovernmentAgentExecutionLaunchAuthorizationAutonomous             SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus = "authorized_autonomous"
)

// SecureCellGovernmentAgentExecutionLaunchGateStatus records one launch gate
// outcome for a government-service execution handoff.
type SecureCellGovernmentAgentExecutionLaunchGateStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchGatePass  SecureCellGovernmentAgentExecutionLaunchGateStatus = "pass"
	SecureCellGovernmentAgentExecutionLaunchGateHold  SecureCellGovernmentAgentExecutionLaunchGateStatus = "hold"
	SecureCellGovernmentAgentExecutionLaunchGateBlock SecureCellGovernmentAgentExecutionLaunchGateStatus = "block"
)

// SecureCellGovernmentAgentExecutionLaunchGate is one deterministic launch
// condition derived from a verified handoff bundle.
type SecureCellGovernmentAgentExecutionLaunchGate struct {
	GateID            string                                             `json:"gate_id"`
	Code              string                                             `json:"code"`
	Status            SecureCellGovernmentAgentExecutionLaunchGateStatus `json:"status"`
	Detail            string                                             `json:"detail"`
	RequiredAction    string                                             `json:"required_action,omitempty"`
	EvidenceBindingID string                                             `json:"evidence_binding_id,omitempty"`
	GeneratedAt       time.Time                                          `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchAuthorization is the final derived
// launch decision operators can use before starting execution.
type SecureCellGovernmentAgentExecutionLaunchAuthorization struct {
	AuthorizationID                      string                                                      `json:"authorization_id"`
	VerificationID                       string                                                      `json:"verification_id"`
	BundleID                             string                                                      `json:"bundle_id"`
	CellID                               string                                                      `json:"cell_id"`
	Name                                 string                                                      `json:"name"`
	Jurisdiction                         string                                                      `json:"jurisdiction,omitempty"`
	ServiceCode                          string                                                      `json:"service_code,omitempty"`
	ServiceTier                          string                                                      `json:"service_tier,omitempty"`
	Status                               SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus `json:"status"`
	VerificationStatus                   SecureCellGovernmentAgentExecutionHandoffVerificationStatus `json:"verification_status"`
	BundleStatus                         SecureCellGovernmentAgentExecutionHandoffBundleStatus       `json:"bundle_status"`
	CarryMode                            SecureCellGovernmentAgentCarryMode                          `json:"carry_mode"`
	CanLaunchNow                         bool                                                        `json:"can_launch_now"`
	CanLaunchAfterOperatorReview         bool                                                        `json:"can_launch_after_operator_review"`
	CanAutonomousLaunch                  bool                                                        `json:"can_autonomous_launch"`
	RequiresOperatorReview               bool                                                        `json:"requires_operator_review"`
	RequiredOperatorAcknowledgementCount int                                                         `json:"required_operator_acknowledgement_count"`
	GateCount                            int                                                         `json:"gate_count"`
	PassGateCount                        int                                                         `json:"pass_gate_count"`
	HoldGateCount                        int                                                         `json:"hold_gate_count"`
	BlockGateCount                       int                                                         `json:"block_gate_count"`
	FailedVerificationCheckCount         int                                                         `json:"failed_verification_check_count"`
	BlockedActionCount                   int                                                         `json:"blocked_action_count"`
	ReleaseGateActionCount               int                                                         `json:"release_gate_action_count"`
	ReceiptCollectionCount               int                                                         `json:"receipt_collection_count"`
	RequiredReceiptTypes                 []string                                                    `json:"required_receipt_types,omitempty"`
	TopBlockerCodes                      []string                                                    `json:"top_blocker_codes,omitempty"`
	MissingPreconditions                 []string                                                    `json:"missing_preconditions,omitempty"`
	WitnessID                            string                                                      `json:"witness_id"`
	LedgerID                             string                                                      `json:"ledger_id"`
	QueueID                              string                                                      `json:"queue_id"`
	VerificationDigest                   string                                                      `json:"verification_digest"`
	BundleDigest                         string                                                      `json:"bundle_digest"`
	LaunchDigest                         string                                                      `json:"launch_digest"`
	Gates                                []SecureCellGovernmentAgentExecutionLaunchGate              `json:"gates"`
	GeneratedAt                          time.Time                                                   `json:"generated_at"`
	UpdatedAt                            time.Time                                                   `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchAuthorization returns the launch decision
// for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchAuthorization(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchAuthorization, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchAuthorizations(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-authorization: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchAuthorizations returns launch decisions
// for matching government-service handoff verifications.
func (s *Service) ListGovernmentAgentExecutionLaunchAuthorizations(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchAuthorization, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-authorization: service is required")
	}
	verifications, err := s.ListGovernmentAgentExecutionHandoffVerifications(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	authorizations := make([]SecureCellGovernmentAgentExecutionLaunchAuthorization, 0, len(verifications))
	for _, verification := range verifications {
		authorizations = append(authorizations, secureCellGovernmentAgentExecutionLaunchAuthorization(verification, now))
	}
	sort.SliceStable(authorizations, func(i, j int) bool {
		if authorizations[i].Status == authorizations[j].Status {
			if authorizations[i].BlockGateCount == authorizations[j].BlockGateCount {
				if authorizations[i].HoldGateCount == authorizations[j].HoldGateCount {
					return authorizations[i].CellID < authorizations[j].CellID
				}
				return authorizations[i].HoldGateCount > authorizations[j].HoldGateCount
			}
			return authorizations[i].BlockGateCount > authorizations[j].BlockGateCount
		}
		return secureCellGovernmentAgentExecutionLaunchAuthorizationStatusRank(authorizations[i].Status) < secureCellGovernmentAgentExecutionLaunchAuthorizationStatusRank(authorizations[j].Status)
	})
	return authorizations, nil
}

func secureCellGovernmentAgentExecutionLaunchAuthorization(
	verification SecureCellGovernmentAgentExecutionHandoffVerification,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchAuthorization {
	gates := []SecureCellGovernmentAgentExecutionLaunchGate{
		secureCellGovernmentAgentExecutionLaunchVerificationGate(verification, generatedAt),
		secureCellGovernmentAgentExecutionLaunchBlockerGate(verification, generatedAt),
		secureCellGovernmentAgentExecutionLaunchReviewGate(verification, generatedAt),
		secureCellGovernmentAgentExecutionLaunchReceiptGate(verification, generatedAt),
		secureCellGovernmentAgentExecutionLaunchDigestGate(verification, generatedAt),
		secureCellGovernmentAgentExecutionLaunchModeGate(verification, generatedAt),
		secureCellGovernmentAgentExecutionLaunchCapabilityGate(verification, generatedAt),
	}
	authorization := SecureCellGovernmentAgentExecutionLaunchAuthorization{
		VerificationID:                       verification.VerificationID,
		BundleID:                             verification.BundleID,
		CellID:                               verification.CellID,
		Name:                                 verification.Name,
		Jurisdiction:                         verification.Jurisdiction,
		ServiceCode:                          verification.ServiceCode,
		ServiceTier:                          verification.ServiceTier,
		VerificationStatus:                   verification.Status,
		BundleStatus:                         verification.BundleStatus,
		CarryMode:                            verification.CarryMode,
		RequiresOperatorReview:               verification.RequiresOperatorReview,
		RequiredOperatorAcknowledgementCount: secureCellGovernmentAgentExecutionLaunchAcknowledgementCount(verification),
		FailedVerificationCheckCount:         verification.FailCount,
		BlockedActionCount:                   verification.BlockedActionCount,
		ReleaseGateActionCount:               verification.ReleaseGateActionCount,
		ReceiptCollectionCount:               verification.ReceiptCollectionCount,
		RequiredReceiptTypes:                 append([]string(nil), verification.RequiredReceiptTypes...),
		TopBlockerCodes:                      append([]string(nil), verification.TopBlockerCodes...),
		MissingPreconditions:                 append([]string(nil), verification.MissingPreconditions...),
		WitnessID:                            verification.WitnessID,
		LedgerID:                             verification.LedgerID,
		QueueID:                              verification.QueueID,
		VerificationDigest:                   verification.VerificationDigest,
		BundleDigest:                         verification.BundleDigest,
		Gates:                                gates,
		GeneratedAt:                          generatedAt.UTC(),
		UpdatedAt:                            verification.UpdatedAt.UTC(),
	}
	for _, gate := range authorization.Gates {
		authorization.GateCount++
		switch gate.Status {
		case SecureCellGovernmentAgentExecutionLaunchGateBlock:
			authorization.BlockGateCount++
		case SecureCellGovernmentAgentExecutionLaunchGateHold:
			authorization.HoldGateCount++
		default:
			authorization.PassGateCount++
		}
	}
	authorization.Status = secureCellGovernmentAgentExecutionLaunchAuthorizationStatus(authorization, verification)
	authorization.CanLaunchNow = authorization.Status == SecureCellGovernmentAgentExecutionLaunchAuthorizationSupervised || authorization.Status == SecureCellGovernmentAgentExecutionLaunchAuthorizationAutonomous
	authorization.CanLaunchAfterOperatorReview = authorization.Status == SecureCellGovernmentAgentExecutionLaunchAuthorizationOperatorReviewRequired && verification.CanHandoff && verification.FailCount == 0 && verification.BlockedActionCount == 0
	authorization.CanAutonomousLaunch = authorization.Status == SecureCellGovernmentAgentExecutionLaunchAuthorizationAutonomous
	authorization.LaunchDigest = secureCellGovernmentAgentExecutionLaunchAuthorizationDigest(authorization)
	authorization.AuthorizationID = "government-agent-execution-launch-authorization:" + authorization.CellID + ":" + authorization.LaunchDigest[:12]
	return authorization
}

func secureCellGovernmentAgentExecutionLaunchVerificationGate(
	verification SecureCellGovernmentAgentExecutionHandoffVerification,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchGate {
	if verification.FailCount > 0 || verification.Status == SecureCellGovernmentAgentExecutionHandoffVerificationFailed {
		return secureCellGovernmentAgentExecutionLaunchGate(
			"VERIFICATION_CLEAR",
			SecureCellGovernmentAgentExecutionLaunchGateBlock,
			"Handoff verification has failed checks.",
			"Regenerate or remediate the handoff verification before launch.",
			verification.VerificationID,
			generatedAt,
		)
	}
	return secureCellGovernmentAgentExecutionLaunchGate(
		"VERIFICATION_CLEAR",
		SecureCellGovernmentAgentExecutionLaunchGatePass,
		"Handoff verification has no failed checks.",
		"",
		verification.VerificationID,
		generatedAt,
	)
}

func secureCellGovernmentAgentExecutionLaunchBlockerGate(
	verification SecureCellGovernmentAgentExecutionHandoffVerification,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchGate {
	if verification.BlockedActionCount > 0 || verification.Status == SecureCellGovernmentAgentExecutionHandoffVerificationWithBlockers {
		return secureCellGovernmentAgentExecutionLaunchGate(
			"BLOCKERS_CLEARED",
			SecureCellGovernmentAgentExecutionLaunchGateBlock,
			"Blocked actions or missing preconditions prevent launch.",
			"Resolve blockers and regenerate the action queue, bundle, and verification.",
			verification.QueueID,
			generatedAt,
		)
	}
	return secureCellGovernmentAgentExecutionLaunchGate(
		"BLOCKERS_CLEARED",
		SecureCellGovernmentAgentExecutionLaunchGatePass,
		"No blocked actions prevent launch.",
		"",
		verification.QueueID,
		generatedAt,
	)
}

func secureCellGovernmentAgentExecutionLaunchReviewGate(
	verification SecureCellGovernmentAgentExecutionHandoffVerification,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchGate {
	if verification.RequiresOperatorReview || verification.ReleaseGateActionCount > 0 {
		return secureCellGovernmentAgentExecutionLaunchGate(
			"OPERATOR_REVIEW_COMPLETE",
			SecureCellGovernmentAgentExecutionLaunchGateHold,
			"Operator review or release-gate acknowledgement is required before launch.",
			"Complete the listed operator acknowledgements and preserve the receipt binding.",
			verification.BundleID,
			generatedAt,
		)
	}
	return secureCellGovernmentAgentExecutionLaunchGate(
		"OPERATOR_REVIEW_COMPLETE",
		SecureCellGovernmentAgentExecutionLaunchGatePass,
		"No operator review gate is pending before launch.",
		"",
		verification.BundleID,
		generatedAt,
	)
}

func secureCellGovernmentAgentExecutionLaunchReceiptGate(
	verification SecureCellGovernmentAgentExecutionHandoffVerification,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchGate {
	if len(verification.RequiredReceiptTypes) == 0 || verification.ReceiptCollectionCount == 0 {
		return secureCellGovernmentAgentExecutionLaunchGate(
			"RECEIPT_RETURN_CONTRACT_READY",
			SecureCellGovernmentAgentExecutionLaunchGateBlock,
			"Launch cannot proceed without a receipt return contract.",
			"Regenerate the receipt ledger and action queue before launch.",
			verification.LedgerID,
			generatedAt,
		)
	}
	return secureCellGovernmentAgentExecutionLaunchGate(
		"RECEIPT_RETURN_CONTRACT_READY",
		SecureCellGovernmentAgentExecutionLaunchGatePass,
		"Required receipt return contract is present.",
		"",
		verification.LedgerID,
		generatedAt,
	)
}

func secureCellGovernmentAgentExecutionLaunchDigestGate(
	verification SecureCellGovernmentAgentExecutionHandoffVerification,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchGate {
	matches := verification.WitnessDigest == verification.ExpectedWitnessDigest &&
		verification.LedgerDigest == verification.ExpectedLedgerDigest &&
		verification.QueueDigest == verification.ExpectedQueueDigest &&
		verification.BundleDigest == verification.ExpectedBundleDigest
	if !matches {
		return secureCellGovernmentAgentExecutionLaunchGate(
			"DIGEST_EXPECTATIONS_MATCH",
			SecureCellGovernmentAgentExecutionLaunchGateBlock,
			"One or more handoff component digests differ from verifier expectations.",
			"Regenerate the changed component and handoff verification before launch.",
			verification.VerificationID,
			generatedAt,
		)
	}
	return secureCellGovernmentAgentExecutionLaunchGate(
		"DIGEST_EXPECTATIONS_MATCH",
		SecureCellGovernmentAgentExecutionLaunchGatePass,
		"Verifier digest expectations match the handoff components.",
		"",
		verification.VerificationID,
		generatedAt,
	)
}

func secureCellGovernmentAgentExecutionLaunchModeGate(
	verification SecureCellGovernmentAgentExecutionHandoffVerification,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchGate {
	if verification.CarryMode == SecureCellGovernmentAgentCarryModeBlocked || strings.TrimSpace(string(verification.CarryMode)) == "" {
		return secureCellGovernmentAgentExecutionLaunchGate(
			"EXECUTION_MODE_DECLARED",
			SecureCellGovernmentAgentExecutionLaunchGateBlock,
			"Execution mode is blocked or undeclared.",
			"Repair workflow carry mode before launch.",
			verification.BundleID,
			generatedAt,
		)
	}
	return secureCellGovernmentAgentExecutionLaunchGate(
		"EXECUTION_MODE_DECLARED",
		SecureCellGovernmentAgentExecutionLaunchGatePass,
		"Execution mode is declared for launch.",
		"",
		verification.BundleID,
		generatedAt,
	)
}

func secureCellGovernmentAgentExecutionLaunchCapabilityGate(
	verification SecureCellGovernmentAgentExecutionHandoffVerification,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchGate {
	if !verification.CanHandoff {
		return secureCellGovernmentAgentExecutionLaunchGate(
			"HANDOFF_CAPABILITY_READY",
			SecureCellGovernmentAgentExecutionLaunchGateBlock,
			"Verified bundle is not handoff-capable yet.",
			"Resolve handoff blockers and regenerate the bundle.",
			verification.BundleID,
			generatedAt,
		)
	}
	return secureCellGovernmentAgentExecutionLaunchGate(
		"HANDOFF_CAPABILITY_READY",
		SecureCellGovernmentAgentExecutionLaunchGatePass,
		"Verified bundle is handoff-capable.",
		"",
		verification.BundleID,
		generatedAt,
	)
}

func secureCellGovernmentAgentExecutionLaunchGate(
	code string,
	status SecureCellGovernmentAgentExecutionLaunchGateStatus,
	detail string,
	requiredAction string,
	evidenceBindingID string,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchGate {
	gate := SecureCellGovernmentAgentExecutionLaunchGate{
		Code:              strings.TrimSpace(code),
		Status:            status,
		Detail:            strings.TrimSpace(detail),
		RequiredAction:    strings.TrimSpace(requiredAction),
		EvidenceBindingID: strings.TrimSpace(evidenceBindingID),
		GeneratedAt:       generatedAt.UTC(),
	}
	core := struct {
		Code              string                                             `json:"code"`
		Status            SecureCellGovernmentAgentExecutionLaunchGateStatus `json:"status"`
		Detail            string                                             `json:"detail"`
		RequiredAction    string                                             `json:"required_action,omitempty"`
		EvidenceBindingID string                                             `json:"evidence_binding_id,omitempty"`
	}{
		Code:              gate.Code,
		Status:            gate.Status,
		Detail:            gate.Detail,
		RequiredAction:    gate.RequiredAction,
		EvidenceBindingID: gate.EvidenceBindingID,
	}
	gate.GateID = "government-agent-execution-launch-gate:" + EvidenceHash(core)[:12]
	return gate
}

func secureCellGovernmentAgentExecutionLaunchAcknowledgementCount(verification SecureCellGovernmentAgentExecutionHandoffVerification) int {
	if !verification.RequiresOperatorReview && verification.ReleaseGateActionCount == 0 {
		return 0
	}
	count := verification.ReleaseGateActionCount
	if count < 1 {
		count = 1
	}
	return count
}

func secureCellGovernmentAgentExecutionLaunchAuthorizationStatus(
	authorization SecureCellGovernmentAgentExecutionLaunchAuthorization,
	verification SecureCellGovernmentAgentExecutionHandoffVerification,
) SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus {
	if authorization.BlockGateCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchAuthorizationBlocked
	}
	if authorization.HoldGateCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchAuthorizationOperatorReviewRequired
	}
	if verification.CanAutonomousHandoff && !verification.RequiresOperatorReview {
		return SecureCellGovernmentAgentExecutionLaunchAuthorizationAutonomous
	}
	return SecureCellGovernmentAgentExecutionLaunchAuthorizationSupervised
}

func secureCellGovernmentAgentExecutionLaunchAuthorizationStatusRank(status SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchAuthorizationBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchAuthorizationOperatorReviewRequired:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchAuthorizationSupervised:
		return 2
	case SecureCellGovernmentAgentExecutionLaunchAuthorizationAutonomous:
		return 3
	default:
		return 4
	}
}

func secureCellGovernmentAgentExecutionLaunchAuthorizationDigest(authorization SecureCellGovernmentAgentExecutionLaunchAuthorization) string {
	gateIDs := make([]string, 0, len(authorization.Gates))
	for _, gate := range authorization.Gates {
		gateIDs = append(gateIDs, gate.GateID)
	}
	core := struct {
		VerificationID                       string                                                      `json:"verification_id"`
		BundleID                             string                                                      `json:"bundle_id"`
		CellID                               string                                                      `json:"cell_id"`
		Status                               SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus `json:"status"`
		CanLaunchNow                         bool                                                        `json:"can_launch_now"`
		CanLaunchAfterOperatorReview         bool                                                        `json:"can_launch_after_operator_review"`
		CanAutonomousLaunch                  bool                                                        `json:"can_autonomous_launch"`
		RequiredOperatorAcknowledgementCount int                                                         `json:"required_operator_acknowledgement_count"`
		GateIDs                              []string                                                    `json:"gate_ids"`
		VerificationDigest                   string                                                      `json:"verification_digest"`
		BundleDigest                         string                                                      `json:"bundle_digest"`
	}{
		VerificationID:                       authorization.VerificationID,
		BundleID:                             authorization.BundleID,
		CellID:                               authorization.CellID,
		Status:                               authorization.Status,
		CanLaunchNow:                         authorization.CanLaunchNow,
		CanLaunchAfterOperatorReview:         authorization.CanLaunchAfterOperatorReview,
		CanAutonomousLaunch:                  authorization.CanAutonomousLaunch,
		RequiredOperatorAcknowledgementCount: authorization.RequiredOperatorAcknowledgementCount,
		GateIDs:                              gateIDs,
		VerificationDigest:                   authorization.VerificationDigest,
		BundleDigest:                         authorization.BundleDigest,
	}
	return EvidenceHash(core)
}
