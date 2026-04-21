package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus
// tracks the latest bilateral response posture over an automated reciprocal
// challenge-appeal alignment action.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusUnreviewed   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus = "unreviewed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus = "acknowledged"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusDisputed     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus = "disputed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusCorrected    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus = "corrected"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusResolved     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus = "resolved"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType
// captures one evidence-bearing cross-org response to an automated reciprocal
// challenge-appeal alignment action.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionAcknowledge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType = "acknowledge_automation"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionDispute     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType = "dispute_automation"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionCorrect     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType = "attest_correction"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionResolve     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType = "attest_resolution"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledgeRequest
// records bilateral acknowledgement that the automated alignment action was
// received and is being handled.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledgeRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDisputeRequest
// records bilateral disagreement with one automated reciprocal challenge-appeal
// alignment action.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDisputeRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Divergences           []string          `json:"divergences,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttestationRequest
// records bilateral evidence that the automated reciprocal alignment exception
// was corrected.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttestationRequest struct {
	ActorDID               string            `json:"actor_did,omitempty"`
	CounterpartySnapshotID string            `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyReference  string            `json:"counterparty_reference,omitempty"`
	Reason                 string            `json:"reason,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttestationRequest
// records bilateral evidence that the automated reciprocal alignment exception
// was fully resolved.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttestationRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFilter
// narrows operator views across automated alignment response evidence.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFilter struct {
	CellID            string                                                                                                       `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                                       `json:"organization_id,omitempty"`
	IncidentID        string                                                                                                       `json:"incident_id,omitempty"`
	ResponseID        string                                                                                                       `json:"response_id,omitempty"`
	DirectiveID       string                                                                                                       `json:"directive_id,omitempty"`
	ExtensionID       string                                                                                                       `json:"extension_id,omitempty"`
	DisputeID         string                                                                                                       `json:"dispute_id,omitempty"`
	AppealID          string                                                                                                       `json:"appeal_id,omitempty"`
	ComparisonKey     string                                                                                                       `json:"comparison_key,omitempty"`
	ChallengeID       string                                                                                                       `json:"challenge_id,omitempty"`
	ChallengeAppealID string                                                                                                       `json:"challenge_appeal_id,omitempty"`
	SnapshotID        string                                                                                                       `json:"snapshot_id,omitempty"`
	Status            SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus          `json:"status,omitempty"`
	AlignmentStatus   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus             `json:"alignment_status,omitempty"`
	ReviewStatus      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus       `json:"review_status,omitempty"`
	ResponseStatus    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus     `json:"response_status,omitempty"`
	Action            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType `json:"action,omitempty"`
	ActorDID          string                                                                                                       `json:"actor_did,omitempty"`
	Limit             int                                                                                                          `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord
// is the operator-facing evidence record for one bilateral response to an
// automated reciprocal challenge-appeal alignment action.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord struct {
	CellID                           string                                                                                                       `json:"cell_id"`
	CellName                         string                                                                                                       `json:"cell_name,omitempty"`
	CellStatus                       SecureCellStatus                                                                                             `json:"cell_status"`
	Jurisdiction                     string                                                                                                       `json:"jurisdiction,omitempty"`
	OrganizationID                   string                                                                                                       `json:"organization_id"`
	SponsorOfRecord                  string                                                                                                       `json:"sponsor_of_record,omitempty"`
	OrganizationName                 string                                                                                                       `json:"organization_name,omitempty"`
	SnapshotID                       string                                                                                                       `json:"snapshot_id"`
	BundleID                         string                                                                                                       `json:"bundle_id,omitempty"`
	ComparisonKey                    string                                                                                                       `json:"comparison_key,omitempty"`
	IncidentID                       string                                                                                                       `json:"incident_id,omitempty"`
	ResponseID                       string                                                                                                       `json:"response_id,omitempty"`
	DirectiveID                      string                                                                                                       `json:"directive_id,omitempty"`
	ExtensionID                      string                                                                                                       `json:"extension_id,omitempty"`
	DisputeID                        string                                                                                                       `json:"dispute_id,omitempty"`
	AppealID                         string                                                                                                       `json:"appeal_id,omitempty"`
	ChallengeID                      string                                                                                                       `json:"challenge_id,omitempty"`
	ChallengeAppealID                string                                                                                                       `json:"challenge_appeal_id,omitempty"`
	Status                           SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus          `json:"status"`
	AlignmentStatus                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus             `json:"alignment_status"`
	ReviewStatus                     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus       `json:"review_status"`
	ResponseStatus                   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus     `json:"response_status"`
	Action                           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType `json:"action"`
	MatchedLocalChallengeAppealID    string                                                                                                       `json:"matched_local_challenge_appeal_id,omitempty"`
	ChallengeAppealStatus            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus                      `json:"challenge_appeal_status,omitempty"`
	VerificationMessage              string                                                                                                       `json:"verification_message,omitempty"`
	Divergences                      []string                                                                                                     `json:"divergences,omitempty"`
	AlignmentAutomationAction        string                                                                                                       `json:"alignment_automation_action,omitempty"`
	AlignmentAutomationTrigger       string                                                                                                       `json:"alignment_automation_trigger,omitempty"`
	AlignmentAutomationPendingAction string                                                                                                       `json:"alignment_automation_pending_action,omitempty"`
	AlignmentAutomationTransitionID  string                                                                                                       `json:"alignment_automation_transition_id,omitempty"`
	AlignmentAutomationActor         string                                                                                                       `json:"alignment_automation_actor,omitempty"`
	AlignmentAutomationReason        string                                                                                                       `json:"alignment_automation_reason,omitempty"`
	CounterpartyReference            string                                                                                                       `json:"counterparty_reference,omitempty"`
	CounterpartySnapshotID           string                                                                                                       `json:"counterparty_snapshot_id,omitempty"`
	TransitionID                     string                                                                                                       `json:"transition_id,omitempty"`
	PolicyReceiptID                  string                                                                                                       `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash                string                                                                                                       `json:"policy_receipt_hash,omitempty"`
	SealID                           string                                                                                                       `json:"seal_id,omitempty"`
	TraceLinkID                      string                                                                                                       `json:"trace_link_id,omitempty"`
	ActorDID                         string                                                                                                       `json:"actor_did,omitempty"`
	Reason                           string                                                                                                       `json:"reason,omitempty"`
	Metadata                         map[string]string                                                                                            `json:"metadata,omitempty"`
	OccurredAt                       time.Time                                                                                                    `json:"occurred_at"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionSpec struct {
	stage                  string
	action                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType
	status                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus
	actorDID               string
	reason                 string
	counterpartyReference  string
	counterpartySnapshotID string
	metadata               map[string]string
	divergences            []string
}

func (s *Service) AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomation(ctx context.Context, cellID string, challengeAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledgeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAction(ctx, cellID, challengeAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionSpec{
		stage:                 "acknowledge_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation",
		action:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionAcknowledge,
		status:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusAcknowledged,
		actorDID:              req.ActorDID,
		reason:                req.Reason,
		counterpartyReference: req.CounterpartyReference,
		metadata:              req.Metadata,
	})
}

func (s *Service) DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomation(ctx context.Context, cellID string, challengeAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDisputeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAction(ctx, cellID, challengeAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionSpec{
		stage:                 "dispute_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation",
		action:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionDispute,
		status:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusDisputed,
		actorDID:              req.ActorDID,
		reason:                req.Reason,
		counterpartyReference: req.CounterpartyReference,
		metadata:              req.Metadata,
		divergences:           req.Divergences,
	})
}

func (s *Service) AttestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrection(ctx context.Context, cellID string, challengeAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttestationRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAction(ctx, cellID, challengeAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionSpec{
		stage:                  "attest_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_correction",
		action:                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionCorrect,
		status:                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusCorrected,
		actorDID:               req.ActorDID,
		reason:                 req.Reason,
		counterpartyReference:  req.CounterpartyReference,
		counterpartySnapshotID: req.CounterpartySnapshotID,
		metadata:               req.Metadata,
	})
}

func (s *Service) AttestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolution(ctx context.Context, cellID string, challengeAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttestationRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAction(ctx, cellID, challengeAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionSpec{
		stage:                 "attest_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_resolution",
		action:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionResolve,
		status:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusResolved,
		actorDID:              req.ActorDID,
		reason:                req.Reason,
		counterpartyReference: req.CounterpartyReference,
		metadata:              req.Metadata,
	})
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFilter(record, filter) {
				continue
			}
			items = append(items, record)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			return items[i].TransitionID > items[j].TransitionID
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAction(ctx context.Context, cellID string, challengeAppealID string, spec secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionSpec) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	localChallengeAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealByID(run, challengeAppealID)
	if err != nil {
		return nil, err
	}
	counterpartySummary, err := secureCellLatestCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealByChallengeAppealID(run, challengeAppealID)
	if err != nil {
		return nil, err
	}
	automationAction := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAction(run, challengeAppealID)
	if automationAction == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: reciprocal alignment automation has not acted on challenge appeal %q", challengeAppealID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(spec.actorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: %w: actor %q is not permitted to coordinate alignment response %q", ErrPolicyDenied, actorDID, challengeAppealID)
	}

	latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAction(run, challengeAppealID)
	sameAutomation := latest != nil && strings.EqualFold(strings.TrimSpace(latest.AlignmentAutomationTransitionID), strings.TrimSpace(automationAction.TransitionID))
	switch spec.action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionAcknowledge:
		if sameAutomation && latest.ResponseStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusAcknowledged {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: automated alignment action for %q is already acknowledged", challengeAppealID)
		}
		if sameAutomation && latest.ResponseStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusResolved {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: automated alignment action for %q is already resolved", challengeAppealID)
		}
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionDispute:
		if sameAutomation && latest.ResponseStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusDisputed {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: automated alignment action for %q is already disputed", challengeAppealID)
		}
		if sameAutomation && latest.ResponseStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusResolved {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: automated alignment action for %q is already resolved", challengeAppealID)
		}
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionCorrect:
		if !sameAutomation || latest == nil || (latest.ResponseStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusAcknowledged && latest.ResponseStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusDisputed && latest.ResponseStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusCorrected) {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: automated alignment action for %q must be acknowledged or disputed before correction is attested", challengeAppealID)
		}
		spec.counterpartySnapshotID = firstNonEmpty(strings.TrimSpace(spec.counterpartySnapshotID), strings.TrimSpace(counterpartySummary.SnapshotID), strings.TrimSpace(automationAction.SnapshotID))
		if strings.TrimSpace(spec.counterpartySnapshotID) == "" {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: counterparty snapshot evidence is required to attest correction for %q", challengeAppealID)
		}
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionResolve:
		if !sameAutomation || latest == nil || (latest.ResponseStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusAcknowledged && latest.ResponseStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusDisputed && latest.ResponseStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusCorrected) {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: automated alignment action for %q must be acknowledged, disputed, or corrected before resolution is attested", challengeAppealID)
		}
		if sameAutomation && latest.ResponseStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusResolved {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: automated alignment action for %q is already resolved", challengeAppealID)
		}
	default:
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: unsupported response action %q", spec.action)
	}

	divergences := uniqueTrimmedStrings(spec.divergences)
	if len(divergences) == 0 && spec.action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionDispute {
		divergences = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDivergences(counterpartySummary)
	}

	receipt, err := s.evaluateStage(ctx, run.request, spec.stage, lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                                                         counterpartySummary.OrganizationID,
		"federation_incident_id":                                                                                             counterpartySummary.IncidentID,
		"federation_incident_response_id":                                                                                    counterpartySummary.ResponseID,
		"federation_incident_directive_id":                                                                                   counterpartySummary.DirectiveID,
		"federation_incident_directive_extension_id":                                                                         counterpartySummary.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                                                 counterpartySummary.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                                                  counterpartySummary.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":                                                  counterpartySummary.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                                         counterpartySummary.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                                  counterpartySummary.ChallengeAppealID,
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_snapshot_id":                             automationAction.SnapshotID,
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_bundle_id":                               automationAction.BundleID,
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_status":                                  string(counterpartySummary.Status),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_status":                        string(counterpartySummary.AlignmentStatus),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_review_status":                           string(counterpartySummary.ReviewStatus),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_response_status":                         string(spec.status),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_response_action":                         string(spec.action),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_response_counterparty_reference":         strings.TrimSpace(spec.counterpartyReference),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_response_counterparty_snapshot_id":       strings.TrimSpace(spec.counterpartySnapshotID),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_divergences":                             strings.Join(divergences, ","),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_action":         strings.TrimSpace(automationAction.Action),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_trigger":        strings.TrimSpace(automationAction.Trigger),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_pending_action": strings.TrimSpace(automationAction.PendingAction),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_transition_id":  strings.TrimSpace(automationAction.TransitionID),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_actor":          firstNonEmpty(strings.TrimSpace(automationAction.AutomatedActor), strings.TrimSpace(automationAction.Actor)),
		"transition_reason": strings.TrimSpace(spec.reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseTransitionSuffix(spec.action), challengeAppealID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseTransitionSuffix(spec.action),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response",
		TargetDID:        challengeAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(spec.reason),
		Metadata: mergeStringMaps(spec.metadata, map[string]string{
			"federation_organization_id":                                                                                                 counterpartySummary.OrganizationID,
			"federation_sponsor_of_record":                                                                                               counterpartySummary.SponsorOfRecord,
			"federation_organization_name":                                                                                               counterpartySummary.OrganizationName,
			"federation_incident_id":                                                                                                     counterpartySummary.IncidentID,
			"federation_incident_response_id":                                                                                            counterpartySummary.ResponseID,
			"federation_incident_directive_id":                                                                                           counterpartySummary.DirectiveID,
			"federation_incident_directive_extension_id":                                                                                 counterpartySummary.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                                                         counterpartySummary.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                                                          counterpartySummary.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":                                                          counterpartySummary.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                                                 counterpartySummary.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                                          counterpartySummary.ChallengeAppealID,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_snapshot_id":                                     automationAction.SnapshotID,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_bundle_id":                                       automationAction.BundleID,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_status":                                          string(counterpartySummary.Status),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_status":                                string(counterpartySummary.AlignmentStatus),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_review_status":                                   string(counterpartySummary.ReviewStatus),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_response_status":                                 string(spec.status),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_response_action":                                 string(spec.action),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_response_counterparty_reference":                 strings.TrimSpace(spec.counterpartyReference),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_response_counterparty_snapshot_id":               strings.TrimSpace(spec.counterpartySnapshotID),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_divergences":                                     strings.Join(divergences, ","),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_matched_local_id":                                counterpartySummary.MatchedLocalChallengeAppealID,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":                         string(counterpartySummary.ChallengeAppealStatus),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_verification_message":                            counterpartySummary.VerificationMessage,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_action":                 strings.TrimSpace(automationAction.Action),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_trigger":                strings.TrimSpace(automationAction.Trigger),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_pending_action":         strings.TrimSpace(automationAction.PendingAction),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_transition_id":          strings.TrimSpace(automationAction.TransitionID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_actor":                  firstNonEmpty(strings.TrimSpace(automationAction.AutomatedActor), strings.TrimSpace(automationAction.Actor)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_reason":                 strings.TrimSpace(automationAction.Reason),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_contract_id":            strings.TrimSpace(automationAction.ContractID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_contract_status_before": string(automationAction.ContractStatusBefore),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_contract_status_after":  string(automationAction.ContractStatusAfter),
			"federation_incident_directive_extension_local_challenge_appeal_id":                                                          localChallengeAppeal.ChallengeAppealID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord, bool) {
	actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionTypeFromTransitionAction(transition.Action)
	if !ok {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord{}, false
	}
	meta := cloneStringMap(transition.Metadata)
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord{
		CellID:                           safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                         safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                       safeSecureCellStatus(run),
		Jurisdiction:                     safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:                   strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:                  strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:                 strings.TrimSpace(meta["federation_organization_name"]),
		SnapshotID:                       strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_snapshot_id"]),
		BundleID:                         strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_bundle_id"]),
		ComparisonKey:                    strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_key"]),
		IncidentID:                       strings.TrimSpace(meta["federation_incident_id"]),
		ResponseID:                       strings.TrimSpace(meta["federation_incident_response_id"]),
		DirectiveID:                      strings.TrimSpace(meta["federation_incident_directive_id"]),
		ExtensionID:                      strings.TrimSpace(meta["federation_incident_directive_extension_id"]),
		DisputeID:                        strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]),
		AppealID:                         strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]),
		ChallengeID:                      strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]),
		ChallengeAppealID:                strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id"]),
		Status:                           SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_status"])),
		AlignmentStatus:                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_status"])),
		ReviewStatus:                     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_review_status"])),
		ResponseStatus:                   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_response_status"])),
		Action:                           actionType,
		MatchedLocalChallengeAppealID:    strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_matched_local_id"]),
		ChallengeAppealStatus:            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_status"])),
		VerificationMessage:              strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_verification_message"]),
		Divergences:                      uniqueTrimmedStrings(strings.Split(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_divergences"]), ",")),
		AlignmentAutomationAction:        strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_action"]),
		AlignmentAutomationTrigger:       strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_trigger"]),
		AlignmentAutomationPendingAction: strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_pending_action"]),
		AlignmentAutomationTransitionID:  strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_transition_id"]),
		AlignmentAutomationActor:         strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_actor"]),
		AlignmentAutomationReason:        strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_reason"]),
		CounterpartyReference:            strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_response_counterparty_reference"]),
		CounterpartySnapshotID:           strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_response_counterparty_snapshot_id"]),
		TransitionID:                     strings.TrimSpace(transition.ID),
		ActorDID:                         strings.TrimSpace(transition.Actor),
		Reason:                           strings.TrimSpace(transition.Reason),
		Metadata:                         meta,
		OccurredAt:                       transition.OccurredAt.UTC(),
	}
	if transition.PolicyReceipt != nil {
		record.PolicyReceiptID = strings.TrimSpace(transition.PolicyReceipt.ID)
		record.PolicyReceiptHash = strings.TrimSpace(transition.PolicyReceipt.ContentHash)
	}
	if transition.ExecutionSeal != nil {
		record.SealID = strings.TrimSpace(transition.ExecutionSeal.SealID)
	}
	if transition.TraceLink != nil {
		record.TraceLinkID = strings.TrimSpace(transition.TraceLink.ID)
	}
	return record, true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionTypeFromTransitionAction(action string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_acknowledged":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionAcknowledge, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_disputed":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionDispute, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_correction_attested":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionCorrect, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_resolution_attested":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionResolve, true
	default:
		return "", false
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseTransitionSuffix(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType) string {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionAcknowledge:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_acknowledged"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionDispute:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_disputed"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionCorrect:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_correction_attested"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionResolve:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_resolution_attested"
	default:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_automation_reviewed"
	}
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFilter) bool {
	if filter.CellID != "" && !strings.EqualFold(strings.TrimSpace(item.CellID), strings.TrimSpace(filter.CellID)) {
		return false
	}
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(item.IncidentID), strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseID), strings.TrimSpace(filter.ResponseID)) {
		return false
	}
	if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(item.DirectiveID), strings.TrimSpace(filter.DirectiveID)) {
		return false
	}
	if filter.ExtensionID != "" && !strings.EqualFold(strings.TrimSpace(item.ExtensionID), strings.TrimSpace(filter.ExtensionID)) {
		return false
	}
	if filter.DisputeID != "" && !strings.EqualFold(strings.TrimSpace(item.DisputeID), strings.TrimSpace(filter.DisputeID)) {
		return false
	}
	if filter.AppealID != "" && !strings.EqualFold(strings.TrimSpace(item.AppealID), strings.TrimSpace(filter.AppealID)) {
		return false
	}
	if filter.ComparisonKey != "" && !strings.EqualFold(strings.TrimSpace(item.ComparisonKey), strings.TrimSpace(filter.ComparisonKey)) {
		return false
	}
	if filter.ChallengeID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(filter.ChallengeID)) {
		return false
	}
	if filter.ChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), strings.TrimSpace(filter.ChallengeAppealID)) {
		return false
	}
	if filter.SnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.SnapshotID), strings.TrimSpace(filter.SnapshotID)) {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.AlignmentStatus != "" && item.AlignmentStatus != filter.AlignmentStatus {
		return false
	}
	if filter.ReviewStatus != "" && item.ReviewStatus != filter.ReviewStatus {
		return false
	}
	if filter.ResponseStatus != "" && item.ResponseStatus != filter.ResponseStatus {
		return false
	}
	if filter.Action != "" && item.Action != filter.Action {
		return false
	}
	if filter.ActorDID != "" && !strings.EqualFold(strings.TrimSpace(item.ActorDID), strings.TrimSpace(filter.ActorDID)) {
		return false
	}
	return true
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAction(run *secureCellRun, challengeAppealID string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord {
	challengeAppealID = strings.TrimSpace(challengeAppealID)
	if challengeAppealID == "" || run == nil || run.result == nil {
		return nil
	}
	var latest *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFromTransition(run, transition)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.ChallengeAppealID), challengeAppealID) {
			continue
		}
		if latest == nil || record.OccurredAt.After(latest.OccurredAt) || (record.OccurredAt.Equal(latest.OccurredAt) && record.TransitionID > latest.TransitionID) {
			recordCopy := record
			latest = &recordCopy
		}
	}
	return latest
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAction(run *secureCellRun, challengeAppealID string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord {
	challengeAppealID = strings.TrimSpace(challengeAppealID)
	if challengeAppealID == "" || run == nil || run.result == nil {
		return nil
	}
	var latest *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord
	for _, transition := range run.result.Transitions {
		if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAction(transition) {
			continue
		}
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionFromTransition(run, transition)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.ChallengeAppealID), challengeAppealID) {
			continue
		}
		if latest == nil || record.OccurredAt.After(latest.OccurredAt) || (record.OccurredAt.Equal(latest.OccurredAt) && record.TransitionID > latest.TransitionID) {
			recordCopy := record
			latest = &recordCopy
		}
	}
	return latest
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord, bool) {
	if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAction(transition) {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord{}, false
	}
	meta := cloneStringMap(transition.Metadata)
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord{
		CellID:                        safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                      safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		Jurisdiction:                  safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		CellStatus:                    safeSecureCellStatus(run),
		OrganizationID:                strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:               strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:              strings.TrimSpace(meta["federation_organization_name"]),
		SnapshotID:                    strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_snapshot_id"]),
		BundleID:                      strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_bundle_id"]),
		ComparisonKey:                 strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_key"]),
		IncidentID:                    strings.TrimSpace(meta["federation_incident_id"]),
		ResponseID:                    strings.TrimSpace(meta["federation_incident_response_id"]),
		DirectiveID:                   strings.TrimSpace(meta["federation_incident_directive_id"]),
		ExtensionID:                   strings.TrimSpace(meta["federation_incident_directive_extension_id"]),
		DisputeID:                     strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]),
		AppealID:                      strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]),
		ChallengeID:                   strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]),
		ChallengeAppealID:             strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id"]),
		ChallengeAppealStatus:         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_status"])),
		Status:                        SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_status"])),
		AlignmentStatus:               SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_status"])),
		ReviewStatus:                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_review_status"])),
		PendingAction:                 strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_pending_action"]),
		MatchedLocalChallengeAppealID: strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_matched_local_id"]),
		VerificationMessage:           strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_verification_message"]),
		AlignmentDivergenceCount:      secureCellMetadataInt(meta, "federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_divergence_count"),
		ReviewActionCount:             secureCellMetadataInt(meta, "federation_counterparty_incident_directive_extension_appeal_reconciliation_review_action_count"),
		ContractID:                    strings.TrimSpace(meta["federation_contract_id"]),
		ContractStatusBefore:          SecureCellFederationContractStatus(strings.TrimSpace(meta["federation_contract_status_before"])),
		ContractStatusAfter:           SecureCellFederationContractStatus(strings.TrimSpace(meta["federation_contract_status_after"])),
		Action:                        strings.TrimSpace(transition.Action),
		Trigger:                       strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_trigger"]),
		TierID:                        strings.TrimSpace(meta["federation_incident_response_tier_id"]),
		TargetDID:                     strings.TrimSpace(meta["federation_incident_response_target_did"]),
		DueAt:                         cloneTimePtr(parseSecureCellTransitionDueAtWithKey(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_due_at")),
		Actor:                         strings.TrimSpace(transition.Actor),
		AutomatedActor:                strings.TrimSpace(meta["automated_actor"]),
		Reason:                        strings.TrimSpace(transition.Reason),
		TransitionID:                  strings.TrimSpace(transition.ID),
		OccurredAt:                    transition.OccurredAt.UTC(),
		Metadata:                      meta,
	}
	return record, true
}
