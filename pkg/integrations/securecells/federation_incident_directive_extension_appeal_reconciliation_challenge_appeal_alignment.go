package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus
// tracks the latest governed bilateral review posture for imported reciprocal
// challenge-appeal bundles.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatusUnreviewed   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus = "unreviewed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatusAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus = "acknowledged"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatusDisputed     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus = "disputed"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionType
// captures one explicit operator review over the latest reciprocal
// challenge-appeal bundle aligned to a local challenge appeal.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionType string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionAcknowledge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionType = "acknowledge_alignment"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionDispute     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionType = "dispute_alignment"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeRequest
// records one governed acknowledgement that the latest reciprocal
// challenge-appeal bundle is aligned and accepted.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeRequest
// records one governed dispute against the latest reciprocal challenge-appeal
// bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeRequest struct {
	ActorDID    string            `json:"actor_did,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Divergences []string          `json:"divergences,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFilter
// narrows operator views across reciprocal challenge-appeal governance.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFilter struct {
	CellID            string                                                                                                 `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                                 `json:"organization_id,omitempty"`
	IncidentID        string                                                                                                 `json:"incident_id,omitempty"`
	ResponseID        string                                                                                                 `json:"response_id,omitempty"`
	DirectiveID       string                                                                                                 `json:"directive_id,omitempty"`
	ExtensionID       string                                                                                                 `json:"extension_id,omitempty"`
	DisputeID         string                                                                                                 `json:"dispute_id,omitempty"`
	AppealID          string                                                                                                 `json:"appeal_id,omitempty"`
	ComparisonKey     string                                                                                                 `json:"comparison_key,omitempty"`
	ChallengeID       string                                                                                                 `json:"challenge_id,omitempty"`
	ChallengeAppealID string                                                                                                 `json:"challenge_appeal_id,omitempty"`
	SnapshotID        string                                                                                                 `json:"snapshot_id,omitempty"`
	Status            SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus    `json:"status,omitempty"`
	AlignmentStatus   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus       `json:"alignment_status,omitempty"`
	ReviewStatus      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus `json:"review_status,omitempty"`
	Action            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionType   `json:"action,omitempty"`
	ActorDID          string                                                                                                 `json:"actor_did,omitempty"`
	Limit             int                                                                                                    `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord
// is the operator-facing evidence record for one governed review of an imported
// reciprocal challenge-appeal bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord struct {
	CellID                          string                                                                                                 `json:"cell_id"`
	CellName                        string                                                                                                 `json:"cell_name,omitempty"`
	CellStatus                      SecureCellStatus                                                                                       `json:"cell_status"`
	Jurisdiction                    string                                                                                                 `json:"jurisdiction,omitempty"`
	OrganizationID                  string                                                                                                 `json:"organization_id"`
	SponsorOfRecord                 string                                                                                                 `json:"sponsor_of_record,omitempty"`
	OrganizationName                string                                                                                                 `json:"organization_name,omitempty"`
	SnapshotID                      string                                                                                                 `json:"snapshot_id"`
	BundleID                        string                                                                                                 `json:"bundle_id,omitempty"`
	ComparisonKey                   string                                                                                                 `json:"comparison_key,omitempty"`
	IncidentID                      string                                                                                                 `json:"incident_id,omitempty"`
	ResponseID                      string                                                                                                 `json:"response_id,omitempty"`
	DirectiveID                     string                                                                                                 `json:"directive_id,omitempty"`
	ExtensionID                     string                                                                                                 `json:"extension_id,omitempty"`
	DisputeID                       string                                                                                                 `json:"dispute_id,omitempty"`
	AppealID                        string                                                                                                 `json:"appeal_id,omitempty"`
	ChallengeID                     string                                                                                                 `json:"challenge_id,omitempty"`
	ChallengeAppealID               string                                                                                                 `json:"challenge_appeal_id,omitempty"`
	ParentChallengeAppealID         string                                                                                                 `json:"parent_challenge_appeal_id,omitempty"`
	ChallengeAppealGeneration       int                                                                                                    `json:"challenge_appeal_generation,omitempty"`
	Status                          SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus    `json:"status"`
	AlignmentStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus       `json:"alignment_status"`
	ReviewStatus                    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus `json:"review_status"`
	Action                          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionType   `json:"action"`
	MatchedLocalChallengeAppealID   string                                                                                                 `json:"matched_local_challenge_appeal_id,omitempty"`
	ChallengeAppealStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus                `json:"challenge_appeal_status,omitempty"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                                                              `json:"appealing_party,omitempty"`
	BoardParty                      SecureCellFederationIncidentResponseParty                                                              `json:"board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                                                              `json:"enforcement_acknowledgement_party,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling                                             `json:"ruling,omitempty"`
	BoardReviewThreshold            int                                                                                                    `json:"board_review_threshold,omitempty"`
	BoardDelegationCount            int                                                                                                    `json:"board_delegation_count,omitempty"`
	BoardRecusalCount               int                                                                                                    `json:"board_recusal_count,omitempty"`
	BoardCommitteeMemberCount       int                                                                                                    `json:"board_committee_member_count,omitempty"`
	BoardRecordedVoteCount          int                                                                                                    `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes           int                                                                                                    `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount         int                                                                                                    `json:"board_missing_quorum_count,omitempty"`
	BoardThresholdSatisfied         bool                                                                                                   `json:"board_threshold_satisfied"`
	RatifyVoteCount                 int                                                                                                    `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount               int                                                                                                    `json:"overturn_vote_count,omitempty"`
	VerificationMessage             string                                                                                                 `json:"verification_message,omitempty"`
	Divergences                     []string                                                                                               `json:"divergences,omitempty"`
	TransitionID                    string                                                                                                 `json:"transition_id,omitempty"`
	PolicyReceiptID                 string                                                                                                 `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash               string                                                                                                 `json:"policy_receipt_hash,omitempty"`
	SealID                          string                                                                                                 `json:"seal_id,omitempty"`
	TraceLinkID                     string                                                                                                 `json:"trace_link_id,omitempty"`
	ActorDID                        string                                                                                                 `json:"actor_did,omitempty"`
	Reason                          string                                                                                                 `json:"reason,omitempty"`
	Metadata                        map[string]string                                                                                      `json:"metadata,omitempty"`
	OccurredAt                      time.Time                                                                                              `json:"occurred_at"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionSpec struct {
	stage       string
	action      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionType
	review      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus
	actorDID    string
	reason      string
	metadata    map[string]string
	divergences []string
}

func (s *Service) AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignment(ctx context.Context, cellID string, challengeAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAction(ctx, cellID, challengeAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionSpec{
		stage:    "acknowledge_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment",
		action:   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionAcknowledge,
		review:   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatusAcknowledged,
		actorDID: req.ActorDID,
		reason:   req.Reason,
		metadata: req.Metadata,
	})
}

func (s *Service) DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignment(ctx context.Context, cellID string, challengeAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAction(ctx, cellID, challengeAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionSpec{
		stage:       "dispute_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment",
		action:      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionDispute,
		review:      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatusDisputed,
		actorDID:    req.ActorDID,
		reason:      req.Reason,
		metadata:    req.Metadata,
		divergences: req.Divergences,
	})
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFilter(record, filter) {
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

func (s *Service) applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAction(ctx context.Context, cellID string, challengeAppealID string, spec secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionSpec) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment: service is required")
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
	actorDID := firstNonEmpty(strings.TrimSpace(spec.actorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment: %w: actor %q is not permitted to review reciprocal challenge appeal %q", ErrPolicyDenied, actorDID, challengeAppealID)
	}
	latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAction(run, challengeAppealID)
	switch spec.action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionAcknowledge:
		if counterpartySummary.AlignmentStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusAligned || counterpartySummary.Status != SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusVerified {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment: only verified aligned reciprocal challenge appeals can be acknowledged")
		}
		if latest != nil && latest.ReviewStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatusAcknowledged && strings.EqualFold(strings.TrimSpace(latest.SnapshotID), strings.TrimSpace(counterpartySummary.SnapshotID)) {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment: reciprocal challenge appeal %q is already acknowledged for snapshot %q", challengeAppealID, counterpartySummary.SnapshotID)
		}
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionDispute:
		if latest != nil && latest.ReviewStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatusDisputed && strings.EqualFold(strings.TrimSpace(latest.SnapshotID), strings.TrimSpace(counterpartySummary.SnapshotID)) {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment: reciprocal challenge appeal %q is already disputed for snapshot %q", challengeAppealID, counterpartySummary.SnapshotID)
		}
	default:
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment: unsupported action %q", spec.action)
	}

	divergences := uniqueTrimmedStrings(spec.divergences)
	if len(divergences) == 0 && spec.action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionDispute {
		divergences = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDivergences(counterpartySummary)
	}

	receipt, err := s.evaluateStage(ctx, run.request, spec.stage, lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                                               counterpartySummary.OrganizationID,
		"federation_incident_id":                                                                                   counterpartySummary.IncidentID,
		"federation_incident_response_id":                                                                          counterpartySummary.ResponseID,
		"federation_incident_directive_id":                                                                         counterpartySummary.DirectiveID,
		"federation_incident_directive_extension_id":                                                               counterpartySummary.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                                       counterpartySummary.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                                        counterpartySummary.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":                                        counterpartySummary.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                               counterpartySummary.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                        counterpartySummary.ChallengeAppealID,
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_snapshot_id":                   counterpartySummary.SnapshotID,
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_bundle_id":                     counterpartySummary.BundleID,
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_status":                        string(counterpartySummary.Status),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment":                     string(counterpartySummary.AlignmentStatus),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_review":                        string(spec.review),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_action":                        string(spec.action),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_divergences":                   strings.Join(divergences, ","),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party":                  string(counterpartySummary.AppealingParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party":               string(counterpartySummary.BoardParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party":                 string(counterpartySummary.EnforcementAcknowledgementParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold":           fmt.Sprintf("%d", counterpartySummary.BoardReviewThreshold),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_delegation_count":    fmt.Sprintf("%d", counterpartySummary.BoardDelegationCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recusal_count":       fmt.Sprintf("%d", counterpartySummary.BoardRecusalCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members":   fmt.Sprintf("%d", counterpartySummary.BoardCommitteeMemberCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes":      fmt.Sprintf("%d", counterpartySummary.BoardRecordedVoteCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes":   fmt.Sprintf("%d", counterpartySummary.BoardOutstandingVotes),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum":      fmt.Sprintf("%d", counterpartySummary.BoardMissingQuorumCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied": fmt.Sprintf("%t", counterpartySummary.BoardThresholdSatisfied),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count":         fmt.Sprintf("%d", counterpartySummary.RatifyVoteCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count":       fmt.Sprintf("%d", counterpartySummary.OverturnVoteCount),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling":       string(counterpartySummary.Ruling),
		"transition_reason": strings.TrimSpace(spec.reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentTransitionSuffix(spec.action), challengeAppealID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentTransitionSuffix(spec.action),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment",
		TargetDID:        challengeAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(spec.reason),
		Metadata: mergeStringMaps(spec.metadata, map[string]string{
			"federation_organization_id":                                                                               counterpartySummary.OrganizationID,
			"federation_sponsor_of_record":                                                                             counterpartySummary.SponsorOfRecord,
			"federation_organization_name":                                                                             counterpartySummary.OrganizationName,
			"federation_incident_id":                                                                                   counterpartySummary.IncidentID,
			"federation_incident_response_id":                                                                          counterpartySummary.ResponseID,
			"federation_incident_directive_id":                                                                         counterpartySummary.DirectiveID,
			"federation_incident_directive_extension_id":                                                               counterpartySummary.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                                       counterpartySummary.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                                        counterpartySummary.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":                                        counterpartySummary.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                               counterpartySummary.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                        counterpartySummary.ChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_parent_id":                 counterpartySummary.ParentChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_generation":                fmt.Sprintf("%d", counterpartySummary.ChallengeAppealGeneration),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_snapshot_id":                   counterpartySummary.SnapshotID,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_bundle_id":                     counterpartySummary.BundleID,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_status":                        string(counterpartySummary.Status),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_status":              string(counterpartySummary.AlignmentStatus),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_review_status":                 string(spec.review),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_action":                        string(spec.action),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_divergences":                   strings.Join(divergences, ","),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_matched_local_id":              counterpartySummary.MatchedLocalChallengeAppealID,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":       string(counterpartySummary.ChallengeAppealStatus),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling":       string(counterpartySummary.Ruling),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_signer":       counterpartySummary.Signer,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_verification_message":          counterpartySummary.VerificationMessage,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party":                  string(counterpartySummary.AppealingParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party":               string(counterpartySummary.BoardParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party":                 string(counterpartySummary.EnforcementAcknowledgementParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold":           fmt.Sprintf("%d", counterpartySummary.BoardReviewThreshold),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_delegation_count":    fmt.Sprintf("%d", counterpartySummary.BoardDelegationCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recusal_count":       fmt.Sprintf("%d", counterpartySummary.BoardRecusalCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members":   fmt.Sprintf("%d", counterpartySummary.BoardCommitteeMemberCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes":      fmt.Sprintf("%d", counterpartySummary.BoardRecordedVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes":   fmt.Sprintf("%d", counterpartySummary.BoardOutstandingVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum":      fmt.Sprintf("%d", counterpartySummary.BoardMissingQuorumCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied": fmt.Sprintf("%t", counterpartySummary.BoardThresholdSatisfied),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count":         fmt.Sprintf("%d", counterpartySummary.RatifyVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count":       fmt.Sprintf("%d", counterpartySummary.OverturnVoteCount),
			"federation_incident_directive_extension_local_challenge_appeal_id":                                        localChallengeAppeal.ChallengeAppealID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord, bool) {
	actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionTypeFromTransitionAction(transition.Action)
	if !ok {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord{}, false
	}
	meta := cloneStringMap(transition.Metadata)
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord{
		CellID:                          safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                        safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                      safeSecureCellStatus(run),
		Jurisdiction:                    safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:                  strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:                 strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:                strings.TrimSpace(meta["federation_organization_name"]),
		SnapshotID:                      strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_snapshot_id"]),
		BundleID:                        strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_bundle_id"]),
		ComparisonKey:                   strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_key"]),
		IncidentID:                      strings.TrimSpace(meta["federation_incident_id"]),
		ResponseID:                      strings.TrimSpace(meta["federation_incident_response_id"]),
		DirectiveID:                     strings.TrimSpace(meta["federation_incident_directive_id"]),
		ExtensionID:                     strings.TrimSpace(meta["federation_incident_directive_extension_id"]),
		DisputeID:                       strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]),
		AppealID:                        strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]),
		ChallengeID:                     strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]),
		ChallengeAppealID:               strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id"]),
		ParentChallengeAppealID:         strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_parent_id"]),
		ChallengeAppealGeneration:       secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_generation"),
		Status:                          SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_status"])),
		AlignmentStatus:                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_status"])),
		ReviewStatus:                    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_review_status"])),
		Action:                          actionType,
		MatchedLocalChallengeAppealID:   strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_matched_local_id"]),
		ChallengeAppealStatus:           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_status"])),
		Ruling:                          SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling"])),
		AppealingParty:                  SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party"])),
		BoardParty:                      SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party"])),
		EnforcementAcknowledgementParty: SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party"])),
		BoardReviewThreshold:            secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold"),
		BoardDelegationCount:            secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_delegation_count"),
		BoardRecusalCount:               secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recusal_count"),
		BoardCommitteeMemberCount:       secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members"),
		BoardRecordedVoteCount:          secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes"),
		BoardOutstandingVotes:           secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes"),
		BoardMissingQuorumCount:         secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum"),
		BoardThresholdSatisfied:         secureCellMetadataBool(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied"),
		RatifyVoteCount:                 secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count"),
		OverturnVoteCount:               secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count"),
		VerificationMessage:             strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_verification_message"]),
		Divergences:                     uniqueTrimmedStrings(strings.Split(strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_reconciliation_divergences"]), ",")),
		TransitionID:                    strings.TrimSpace(transition.ID),
		ActorDID:                        strings.TrimSpace(transition.Actor),
		Reason:                          strings.TrimSpace(transition.Reason),
		Metadata:                        meta,
		OccurredAt:                      transition.OccurredAt.UTC(),
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionTypeFromTransitionAction(action string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_acknowledged":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionAcknowledge, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_disputed":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionDispute, true
	default:
		return "", false
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentTransitionSuffix(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionType) string {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionAcknowledge:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_acknowledged"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionDispute:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_disputed"
	default:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_reviewed"
	}
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFilter) bool {
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
	if filter.Action != "" && item.Action != filter.Action {
		return false
	}
	if filter.ActorDID != "" && !strings.EqualFold(strings.TrimSpace(item.ActorDID), strings.TrimSpace(filter.ActorDID)) {
		return false
	}
	return true
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAction(run *secureCellRun, challengeAppealID string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord {
	challengeAppealID = strings.TrimSpace(challengeAppealID)
	if challengeAppealID == "" || run == nil || run.result == nil {
		return nil
	}
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFromTransition(run, transition)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.ChallengeAppealID), challengeAppealID) {
			continue
		}
		return &record
	}
	return nil
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStateForSnapshot(run *secureCellRun, snapshotID string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus, string, *time.Time, int) {
	snapshotID = strings.TrimSpace(snapshotID)
	if snapshotID == "" || run == nil || run.result == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatusUnreviewed, "", nil, 0
	}
	status := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatusUnreviewed
	var actor string
	var occurredAt *time.Time
	count := 0
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFromTransition(run, transition)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.SnapshotID), snapshotID) {
			continue
		}
		count++
		if count == 1 {
			status = record.ReviewStatus
			actor = record.ActorDID
			at := record.OccurredAt.UTC()
			occurredAt = &at
		}
	}
	return status, actor, occurredAt, count
}

func secureCellLatestCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealByChallengeAppealID(run *secureCellRun, challengeAppealID string) (*SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, error) {
	challengeAppealID = strings.TrimSpace(challengeAppealID)
	if challengeAppealID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment: challenge appeal ID is required")
	}
	if run == nil || run.result == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment: secure cell result is required")
	}
	var latest *SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary
	for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppeals {
		if !strings.EqualFold(strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.ChallengeAppealID), challengeAppealID) {
			continue
		}
		candidate := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummaryFromRun(run, snapshot)
		if latest == nil || candidate.ReceivedAt.After(latest.ReceivedAt) || (candidate.ReceivedAt.Equal(latest.ReceivedAt) && strings.Compare(candidate.SnapshotID, latest.SnapshotID) > 0) {
			copy := candidate
			latest = &copy
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment: reciprocal challenge appeal bundle for %q not found", challengeAppealID)
	}
	return latest, nil
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDivergences(summary *SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary) []string {
	if summary == nil {
		return nil
	}
	diffs := make([]string, 0, 4)
	if summary.AlignmentStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusDivergent {
		diffs = append(diffs, "alignment_divergent")
	}
	if summary.AlignmentStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusCounterpartyOnly {
		diffs = append(diffs, "counterparty_only")
	}
	if summary.Status != SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusVerified {
		diffs = append(diffs, "bundle_"+string(summary.Status))
	}
	if strings.TrimSpace(summary.VerificationMessage) != "" {
		diffs = append(diffs, strings.TrimSpace(summary.VerificationMessage))
	}
	if summary.AlignmentDivergenceCount > 0 && summary.AlignmentStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusAligned {
		diffs = append(diffs, fmt.Sprintf("alignment_divergence_count_%d", summary.AlignmentDivergenceCount))
	}
	return uniqueTrimmedStrings(diffs)
}
