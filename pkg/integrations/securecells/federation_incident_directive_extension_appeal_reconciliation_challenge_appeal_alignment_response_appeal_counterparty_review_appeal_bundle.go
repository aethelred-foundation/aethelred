package securecells

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter
// narrows first-class operator queries over rehearing boards opened from
// imported counterparty correction-board ruling disputes.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter struct {
	CellID                       string                                                                                                                           `json:"cell_id,omitempty"`
	AppealReviewID               string                                                                                                                           `json:"appeal_review_id,omitempty"`
	ReviewID                     string                                                                                                                           `json:"review_id,omitempty"`
	OrganizationID               string                                                                                                                           `json:"organization_id,omitempty"`
	IncidentID                   string                                                                                                                           `json:"incident_id,omitempty"`
	ResponseID                   string                                                                                                                           `json:"response_id,omitempty"`
	DirectiveID                  string                                                                                                                           `json:"directive_id,omitempty"`
	ExtensionID                  string                                                                                                                           `json:"extension_id,omitempty"`
	DisputeID                    string                                                                                                                           `json:"dispute_id,omitempty"`
	AppealID                     string                                                                                                                           `json:"appeal_id,omitempty"`
	ChallengeID                  string                                                                                                                           `json:"challenge_id,omitempty"`
	ChallengeAppealID            string                                                                                                                           `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID             string                                                                                                                           `json:"response_appeal_id,omitempty"`
	BoardResponseAppealID        string                                                                                                                           `json:"board_response_appeal_id,omitempty"`
	CounterpartySnapshotID       string                                                                                                                           `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyResponseAppealID string                                                                                                                           `json:"counterparty_response_appeal_id,omitempty"`
	ReviewStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus `json:"review_status,omitempty"`
	BoardResponseAppealStatus    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                   `json:"board_response_appeal_status,omitempty"`
	Limit                        int                                                                                                                              `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary
// projects one first-class bilateral rehearing board that was opened from an
// imported counterparty ruling dispute.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary struct {
	AppealReviewID                   string                                                                                                                           `json:"appeal_review_id"`
	ReviewID                         string                                                                                                                           `json:"review_id"`
	CellID                           string                                                                                                                           `json:"cell_id"`
	CellName                         string                                                                                                                           `json:"cell_name,omitempty"`
	CellStatus                       SecureCellStatus                                                                                                                 `json:"cell_status"`
	Jurisdiction                     string                                                                                                                           `json:"jurisdiction,omitempty"`
	OrganizationID                   string                                                                                                                           `json:"organization_id"`
	SponsorOfRecord                  string                                                                                                                           `json:"sponsor_of_record,omitempty"`
	OrganizationName                 string                                                                                                                           `json:"organization_name,omitempty"`
	IncidentID                       string                                                                                                                           `json:"incident_id,omitempty"`
	ResponseID                       string                                                                                                                           `json:"response_id,omitempty"`
	DirectiveID                      string                                                                                                                           `json:"directive_id,omitempty"`
	ExtensionID                      string                                                                                                                           `json:"extension_id,omitempty"`
	DisputeID                        string                                                                                                                           `json:"dispute_id,omitempty"`
	AppealID                         string                                                                                                                           `json:"appeal_id,omitempty"`
	ChallengeID                      string                                                                                                                           `json:"challenge_id,omitempty"`
	ChallengeAppealID                string                                                                                                                           `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID                 string                                                                                                                           `json:"response_appeal_id,omitempty"`
	ResponseAppealStatus             SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                   `json:"response_appeal_status,omitempty"`
	ResponseStatus                   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                         `json:"response_status,omitempty"`
	ResponseAction                   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                     `json:"response_action,omitempty"`
	ResponseTransitionID             string                                                                                                                           `json:"response_transition_id,omitempty"`
	LocalRuling                      SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                       `json:"local_ruling,omitempty"`
	CounterpartySnapshotID           string                                                                                                                           `json:"counterparty_snapshot_id"`
	CounterpartyBundleID             string                                                                                                                           `json:"counterparty_bundle_id,omitempty"`
	CounterpartyBundleStatus         SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus             `json:"counterparty_bundle_status,omitempty"`
	CounterpartyBundleVerified       bool                                                                                                                             `json:"counterparty_bundle_verified"`
	CounterpartySigner               string                                                                                                                           `json:"counterparty_signer,omitempty"`
	CounterpartyResponseAppealID     string                                                                                                                           `json:"counterparty_response_appeal_id"`
	CounterpartyResponseAppealStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                   `json:"counterparty_response_appeal_status,omitempty"`
	CounterpartyResponseStatus       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                         `json:"counterparty_response_status,omitempty"`
	CounterpartyResponseAction       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                     `json:"counterparty_response_action,omitempty"`
	CounterpartyResponseTransitionID string                                                                                                                           `json:"counterparty_response_transition_id,omitempty"`
	CounterpartyRuling               SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                       `json:"counterparty_ruling,omitempty"`
	CounterpartyReference            string                                                                                                                           `json:"counterparty_reference,omitempty"`
	ReviewStatus                     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus `json:"review_status,omitempty"`
	LatestReviewAction               SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType   `json:"latest_review_action,omitempty"`
	ReviewActionCount                int                                                                                                                              `json:"review_action_count"`
	ReviewLastReviewedAt             *time.Time                                                                                                                       `json:"review_last_reviewed_at,omitempty"`
	BoardResponseAppealID            string                                                                                                                           `json:"board_response_appeal_id"`
	BoardParentResponseAppealID      string                                                                                                                           `json:"board_parent_response_appeal_id,omitempty"`
	BoardResponseAppealGeneration    int                                                                                                                              `json:"board_response_appeal_generation,omitempty"`
	BoardResponseAppealStatus        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                   `json:"board_response_appeal_status,omitempty"`
	BoardResponseStatus              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                         `json:"board_response_status,omitempty"`
	BoardResponseAction              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                     `json:"board_response_action,omitempty"`
	BoardResponseTransitionID        string                                                                                                                           `json:"board_response_transition_id,omitempty"`
	BoardAppealingParty              SecureCellFederationIncidentResponseParty                                                                                        `json:"board_appealing_party,omitempty"`
	BoardCorrectionBoardParty        SecureCellFederationIncidentResponseParty                                                                                        `json:"board_correction_board_party,omitempty"`
	BoardEnforcementParty            SecureCellFederationIncidentResponseParty                                                                                        `json:"board_enforcement_acknowledgement_party,omitempty"`
	BoardSummary                     string                                                                                                                           `json:"board_summary,omitempty"`
	BoardDescription                 string                                                                                                                           `json:"board_description,omitempty"`
	BoardReviewThreshold             int                                                                                                                              `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs        []string                                                                                                                         `json:"eligible_board_reviewer_dids,omitempty"`
	BoardDelegationCount             int                                                                                                                              `json:"board_delegation_count,omitempty"`
	BoardRecusalCount                int                                                                                                                              `json:"board_recusal_count,omitempty"`
	BoardCommitteeMemberCount        int                                                                                                                              `json:"board_committee_member_count,omitempty"`
	BoardRecordedVoteCount           int                                                                                                                              `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes            int                                                                                                                              `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount          int                                                                                                                              `json:"board_missing_quorum_count,omitempty"`
	BoardThresholdSatisfied          bool                                                                                                                             `json:"board_threshold_satisfied"`
	BoardRatifyVoteCount             int                                                                                                                              `json:"board_ratify_vote_count,omitempty"`
	BoardOverturnVoteCount           int                                                                                                                              `json:"board_overturn_vote_count,omitempty"`
	BoardRuling                      SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                       `json:"board_ruling,omitempty"`
	BoardRulingSummary               string                                                                                                                           `json:"board_ruling_summary,omitempty"`
	BoardRulingDescription           string                                                                                                                           `json:"board_ruling_description,omitempty"`
	BoardActionCount                 int                                                                                                                              `json:"board_action_count,omitempty"`
	BoardAutomationActionCount       int                                                                                                                              `json:"board_automation_action_count,omitempty"`
	CreatedAt                        time.Time                                                                                                                        `json:"created_at"`
	UpdatedAt                        time.Time                                                                                                                        `json:"updated_at"`
	ControlLedgerID                  string                                                                                                                           `json:"control_ledger_id,omitempty"`
	ControlLedgerHash                string                                                                                                                           `json:"control_ledger_hash,omitempty"`
	PortablePackageHash              string                                                                                                                           `json:"portable_package_hash,omitempty"`
	PortablePackageSigned            bool                                                                                                                             `json:"portable_package_signed"`
	PortablePackageAnchored          bool                                                                                                                             `json:"portable_package_anchored"`
	Metadata                         map[string]string                                                                                                                `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSignature
// captures detached signer metadata for one portable bilateral imported-ruling
// appeal-board bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle
// is the signed portable auditor package for one local rehearing board opened
// from an imported counterparty ruling dispute.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle struct {
	ID                           string                                                                                                                                           `json:"id"`
	Version                      string                                                                                                                                           `json:"version"`
	Name                         string                                                                                                                                           `json:"name"`
	GeneratedAt                  time.Time                                                                                                                                        `json:"generated_at"`
	ExpiresAt                    *time.Time                                                                                                                                       `json:"expires_at,omitempty"`
	CellID                       string                                                                                                                                           `json:"cell_id"`
	CellName                     string                                                                                                                                           `json:"cell_name,omitempty"`
	CellStatus                   SecureCellStatus                                                                                                                                 `json:"cell_status"`
	Jurisdiction                 string                                                                                                                                           `json:"jurisdiction,omitempty"`
	Framework                    string                                                                                                                                           `json:"framework,omitempty"`
	Organization                 SecureCellFederationOrganizationSummary                                                                                                          `json:"organization"`
	ReviewAppeal                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary          `json:"review_appeal"`
	Review                       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummary                `json:"review"`
	CounterpartyAppeal           SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary                      `json:"counterparty_appeal"`
	LocalBoardResponseAppeal     *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary                                 `json:"local_board_response_appeal,omitempty"`
	CounterpartyActions          []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord               `json:"counterparty_actions,omitempty"`
	LocalBoardResponseActions    []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord                           `json:"local_board_response_actions,omitempty"`
	LocalBoardResponseRecusals   []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary                         `json:"local_board_response_recusals,omitempty"`
	LocalBoardResponseAutomation []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord                 `json:"local_board_response_automation_actions,omitempty"`
	CounterpartyReviewBundleHash string                                                                                                                                           `json:"counterparty_review_bundle_hash,omitempty"`
	AlignmentResponseBundleHash  string                                                                                                                                           `json:"alignment_response_bundle_hash,omitempty"`
	ChallengeAppealBundleHash    string                                                                                                                                           `json:"challenge_appeal_bundle_hash,omitempty"`
	Controls                     []SecureCellFederationTrustPackControl                                                                                                           `json:"controls,omitempty"`
	OperatorSurfaces             []SecureCellFederationOperatorSurface                                                                                                            `json:"operator_surfaces,omitempty"`
	ControlLedgerID              string                                                                                                                                           `json:"control_ledger_id,omitempty"`
	ControlLedgerHash            string                                                                                                                                           `json:"control_ledger_hash,omitempty"`
	PortablePackageHash          string                                                                                                                                           `json:"portable_package_hash,omitempty"`
	PortablePackageSigned        bool                                                                                                                                             `json:"portable_package_signed"`
	PortablePackageAnchored      bool                                                                                                                                             `json:"portable_package_anchored"`
	ContentHash                  string                                                                                                                                           `json:"content_hash,omitempty"`
	Signature                    *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSignature `json:"signature,omitempty"`
	Metadata                     map[string]string                                                                                                                                `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleOptions
// lets callers tune portable appeal-board bundle identity and operator hints.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals(ctx context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: service is required")
	}
	if strings.TrimSpace(filter.CellID) == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: cell ID is required")
	}
	run, err := s.getRun(filter.CellID)
	if err != nil {
		return nil, err
	}
	reviews, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviews(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewFilter{
		CellID:                       filter.CellID,
		ReviewID:                     filter.ReviewID,
		OrganizationID:               filter.OrganizationID,
		IncidentID:                   filter.IncidentID,
		ResponseID:                   filter.ResponseID,
		DirectiveID:                  filter.DirectiveID,
		ExtensionID:                  filter.ExtensionID,
		DisputeID:                    filter.DisputeID,
		AppealID:                     filter.AppealID,
		ChallengeID:                  filter.ChallengeID,
		ChallengeAppealID:            filter.ChallengeAppealID,
		ResponseAppealID:             filter.ResponseAppealID,
		CounterpartySnapshotID:       filter.CounterpartySnapshotID,
		CounterpartyResponseAppealID: filter.CounterpartyResponseAppealID,
		ReviewStatus:                 filter.ReviewStatus,
	})
	if err != nil {
		return nil, err
	}

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary, 0)
	for _, review := range reviews {
		boardAppeal, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFromRun(run, review)
		if !ok {
			continue
		}
		item := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryFromReview(run, review, boardAppeal)
		if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter(item, filter) {
			continue
		}
		items = append(items, item)
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].AppealReviewID < items[j].AppealReviewID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(ctx context.Context, cellID string, appealReviewID string, options SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleOptions) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	items, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter{
		CellID:         cellID,
		AppealReviewID: appealReviewID,
		Limit:          1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: %w: appeal review %q", ErrFederationIncidentDirectiveNotFound, appealReviewID)
	}
	item := items[0]
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, item.OrganizationID)
	if err != nil {
		return nil, err
	}
	reviews, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviews(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewFilter{
		CellID:   cellID,
		ReviewID: item.ReviewID,
		Limit:    1,
	})
	if err != nil {
		return nil, err
	}
	if len(reviews) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: %w: review %q", ErrFederationIncidentDirectiveNotFound, item.ReviewID)
	}
	review := reviews[0]
	counterpartyAppeal, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummaryBySnapshotAndAppeal(run, item.CounterpartySnapshotID, item.CounterpartyResponseAppealID)
	if err != nil {
		return nil, err
	}
	counterpartyActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFilter{
		CellID:                       cellID,
		ChallengeAppealID:            item.ChallengeAppealID,
		ResponseAppealID:             item.ResponseAppealID,
		CounterpartySnapshotID:       item.CounterpartySnapshotID,
		CounterpartyResponseAppealID: item.CounterpartyResponseAppealID,
	})
	if err != nil {
		return nil, err
	}

	var boardAppeal *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary
	if appeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, item.BoardResponseAppealID); err == nil && appeal != nil {
		copy := *appeal
		boardAppeal = &copy
	}
	boardActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter{
		CellID:            cellID,
		ChallengeAppealID: item.ChallengeAppealID,
		ResponseAppealID:  item.BoardResponseAppealID,
	})
	if err != nil {
		return nil, err
	}
	boardRecusals, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter{
		CellID:            cellID,
		ChallengeAppealID: item.ChallengeAppealID,
		ResponseAppealID:  item.BoardResponseAppealID,
	})
	if err != nil {
		return nil, err
	}
	boardAutomation, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionFilter{
		CellID:            cellID,
		ChallengeAppealID: item.ChallengeAppealID,
		ResponseAppealID:  item.BoardResponseAppealID,
	})
	if err != nil {
		return nil, err
	}
	reviewBundle, err := s.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle(ctx, cellID, item.ReviewID, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleOptions{})
	if err != nil {
		return nil, err
	}
	alignmentResponseBundle, err := s.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle(ctx, cellID, item.ChallengeAppealID, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleOptions{})
	if err != nil {
		return nil, err
	}
	challengeAppealBundle, err := s.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle(ctx, cellID, item.ChallengeAppealID, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleOptions{})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle{
		ID:                           firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-counterparty-review-appeal-bundle", run.result.CellID, item.AppealReviewID)),
		Version:                      firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:                         firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Counterparty Ruling Appeal Bundle %s", item.AppealReviewID)),
		GeneratedAt:                  now,
		ExpiresAt:                    cloneTimePtr(&expiresAt),
		CellID:                       run.result.CellID,
		CellName:                     run.result.Name,
		CellStatus:                   run.result.Status,
		Jurisdiction:                 run.request.Jurisdiction,
		Framework:                    firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:                 orgSummary,
		ReviewAppeal:                 item,
		Review:                       review,
		CounterpartyAppeal:           counterpartyAppeal,
		LocalBoardResponseAppeal:     boardAppeal,
		CounterpartyActions:          append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord(nil), counterpartyActions...),
		LocalBoardResponseActions:    append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord(nil), boardActions...),
		LocalBoardResponseRecusals:   append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary(nil), boardRecusals...),
		LocalBoardResponseAutomation: append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord(nil), boardAutomation...),
		CounterpartyReviewBundleHash: strings.TrimSpace(reviewBundle.ContentHash),
		AlignmentResponseBundleHash:  strings.TrimSpace(alignmentResponseBundle.ContentHash),
		ChallengeAppealBundleHash:    strings.TrimSpace(challengeAppealBundle.ContentHash),
		Controls:                     secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:             cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:                     cloneStringMap(options.Metadata),
	}
	if run.result.ControlLedger != nil && run.result.ControlLedger.Bundle != nil {
		bundle.ControlLedgerID = strings.TrimSpace(run.result.ControlLedger.Bundle.ID)
		bundle.ControlLedgerHash = strings.TrimSpace(run.result.ControlLedger.Bundle.ContentHash)
	}
	if run.result.PortablePackage != nil {
		bundle.PortablePackageHash = strings.TrimSpace(run.result.PortablePackage.PackageHash)
		bundle.PortablePackageSigned = run.result.PortablePackage.Signature != nil
		bundle.PortablePackageAnchored = run.result.PortablePackage.AuditAnchor != nil
	}
	if s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSigner != nil {
		if err := s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: external bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

func VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: bundle is required")
	}
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: signature verification failed")
	}
	return nil
}

func SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleEd25519(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSignature{
		Algorithm: secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSignatureAlgorithmED25519,
		Signer:    strings.TrimSpace(signer),
		KeyID:     fmt.Sprintf("ed25519:%x", sha256.Sum256(publicKey)),
		Signature: hex.EncodeToString(signature),
		SignedAt:  now,
	}
	if includeVerificationKeys {
		bundle.Signature.PublicKey = hex.EncodeToString(publicKey)
	}
	return nil
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleDigest(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFromRun(run *secureCellRun, review SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummary) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, bool) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary{}, false
	}
	var selected *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary
	for _, appeal := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run) {
		if !strings.EqualFold(strings.TrimSpace(appeal.ChallengeAppealID), strings.TrimSpace(review.ChallengeAppealID)) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(appeal.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_escalated"]), "true") {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(appeal.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_snapshot_id"]), strings.TrimSpace(review.CounterpartySnapshotID)) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(appeal.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_response_appeal_id"]), strings.TrimSpace(review.CounterpartyResponseAppealID)) {
			continue
		}
		candidate := appeal
		if selected == nil ||
			candidate.ResponseAppealGeneration > selected.ResponseAppealGeneration ||
			(candidate.ResponseAppealGeneration == selected.ResponseAppealGeneration && candidate.UpdatedAt.After(selected.UpdatedAt)) {
			selected = &candidate
		}
	}
	if selected == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary{}, false
	}
	return *selected, true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryFromReview(run *secureCellRun, review SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummary, boardAppeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary {
	item := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary{
		AppealReviewID:                   secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealID(review.ReviewID, boardAppeal.ResponseAppealID),
		ReviewID:                         review.ReviewID,
		CellID:                           review.CellID,
		CellName:                         review.CellName,
		CellStatus:                       review.CellStatus,
		Jurisdiction:                     review.Jurisdiction,
		OrganizationID:                   review.OrganizationID,
		SponsorOfRecord:                  review.SponsorOfRecord,
		OrganizationName:                 review.OrganizationName,
		IncidentID:                       review.IncidentID,
		ResponseID:                       review.ResponseID,
		DirectiveID:                      review.DirectiveID,
		ExtensionID:                      review.ExtensionID,
		DisputeID:                        review.DisputeID,
		AppealID:                         review.AppealID,
		ChallengeID:                      review.ChallengeID,
		ChallengeAppealID:                review.ChallengeAppealID,
		ResponseAppealID:                 review.ResponseAppealID,
		ResponseAppealStatus:             review.ResponseAppealStatus,
		ResponseStatus:                   review.ResponseStatus,
		ResponseAction:                   review.ResponseAction,
		ResponseTransitionID:             review.ResponseTransitionID,
		LocalRuling:                      review.LocalRuling,
		CounterpartySnapshotID:           review.CounterpartySnapshotID,
		CounterpartyBundleID:             review.CounterpartyBundleID,
		CounterpartyBundleStatus:         review.CounterpartyBundleStatus,
		CounterpartyBundleVerified:       review.CounterpartyBundleVerified,
		CounterpartySigner:               review.CounterpartySigner,
		CounterpartyResponseAppealID:     review.CounterpartyResponseAppealID,
		CounterpartyResponseAppealStatus: review.CounterpartyResponseAppealStatus,
		CounterpartyResponseStatus:       review.CounterpartyResponseStatus,
		CounterpartyResponseAction:       review.CounterpartyResponseAction,
		CounterpartyResponseTransitionID: review.CounterpartyResponseTransitionID,
		CounterpartyRuling:               review.CounterpartyRuling,
		CounterpartyReference:            firstNonEmpty(strings.TrimSpace(boardAppeal.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_reference"]), review.CounterpartyReference),
		ReviewStatus:                     review.ReviewStatus,
		LatestReviewAction:               review.LatestReviewAction,
		ReviewActionCount:                review.ReviewActionCount,
		ReviewLastReviewedAt:             cloneTimePtr(review.LastReviewedAt),
		BoardResponseAppealID:            boardAppeal.ResponseAppealID,
		BoardParentResponseAppealID:      boardAppeal.ParentResponseAppealID,
		BoardResponseAppealGeneration:    boardAppeal.ResponseAppealGeneration,
		BoardResponseAppealStatus:        boardAppeal.Status,
		BoardResponseStatus:              boardAppeal.ResponseStatus,
		BoardResponseAction:              boardAppeal.ResponseAction,
		BoardResponseTransitionID:        boardAppeal.ResponseTransitionID,
		BoardAppealingParty:              boardAppeal.AppealingParty,
		BoardCorrectionBoardParty:        boardAppeal.CorrectionBoardParty,
		BoardEnforcementParty:            boardAppeal.EnforcementAcknowledgementParty,
		BoardSummary:                     boardAppeal.Summary,
		BoardDescription:                 boardAppeal.Description,
		BoardReviewThreshold:             boardAppeal.BoardReviewThreshold,
		EligibleBoardReviewerDIDs:        append([]string(nil), boardAppeal.EligibleBoardReviewerDIDs...),
		BoardDelegationCount:             boardAppeal.BoardDelegationCount,
		BoardRecusalCount:                boardAppeal.BoardRecusalCount,
		BoardCommitteeMemberCount:        boardAppeal.BoardCommitteeMemberCount,
		BoardRecordedVoteCount:           boardAppeal.BoardRecordedVoteCount,
		BoardOutstandingVotes:            boardAppeal.BoardOutstandingVotes,
		BoardMissingQuorumCount:          boardAppeal.BoardMissingQuorumCount,
		BoardThresholdSatisfied:          boardAppeal.BoardThresholdSatisfied,
		BoardRatifyVoteCount:             boardAppeal.RatifyVoteCount,
		BoardOverturnVoteCount:           boardAppeal.OverturnVoteCount,
		BoardRuling:                      boardAppeal.Ruling,
		BoardRulingSummary:               boardAppeal.RulingSummary,
		BoardRulingDescription:           boardAppeal.RulingDescription,
		BoardActionCount:                 boardAppeal.ActionCount,
		CreatedAt:                        boardAppeal.CreatedAt,
		UpdatedAt:                        boardAppeal.UpdatedAt,
		ControlLedgerID:                  review.ControlLedgerID,
		ControlLedgerHash:                review.ControlLedgerHash,
		PortablePackageHash:              review.PortablePackageHash,
		PortablePackageSigned:            review.PortablePackageSigned,
		PortablePackageAnchored:          review.PortablePackageAnchored,
		Metadata:                         cloneStringMap(boardAppeal.Metadata),
	}
	item.BoardAutomationActionCount = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionCountForResponseAppeal(run, boardAppeal.ResponseAppealID)
	return item
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealID(reviewID string, boardResponseAppealID string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(reviewID) + "|" + strings.TrimSpace(boardResponseAppealID)))
	return fmt.Sprintf("fed-counterparty-review-appeal-%x", digest[:8])
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter) bool {
	if filter.AppealReviewID != "" && !strings.EqualFold(strings.TrimSpace(item.AppealReviewID), strings.TrimSpace(filter.AppealReviewID)) {
		return false
	}
	if filter.ReviewID != "" && !strings.EqualFold(strings.TrimSpace(item.ReviewID), strings.TrimSpace(filter.ReviewID)) {
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
	if filter.ChallengeID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(filter.ChallengeID)) {
		return false
	}
	if filter.ChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), strings.TrimSpace(filter.ChallengeAppealID)) {
		return false
	}
	if filter.ResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseAppealID), strings.TrimSpace(filter.ResponseAppealID)) {
		return false
	}
	if filter.BoardResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.BoardResponseAppealID), strings.TrimSpace(filter.BoardResponseAppealID)) {
		return false
	}
	if filter.CounterpartySnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartySnapshotID), strings.TrimSpace(filter.CounterpartySnapshotID)) {
		return false
	}
	if filter.CounterpartyResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyResponseAppealID), strings.TrimSpace(filter.CounterpartyResponseAppealID)) {
		return false
	}
	if filter.ReviewStatus != "" && item.ReviewStatus != filter.ReviewStatus {
		return false
	}
	if filter.BoardResponseAppealStatus != "" && item.BoardResponseAppealStatus != filter.BoardResponseAppealStatus {
		return false
	}
	return true
}
