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

const secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter
// narrows first-class operator queries over local rehearing boards opened from
// disputed imported reciprocal appeal-board review trails.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter struct {
	CellID                     string                                                                                                                                       `json:"cell_id,omitempty"`
	OrganizationID             string                                                                                                                                       `json:"organization_id,omitempty"`
	IncidentID                 string                                                                                                                                       `json:"incident_id,omitempty"`
	ResponseID                 string                                                                                                                                       `json:"response_id,omitempty"`
	DirectiveID                string                                                                                                                                       `json:"directive_id,omitempty"`
	ExtensionID                string                                                                                                                                       `json:"extension_id,omitempty"`
	DisputeID                  string                                                                                                                                       `json:"dispute_id,omitempty"`
	AppealID                   string                                                                                                                                       `json:"appeal_id,omitempty"`
	ChallengeID                string                                                                                                                                       `json:"challenge_id,omitempty"`
	ChallengeAppealID          string                                                                                                                                       `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID           string                                                                                                                                       `json:"response_appeal_id,omitempty"`
	SnapshotID                 string                                                                                                                                       `json:"snapshot_id,omitempty"`
	CounterpartyReviewID       string                                                                                                                                       `json:"counterparty_review_id,omitempty"`
	CounterpartyReviewAppealID string                                                                                                                                       `json:"counterparty_review_appeal_id,omitempty"`
	ReviewStatus               SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus `json:"review_status,omitempty"`
	ResponseAppealStatus       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                               `json:"response_appeal_status,omitempty"`
	Limit                      int                                                                                                                                          `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary
// projects one local governed rehearing board that was opened from a disputed
// imported reciprocal appeal-board review trail.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary struct {
	CellID                          string                                                                                                                                             `json:"cell_id"`
	CellName                        string                                                                                                                                             `json:"cell_name,omitempty"`
	CellStatus                      SecureCellStatus                                                                                                                                   `json:"cell_status"`
	Jurisdiction                    string                                                                                                                                             `json:"jurisdiction,omitempty"`
	OrganizationID                  string                                                                                                                                             `json:"organization_id"`
	SponsorOfRecord                 string                                                                                                                                             `json:"sponsor_of_record,omitempty"`
	OrganizationName                string                                                                                                                                             `json:"organization_name,omitempty"`
	IncidentID                      string                                                                                                                                             `json:"incident_id,omitempty"`
	ResponseID                      string                                                                                                                                             `json:"response_id,omitempty"`
	DirectiveID                     string                                                                                                                                             `json:"directive_id,omitempty"`
	ExtensionID                     string                                                                                                                                             `json:"extension_id,omitempty"`
	DisputeID                       string                                                                                                                                             `json:"dispute_id,omitempty"`
	AppealID                        string                                                                                                                                             `json:"appeal_id,omitempty"`
	ChallengeID                     string                                                                                                                                             `json:"challenge_id,omitempty"`
	ChallengeAppealID               string                                                                                                                                             `json:"challenge_appeal_id,omitempty"`
	ReviewSnapshotID                string                                                                                                                                             `json:"review_snapshot_id"`
	ReviewBundleID                  string                                                                                                                                             `json:"review_bundle_id,omitempty"`
	ReviewBundleStatus              SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus `json:"review_bundle_status,omitempty"`
	ReviewBundleVerified            bool                                                                                                                                               `json:"review_bundle_verified"`
	ReviewSigner                    string                                                                                                                                             `json:"review_signer,omitempty"`
	CounterpartyReviewID            string                                                                                                                                             `json:"counterparty_review_id,omitempty"`
	CounterpartyReviewAppealID      string                                                                                                                                             `json:"counterparty_review_appeal_id,omitempty"`
	ReviewStatus                    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus       `json:"review_status,omitempty"`
	LatestReviewAction              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType   `json:"latest_review_action,omitempty"`
	ReviewActionCount               int                                                                                                                                                `json:"review_action_count"`
	ReviewLastReviewedAt            *time.Time                                                                                                                                         `json:"review_last_reviewed_at,omitempty"`
	PriorBoardResponseAppealID      string                                                                                                                                             `json:"prior_board_response_appeal_id,omitempty"`
	PriorBoardResponseAppealStatus  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                     `json:"prior_board_response_appeal_status,omitempty"`
	PriorBoardResponseStatus        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                           `json:"prior_board_response_status,omitempty"`
	PriorBoardResponseAction        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                       `json:"prior_board_response_action,omitempty"`
	PriorBoardResponseTransitionID  string                                                                                                                                             `json:"prior_board_response_transition_id,omitempty"`
	PriorBoardRuling                SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                                         `json:"prior_board_ruling,omitempty"`
	PriorBoardActionCount           int                                                                                                                                                `json:"prior_board_action_count"`
	PriorBoardRecusalCount          int                                                                                                                                                `json:"prior_board_recusal_count"`
	PriorBoardAutomationActionCount int                                                                                                                                                `json:"prior_board_automation_action_count"`
	ResponseAppealID                string                                                                                                                                             `json:"response_appeal_id"`
	ParentResponseAppealID          string                                                                                                                                             `json:"parent_response_appeal_id,omitempty"`
	ResponseAppealGeneration        int                                                                                                                                                `json:"response_appeal_generation"`
	ResponseAppealStatus            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                     `json:"response_appeal_status,omitempty"`
	ResponseStatus                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                           `json:"response_status,omitempty"`
	ResponseAction                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                       `json:"response_action,omitempty"`
	ResponseTransitionID            string                                                                                                                                             `json:"response_transition_id,omitempty"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                                                                                                          `json:"appealing_party,omitempty"`
	CorrectionBoardParty            SecureCellFederationIncidentResponseParty                                                                                                          `json:"correction_board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                                                                                                          `json:"enforcement_acknowledgement_party,omitempty"`
	Summary                         string                                                                                                                                             `json:"summary,omitempty"`
	Description                     string                                                                                                                                             `json:"description,omitempty"`
	BoardReviewThreshold            int                                                                                                                                                `json:"board_review_threshold"`
	EligibleBoardReviewerDIDs       []string                                                                                                                                           `json:"eligible_board_reviewer_dids,omitempty"`
	BoardDelegationCount            int                                                                                                                                                `json:"board_delegation_count"`
	BoardRecusalCount               int                                                                                                                                                `json:"board_recusal_count"`
	BoardCommitteeMemberCount       int                                                                                                                                                `json:"board_committee_member_count"`
	BoardRecordedVoteCount          int                                                                                                                                                `json:"board_recorded_vote_count"`
	BoardOutstandingVotes           int                                                                                                                                                `json:"board_outstanding_votes"`
	BoardMissingQuorumCount         int                                                                                                                                                `json:"board_missing_quorum_count"`
	BoardThresholdSatisfied         bool                                                                                                                                               `json:"board_threshold_satisfied"`
	BoardRatifyVoteCount            int                                                                                                                                                `json:"board_ratify_vote_count"`
	BoardOverturnVoteCount          int                                                                                                                                                `json:"board_overturn_vote_count"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                                         `json:"ruling,omitempty"`
	RulingSummary                   string                                                                                                                                             `json:"ruling_summary,omitempty"`
	RulingDescription               string                                                                                                                                             `json:"ruling_description,omitempty"`
	ActionCount                     int                                                                                                                                                `json:"action_count"`
	AutomationActionCount           int                                                                                                                                                `json:"automation_action_count"`
	CreatedAt                       time.Time                                                                                                                                          `json:"created_at"`
	UpdatedAt                       time.Time                                                                                                                                          `json:"updated_at"`
	ControlLedgerID                 string                                                                                                                                             `json:"control_ledger_id,omitempty"`
	ControlLedgerHash               string                                                                                                                                             `json:"control_ledger_hash,omitempty"`
	PortablePackageHash             string                                                                                                                                             `json:"portable_package_hash,omitempty"`
	PortablePackageSigned           bool                                                                                                                                               `json:"portable_package_signed"`
	PortablePackageAnchored         bool                                                                                                                                               `json:"portable_package_anchored"`
	Metadata                        map[string]string                                                                                                                                  `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSignature
// carries detached signer metadata for one portable bilateral review-appeal
// bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle
// packages the first-class local rehearing board opened from a disputed
// imported reciprocal appeal-board review path.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle struct {
	ID                                       string                                                                                                                                                       `json:"id"`
	Version                                  string                                                                                                                                                       `json:"version"`
	Name                                     string                                                                                                                                                       `json:"name"`
	GeneratedAt                              time.Time                                                                                                                                                    `json:"generated_at"`
	ExpiresAt                                *time.Time                                                                                                                                                   `json:"expires_at,omitempty"`
	CellID                                   string                                                                                                                                                       `json:"cell_id"`
	CellName                                 string                                                                                                                                                       `json:"cell_name,omitempty"`
	CellStatus                               SecureCellStatus                                                                                                                                             `json:"cell_status"`
	Jurisdiction                             string                                                                                                                                                       `json:"jurisdiction,omitempty"`
	Framework                                string                                                                                                                                                       `json:"framework,omitempty"`
	Organization                             SecureCellFederationOrganizationSummary                                                                                                                      `json:"organization"`
	ReviewAppeal                             SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary          `json:"review_appeal"`
	Review                                   SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary          `json:"review"`
	ReviewActions                            []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord               `json:"review_actions,omitempty"`
	PriorBoardResponseAppeal                 *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary                                             `json:"prior_board_response_appeal,omitempty"`
	PriorBoardResponseActions                []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord                                       `json:"prior_board_response_actions,omitempty"`
	PriorBoardResponseRecusals               []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary                                     `json:"prior_board_response_recusals,omitempty"`
	PriorBoardResponseAutomation             []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord                             `json:"prior_board_response_automation,omitempty"`
	ReviewAppealActions                      []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord                                       `json:"review_appeal_actions,omitempty"`
	ReviewAppealRecusals                     []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary                                     `json:"review_appeal_recusals,omitempty"`
	ReviewAppealAutomation                   []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord                             `json:"review_appeal_automation,omitempty"`
	CounterpartyReviewAppealReviewBundleHash string                                                                                                                                                       `json:"counterparty_review_appeal_review_bundle_hash,omitempty"`
	CounterpartyReviewAppealBundleHash       string                                                                                                                                                       `json:"counterparty_review_appeal_bundle_hash,omitempty"`
	CounterpartyReviewBundleHash             string                                                                                                                                                       `json:"counterparty_review_bundle_hash,omitempty"`
	AlignmentResponseBundleHash              string                                                                                                                                                       `json:"alignment_response_bundle_hash,omitempty"`
	ChallengeAppealBundleHash                string                                                                                                                                                       `json:"challenge_appeal_bundle_hash,omitempty"`
	Controls                                 []SecureCellFederationTrustPackControl                                                                                                                       `json:"controls,omitempty"`
	OperatorSurfaces                         []SecureCellFederationOperatorSurface                                                                                                                        `json:"operator_surfaces,omitempty"`
	ControlLedgerID                          string                                                                                                                                                       `json:"control_ledger_id,omitempty"`
	ControlLedgerHash                        string                                                                                                                                                       `json:"control_ledger_hash,omitempty"`
	PortablePackageHash                      string                                                                                                                                                       `json:"portable_package_hash,omitempty"`
	PortablePackageSigned                    bool                                                                                                                                                         `json:"portable_package_signed"`
	PortablePackageAnchored                  bool                                                                                                                                                         `json:"portable_package_anchored"`
	ContentHash                              string                                                                                                                                                       `json:"content_hash,omitempty"`
	Signature                                *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSignature `json:"signature,omitempty"`
	Metadata                                 map[string]string                                                                                                                                            `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleOptions
// lets callers tune review-appeal bundle identity and operator hints.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals(ctx context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: service is required")
	}
	if strings.TrimSpace(filter.CellID) == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: cell ID is required")
	}
	run, err := s.getRun(filter.CellID)
	if err != nil {
		return nil, err
	}
	reviews, err := s.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals(ctx, SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter{
		CellID:                     filter.CellID,
		OrganizationID:             filter.OrganizationID,
		IncidentID:                 filter.IncidentID,
		ResponseID:                 filter.ResponseID,
		DirectiveID:                filter.DirectiveID,
		ExtensionID:                filter.ExtensionID,
		DisputeID:                  filter.DisputeID,
		AppealID:                   filter.AppealID,
		ChallengeID:                filter.ChallengeID,
		ChallengeAppealID:          filter.ChallengeAppealID,
		SnapshotID:                 filter.SnapshotID,
		CounterpartyReviewID:       filter.CounterpartyReviewID,
		CounterpartyReviewAppealID: filter.CounterpartyReviewAppealID,
		ReviewStatus:               filter.ReviewStatus,
	})
	if err != nil {
		return nil, err
	}

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary, 0)
	for _, review := range reviews {
		reviewAppeal, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFromRun(run, review)
		if !ok {
			continue
		}
		item := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummaryFromReview(run, review, reviewAppeal)
		if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter(item, filter) {
			continue
		}
		items = append(items, item)
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].ResponseAppealID < items[j].ResponseAppealID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(ctx context.Context, cellID string, responseAppealID string, options SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleOptions) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	items, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter{
		CellID:           cellID,
		ResponseAppealID: responseAppealID,
		Limit:            1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: %w: response appeal %q", ErrFederationIncidentDirectiveNotFound, responseAppealID)
	}
	item := items[0]
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, item.OrganizationID)
	if err != nil {
		return nil, err
	}
	reviews, err := s.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals(ctx, SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter{
		CellID:     cellID,
		SnapshotID: item.ReviewSnapshotID,
		Limit:      1,
	})
	if err != nil {
		return nil, err
	}
	if len(reviews) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: %w: review snapshot %q", ErrFederationIncidentDirectiveNotFound, item.ReviewSnapshotID)
	}
	review := reviews[0]
	reviewActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewFilter{
		CellID:     cellID,
		SnapshotID: item.ReviewSnapshotID,
	})
	if err != nil {
		return nil, err
	}

	var priorBoardAppeal *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary
	priorBoardActions := []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord(nil)
	priorBoardRecusals := []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary(nil)
	priorBoardAutomation := []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord(nil)
	if strings.TrimSpace(item.PriorBoardResponseAppealID) != "" {
		if appeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, item.PriorBoardResponseAppealID); err == nil && appeal != nil {
			copy := *appeal
			priorBoardAppeal = &copy
		}
		priorBoardActions, err = s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter{
			CellID:            cellID,
			ChallengeAppealID: item.ChallengeAppealID,
			ResponseAppealID:  item.PriorBoardResponseAppealID,
		})
		if err != nil {
			return nil, err
		}
		priorBoardRecusals, err = s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter{
			CellID:            cellID,
			ChallengeAppealID: item.ChallengeAppealID,
			ResponseAppealID:  item.PriorBoardResponseAppealID,
		})
		if err != nil {
			return nil, err
		}
		priorBoardAutomation, err = s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionFilter{
			CellID:            cellID,
			ChallengeAppealID: item.ChallengeAppealID,
			ResponseAppealID:  item.PriorBoardResponseAppealID,
		})
		if err != nil {
			return nil, err
		}
	}

	reviewAppealActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter{
		CellID:            cellID,
		ChallengeAppealID: item.ChallengeAppealID,
		ResponseAppealID:  item.ResponseAppealID,
	})
	if err != nil {
		return nil, err
	}
	reviewAppealRecusals, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter{
		CellID:            cellID,
		ChallengeAppealID: item.ChallengeAppealID,
		ResponseAppealID:  item.ResponseAppealID,
	})
	if err != nil {
		return nil, err
	}
	reviewAppealAutomation, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionFilter{
		CellID:            cellID,
		ChallengeAppealID: item.ChallengeAppealID,
		ResponseAppealID:  item.ResponseAppealID,
	})
	if err != nil {
		return nil, err
	}
	reviewBundle, err := s.BuildFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle(ctx, cellID, item.ReviewSnapshotID, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleOptions{})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle{
		ID:                                       firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-counterparty-review-appeal-review-appeal-bundle", run.result.CellID, item.ResponseAppealID)),
		Version:                                  firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:                                     firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Counterparty Ruling Review Appeal Bundle %s", item.ResponseAppealID)),
		GeneratedAt:                              now,
		ExpiresAt:                                cloneTimePtr(&expiresAt),
		CellID:                                   run.result.CellID,
		CellName:                                 run.result.Name,
		CellStatus:                               run.result.Status,
		Jurisdiction:                             run.request.Jurisdiction,
		Framework:                                firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:                             orgSummary,
		ReviewAppeal:                             item,
		Review:                                   review,
		ReviewActions:                            append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord(nil), reviewActions...),
		PriorBoardResponseAppeal:                 priorBoardAppeal,
		PriorBoardResponseActions:                append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord(nil), priorBoardActions...),
		PriorBoardResponseRecusals:               append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary(nil), priorBoardRecusals...),
		PriorBoardResponseAutomation:             append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord(nil), priorBoardAutomation...),
		ReviewAppealActions:                      append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord(nil), reviewAppealActions...),
		ReviewAppealRecusals:                     append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary(nil), reviewAppealRecusals...),
		ReviewAppealAutomation:                   append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord(nil), reviewAppealAutomation...),
		CounterpartyReviewAppealReviewBundleHash: strings.TrimSpace(reviewBundle.ContentHash),
		CounterpartyReviewAppealBundleHash:       strings.TrimSpace(reviewBundle.CounterpartyReviewAppealBundleHash),
		CounterpartyReviewBundleHash:             strings.TrimSpace(reviewBundle.CounterpartyReviewBundleHash),
		AlignmentResponseBundleHash:              strings.TrimSpace(reviewBundle.AlignmentResponseBundleHash),
		ChallengeAppealBundleHash:                strings.TrimSpace(reviewBundle.ChallengeAppealBundleHash),
		Controls:                                 secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:                         cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:                                 cloneStringMap(options.Metadata),
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
	if s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSigner != nil {
		if err := s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: external bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

func VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: bundle is required")
	}
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: signature verification failed")
	}
	return nil
}

func SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleEd25519(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSignature{
		Algorithm: secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSignatureAlgorithmED25519,
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleDigest(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFromRun(run *secureCellRun, review SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, bool) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary{}, false
	}
	var selected *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary
	for _, appeal := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run) {
		if !strings.EqualFold(strings.TrimSpace(appeal.ChallengeAppealID), strings.TrimSpace(review.ChallengeAppealID)) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(appeal.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_escalated"]), "true") {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(appeal.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_snapshot_id"]), strings.TrimSpace(review.SnapshotID)) {
			continue
		}
		if strings.TrimSpace(review.CounterpartyReviewAppealID) != "" &&
			!strings.EqualFold(strings.TrimSpace(appeal.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_id"]), strings.TrimSpace(review.CounterpartyReviewAppealID)) {
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummaryFromReview(run *secureCellRun, review SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary, reviewAppeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary {
	item := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary{
		CellID:                          review.CellID,
		CellName:                        review.CellName,
		CellStatus:                      review.CellStatus,
		Jurisdiction:                    review.Jurisdiction,
		OrganizationID:                  review.OrganizationID,
		SponsorOfRecord:                 review.SponsorOfRecord,
		OrganizationName:                review.OrganizationName,
		IncidentID:                      review.IncidentID,
		ResponseID:                      review.ResponseID,
		DirectiveID:                     review.DirectiveID,
		ExtensionID:                     review.ExtensionID,
		DisputeID:                       review.DisputeID,
		AppealID:                        review.AppealID,
		ChallengeID:                     review.ChallengeID,
		ChallengeAppealID:               review.ChallengeAppealID,
		ReviewSnapshotID:                review.SnapshotID,
		ReviewBundleID:                  review.BundleID,
		ReviewBundleStatus:              review.Status,
		ReviewBundleVerified:            review.Verified,
		ReviewSigner:                    review.Signer,
		CounterpartyReviewID:            review.CounterpartyReviewID,
		CounterpartyReviewAppealID:      review.CounterpartyReviewAppealID,
		ReviewStatus:                    review.ReviewStatus,
		LatestReviewAction:              secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType(run, review.SnapshotID),
		ReviewActionCount:               review.ReviewActionCount,
		ReviewLastReviewedAt:            cloneTimePtr(review.LastReviewedAt),
		PriorBoardResponseAppealID:      review.CounterpartyBoardResponseAppealID,
		PriorBoardResponseAppealStatus:  review.CounterpartyBoardResponseAppealStatus,
		PriorBoardResponseStatus:        review.CounterpartyBoardResponseStatus,
		PriorBoardResponseAction:        review.CounterpartyBoardResponseAction,
		PriorBoardResponseTransitionID:  review.CounterpartyBoardResponseTransitionID,
		PriorBoardRuling:                review.CounterpartyBoardRuling,
		ResponseAppealID:                reviewAppeal.ResponseAppealID,
		ParentResponseAppealID:          reviewAppeal.ParentResponseAppealID,
		ResponseAppealGeneration:        reviewAppeal.ResponseAppealGeneration,
		ResponseAppealStatus:            reviewAppeal.Status,
		ResponseStatus:                  reviewAppeal.ResponseStatus,
		ResponseAction:                  reviewAppeal.ResponseAction,
		ResponseTransitionID:            reviewAppeal.ResponseTransitionID,
		AppealingParty:                  reviewAppeal.AppealingParty,
		CorrectionBoardParty:            reviewAppeal.CorrectionBoardParty,
		EnforcementAcknowledgementParty: reviewAppeal.EnforcementAcknowledgementParty,
		Summary:                         reviewAppeal.Summary,
		Description:                     reviewAppeal.Description,
		BoardReviewThreshold:            reviewAppeal.BoardReviewThreshold,
		EligibleBoardReviewerDIDs:       append([]string(nil), reviewAppeal.EligibleBoardReviewerDIDs...),
		BoardDelegationCount:            reviewAppeal.BoardDelegationCount,
		BoardRecusalCount:               reviewAppeal.BoardRecusalCount,
		BoardCommitteeMemberCount:       reviewAppeal.BoardCommitteeMemberCount,
		BoardRecordedVoteCount:          reviewAppeal.BoardRecordedVoteCount,
		BoardOutstandingVotes:           reviewAppeal.BoardOutstandingVotes,
		BoardMissingQuorumCount:         reviewAppeal.BoardMissingQuorumCount,
		BoardThresholdSatisfied:         reviewAppeal.BoardThresholdSatisfied,
		BoardRatifyVoteCount:            reviewAppeal.RatifyVoteCount,
		BoardOverturnVoteCount:          reviewAppeal.OverturnVoteCount,
		Ruling:                          reviewAppeal.Ruling,
		RulingSummary:                   reviewAppeal.RulingSummary,
		RulingDescription:               reviewAppeal.RulingDescription,
		ActionCount:                     reviewAppeal.ActionCount,
		CreatedAt:                       reviewAppeal.CreatedAt,
		UpdatedAt:                       reviewAppeal.UpdatedAt,
		ControlLedgerID:                 review.ControlLedgerID,
		ControlLedgerHash:               review.ControlLedgerHash,
		PortablePackageHash:             review.PortablePackageHash,
		PortablePackageSigned:           review.PortablePackageSigned,
		PortablePackageAnchored:         review.PortablePackageAnchored,
		Metadata:                        cloneStringMap(reviewAppeal.Metadata),
	}
	item.PriorBoardActionCount = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionCountForResponseAppeal(run, review.CounterpartyBoardResponseAppealID)
	item.PriorBoardAutomationActionCount = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionCountForResponseAppeal(run, review.CounterpartyBoardResponseAppealID)
	item.PriorBoardRecusalCount = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalCountForResponseAppeal(run, review.CounterpartyBoardResponseAppealID)
	item.AutomationActionCount = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionCountForResponseAppeal(run, reviewAppeal.ResponseAppealID)
	return item
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter) bool {
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
	if filter.SnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.ReviewSnapshotID), strings.TrimSpace(filter.SnapshotID)) {
		return false
	}
	if filter.CounterpartyReviewID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyReviewID), strings.TrimSpace(filter.CounterpartyReviewID)) {
		return false
	}
	if filter.CounterpartyReviewAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyReviewAppealID), strings.TrimSpace(filter.CounterpartyReviewAppealID)) {
		return false
	}
	if filter.ReviewStatus != "" && item.ReviewStatus != filter.ReviewStatus {
		return false
	}
	if filter.ResponseAppealStatus != "" && item.ResponseAppealStatus != filter.ResponseAppealStatus {
		return false
	}
	return true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealReviewAppealStatusCount(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary, status SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus) int {
	total := 0
	for _, item := range items {
		if item.ResponseAppealStatus == status {
			total++
		}
	}
	return total
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionCountForResponseAppeal(run *secureCellRun, responseAppealID string) int {
	if run == nil || run.result == nil || strings.TrimSpace(responseAppealID) == "" {
		return 0
	}
	count := 0
	for _, appeal := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run) {
		if strings.EqualFold(strings.TrimSpace(appeal.ResponseAppealID), strings.TrimSpace(responseAppealID)) {
			count = appeal.ActionCount
			break
		}
	}
	return count
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalCountForResponseAppeal(run *secureCellRun, responseAppealID string) int {
	if run == nil || run.result == nil || strings.TrimSpace(responseAppealID) == "" {
		return 0
	}
	count := 0
	for _, appeal := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run) {
		if strings.EqualFold(strings.TrimSpace(appeal.ResponseAppealID), strings.TrimSpace(responseAppealID)) {
			count = appeal.BoardRecusalCount
			break
		}
	}
	return count
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType(run *secureCellRun, snapshotID string) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType {
	latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAction(run, snapshotID)
	if latest == nil {
		return ""
	}
	return latest.Action
}
