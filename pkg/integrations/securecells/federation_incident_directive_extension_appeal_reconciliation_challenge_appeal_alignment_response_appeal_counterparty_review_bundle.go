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

const secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewFilter
// narrows operator queries over bilateral review chains for imported
// counterparty correction-board rulings.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewFilter struct {
	CellID                       string                                                                                                                           `json:"cell_id,omitempty"`
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
	CounterpartySnapshotID       string                                                                                                                           `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyResponseAppealID string                                                                                                                           `json:"counterparty_response_appeal_id,omitempty"`
	AlignmentStatus              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus                                 `json:"alignment_status,omitempty"`
	ReviewStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus `json:"review_status,omitempty"`
	Limit                        int                                                                                                                              `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummary
// projects one first-class bilateral review chain over an imported
// counterparty correction-board ruling and the local governed response to it.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummary struct {
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
	ParentResponseAppealID           string                                                                                                                           `json:"parent_response_appeal_id,omitempty"`
	ResponseAppealGeneration         int                                                                                                                              `json:"response_appeal_generation,omitempty"`
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
	AlignmentStatus                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus                                 `json:"alignment_status,omitempty"`
	AlignmentDivergenceCount         int                                                                                                                              `json:"alignment_divergence_count"`
	ReviewStatus                     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus `json:"review_status"`
	LatestReviewAction               SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType   `json:"latest_review_action,omitempty"`
	LastReviewedBy                   string                                                                                                                           `json:"last_reviewed_by,omitempty"`
	LastReviewedAt                   *time.Time                                                                                                                       `json:"last_reviewed_at,omitempty"`
	ReviewActionCount                int                                                                                                                              `json:"review_action_count"`
	ResponseAppealActionCount        int                                                                                                                              `json:"response_appeal_action_count"`
	ResponseAppealRecusalCount       int                                                                                                                              `json:"response_appeal_recusal_count"`
	ResponseAppealAutomationCount    int                                                                                                                              `json:"response_appeal_automation_action_count"`
	CreatedAt                        *time.Time                                                                                                                       `json:"created_at,omitempty"`
	ReceivedAt                       time.Time                                                                                                                        `json:"received_at"`
	GeneratedAt                      time.Time                                                                                                                        `json:"generated_at"`
	ExpiresAt                        *time.Time                                                                                                                       `json:"expires_at,omitempty"`
	VerificationMessage              string                                                                                                                           `json:"verification_message,omitempty"`
	MatchedLocalResponseAppealID     string                                                                                                                           `json:"matched_local_response_appeal_id,omitempty"`
	ControlLedgerID                  string                                                                                                                           `json:"control_ledger_id,omitempty"`
	ControlLedgerHash                string                                                                                                                           `json:"control_ledger_hash,omitempty"`
	PortablePackageHash              string                                                                                                                           `json:"portable_package_hash,omitempty"`
	PortablePackageSigned            bool                                                                                                                             `json:"portable_package_signed"`
	PortablePackageAnchored          bool                                                                                                                             `json:"portable_package_anchored"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleSignature
// captures detached signer metadata for one portable bilateral review bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle
// is the signed auditor package for one imported counterparty ruling review
// chain and the local governed response to it.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle struct {
	ID                            string                                                                                                                                     `json:"id"`
	Version                       string                                                                                                                                     `json:"version"`
	Name                          string                                                                                                                                     `json:"name"`
	GeneratedAt                   time.Time                                                                                                                                  `json:"generated_at"`
	ExpiresAt                     *time.Time                                                                                                                                 `json:"expires_at,omitempty"`
	CellID                        string                                                                                                                                     `json:"cell_id"`
	CellName                      string                                                                                                                                     `json:"cell_name,omitempty"`
	CellStatus                    SecureCellStatus                                                                                                                           `json:"cell_status"`
	Jurisdiction                  string                                                                                                                                     `json:"jurisdiction,omitempty"`
	Framework                     string                                                                                                                                     `json:"framework,omitempty"`
	Organization                  SecureCellFederationOrganizationSummary                                                                                                    `json:"organization"`
	Review                        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummary          `json:"review"`
	CounterpartyAppeal            SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary                `json:"counterparty_appeal"`
	LocalResponseAppeal           *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary                           `json:"local_response_appeal,omitempty"`
	CounterpartyActions           []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord         `json:"counterparty_actions,omitempty"`
	LocalResponseAppealActions    []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord                     `json:"local_response_appeal_actions,omitempty"`
	LocalResponseAppealRecusals   []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary                   `json:"local_response_appeal_recusals,omitempty"`
	LocalResponseAppealAutomation []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord           `json:"local_response_appeal_automation_actions,omitempty"`
	AlignmentResponseBundleHash   string                                                                                                                                     `json:"alignment_response_bundle_hash,omitempty"`
	Controls                      []SecureCellFederationTrustPackControl                                                                                                     `json:"controls,omitempty"`
	OperatorSurfaces              []SecureCellFederationOperatorSurface                                                                                                      `json:"operator_surfaces,omitempty"`
	ControlLedgerID               string                                                                                                                                     `json:"control_ledger_id,omitempty"`
	ControlLedgerHash             string                                                                                                                                     `json:"control_ledger_hash,omitempty"`
	PortablePackageHash           string                                                                                                                                     `json:"portable_package_hash,omitempty"`
	PortablePackageSigned         bool                                                                                                                                       `json:"portable_package_signed"`
	PortablePackageAnchored       bool                                                                                                                                       `json:"portable_package_anchored"`
	ContentHash                   string                                                                                                                                     `json:"content_hash,omitempty"`
	Signature                     *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleSignature `json:"signature,omitempty"`
	Metadata                      map[string]string                                                                                                                          `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleOptions
// lets callers tune bundle identity and operator-surface hints.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviews(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummary, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review: service is required")
	}
	if strings.TrimSpace(filter.CellID) == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review: cell ID is required")
	}
	run, err := s.getRun(filter.CellID)
	if err != nil {
		return nil, err
	}
	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummary, 0)
	for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponses {
		for _, counterpartyAppeal := range secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummariesFromRun(run, snapshot) {
			item := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummaryFromCounterparty(run, snapshot, counterpartyAppeal)
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewFilter(item, filter) {
				continue
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i].ReceivedAt
		if items[i].LastReviewedAt != nil {
			left = items[i].LastReviewedAt.UTC()
		}
		right := items[j].ReceivedAt
		if items[j].LastReviewedAt != nil {
			right = items[j].LastReviewedAt.UTC()
		}
		if left.Equal(right) {
			return items[i].ReviewID < items[j].ReviewID
		}
		return left.After(right)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

// BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle
// returns the signed auditor bundle for one bilateral imported-ruling review chain.
func (s *Service) BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle(ctx context.Context, cellID string, reviewID string, options SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleOptions) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	reviews, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviews(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewFilter{
		CellID:   cellID,
		ReviewID: reviewID,
		Limit:    1,
	})
	if err != nil {
		return nil, err
	}
	if len(reviews) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: %w: review %q", ErrFederationIncidentDirectiveNotFound, reviewID)
	}
	review := reviews[0]
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, review.OrganizationID)
	if err != nil {
		return nil, err
	}
	counterpartyAppeal, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummaryBySnapshotAndAppeal(run, review.CounterpartySnapshotID, review.CounterpartyResponseAppealID)
	if err != nil {
		return nil, err
	}
	counterpartyActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFilter{
		CellID:                       cellID,
		ChallengeAppealID:            review.ChallengeAppealID,
		ResponseAppealID:             review.ResponseAppealID,
		CounterpartySnapshotID:       review.CounterpartySnapshotID,
		CounterpartyResponseAppealID: review.CounterpartyResponseAppealID,
	})
	if err != nil {
		return nil, err
	}

	var localAppeal *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary
	localAppealActions := []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord(nil)
	localAppealRecusals := []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary(nil)
	localAppealAutomation := []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord(nil)
	if strings.TrimSpace(review.ResponseAppealID) != "" {
		selectedAppealID := strings.TrimSpace(review.ResponseAppealID)
		if latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealForChallengeAppeal(run, review.ChallengeAppealID); latest != nil &&
			strings.EqualFold(strings.TrimSpace(latest.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_snapshot_id"]), strings.TrimSpace(review.CounterpartySnapshotID)) &&
			strings.EqualFold(strings.TrimSpace(latest.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_response_appeal_id"]), strings.TrimSpace(review.CounterpartyResponseAppealID)) {
			selectedAppealID = strings.TrimSpace(latest.ResponseAppealID)
		}
		if appeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, selectedAppealID); err == nil && appeal != nil {
			copy := *appeal
			localAppeal = &copy
		}
		localAppealActions, err = s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter{
			CellID:            cellID,
			ChallengeAppealID: review.ChallengeAppealID,
			ResponseAppealID:  selectedAppealID,
		})
		if err != nil {
			return nil, err
		}
		localAppealRecusals, err = s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter{
			CellID:            cellID,
			ChallengeAppealID: review.ChallengeAppealID,
			ResponseAppealID:  selectedAppealID,
		})
		if err != nil {
			return nil, err
		}
		localAppealAutomation, err = s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionFilter{
			CellID:            cellID,
			ChallengeAppealID: review.ChallengeAppealID,
			ResponseAppealID:  selectedAppealID,
		})
		if err != nil {
			return nil, err
		}
	}

	alignmentResponseBundle, err := s.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle(ctx, cellID, review.ChallengeAppealID, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleOptions{})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle{
		ID:                            firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-counterparty-review-bundle", run.result.CellID, review.ReviewID)),
		Version:                       firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:                          firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Counterparty Ruling Review Bundle %s", review.ReviewID)),
		GeneratedAt:                   now,
		ExpiresAt:                     cloneTimePtr(&expiresAt),
		CellID:                        run.result.CellID,
		CellName:                      run.result.Name,
		CellStatus:                    run.result.Status,
		Jurisdiction:                  run.request.Jurisdiction,
		Framework:                     firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:                  orgSummary,
		Review:                        review,
		CounterpartyAppeal:            counterpartyAppeal,
		LocalResponseAppeal:           localAppeal,
		CounterpartyActions:           append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord(nil), counterpartyActions...),
		LocalResponseAppealActions:    append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord(nil), localAppealActions...),
		LocalResponseAppealRecusals:   append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary(nil), localAppealRecusals...),
		LocalResponseAppealAutomation: append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord(nil), localAppealAutomation...),
		AlignmentResponseBundleHash:   strings.TrimSpace(alignmentResponseBundle.ContentHash),
		Controls:                      secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:              cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:                      cloneStringMap(options.Metadata),
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
	if s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleSigner != nil {
		if err := s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: external bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

func VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: bundle is required")
	}
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: signature verification failed")
	}
	return nil
}

func SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleEd25519(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleSignature{
		Algorithm: secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleSignatureAlgorithmED25519,
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleDigest(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummaryFromCounterparty(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseSnapshot, counterpartyAppeal SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummary {
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	localResponseAppealID := strings.TrimSpace(counterpartyAppeal.MatchedLocalResponseAppealID)
	latestCounterpartyReview := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewActionByTarget(run, counterpartyAppeal.SnapshotID, counterpartyAppeal.ResponseAppealID)
	if localResponseAppealID == "" && latestCounterpartyReview != nil {
		localResponseAppealID = strings.TrimSpace(latestCounterpartyReview.ResponseAppealID)
	}

	var localAppeal *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary
	if localResponseAppealID != "" {
		localAppeal, _ = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, localResponseAppealID)
	}

	lastReviewedBy := strings.TrimSpace(counterpartyAppeal.LastReviewedBy)
	lastReviewedAt := cloneTimePtr(counterpartyAppeal.LastReviewedAt)
	latestReviewAction := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType("")
	counterpartyReference := ""
	if latestCounterpartyReview != nil {
		lastReviewedBy = strings.TrimSpace(latestCounterpartyReview.ActorDID)
		at := latestCounterpartyReview.OccurredAt.UTC()
		lastReviewedAt = &at
		latestReviewAction = latestCounterpartyReview.Action
		counterpartyReference = strings.TrimSpace(latestCounterpartyReview.CounterpartyReference)
	}

	responseAppealActionCount := 0
	responseAppealRecusalCount := 0
	responseAppealAutomationCount := 0
	responseAppealID := localResponseAppealID
	parentResponseAppealID := ""
	responseAppealGeneration := 0
	responseAppealStatus := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus("")
	responseStatus := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus("")
	responseAction := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType("")
	responseTransitionID := ""
	localRuling := SecureCellFederationIncidentDirectiveExtensionAppealRuling("")
	var createdAt *time.Time
	if localAppeal != nil {
		responseAppealID = strings.TrimSpace(localAppeal.ResponseAppealID)
		parentResponseAppealID = strings.TrimSpace(localAppeal.ParentResponseAppealID)
		responseAppealGeneration = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGeneration(*localAppeal)
		responseAppealStatus = localAppeal.Status
		responseStatus = localAppeal.ResponseStatus
		responseAction = localAppeal.ResponseAction
		responseTransitionID = strings.TrimSpace(localAppeal.ResponseTransitionID)
		localRuling = localAppeal.Ruling
		if !localAppeal.CreatedAt.IsZero() {
			at := localAppeal.CreatedAt.UTC()
			createdAt = &at
		}
		responseAppealActionCount = localAppeal.ActionCount
		responseAppealRecusalCount = localAppeal.BoardRecusalCount
		responseAppealAutomationCount = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionCountForResponseAppeal(run, localAppeal.ResponseAppealID)
	}
	if latestCounterpartyReview != nil {
		if latestCounterpartyReview.LocalResponseAppealStatus != "" {
			responseAppealStatus = latestCounterpartyReview.LocalResponseAppealStatus
		}
		if latestCounterpartyReview.LocalResponseStatus != "" {
			responseStatus = latestCounterpartyReview.LocalResponseStatus
		}
		if latestCounterpartyReview.LocalResponseAction != "" {
			responseAction = latestCounterpartyReview.LocalResponseAction
		}
		if strings.TrimSpace(latestCounterpartyReview.LocalResponseTransitionID) != "" {
			responseTransitionID = strings.TrimSpace(latestCounterpartyReview.LocalResponseTransitionID)
		}
		if latestCounterpartyReview.LocalRuling != "" {
			localRuling = latestCounterpartyReview.LocalRuling
		}
	}

	reviewID := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewID(
		safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		counterpartyAppeal.SnapshotID,
		counterpartyAppeal.ResponseAppealID,
		responseAppealID,
	)
	item := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummary{
		ReviewID:                         reviewID,
		CellID:                           safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                         safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                       safeSecureCellStatus(run),
		Jurisdiction:                     safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:                   strings.TrimSpace(snapshot.OrganizationID),
		SponsorOfRecord:                  strings.TrimSpace(orgSummary.SponsorOfRecord),
		OrganizationName:                 strings.TrimSpace(orgSummary.OrganizationName),
		IncidentID:                       strings.TrimSpace(counterpartyAppeal.IncidentID),
		ResponseID:                       strings.TrimSpace(counterpartyAppeal.ResponseID),
		DirectiveID:                      strings.TrimSpace(counterpartyAppeal.DirectiveID),
		ExtensionID:                      strings.TrimSpace(counterpartyAppeal.ExtensionID),
		DisputeID:                        strings.TrimSpace(counterpartyAppeal.DisputeID),
		AppealID:                         strings.TrimSpace(counterpartyAppeal.AppealID),
		ChallengeID:                      strings.TrimSpace(counterpartyAppeal.ChallengeID),
		ChallengeAppealID:                strings.TrimSpace(counterpartyAppeal.ChallengeAppealID),
		ResponseAppealID:                 responseAppealID,
		ParentResponseAppealID:           parentResponseAppealID,
		ResponseAppealGeneration:         responseAppealGeneration,
		ResponseAppealStatus:             responseAppealStatus,
		ResponseStatus:                   responseStatus,
		ResponseAction:                   responseAction,
		ResponseTransitionID:             responseTransitionID,
		LocalRuling:                      localRuling,
		CounterpartySnapshotID:           strings.TrimSpace(counterpartyAppeal.SnapshotID),
		CounterpartyBundleID:             strings.TrimSpace(counterpartyAppeal.BundleID),
		CounterpartyBundleStatus:         counterpartyAppeal.Status,
		CounterpartyBundleVerified:       counterpartyAppeal.Verified,
		CounterpartySigner:               strings.TrimSpace(counterpartyAppeal.Signer),
		CounterpartyResponseAppealID:     strings.TrimSpace(counterpartyAppeal.ResponseAppealID),
		CounterpartyResponseAppealStatus: counterpartyAppeal.ResponseAppealStatus,
		CounterpartyResponseStatus:       counterpartyAppeal.ResponseStatus,
		CounterpartyResponseAction:       counterpartyAppeal.ResponseAction,
		CounterpartyResponseTransitionID: strings.TrimSpace(counterpartyAppeal.ResponseTransitionID),
		CounterpartyRuling:               counterpartyAppeal.Ruling,
		CounterpartyReference:            counterpartyReference,
		AlignmentStatus:                  counterpartyAppeal.AlignmentStatus,
		AlignmentDivergenceCount:         counterpartyAppeal.AlignmentDivergenceCount,
		ReviewStatus:                     counterpartyAppeal.ReviewStatus,
		LatestReviewAction:               latestReviewAction,
		LastReviewedBy:                   lastReviewedBy,
		LastReviewedAt:                   lastReviewedAt,
		ReviewActionCount:                counterpartyAppeal.ReviewActionCount,
		ResponseAppealActionCount:        responseAppealActionCount,
		ResponseAppealRecusalCount:       responseAppealRecusalCount,
		ResponseAppealAutomationCount:    responseAppealAutomationCount,
		CreatedAt:                        createdAt,
		ReceivedAt:                       snapshot.ReceivedAt.UTC(),
		GeneratedAt:                      counterpartyAppeal.GeneratedAt.UTC(),
		ExpiresAt:                        cloneTimePtr(counterpartyAppeal.ExpiresAt),
		VerificationMessage:              strings.TrimSpace(counterpartyAppeal.VerificationMessage),
		MatchedLocalResponseAppealID:     strings.TrimSpace(counterpartyAppeal.MatchedLocalResponseAppealID),
		ControlLedgerID:                  strings.TrimSpace(counterpartyAppeal.ControlLedgerID),
		ControlLedgerHash:                strings.TrimSpace(counterpartyAppeal.ControlLedgerHash),
		PortablePackageHash:              strings.TrimSpace(counterpartyAppeal.PortablePackageHash),
		PortablePackageSigned:            counterpartyAppeal.PortablePackageSigned,
		PortablePackageAnchored:          counterpartyAppeal.PortablePackageAnchored,
	}
	return item
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewID(cellID string, counterpartySnapshotID string, counterpartyResponseAppealID string, responseAppealID string) string {
	return fmt.Sprintf("%s-federation-counterparty-response-appeal-review-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(cellID),
		strings.TrimSpace(counterpartySnapshotID),
		strings.TrimSpace(counterpartyResponseAppealID),
		strings.TrimSpace(responseAppealID),
	}, "|"))))
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewActionByTarget(run *secureCellRun, snapshotID string, counterpartyResponseAppealID string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord {
	var latest *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFromTransition(run, transition)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.CounterpartySnapshotID), strings.TrimSpace(snapshotID)) || !strings.EqualFold(strings.TrimSpace(record.CounterpartyResponseAppealID), strings.TrimSpace(counterpartyResponseAppealID)) {
			continue
		}
		recordCopy := record
		latest = &recordCopy
	}
	return latest
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionCountForResponseAppeal(run *secureCellRun, responseAppealID string) int {
	count := 0
	for _, transition := range run.result.Transitions {
		if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAction(transition) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id"]), strings.TrimSpace(responseAppealID)) {
			continue
		}
		count++
	}
	return count
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewSummary, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewFilter) bool {
	if filter.ReviewID != "" && !strings.EqualFold(strings.TrimSpace(item.ReviewID), strings.TrimSpace(filter.ReviewID)) {
		return false
	}
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
	if filter.ChallengeID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(filter.ChallengeID)) {
		return false
	}
	if filter.ChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), strings.TrimSpace(filter.ChallengeAppealID)) {
		return false
	}
	if filter.ResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseAppealID), strings.TrimSpace(filter.ResponseAppealID)) {
		return false
	}
	if filter.CounterpartySnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartySnapshotID), strings.TrimSpace(filter.CounterpartySnapshotID)) {
		return false
	}
	if filter.CounterpartyResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyResponseAppealID), strings.TrimSpace(filter.CounterpartyResponseAppealID)) {
		return false
	}
	if filter.AlignmentStatus != "" && item.AlignmentStatus != filter.AlignmentStatus {
		return false
	}
	if filter.ReviewStatus != "" && item.ReviewStatus != filter.ReviewStatus {
		return false
	}
	return true
}
