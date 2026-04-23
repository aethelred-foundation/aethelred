package securecells

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSnapshot
// persists one imported signed bilateral rehearing-board bundle over a
// counterparty review-appeal ruling.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSnapshot struct {
	SnapshotID          string                                                                                                                                             `json:"snapshot_id"`
	OrganizationID      string                                                                                                                                             `json:"organization_id"`
	Bundle              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle `json:"bundle"`
	Status              SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus `json:"status"`
	Verified            bool                                                                                                                                               `json:"verified"`
	VerificationMessage string                                                                                                                                             `json:"verification_message,omitempty"`
	Signer              string                                                                                                                                             `json:"signer,omitempty"`
	ReceivedBy          string                                                                                                                                             `json:"received_by,omitempty"`
	ReceivedAt          time.Time                                                                                                                                          `json:"received_at"`
	Metadata            map[string]string                                                                                                                                  `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleIntakeRequest
// ingests one signed bilateral imported rehearing-board bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleIntakeRequest struct {
	ActorDID string                                                                                                                                              `json:"actor_did,omitempty"`
	Bundle   *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle `json:"bundle,omitempty"`
	Reason   string                                                                                                                                              `json:"reason,omitempty"`
	Metadata map[string]string                                                                                                                                   `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter
// narrows operator queries across imported signed rehearing-board bundles.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter struct {
	CellID                     string                                                                                                                                             `json:"cell_id,omitempty"`
	OrganizationID             string                                                                                                                                             `json:"organization_id,omitempty"`
	IncidentID                 string                                                                                                                                             `json:"incident_id,omitempty"`
	ResponseID                 string                                                                                                                                             `json:"response_id,omitempty"`
	DirectiveID                string                                                                                                                                             `json:"directive_id,omitempty"`
	ExtensionID                string                                                                                                                                             `json:"extension_id,omitempty"`
	DisputeID                  string                                                                                                                                             `json:"dispute_id,omitempty"`
	AppealID                   string                                                                                                                                             `json:"appeal_id,omitempty"`
	ChallengeID                string                                                                                                                                             `json:"challenge_id,omitempty"`
	ChallengeAppealID          string                                                                                                                                             `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID           string                                                                                                                                             `json:"response_appeal_id,omitempty"`
	SnapshotID                 string                                                                                                                                             `json:"snapshot_id,omitempty"`
	ReviewSnapshotID           string                                                                                                                                             `json:"review_snapshot_id,omitempty"`
	CounterpartyReviewID       string                                                                                                                                             `json:"counterparty_review_id,omitempty"`
	CounterpartyReviewAppealID string                                                                                                                                             `json:"counterparty_review_appeal_id,omitempty"`
	Status                     SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus `json:"status,omitempty"`
	Limit                      int                                                                                                                                                `json:"limit,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary
// projects one imported signed rehearing-board bundle for operator query/export.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary struct {
	CellID                         string                                                                                                                                             `json:"cell_id"`
	CellName                       string                                                                                                                                             `json:"cell_name,omitempty"`
	CellStatus                     SecureCellStatus                                                                                                                                   `json:"cell_status"`
	Jurisdiction                   string                                                                                                                                             `json:"jurisdiction,omitempty"`
	OrganizationID                 string                                                                                                                                             `json:"organization_id"`
	SponsorOfRecord                string                                                                                                                                             `json:"sponsor_of_record,omitempty"`
	OrganizationName               string                                                                                                                                             `json:"organization_name,omitempty"`
	OrganizationStatus             SecureCellFederationOrganizationStatus                                                                                                             `json:"organization_status,omitempty"`
	SnapshotID                     string                                                                                                                                             `json:"snapshot_id"`
	BundleID                       string                                                                                                                                             `json:"bundle_id,omitempty"`
	BundleVersion                  string                                                                                                                                             `json:"bundle_version,omitempty"`
	BundleName                     string                                                                                                                                             `json:"bundle_name,omitempty"`
	Status                         SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus `json:"status,omitempty"`
	Verified                       bool                                                                                                                                               `json:"verified"`
	VerificationMessage            string                                                                                                                                             `json:"verification_message,omitempty"`
	Signer                         string                                                                                                                                             `json:"signer,omitempty"`
	IncidentID                     string                                                                                                                                             `json:"incident_id,omitempty"`
	ResponseID                     string                                                                                                                                             `json:"response_id,omitempty"`
	DirectiveID                    string                                                                                                                                             `json:"directive_id,omitempty"`
	ExtensionID                    string                                                                                                                                             `json:"extension_id,omitempty"`
	DisputeID                      string                                                                                                                                             `json:"dispute_id,omitempty"`
	AppealID                       string                                                                                                                                             `json:"appeal_id,omitempty"`
	ChallengeID                    string                                                                                                                                             `json:"challenge_id,omitempty"`
	ChallengeAppealID              string                                                                                                                                             `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID               string                                                                                                                                             `json:"response_appeal_id,omitempty"`
	ResponseAppealGeneration       int                                                                                                                                                `json:"response_appeal_generation,omitempty"`
	ResponseAppealStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                     `json:"response_appeal_status,omitempty"`
	ResponseStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                           `json:"response_status,omitempty"`
	ResponseAction                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                       `json:"response_action,omitempty"`
	ResponseTransitionID           string                                                                                                                                             `json:"response_transition_id,omitempty"`
	Ruling                         SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                                         `json:"ruling,omitempty"`
	ReviewSnapshotID               string                                                                                                                                             `json:"review_snapshot_id,omitempty"`
	ReviewBundleID                 string                                                                                                                                             `json:"review_bundle_id,omitempty"`
	ReviewBundleStatus             SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus `json:"review_bundle_status,omitempty"`
	ReviewStatus                   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus       `json:"review_status,omitempty"`
	LatestReviewAction             SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType   `json:"latest_review_action,omitempty"`
	ReviewActionCount              int                                                                                                                                                `json:"review_action_count,omitempty"`
	CounterpartyReviewID           string                                                                                                                                             `json:"counterparty_review_id,omitempty"`
	CounterpartyReviewAppealID     string                                                                                                                                             `json:"counterparty_review_appeal_id,omitempty"`
	PriorBoardResponseAppealID     string                                                                                                                                             `json:"prior_board_response_appeal_id,omitempty"`
	PriorBoardResponseAppealStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                     `json:"prior_board_response_appeal_status,omitempty"`
	PriorBoardResponseStatus       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                           `json:"prior_board_response_status,omitempty"`
	PriorBoardResponseAction       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                       `json:"prior_board_response_action,omitempty"`
	GeneratedAt                    time.Time                                                                                                                                          `json:"generated_at"`
	ExpiresAt                      *time.Time                                                                                                                                         `json:"expires_at,omitempty"`
	ReceivedAt                     time.Time                                                                                                                                          `json:"received_at"`
	ControlLedgerID                string                                                                                                                                             `json:"control_ledger_id,omitempty"`
	ControlLedgerHash              string                                                                                                                                             `json:"control_ledger_hash,omitempty"`
	PortablePackageHash            string                                                                                                                                             `json:"portable_package_hash,omitempty"`
	PortablePackageSigned          bool                                                                                                                                               `json:"portable_package_signed"`
	PortablePackageAnchored        bool                                                                                                                                               `json:"portable_package_anchored"`
	ContentHash                    string                                                                                                                                             `json:"content_hash,omitempty"`
	ReceivedBy                     string                                                                                                                                             `json:"received_by,omitempty"`
	Metadata                       map[string]string                                                                                                                                  `json:"metadata,omitempty"`
}

func (s *Service) IngestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(ctx context.Context, cellID string, organizationID string, intake SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleIntakeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, organizationID)
	if err != nil {
		return nil, err
	}
	if intake.Bundle == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: bundle is required")
	}
	bundle := secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(*intake.Bundle)
	actorDID := firstNonEmpty(strings.TrimSpace(intake.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: %w: actor %q is not permitted to intake reciprocal rehearing-board bundles", ErrPolicyDenied, actorDID)
	}

	verificationErr := VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(&bundle)
	if verificationErr == nil {
		verificationErr = secureCellValidateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSemantics(&bundle, strings.TrimSpace(orgSummary.OrganizationID))
	}
	now := time.Now().UTC()
	status, verificationMessage, verified := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleStatusAt(&bundle, verificationErr, now)

	localResponseAppealID := strings.TrimSpace(bundle.ReviewAppeal.ResponseAppealID)
	if localResponseAppealID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: local response appeal reference is required")
	}
	if _, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, localResponseAppealID); err != nil {
		return nil, err
	}

	receipt, err := s.evaluateStage(ctx, run.request, "intake_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_bundle", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":   strings.TrimSpace(orgSummary.OrganizationID),
		"federation_sponsor_of_record": strings.TrimSpace(orgSummary.SponsorOfRecord),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                                                                        strings.TrimSpace(bundle.ReviewAppeal.ChallengeAppealID),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_id":     strings.TrimSpace(bundle.ReviewAppeal.ResponseAppealID),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_snapshot_id":   strings.TrimSpace(bundle.ReviewAppeal.ReviewSnapshotID),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_bundle_status": string(status),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_bundle_signer": secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSignerName(&bundle),
		"transition_reason": strings.TrimSpace(intake.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: %w", ErrPolicyDenied)
	}

	snapshot := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSnapshot{
		SnapshotID:          fmt.Sprintf("%s-federation-counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", strings.TrimSpace(orgSummary.OrganizationID), strings.TrimSpace(bundle.ID), now.Format(time.RFC3339Nano))))),
		OrganizationID:      strings.TrimSpace(orgSummary.OrganizationID),
		Bundle:              bundle,
		Status:              status,
		Verified:            verified,
		VerificationMessage: strings.TrimSpace(verificationMessage),
		Signer:              secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSignerName(&bundle),
		ReceivedBy:          actorDID,
		ReceivedAt:          now,
		Metadata:            cloneStringMap(intake.Metadata),
	}
	run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals = append(run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals, snapshot)
	run.result.UpdatedAt = receipt.EvaluatedAt.UTC()

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_bundle_ingested", snapshot.SnapshotID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_bundle_ingested",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_bundle",
		TargetDID:        snapshot.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(intake.Reason),
		Metadata: mergeStringMaps(intake.Metadata, map[string]string{
			"federation_organization_id":                                                        snapshot.OrganizationID,
			"federation_sponsor_of_record":                                                      strings.TrimSpace(orgSummary.SponsorOfRecord),
			"federation_organization_name":                                                      strings.TrimSpace(orgSummary.OrganizationName),
			"federation_incident_id":                                                            strings.TrimSpace(bundle.ReviewAppeal.IncidentID),
			"federation_incident_response_id":                                                   strings.TrimSpace(bundle.ReviewAppeal.ResponseID),
			"federation_incident_directive_id":                                                  strings.TrimSpace(bundle.ReviewAppeal.DirectiveID),
			"federation_incident_directive_extension_id":                                        strings.TrimSpace(bundle.ReviewAppeal.ExtensionID),
			"federation_incident_directive_extension_dispute_id":                                strings.TrimSpace(bundle.ReviewAppeal.DisputeID),
			"federation_incident_directive_extension_appeal_id":                                 strings.TrimSpace(bundle.ReviewAppeal.AppealID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":        strings.TrimSpace(bundle.ReviewAppeal.ChallengeID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id": strings.TrimSpace(bundle.ReviewAppeal.ChallengeAppealID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_snapshot_id": snapshot.SnapshotID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_bundle_id":   strings.TrimSpace(bundle.ID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_snapshot_id":        strings.TrimSpace(bundle.ReviewAppeal.ReviewSnapshotID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_bundle_id":          strings.TrimSpace(bundle.ReviewAppeal.ReviewBundleID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_status":      string(status),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_signer":      strings.TrimSpace(snapshot.Signer),
		}),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals(_ context.Context, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter) ([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals {
			item := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummaryFromSnapshot(run, snapshot)
			if !matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter(item, filter) {
				continue
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ReceivedAt.Equal(items[j].ReceivedAt) {
			return items[i].SnapshotID > items[j].SnapshotID
		}
		return items[i].ReceivedAt.After(items[j].ReceivedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) GetFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(_ context.Context, cellID string, snapshotID string) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals {
		if strings.EqualFold(strings.TrimSpace(snapshot.SnapshotID), strings.TrimSpace(snapshotID)) {
			bundle := secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(snapshot.Bundle)
			return &bundle, nil
		}
	}
	return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: %w: counterparty review appeal snapshot %q", ErrFederationIncidentDirectiveNotFound, snapshotID)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleStatusAt(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle, verificationErr error, now time.Time) (SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus, string, bool) {
	if verificationErr != nil {
		return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusInvalid, verificationErr.Error(), false
	}
	if bundle != nil && bundle.ExpiresAt != nil {
		if bundle.ExpiresAt.Before(now) {
			return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusExpired, "bundle has expired", false
		}
		if bundle.ExpiresAt.Before(now.Add(24 * time.Hour)) {
			return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusStale, "bundle is nearing expiry", true
		}
	}
	return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusVerified, "", true
}

func secureCellValidateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSemantics(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle, expectedOrganizationID string) error {
	if bundle == nil {
		return fmt.Errorf("bundle is required")
	}
	if expectedOrganizationID != "" && !strings.EqualFold(strings.TrimSpace(bundle.Organization.OrganizationID), strings.TrimSpace(expectedOrganizationID)) {
		return fmt.Errorf("organization mismatch")
	}
	if strings.TrimSpace(bundle.ReviewAppeal.ResponseAppealID) == "" {
		return fmt.Errorf("review appeal response appeal ID is required")
	}
	if strings.TrimSpace(bundle.ReviewAppeal.ReviewSnapshotID) == "" {
		return fmt.Errorf("review snapshot ID is required")
	}
	return nil
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSignerName(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle) string {
	if bundle == nil || bundle.Signature == nil {
		return ""
	}
	return strings.TrimSpace(bundle.Signature.Signer)
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummaryFromSnapshot(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSnapshot) SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary {
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	item := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary{
		CellID:                     safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                   safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                 safeSecureCellStatus(run),
		Jurisdiction:               safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:             strings.TrimSpace(snapshot.OrganizationID),
		SponsorOfRecord:            strings.TrimSpace(orgSummary.SponsorOfRecord),
		OrganizationName:           strings.TrimSpace(orgSummary.OrganizationName),
		OrganizationStatus:         orgSummary.Status,
		SnapshotID:                 strings.TrimSpace(snapshot.SnapshotID),
		BundleID:                   strings.TrimSpace(snapshot.Bundle.ID),
		BundleVersion:              strings.TrimSpace(snapshot.Bundle.Version),
		BundleName:                 strings.TrimSpace(snapshot.Bundle.Name),
		Status:                     snapshot.Status,
		Verified:                   snapshot.Verified,
		VerificationMessage:        strings.TrimSpace(snapshot.VerificationMessage),
		Signer:                     strings.TrimSpace(snapshot.Signer),
		IncidentID:                 strings.TrimSpace(snapshot.Bundle.ReviewAppeal.IncidentID),
		ResponseID:                 strings.TrimSpace(snapshot.Bundle.ReviewAppeal.ResponseID),
		DirectiveID:                strings.TrimSpace(snapshot.Bundle.ReviewAppeal.DirectiveID),
		ExtensionID:                strings.TrimSpace(snapshot.Bundle.ReviewAppeal.ExtensionID),
		DisputeID:                  strings.TrimSpace(snapshot.Bundle.ReviewAppeal.DisputeID),
		AppealID:                   strings.TrimSpace(snapshot.Bundle.ReviewAppeal.AppealID),
		ChallengeID:                strings.TrimSpace(snapshot.Bundle.ReviewAppeal.ChallengeID),
		ChallengeAppealID:          strings.TrimSpace(snapshot.Bundle.ReviewAppeal.ChallengeAppealID),
		ResponseAppealID:           strings.TrimSpace(snapshot.Bundle.ReviewAppeal.ResponseAppealID),
		ResponseAppealGeneration:   snapshot.Bundle.ReviewAppeal.ResponseAppealGeneration,
		ResponseAppealStatus:       snapshot.Bundle.ReviewAppeal.ResponseAppealStatus,
		ResponseStatus:             snapshot.Bundle.ReviewAppeal.ResponseStatus,
		ResponseAction:             snapshot.Bundle.ReviewAppeal.ResponseAction,
		ResponseTransitionID:       strings.TrimSpace(snapshot.Bundle.ReviewAppeal.ResponseTransitionID),
		Ruling:                     snapshot.Bundle.ReviewAppeal.Ruling,
		ReviewSnapshotID:           strings.TrimSpace(snapshot.Bundle.ReviewAppeal.ReviewSnapshotID),
		ReviewBundleID:             strings.TrimSpace(snapshot.Bundle.ReviewAppeal.ReviewBundleID),
		ReviewBundleStatus:         snapshot.Bundle.ReviewAppeal.ReviewBundleStatus,
		ReviewStatus:               snapshot.Bundle.Review.ReviewStatus,
		LatestReviewAction:         secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionTypeFromRecords(snapshot.Bundle.ReviewActions),
		ReviewActionCount:          len(snapshot.Bundle.ReviewActions),
		CounterpartyReviewID:       strings.TrimSpace(snapshot.Bundle.Review.CounterpartyReviewID),
		CounterpartyReviewAppealID: strings.TrimSpace(snapshot.Bundle.Review.CounterpartyReviewAppealID),
		GeneratedAt:                snapshot.Bundle.GeneratedAt.UTC(),
		ExpiresAt:                  cloneTimePtr(snapshot.Bundle.ExpiresAt),
		ReceivedAt:                 snapshot.ReceivedAt.UTC(),
		ControlLedgerID:            strings.TrimSpace(snapshot.Bundle.ControlLedgerID),
		ControlLedgerHash:          strings.TrimSpace(snapshot.Bundle.ControlLedgerHash),
		PortablePackageHash:        strings.TrimSpace(snapshot.Bundle.PortablePackageHash),
		PortablePackageSigned:      snapshot.Bundle.PortablePackageSigned,
		PortablePackageAnchored:    snapshot.Bundle.PortablePackageAnchored,
		ContentHash:                strings.TrimSpace(snapshot.Bundle.ContentHash),
		ReceivedBy:                 strings.TrimSpace(snapshot.ReceivedBy),
		Metadata:                   cloneStringMap(snapshot.Metadata),
	}
	if snapshot.Bundle.PriorBoardResponseAppeal != nil {
		item.PriorBoardResponseAppealID = strings.TrimSpace(snapshot.Bundle.PriorBoardResponseAppeal.ResponseAppealID)
		item.PriorBoardResponseAppealStatus = snapshot.Bundle.PriorBoardResponseAppeal.Status
		item.PriorBoardResponseStatus = snapshot.Bundle.PriorBoardResponseAppeal.ResponseStatus
		item.PriorBoardResponseAction = snapshot.Bundle.PriorBoardResponseAppeal.ResponseAction
	}
	return item
}

func matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter(item SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter) bool {
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
	if filter.SnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.SnapshotID), strings.TrimSpace(filter.SnapshotID)) {
		return false
	}
	if filter.ReviewSnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.ReviewSnapshotID), strings.TrimSpace(filter.ReviewSnapshotID)) {
		return false
	}
	if filter.CounterpartyReviewID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyReviewID), strings.TrimSpace(filter.CounterpartyReviewID)) {
		return false
	}
	if filter.CounterpartyReviewAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyReviewAppealID), strings.TrimSpace(filter.CounterpartyReviewAppealID)) {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	return true
}

func secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(in SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle {
	data, _ := json.Marshal(in)
	var out SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle
	_ = json.Unmarshal(data, &out)
	return out
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealsByStatus(items []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSnapshot, status SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus) []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSnapshot {
	if len(items) == 0 {
		return nil
	}
	filtered := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSnapshot, 0, len(items))
	for _, item := range items {
		if item.Status == status {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionTypeFromRecords(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType {
	if len(items) == 0 {
		return ""
	}
	return items[0].Action
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusUnreviewed   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatus = "unreviewed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatus = "acknowledged"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusDisputed     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatus = "disputed"
)

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionAcknowledge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType = "acknowledge_counterparty_ruling"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionDispute     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType = "dispute_counterparty_ruling"
)

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealAcknowledgeRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	SnapshotID            string            `json:"snapshot_id,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealDisputeRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	SnapshotID            string            `json:"snapshot_id,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Divergences           []string          `json:"divergences,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewFilter struct {
	CellID            string                                                                                                                                                       `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                                                                                       `json:"organization_id,omitempty"`
	IncidentID        string                                                                                                                                                       `json:"incident_id,omitempty"`
	ResponseID        string                                                                                                                                                       `json:"response_id,omitempty"`
	DirectiveID       string                                                                                                                                                       `json:"directive_id,omitempty"`
	ExtensionID       string                                                                                                                                                       `json:"extension_id,omitempty"`
	DisputeID         string                                                                                                                                                       `json:"dispute_id,omitempty"`
	AppealID          string                                                                                                                                                       `json:"appeal_id,omitempty"`
	ChallengeID       string                                                                                                                                                       `json:"challenge_id,omitempty"`
	ChallengeAppealID string                                                                                                                                                       `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID  string                                                                                                                                                       `json:"response_appeal_id,omitempty"`
	SnapshotID        string                                                                                                                                                       `json:"snapshot_id,omitempty"`
	Action            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType `json:"action,omitempty"`
	LocalReviewStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatus     `json:"local_review_status,omitempty"`
	ActorDID          string                                                                                                                                                       `json:"actor_did,omitempty"`
	Limit             int                                                                                                                                                          `json:"limit,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord struct {
	CellID                string                                                                                                                                                       `json:"cell_id"`
	CellName              string                                                                                                                                                       `json:"cell_name,omitempty"`
	CellStatus            SecureCellStatus                                                                                                                                             `json:"cell_status"`
	Jurisdiction          string                                                                                                                                                       `json:"jurisdiction,omitempty"`
	OrganizationID        string                                                                                                                                                       `json:"organization_id"`
	SponsorOfRecord       string                                                                                                                                                       `json:"sponsor_of_record,omitempty"`
	OrganizationName      string                                                                                                                                                       `json:"organization_name,omitempty"`
	IncidentID            string                                                                                                                                                       `json:"incident_id,omitempty"`
	ResponseID            string                                                                                                                                                       `json:"response_id,omitempty"`
	DirectiveID           string                                                                                                                                                       `json:"directive_id,omitempty"`
	ExtensionID           string                                                                                                                                                       `json:"extension_id,omitempty"`
	DisputeID             string                                                                                                                                                       `json:"dispute_id,omitempty"`
	AppealID              string                                                                                                                                                       `json:"appeal_id,omitempty"`
	ChallengeID           string                                                                                                                                                       `json:"challenge_id,omitempty"`
	ChallengeAppealID     string                                                                                                                                                       `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID      string                                                                                                                                                       `json:"response_appeal_id,omitempty"`
	ResponseAppealStatus  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                               `json:"response_appeal_status,omitempty"`
	ResponseStatus        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                                     `json:"response_status,omitempty"`
	ResponseAction        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                                 `json:"response_action,omitempty"`
	Ruling                SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                                                   `json:"ruling,omitempty"`
	SnapshotID            string                                                                                                                                                       `json:"snapshot_id"`
	BundleID              string                                                                                                                                                       `json:"bundle_id,omitempty"`
	ReviewSnapshotID      string                                                                                                                                                       `json:"review_snapshot_id,omitempty"`
	ReviewBundleID        string                                                                                                                                                       `json:"review_bundle_id,omitempty"`
	ImportedStatus        SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus           `json:"imported_status,omitempty"`
	LocalReviewStatus     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatus     `json:"local_review_status"`
	Action                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType `json:"action"`
	ActorDID              string                                                                                                                                                       `json:"actor_did,omitempty"`
	CounterpartyReference string                                                                                                                                                       `json:"counterparty_reference,omitempty"`
	Divergences           []string                                                                                                                                                     `json:"divergences,omitempty"`
	TransitionID          string                                                                                                                                                       `json:"transition_id,omitempty"`
	PolicyReceiptID       string                                                                                                                                                       `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash     string                                                                                                                                                       `json:"policy_receipt_hash,omitempty"`
	SealID                string                                                                                                                                                       `json:"seal_id,omitempty"`
	TraceLinkID           string                                                                                                                                                       `json:"trace_link_id,omitempty"`
	Reason                string                                                                                                                                                       `json:"reason,omitempty"`
	Metadata              map[string]string                                                                                                                                            `json:"metadata,omitempty"`
	OccurredAt            time.Time                                                                                                                                                    `json:"occurred_at"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionSpec struct {
	stage                 string
	action                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType
	localReviewStatus     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatus
	actorDID              string
	snapshotID            string
	counterpartyReference string
	reason                string
	divergences           []string
	metadata              map[string]string
}

func (s *Service) AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealRuling(ctx context.Context, cellID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealAcknowledgeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewAction(ctx, cellID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionSpec{
		stage:                 "acknowledge_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_ruling",
		action:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionAcknowledge,
		localReviewStatus:     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusAcknowledged,
		actorDID:              req.ActorDID,
		snapshotID:            req.SnapshotID,
		counterpartyReference: req.CounterpartyReference,
		reason:                req.Reason,
		metadata:              req.Metadata,
	})
}

func (s *Service) DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealRuling(ctx context.Context, cellID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealDisputeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewAction(ctx, cellID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionSpec{
		stage:                 "dispute_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_ruling",
		action:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionDispute,
		localReviewStatus:     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusDisputed,
		actorDID:              req.ActorDID,
		snapshotID:            req.SnapshotID,
		counterpartyReference: req.CounterpartyReference,
		reason:                req.Reason,
		divergences:           req.Divergences,
		metadata:              req.Metadata,
	})
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewFilter(record, filter) {
				continue
			}
			items = append(items, record)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		iPriority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionPriority(items[i].Action)
		jPriority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionPriority(items[j].Action)
		if iPriority != jPriority {
			return iPriority > jPriority
		}
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

func (s *Service) applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewAction(ctx context.Context, cellID string, spec secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionSpec) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummaryBySnapshot(run, strings.TrimSpace(spec.snapshotID))
	if err != nil {
		return nil, err
	}
	localReviewAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, summary.ResponseAppealID)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(spec.actorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: %w: actor %q is not permitted to review imported reciprocal rehearing-board ruling %q", ErrPolicyDenied, actorDID, summary.SnapshotID)
	}
	latestReview := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewAction(run, summary.SnapshotID)
	if latestReview != nil && latestReview.LocalReviewStatus == spec.localReviewStatus {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: reciprocal rehearing-board snapshot %q is already %s", summary.SnapshotID, spec.localReviewStatus)
	}
	divergences := uniqueTrimmedStrings(spec.divergences)
	if spec.action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionDispute && len(divergences) == 0 {
		divergences = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealDivergences(*localReviewAppeal, summary)
	}

	receipt, err := s.evaluateStage(ctx, run.request, spec.stage, lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                        summary.OrganizationID,
		"federation_incident_id":                                                            summary.IncidentID,
		"federation_incident_response_id":                                                   summary.ResponseID,
		"federation_incident_directive_id":                                                  summary.DirectiveID,
		"federation_incident_directive_extension_id":                                        summary.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                summary.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                 summary.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":        summary.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id": summary.ChallengeAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_snapshot_id":   summary.SnapshotID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_bundle_id":     summary.BundleID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_id":            summary.ResponseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_status":        string(summary.Status),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_status": string(spec.localReviewStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_action": string(spec.action),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_divergences":   strings.Join(divergences, ","),
		"transition_reason": strings.TrimSpace(spec.reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewTransitionSuffix(spec.action), summary.SnapshotID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewTransitionSuffix(spec.action),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal",
		TargetDID:        summary.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(spec.reason),
		Metadata: mergeStringMaps(spec.metadata, map[string]string{
			"federation_organization_id":                                                        summary.OrganizationID,
			"federation_sponsor_of_record":                                                      summary.SponsorOfRecord,
			"federation_organization_name":                                                      summary.OrganizationName,
			"federation_incident_id":                                                            summary.IncidentID,
			"federation_incident_response_id":                                                   summary.ResponseID,
			"federation_incident_directive_id":                                                  summary.DirectiveID,
			"federation_incident_directive_extension_id":                                        summary.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                summary.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                 summary.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":        summary.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id": summary.ChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_snapshot_id":            summary.SnapshotID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_bundle_id":              summary.BundleID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_id":                     summary.ResponseAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_snapshot_id":                   summary.ReviewSnapshotID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_bundle_id":                     summary.ReviewBundleID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_status":                 string(summary.Status),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_status":          string(spec.localReviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_action":          string(spec.action),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_counterparty_reference": strings.TrimSpace(spec.counterpartyReference),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_divergences":            strings.Join(divergences, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":                                                          string(summary.ResponseAppealStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_status":                                                                 string(summary.ResponseStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_action":                                                                 string(summary.ResponseAction),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_ruling":                                                                 string(summary.Ruling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_transition_id":                                                          summary.ResponseTransitionID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummaryBySnapshot(run *secureCellRun, snapshotID string) (SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary, error) {
	for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals {
		if strings.EqualFold(strings.TrimSpace(snapshot.SnapshotID), strings.TrimSpace(snapshotID)) {
			return secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummaryFromSnapshot(run, snapshot), nil
		}
	}
	return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary{}, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal: %w: snapshot %q", ErrFederationIncidentDirectiveNotFound, snapshotID)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealDivergences(local SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, imported SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummary) []string {
	divergences := make([]string, 0, 4)
	if local.Status != imported.ResponseAppealStatus {
		divergences = append(divergences, "response_appeal_status")
	}
	if local.ResponseStatus != imported.ResponseStatus {
		divergences = append(divergences, "response_status")
	}
	if local.ResponseAction != imported.ResponseAction {
		divergences = append(divergences, "response_action")
	}
	if local.Ruling != imported.Ruling {
		divergences = append(divergences, "ruling")
	}
	return uniqueTrimmedStrings(divergences)
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewAction(run *secureCellRun, snapshotID string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord {
	var latest *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord
	currentPriority := 0
	for _, transition := range run.result.Transitions {
		actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionTypeFromTransition(transition.Action, transition.Metadata)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_snapshot_id"]), strings.TrimSpace(snapshotID)) {
			continue
		}
		record := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord{
			SnapshotID:        strings.TrimSpace(snapshotID),
			Action:            actionType,
			LocalReviewStatus: secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusForAction(actionType),
			ActorDID:          strings.TrimSpace(transition.Actor),
			OccurredAt:        transition.OccurredAt.UTC(),
			TransitionID:      strings.TrimSpace(transition.ID),
			Metadata:          cloneStringMap(transition.Metadata),
		}
		priority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionPriority(actionType)
		if priority < currentPriority {
			continue
		}
		if priority == currentPriority && latest != nil && (record.OccurredAt.Before(latest.OccurredAt) || (record.OccurredAt.Equal(latest.OccurredAt) && strings.Compare(record.TransitionID, latest.TransitionID) <= 0)) {
			continue
		}
		latest = record
		currentPriority = priority
	}
	return latest
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord, bool) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord{}, false
	}
	actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionTypeFromTransition(transition.Action, transition.Metadata)
	if !ok {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord{}, false
	}
	snapshotID := strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_snapshot_id"])
	if snapshotID == "" {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord{}, false
	}
	summary, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealSummaryBySnapshot(run, snapshotID)
	if err != nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord{}, false
	}
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord{
		CellID:                summary.CellID,
		CellName:              summary.CellName,
		CellStatus:            summary.CellStatus,
		Jurisdiction:          summary.Jurisdiction,
		OrganizationID:        summary.OrganizationID,
		SponsorOfRecord:       summary.SponsorOfRecord,
		OrganizationName:      summary.OrganizationName,
		IncidentID:            summary.IncidentID,
		ResponseID:            summary.ResponseID,
		DirectiveID:           summary.DirectiveID,
		ExtensionID:           summary.ExtensionID,
		DisputeID:             summary.DisputeID,
		AppealID:              summary.AppealID,
		ChallengeID:           summary.ChallengeID,
		ChallengeAppealID:     summary.ChallengeAppealID,
		ResponseAppealID:      summary.ResponseAppealID,
		ResponseAppealStatus:  summary.ResponseAppealStatus,
		ResponseStatus:        summary.ResponseStatus,
		ResponseAction:        summary.ResponseAction,
		Ruling:                summary.Ruling,
		SnapshotID:            summary.SnapshotID,
		BundleID:              summary.BundleID,
		ReviewSnapshotID:      summary.ReviewSnapshotID,
		ReviewBundleID:        summary.ReviewBundleID,
		ImportedStatus:        summary.Status,
		LocalReviewStatus:     secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusForAction(actionType),
		Action:                actionType,
		ActorDID:              strings.TrimSpace(transition.Actor),
		CounterpartyReference: strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_counterparty_reference"]),
		Divergences:           secureCellSplitAndTrim(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_divergences"], ","),
		TransitionID:          strings.TrimSpace(transition.ID),
		Reason:                strings.TrimSpace(transition.Reason),
		Metadata:              cloneStringMap(transition.Metadata),
		OccurredAt:            transition.OccurredAt.UTC(),
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

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewFilter) bool {
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
	if filter.SnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.SnapshotID), strings.TrimSpace(filter.SnapshotID)) {
		return false
	}
	if filter.Action != "" && item.Action != filter.Action {
		return false
	}
	if filter.LocalReviewStatus != "" && item.LocalReviewStatus != filter.LocalReviewStatus {
		return false
	}
	if filter.ActorDID != "" && !strings.EqualFold(strings.TrimSpace(item.ActorDID), strings.TrimSpace(filter.ActorDID)) {
		return false
	}
	return true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusForAction(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatus {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionAcknowledge:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusAcknowledged
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionDispute:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusDisputed
	default:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusUnreviewed
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionTypeFromTransition(action string, metadata map[string]string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_ruling_acknowledged":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionAcknowledge, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_ruling_disputed":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionDispute, true
	default:
		_ = metadata
		return "", false
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewTransitionSuffix(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType) string {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionAcknowledge:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_ruling_acknowledged"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionDispute:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_ruling_disputed"
	default:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_reviewed"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionPriority(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType) int {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionDispute:
		return 2
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionAcknowledge:
		return 1
	default:
		return 0
	}
}
