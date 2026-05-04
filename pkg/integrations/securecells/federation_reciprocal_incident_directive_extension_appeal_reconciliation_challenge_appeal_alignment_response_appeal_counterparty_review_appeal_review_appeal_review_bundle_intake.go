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

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSnapshot
// persists one imported signed reciprocal review bundle over a rehearing-board
// ruling.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSnapshot struct {
	SnapshotID          string                                                                                                                                                   `json:"snapshot_id"`
	OrganizationID      string                                                                                                                                                   `json:"organization_id"`
	Bundle              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle `json:"bundle"`
	Status              SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus       `json:"status"`
	Verified            bool                                                                                                                                                     `json:"verified"`
	VerificationMessage string                                                                                                                                                   `json:"verification_message,omitempty"`
	Signer              string                                                                                                                                                   `json:"signer,omitempty"`
	ReceivedBy          string                                                                                                                                                   `json:"received_by,omitempty"`
	ReceivedAt          time.Time                                                                                                                                                `json:"received_at"`
	Metadata            map[string]string                                                                                                                                        `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleIntakeRequest
// imports a signed reciprocal rehearing review bundle for local governance.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleIntakeRequest struct {
	ActorDID string                                                                                                                                                    `json:"actor_did,omitempty"`
	Bundle   *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle `json:"bundle,omitempty"`
	Reason   string                                                                                                                                                    `json:"reason,omitempty"`
	Metadata map[string]string                                                                                                                                         `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleFilter
// narrows imported reciprocal review-bundle operator queries.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleFilter struct {
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
	ReviewedSnapshotID         string                                                                                                                                             `json:"reviewed_snapshot_id,omitempty"`
	CounterpartyReviewID       string                                                                                                                                             `json:"counterparty_review_id,omitempty"`
	CounterpartyReviewAppealID string                                                                                                                                             `json:"counterparty_review_appeal_id,omitempty"`
	Status                     SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus `json:"status,omitempty"`
	Limit                      int                                                                                                                                                `json:"limit,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummary
// projects imported reciprocal review bundles for operator query and export.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummary struct {
	CellID                         string                                                                                                                                                       `json:"cell_id"`
	CellName                       string                                                                                                                                                       `json:"cell_name,omitempty"`
	CellStatus                     SecureCellStatus                                                                                                                                             `json:"cell_status"`
	Jurisdiction                   string                                                                                                                                                       `json:"jurisdiction,omitempty"`
	OrganizationID                 string                                                                                                                                                       `json:"organization_id"`
	SponsorOfRecord                string                                                                                                                                                       `json:"sponsor_of_record,omitempty"`
	OrganizationName               string                                                                                                                                                       `json:"organization_name,omitempty"`
	OrganizationStatus             SecureCellFederationOrganizationStatus                                                                                                                       `json:"organization_status,omitempty"`
	SnapshotID                     string                                                                                                                                                       `json:"snapshot_id"`
	BundleID                       string                                                                                                                                                       `json:"bundle_id,omitempty"`
	BundleVersion                  string                                                                                                                                                       `json:"bundle_version,omitempty"`
	BundleName                     string                                                                                                                                                       `json:"bundle_name,omitempty"`
	Status                         SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus           `json:"status,omitempty"`
	Verified                       bool                                                                                                                                                         `json:"verified"`
	VerificationMessage            string                                                                                                                                                       `json:"verification_message,omitempty"`
	Signer                         string                                                                                                                                                       `json:"signer,omitempty"`
	IncidentID                     string                                                                                                                                                       `json:"incident_id,omitempty"`
	ResponseID                     string                                                                                                                                                       `json:"response_id,omitempty"`
	DirectiveID                    string                                                                                                                                                       `json:"directive_id,omitempty"`
	ExtensionID                    string                                                                                                                                                       `json:"extension_id,omitempty"`
	DisputeID                      string                                                                                                                                                       `json:"dispute_id,omitempty"`
	AppealID                       string                                                                                                                                                       `json:"appeal_id,omitempty"`
	ChallengeID                    string                                                                                                                                                       `json:"challenge_id,omitempty"`
	ChallengeAppealID              string                                                                                                                                                       `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID               string                                                                                                                                                       `json:"response_appeal_id,omitempty"`
	ResponseAppealGeneration       int                                                                                                                                                          `json:"response_appeal_generation,omitempty"`
	ResponseAppealStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                               `json:"response_appeal_status,omitempty"`
	ResponseStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                                     `json:"response_status,omitempty"`
	ResponseAction                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                                 `json:"response_action,omitempty"`
	ResponseTransitionID           string                                                                                                                                                       `json:"response_transition_id,omitempty"`
	Ruling                         SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                                                   `json:"ruling,omitempty"`
	ReviewedSnapshotID             string                                                                                                                                                       `json:"reviewed_snapshot_id,omitempty"`
	ReviewedBundleID               string                                                                                                                                                       `json:"reviewed_bundle_id,omitempty"`
	ReviewedBundleStatus           SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus           `json:"reviewed_bundle_status,omitempty"`
	ReviewedReviewStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatus     `json:"reviewed_review_status,omitempty"`
	LatestReviewedAction           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType `json:"latest_reviewed_action,omitempty"`
	ReviewedActionCount            int                                                                                                                                                          `json:"reviewed_action_count,omitempty"`
	CounterpartyReviewID           string                                                                                                                                                       `json:"counterparty_review_id,omitempty"`
	CounterpartyReviewAppealID     string                                                                                                                                                       `json:"counterparty_review_appeal_id,omitempty"`
	LocalBoardResponseAppealID     string                                                                                                                                                       `json:"local_board_response_appeal_id,omitempty"`
	LocalBoardResponseAppealStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                               `json:"local_board_response_appeal_status,omitempty"`
	LocalBoardResponseStatus       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                                     `json:"local_board_response_status,omitempty"`
	LocalBoardResponseAction       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                                 `json:"local_board_response_action,omitempty"`
	GeneratedAt                    time.Time                                                                                                                                                    `json:"generated_at"`
	ExpiresAt                      *time.Time                                                                                                                                                   `json:"expires_at,omitempty"`
	ReceivedAt                     time.Time                                                                                                                                                    `json:"received_at"`
	ControlLedgerID                string                                                                                                                                                       `json:"control_ledger_id,omitempty"`
	ControlLedgerHash              string                                                                                                                                                       `json:"control_ledger_hash,omitempty"`
	PortablePackageHash            string                                                                                                                                                       `json:"portable_package_hash,omitempty"`
	PortablePackageSigned          bool                                                                                                                                                         `json:"portable_package_signed"`
	PortablePackageAnchored        bool                                                                                                                                                         `json:"portable_package_anchored"`
	ContentHash                    string                                                                                                                                                       `json:"content_hash,omitempty"`
	ReceivedBy                     string                                                                                                                                                       `json:"received_by,omitempty"`
	Metadata                       map[string]string                                                                                                                                            `json:"metadata,omitempty"`
}

func (s *Service) IngestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle(ctx context.Context, cellID string, organizationID string, intake SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleIntakeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: service is required")
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
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: bundle is required")
	}
	bundle := secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle(*intake.Bundle)
	actorDID := firstNonEmpty(strings.TrimSpace(intake.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: %w: actor %q is not permitted to intake reciprocal review bundles", ErrPolicyDenied, actorDID)
	}

	verificationErr := VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle(&bundle)
	if verificationErr == nil {
		verificationErr = secureCellValidateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSemantics(&bundle, strings.TrimSpace(orgSummary.OrganizationID))
	}
	now := time.Now().UTC()
	status, verificationMessage, verified := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleStatusAt(&bundle, verificationErr, now)

	localResponseAppealID := strings.TrimSpace(bundle.Review.ResponseAppealID)
	if localResponseAppealID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: local response appeal reference is required")
	}
	if _, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, localResponseAppealID); err != nil {
		return nil, err
	}

	receipt, err := s.evaluateStage(ctx, run.request, "intake_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":   strings.TrimSpace(orgSummary.OrganizationID),
		"federation_sponsor_of_record": strings.TrimSpace(orgSummary.SponsorOfRecord),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                                                                                      strings.TrimSpace(bundle.Review.ChallengeAppealID),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_snapshot_id":          strings.TrimSpace(bundle.Review.SnapshotID),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_status": string(status),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_signer": secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSignerName(&bundle),
		"transition_reason": strings.TrimSpace(intake.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: %w", ErrPolicyDenied)
	}

	snapshot := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSnapshot{
		SnapshotID:          fmt.Sprintf("%s-federation-counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", strings.TrimSpace(orgSummary.OrganizationID), strings.TrimSpace(bundle.ID), now.Format(time.RFC3339Nano))))),
		OrganizationID:      strings.TrimSpace(orgSummary.OrganizationID),
		Bundle:              bundle,
		Status:              status,
		Verified:            verified,
		VerificationMessage: strings.TrimSpace(verificationMessage),
		Signer:              secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSignerName(&bundle),
		ReceivedBy:          actorDID,
		ReceivedAt:          now,
		Metadata:            cloneStringMap(intake.Metadata),
	}
	run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundles = append(run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundles, snapshot)
	run.result.UpdatedAt = receipt.EvaluatedAt.UTC()

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_ingested", snapshot.SnapshotID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_ingested",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle",
		TargetDID:        snapshot.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(intake.Reason),
		Metadata: mergeStringMaps(intake.Metadata, map[string]string{
			"federation_organization_id":                                                        snapshot.OrganizationID,
			"federation_sponsor_of_record":                                                      strings.TrimSpace(orgSummary.SponsorOfRecord),
			"federation_organization_name":                                                      strings.TrimSpace(orgSummary.OrganizationName),
			"federation_incident_id":                                                            strings.TrimSpace(bundle.Review.IncidentID),
			"federation_incident_response_id":                                                   strings.TrimSpace(bundle.Review.ResponseID),
			"federation_incident_directive_id":                                                  strings.TrimSpace(bundle.Review.DirectiveID),
			"federation_incident_directive_extension_id":                                        strings.TrimSpace(bundle.Review.ExtensionID),
			"federation_incident_directive_extension_dispute_id":                                strings.TrimSpace(bundle.Review.DisputeID),
			"federation_incident_directive_extension_appeal_id":                                 strings.TrimSpace(bundle.Review.AppealID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":        strings.TrimSpace(bundle.Review.ChallengeID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id": strings.TrimSpace(bundle.Review.ChallengeAppealID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_snapshot_id": snapshot.SnapshotID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_id":          strings.TrimSpace(bundle.ID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_snapshot_id":               strings.TrimSpace(bundle.Review.SnapshotID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_bundle_id":                 strings.TrimSpace(bundle.Review.BundleID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_status":      string(status),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_signer":      strings.TrimSpace(snapshot.Signer),
		}),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundles(_ context.Context, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleFilter) ([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundles {
			item := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummaryFromSnapshot(run, snapshot)
			if !matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleFilter(item, filter) {
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

func (s *Service) GetFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle(_ context.Context, cellID string, snapshotID string) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundles {
		if strings.EqualFold(strings.TrimSpace(snapshot.SnapshotID), strings.TrimSpace(snapshotID)) {
			bundle := secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle(snapshot.Bundle)
			return &bundle, nil
		}
	}
	return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: %w: snapshot %q", ErrFederationIncidentDirectiveNotFound, snapshotID)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleStatusAt(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle, verificationErr error, now time.Time) (SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus, string, bool) {
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

func secureCellValidateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSemantics(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle, expectedOrganizationID string) error {
	if bundle == nil {
		return fmt.Errorf("bundle is required")
	}
	if expectedOrganizationID != "" && !strings.EqualFold(strings.TrimSpace(bundle.Organization.OrganizationID), strings.TrimSpace(expectedOrganizationID)) {
		return fmt.Errorf("organization mismatch")
	}
	if strings.TrimSpace(bundle.Review.SnapshotID) == "" {
		return fmt.Errorf("reviewed snapshot ID is required")
	}
	if strings.TrimSpace(bundle.Review.ResponseAppealID) == "" {
		return fmt.Errorf("reviewed response appeal ID is required")
	}
	return nil
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSignerName(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle) string {
	if bundle == nil || bundle.Signature == nil {
		return ""
	}
	return strings.TrimSpace(bundle.Signature.Signer)
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummaryFromSnapshot(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSnapshot) SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummary {
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	item := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummary{
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
		IncidentID:                 strings.TrimSpace(snapshot.Bundle.Review.IncidentID),
		ResponseID:                 strings.TrimSpace(snapshot.Bundle.Review.ResponseID),
		DirectiveID:                strings.TrimSpace(snapshot.Bundle.Review.DirectiveID),
		ExtensionID:                strings.TrimSpace(snapshot.Bundle.Review.ExtensionID),
		DisputeID:                  strings.TrimSpace(snapshot.Bundle.Review.DisputeID),
		AppealID:                   strings.TrimSpace(snapshot.Bundle.Review.AppealID),
		ChallengeID:                strings.TrimSpace(snapshot.Bundle.Review.ChallengeID),
		ChallengeAppealID:          strings.TrimSpace(snapshot.Bundle.Review.ChallengeAppealID),
		ResponseAppealID:           strings.TrimSpace(snapshot.Bundle.Review.ResponseAppealID),
		ResponseAppealGeneration:   snapshot.Bundle.Review.ResponseAppealGeneration,
		ResponseAppealStatus:       snapshot.Bundle.Review.ResponseAppealStatus,
		ResponseStatus:             snapshot.Bundle.Review.ResponseStatus,
		ResponseAction:             snapshot.Bundle.Review.ResponseAction,
		ResponseTransitionID:       strings.TrimSpace(snapshot.Bundle.Review.ResponseTransitionID),
		Ruling:                     snapshot.Bundle.Review.Ruling,
		ReviewedSnapshotID:         strings.TrimSpace(snapshot.Bundle.Review.SnapshotID),
		ReviewedBundleID:           strings.TrimSpace(snapshot.Bundle.Review.BundleID),
		ReviewedBundleStatus:       snapshot.Bundle.Review.Status,
		ReviewedReviewStatus:       snapshot.Bundle.ReviewActionsLatestStatus(),
		LatestReviewedAction:       secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionTypeFromRecords(snapshot.Bundle.ReviewActions),
		ReviewedActionCount:        len(snapshot.Bundle.ReviewActions),
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
	if snapshot.Bundle.LocalBoardResponseAppeal != nil {
		item.LocalBoardResponseAppealID = strings.TrimSpace(snapshot.Bundle.LocalBoardResponseAppeal.ResponseAppealID)
		item.LocalBoardResponseAppealStatus = snapshot.Bundle.LocalBoardResponseAppeal.Status
		item.LocalBoardResponseStatus = snapshot.Bundle.LocalBoardResponseAppeal.ResponseStatus
		item.LocalBoardResponseAction = snapshot.Bundle.LocalBoardResponseAppeal.ResponseAction
	}
	return item
}

func matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleFilter(item SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummary, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleFilter) bool {
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
	if filter.ReviewedSnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.ReviewedSnapshotID), strings.TrimSpace(filter.ReviewedSnapshotID)) {
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

func secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle(in SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle {
	data, _ := json.Marshal(in)
	var out SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle
	_ = json.Unmarshal(data, &out)
	return out
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundlesByStatus(items []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSnapshot, status SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus) []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSnapshot {
	if len(items) == 0 {
		return nil
	}
	filtered := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSnapshot, 0, len(items))
	for _, item := range items {
		if item.Status == status {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionTypeFromRecords(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewRecord) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionType {
	if len(items) == 0 {
		return ""
	}
	return items[0].Action
}

func (bundle SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle) ReviewActionsLatestStatus() SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatus {
	if len(bundle.ReviewActions) == 0 {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewStatusUnreviewed
	}
	return bundle.ReviewActions[0].LocalReviewStatus
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusUnreviewed   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatus = "unreviewed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatus = "acknowledged"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusDisputed     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatus = "disputed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusEscalated    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatus = "escalated"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusResolved     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatus = "resolved"
)

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionAcknowledge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType = "acknowledge_counterparty_ruling"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionDispute     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType = "dispute_counterparty_ruling"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionEscalate    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType = "escalate_counterparty_ruling_dispute"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionResolve     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType = "resolve_counterparty_ruling_dispute"
)

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleAcknowledgeRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	SnapshotID            string            `json:"snapshot_id,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDisputeRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	SnapshotID            string            `json:"snapshot_id,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Divergences           []string          `json:"divergences,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDisputeEscalationRequest struct {
	ActorDID                            string                                    `json:"actor_did,omitempty"`
	SnapshotID                          string                                    `json:"snapshot_id,omitempty"`
	CounterpartyReference               string                                    `json:"counterparty_reference,omitempty"`
	AppealingParty                      SecureCellFederationIncidentResponseParty `json:"appealing_party,omitempty"`
	CorrectionBoardParty                SecureCellFederationIncidentResponseParty `json:"correction_board_party,omitempty"`
	EnforcementAcknowledgementParty     SecureCellFederationIncidentResponseParty `json:"enforcement_acknowledgement_party,omitempty"`
	Summary                             string                                    `json:"summary,omitempty"`
	Description                         string                                    `json:"description,omitempty"`
	EvidenceIDs                         []string                                  `json:"evidence_ids,omitempty"`
	Divergences                         []string                                  `json:"divergences,omitempty"`
	CorrectionBoardReviewThreshold      int                                       `json:"correction_board_review_threshold,omitempty"`
	EligibleCorrectionBoardReviewerDIDs []string                                  `json:"eligible_correction_board_reviewer_dids,omitempty"`
	Reason                              string                                    `json:"reason,omitempty"`
	Metadata                            map[string]string                         `json:"metadata,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewFilter struct {
	CellID            string                                                                                                                                                                   `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                                                                                                   `json:"organization_id,omitempty"`
	IncidentID        string                                                                                                                                                                   `json:"incident_id,omitempty"`
	ResponseID        string                                                                                                                                                                   `json:"response_id,omitempty"`
	DirectiveID       string                                                                                                                                                                   `json:"directive_id,omitempty"`
	ExtensionID       string                                                                                                                                                                   `json:"extension_id,omitempty"`
	DisputeID         string                                                                                                                                                                   `json:"dispute_id,omitempty"`
	AppealID          string                                                                                                                                                                   `json:"appeal_id,omitempty"`
	ChallengeID       string                                                                                                                                                                   `json:"challenge_id,omitempty"`
	ChallengeAppealID string                                                                                                                                                                   `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID  string                                                                                                                                                                   `json:"response_appeal_id,omitempty"`
	SnapshotID        string                                                                                                                                                                   `json:"snapshot_id,omitempty"`
	Action            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType `json:"action,omitempty"`
	LocalReviewStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatus     `json:"local_review_status,omitempty"`
	ActorDID          string                                                                                                                                                                   `json:"actor_did,omitempty"`
	Limit             int                                                                                                                                                                      `json:"limit,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord struct {
	CellID                string                                                                                                                                                                   `json:"cell_id"`
	CellName              string                                                                                                                                                                   `json:"cell_name,omitempty"`
	CellStatus            SecureCellStatus                                                                                                                                                         `json:"cell_status"`
	Jurisdiction          string                                                                                                                                                                   `json:"jurisdiction,omitempty"`
	OrganizationID        string                                                                                                                                                                   `json:"organization_id"`
	SponsorOfRecord       string                                                                                                                                                                   `json:"sponsor_of_record,omitempty"`
	OrganizationName      string                                                                                                                                                                   `json:"organization_name,omitempty"`
	IncidentID            string                                                                                                                                                                   `json:"incident_id,omitempty"`
	ResponseID            string                                                                                                                                                                   `json:"response_id,omitempty"`
	DirectiveID           string                                                                                                                                                                   `json:"directive_id,omitempty"`
	ExtensionID           string                                                                                                                                                                   `json:"extension_id,omitempty"`
	DisputeID             string                                                                                                                                                                   `json:"dispute_id,omitempty"`
	AppealID              string                                                                                                                                                                   `json:"appeal_id,omitempty"`
	ChallengeID           string                                                                                                                                                                   `json:"challenge_id,omitempty"`
	ChallengeAppealID     string                                                                                                                                                                   `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID      string                                                                                                                                                                   `json:"response_appeal_id,omitempty"`
	ResponseAppealStatus  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                                           `json:"response_appeal_status,omitempty"`
	ResponseStatus        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                                                 `json:"response_status,omitempty"`
	ResponseAction        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                                             `json:"response_action,omitempty"`
	Ruling                SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                                                               `json:"ruling,omitempty"`
	SnapshotID            string                                                                                                                                                                   `json:"snapshot_id"`
	BundleID              string                                                                                                                                                                   `json:"bundle_id,omitempty"`
	ReviewedSnapshotID    string                                                                                                                                                                   `json:"reviewed_snapshot_id,omitempty"`
	ReviewedBundleID      string                                                                                                                                                                   `json:"reviewed_bundle_id,omitempty"`
	ImportedStatus        SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus                       `json:"imported_status,omitempty"`
	LocalReviewStatus     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatus     `json:"local_review_status"`
	Action                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType `json:"action"`
	ActorDID              string                                                                                                                                                                   `json:"actor_did,omitempty"`
	CounterpartyReference string                                                                                                                                                                   `json:"counterparty_reference,omitempty"`
	Divergences           []string                                                                                                                                                                 `json:"divergences,omitempty"`
	TransitionID          string                                                                                                                                                                   `json:"transition_id,omitempty"`
	PolicyReceiptID       string                                                                                                                                                                   `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash     string                                                                                                                                                                   `json:"policy_receipt_hash,omitempty"`
	SealID                string                                                                                                                                                                   `json:"seal_id,omitempty"`
	TraceLinkID           string                                                                                                                                                                   `json:"trace_link_id,omitempty"`
	Reason                string                                                                                                                                                                   `json:"reason,omitempty"`
	Metadata              map[string]string                                                                                                                                                        `json:"metadata,omitempty"`
	OccurredAt            time.Time                                                                                                                                                                `json:"occurred_at"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionSpec struct {
	stage                 string
	action                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType
	localReviewStatus     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatus
	actorDID              string
	snapshotID            string
	counterpartyReference string
	reason                string
	divergences           []string
	metadata              map[string]string
}

func (s *Service) AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleRuling(ctx context.Context, cellID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleAcknowledgeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewAction(ctx, cellID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionSpec{
		stage:                 "acknowledge_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_ruling",
		action:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionAcknowledge,
		localReviewStatus:     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusAcknowledged,
		actorDID:              req.ActorDID,
		snapshotID:            req.SnapshotID,
		counterpartyReference: req.CounterpartyReference,
		reason:                req.Reason,
		metadata:              req.Metadata,
	})
}

func (s *Service) DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleRuling(ctx context.Context, cellID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDisputeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewAction(ctx, cellID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionSpec{
		stage:                 "dispute_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_ruling",
		action:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionDispute,
		localReviewStatus:     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusDisputed,
		actorDID:              req.ActorDID,
		snapshotID:            req.SnapshotID,
		counterpartyReference: req.CounterpartyReference,
		reason:                req.Reason,
		divergences:           req.Divergences,
		metadata:              req.Metadata,
	})
}

// EscalateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDispute
// opens a fresh governed rehearing when an imported reciprocal review bundle is
// disputed locally.
func (s *Service) EscalateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDispute(ctx context.Context, cellID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDisputeEscalationRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummaryBySnapshot(run, strings.TrimSpace(req.SnapshotID))
	if err != nil {
		return nil, err
	}
	rehearingTargetResponseAppealID := firstNonEmpty(summary.LocalBoardResponseAppealID, summary.ResponseAppealID)
	localReviewAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, rehearingTargetResponseAppealID)
	if err != nil {
		return nil, err
	}
	latestReview := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewAction(run, summary.SnapshotID)
	if latestReview == nil || latestReview.LocalReviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusDisputed {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: %w: disputed imported reciprocal review bundle is required before escalation for snapshot %q", ErrFederationIncidentDirectiveImmutable, summary.SnapshotID)
	}
	divergences := uniqueTrimmedStrings(append(append([]string(nil), latestReview.Divergences...), req.Divergences...))
	summaryText := firstNonEmpty(strings.TrimSpace(req.Summary), fmt.Sprintf("Escalate disputed imported reciprocal review bundle %s into governed rehearing", summary.ResponseAppealID))
	description := firstNonEmpty(strings.TrimSpace(req.Description), "The local organization escalated the disputed imported reciprocal review bundle into a fresh signed rehearing generation.")
	reason := firstNonEmpty(strings.TrimSpace(req.Reason), "escalate disputed imported reciprocal review bundle into governed rehearing")
	metadata := mergeStringMaps(req.Metadata, map[string]string{
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_escalated":                      "true",
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_snapshot_id":                    summary.SnapshotID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_id":                             summary.BundleID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_snapshot_id":                                  summary.ReviewedSnapshotID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_bundle_id":                                    summary.ReviewedBundleID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_transition_id":                  latestReview.TransitionID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_counterparty_reference":         firstNonEmpty(strings.TrimSpace(req.CounterpartyReference), strings.TrimSpace(latestReview.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_counterparty_reference"])),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_review_status":                  string(latestReview.LocalReviewStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_review_action":                  string(latestReview.Action),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_divergences":                    strings.Join(divergences, ","),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_local_board_response_appeal_id": summary.LocalBoardResponseAppealID,
	})
	return s.RehearFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(ctx, cellID, localReviewAppeal.ResponseAppealID, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest{
		ActorDID:                            req.ActorDID,
		AppealingParty:                      req.AppealingParty,
		CorrectionBoardParty:                req.CorrectionBoardParty,
		EnforcementAcknowledgementParty:     req.EnforcementAcknowledgementParty,
		Summary:                             summaryText,
		Description:                         description,
		EvidenceIDs:                         append([]string(nil), req.EvidenceIDs...),
		CorrectionBoardReviewThreshold:      req.CorrectionBoardReviewThreshold,
		EligibleCorrectionBoardReviewerDIDs: append([]string(nil), req.EligibleCorrectionBoardReviewerDIDs...),
		Reason:                              reason,
		Metadata:                            metadata,
	})
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewFilter(record, filter) {
				continue
			}
			items = append(items, record)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		iPriority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionPriority(items[i].Action)
		jPriority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionPriority(items[j].Action)
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

func (s *Service) applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewAction(ctx context.Context, cellID string, spec secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionSpec) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummaryBySnapshot(run, strings.TrimSpace(spec.snapshotID))
	if err != nil {
		return nil, err
	}
	rehearingTargetResponseAppealID := firstNonEmpty(summary.LocalBoardResponseAppealID, summary.ResponseAppealID)
	localReviewAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, rehearingTargetResponseAppealID)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(spec.actorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: %w: actor %q is not permitted to review imported reciprocal review bundle %q", ErrPolicyDenied, actorDID, summary.SnapshotID)
	}
	latestReview := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewAction(run, summary.SnapshotID)
	if latestReview != nil && latestReview.LocalReviewStatus == spec.localReviewStatus {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: reciprocal review bundle snapshot %q is already %s", summary.SnapshotID, spec.localReviewStatus)
	}
	divergences := uniqueTrimmedStrings(spec.divergences)
	if spec.action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionDispute && len(divergences) == 0 {
		divergences = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDivergences(*localReviewAppeal, summary)
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
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_snapshot_id":   summary.SnapshotID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_id":            summary.BundleID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_status":        string(summary.Status),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_review_status": string(spec.localReviewStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_review_action": string(spec.action),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_divergences":   strings.Join(divergences, ","),
		"transition_reason": strings.TrimSpace(spec.reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewTransitionSuffix(spec.action), summary.SnapshotID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewTransitionSuffix(spec.action),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle",
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
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_snapshot_id":            summary.SnapshotID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_id":                     summary.BundleID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_snapshot_id":                          summary.ReviewedSnapshotID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_bundle_id":                            summary.ReviewedBundleID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_status":                 string(summary.Status),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_review_status":          string(spec.localReviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_review_action":          string(spec.action),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_counterparty_reference": strings.TrimSpace(spec.counterpartyReference),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_divergences":            strings.Join(divergences, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":                                                                        string(summary.ResponseAppealStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_status":                                                                               string(summary.ResponseStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_action":                                                                               string(summary.ResponseAction),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_ruling":                                                                               string(summary.Ruling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_transition_id":                                                                        summary.ResponseTransitionID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummaryBySnapshot(run *secureCellRun, snapshotID string) (SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummary, error) {
	for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundles {
		if strings.EqualFold(strings.TrimSpace(snapshot.SnapshotID), strings.TrimSpace(snapshotID)) {
			return secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummaryFromSnapshot(run, snapshot), nil
		}
	}
	return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummary{}, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle: %w: snapshot %q", ErrFederationIncidentDirectiveNotFound, snapshotID)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDivergences(local SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, imported SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummary) []string {
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

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewAction(run *secureCellRun, snapshotID string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord {
	var latest *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord
	currentPriority := 0
	for _, transition := range run.result.Transitions {
		actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionTypeFromTransition(transition.Action, transition.Metadata)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_snapshot_id"]), strings.TrimSpace(snapshotID)) {
			continue
		}
		record := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord{
			SnapshotID:        strings.TrimSpace(snapshotID),
			Action:            actionType,
			LocalReviewStatus: secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusForAction(actionType),
			ActorDID:          strings.TrimSpace(transition.Actor),
			OccurredAt:        transition.OccurredAt.UTC(),
			TransitionID:      strings.TrimSpace(transition.ID),
			Metadata:          cloneStringMap(transition.Metadata),
		}
		priority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionPriority(actionType)
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord, bool) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord{}, false
	}
	actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionTypeFromTransition(transition.Action, transition.Metadata)
	if !ok {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord{}, false
	}
	snapshotID := strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_snapshot_id"])
	if snapshotID == "" {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord{}, false
	}
	summary, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSummaryBySnapshot(run, snapshotID)
	if err != nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord{}, false
	}
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord{
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
		ReviewedSnapshotID:    summary.ReviewedSnapshotID,
		ReviewedBundleID:      summary.ReviewedBundleID,
		ImportedStatus:        summary.Status,
		LocalReviewStatus:     secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusForAction(actionType),
		Action:                actionType,
		ActorDID:              strings.TrimSpace(transition.Actor),
		CounterpartyReference: strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_counterparty_reference"]),
		Divergences:           secureCellSplitAndTrim(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_divergences"], ","),
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

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewRecord, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewFilter) bool {
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusForAction(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatus {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionAcknowledge:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusAcknowledged
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionDispute:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusDisputed
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionEscalate:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusEscalated
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionResolve:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusResolved
	default:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewStatusUnreviewed
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionTypeFromTransition(action string, metadata map[string]string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_ruling_acknowledged":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionAcknowledge, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_ruling_disputed":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionDispute, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_rehearing_requested":
		if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleEscalationMeta(metadata) {
			return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionEscalate, true
		}
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruled":
		if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleEscalationMeta(metadata) {
			return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionResolve, true
		}
	default:
		_ = metadata
		return "", false
	}
	return "", false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewTransitionSuffix(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType) string {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionAcknowledge:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_ruling_acknowledged"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionDispute:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_ruling_disputed"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionEscalate:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_ruling_escalated"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionResolve:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_ruling_resolved"
	default:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_reviewed"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionPriority(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionType) int {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionDispute:
		return 2
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionAcknowledge:
		return 1
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionEscalate:
		return 3
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionResolve:
		return 4
	default:
		return 0
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleEscalationMeta(metadata map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_appeal_review_bundle_escalated"]), "true")
}
