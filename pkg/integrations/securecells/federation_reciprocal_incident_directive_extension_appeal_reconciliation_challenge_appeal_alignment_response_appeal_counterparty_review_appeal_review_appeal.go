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
