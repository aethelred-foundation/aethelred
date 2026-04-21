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

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus
// tracks verification and freshness posture for one imported reconciliation
// challenge-appeal bundle.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus string

const (
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusVerified SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus = "verified"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusStale    SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus = "stale"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusExpired  SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus = "expired"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusInvalid  SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus = "invalid"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus
// captures bilateral alignment posture between imported and local challenge
// appeal board state.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusAligned          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus = "aligned"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusDivergent        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus = "divergent"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusCounterpartyOnly SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus = "counterparty_only"
)

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSnapshot
// persists one imported signed challenge-appeal bundle in the secure-cell
// trace.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSnapshot struct {
	SnapshotID          string                                                                                              `json:"snapshot_id"`
	OrganizationID      string                                                                                              `json:"organization_id"`
	Bundle              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle             `json:"bundle"`
	Status              SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus `json:"status"`
	Verified            bool                                                                                                `json:"verified"`
	VerificationMessage string                                                                                              `json:"verification_message,omitempty"`
	Signer              string                                                                                              `json:"signer,omitempty"`
	ReceivedBy          string                                                                                              `json:"received_by,omitempty"`
	ReceivedAt          time.Time                                                                                           `json:"received_at"`
	Metadata            map[string]string                                                                                   `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter
// narrows operator queries across imported counterparty challenge-appeal bundles.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter struct {
	CellID                  string                                                                                              `json:"cell_id,omitempty"`
	OrganizationID          string                                                                                              `json:"organization_id,omitempty"`
	IncidentID              string                                                                                              `json:"incident_id,omitempty"`
	ResponseID              string                                                                                              `json:"response_id,omitempty"`
	DirectiveID             string                                                                                              `json:"directive_id,omitempty"`
	ExtensionID             string                                                                                              `json:"extension_id,omitempty"`
	DisputeID               string                                                                                              `json:"dispute_id,omitempty"`
	AppealID                string                                                                                              `json:"appeal_id,omitempty"`
	ComparisonKey           string                                                                                              `json:"comparison_key,omitempty"`
	ChallengeID             string                                                                                              `json:"challenge_id,omitempty"`
	ChallengeAppealID       string                                                                                              `json:"challenge_appeal_id,omitempty"`
	ParentChallengeAppealID string                                                                                              `json:"parent_challenge_appeal_id,omitempty"`
	Status                  SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus `json:"status,omitempty"`
	AlignmentStatus         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus    `json:"alignment_status,omitempty"`
	Signer                  string                                                                                              `json:"signer,omitempty"`
	Limit                   int                                                                                                 `json:"limit,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary
// is the operator-facing summary of one imported reconciliation challenge
// appeal bundle.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary struct {
	CellID                          string                                                                                              `json:"cell_id"`
	CellName                        string                                                                                              `json:"cell_name,omitempty"`
	CellStatus                      SecureCellStatus                                                                                    `json:"cell_status"`
	Jurisdiction                    string                                                                                              `json:"jurisdiction,omitempty"`
	OrganizationID                  string                                                                                              `json:"organization_id"`
	SponsorOfRecord                 string                                                                                              `json:"sponsor_of_record,omitempty"`
	OrganizationName                string                                                                                              `json:"organization_name,omitempty"`
	SnapshotID                      string                                                                                              `json:"snapshot_id"`
	BundleID                        string                                                                                              `json:"bundle_id,omitempty"`
	BundleVersion                   string                                                                                              `json:"bundle_version,omitempty"`
	BundleName                      string                                                                                              `json:"bundle_name,omitempty"`
	Status                          SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus `json:"status"`
	Verified                        bool                                                                                                `json:"verified"`
	Signer                          string                                                                                              `json:"signer,omitempty"`
	KeyID                           string                                                                                              `json:"key_id,omitempty"`
	IncidentID                      string                                                                                              `json:"incident_id,omitempty"`
	ResponseID                      string                                                                                              `json:"response_id,omitempty"`
	DirectiveID                     string                                                                                              `json:"directive_id,omitempty"`
	ExtensionID                     string                                                                                              `json:"extension_id,omitempty"`
	DisputeID                       string                                                                                              `json:"dispute_id,omitempty"`
	AppealID                        string                                                                                              `json:"appeal_id,omitempty"`
	ComparisonKey                   string                                                                                              `json:"comparison_key,omitempty"`
	ChallengeID                     string                                                                                              `json:"challenge_id,omitempty"`
	ChallengeAppealID               string                                                                                              `json:"challenge_appeal_id,omitempty"`
	ParentChallengeAppealID         string                                                                                              `json:"parent_challenge_appeal_id,omitempty"`
	ChallengeAppealGeneration       int                                                                                                 `json:"challenge_appeal_generation,omitempty"`
	ChallengeAppealStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus             `json:"challenge_appeal_status,omitempty"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                                                           `json:"appealing_party,omitempty"`
	BoardParty                      SecureCellFederationIncidentResponseParty                                                           `json:"board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                                                           `json:"enforcement_acknowledgement_party,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling                                          `json:"ruling,omitempty"`
	BoardReviewThreshold            int                                                                                                 `json:"board_review_threshold,omitempty"`
	BoardDelegationCount            int                                                                                                 `json:"board_delegation_count,omitempty"`
	BoardRecusalCount               int                                                                                                 `json:"board_recusal_count,omitempty"`
	BoardCommitteeMemberCount       int                                                                                                 `json:"board_committee_member_count,omitempty"`
	BoardRecordedVoteCount          int                                                                                                 `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes           int                                                                                                 `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount         int                                                                                                 `json:"board_missing_quorum_count,omitempty"`
	BoardThresholdSatisfied         bool                                                                                                `json:"board_threshold_satisfied"`
	RatifyVoteCount                 int                                                                                                 `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount               int                                                                                                 `json:"overturn_vote_count,omitempty"`
	GeneratedAt                     time.Time                                                                                           `json:"generated_at,omitempty"`
	ExpiresAt                       *time.Time                                                                                          `json:"expires_at,omitempty"`
	ReceivedAt                      time.Time                                                                                           `json:"received_at,omitempty"`
	ControlLedgerID                 string                                                                                              `json:"control_ledger_id,omitempty"`
	ControlLedgerHash               string                                                                                              `json:"control_ledger_hash,omitempty"`
	PortablePackageHash             string                                                                                              `json:"portable_package_hash,omitempty"`
	PortablePackageSigned           bool                                                                                                `json:"portable_package_signed"`
	PortablePackageAnchored         bool                                                                                                `json:"portable_package_anchored"`
	VerificationMessage             string                                                                                              `json:"verification_message,omitempty"`
	MatchedLocalChallengeAppealID   string                                                                                              `json:"matched_local_challenge_appeal_id,omitempty"`
	AlignmentStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus    `json:"alignment_status,omitempty"`
	AlignmentDivergenceCount        int                                                                                                 `json:"alignment_divergence_count"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleIntakeRequest
// ingests one signed counterparty challenge-appeal bundle into the evidence chain.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleIntakeRequest struct {
	ActorDID string                                                                                   `json:"actor_did,omitempty"`
	Bundle   *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle `json:"bundle,omitempty"`
	Reason   string                                                                                   `json:"reason,omitempty"`
	Metadata map[string]string                                                                        `json:"metadata,omitempty"`
}

func (s *Service) IngestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle(ctx context.Context, cellID string, organizationID string, intake SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleIntakeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, _, err := secureCellFederationOrganizationSummaryAndRef(run, organizationID)
	if err != nil {
		return nil, err
	}
	if intake.Bundle == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: bundle is required")
	}
	bundle := secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle(*intake.Bundle)
	actorDID := firstNonEmpty(strings.TrimSpace(intake.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: actor %q is not permitted to intake challenge appeal bundles", ErrPolicyDenied, actorDID)
	}

	verificationErr := VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle(&bundle)
	if verificationErr == nil {
		verificationErr = secureCellValidateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSemantics(&bundle, strings.TrimSpace(summary.OrganizationID))
	}
	now := time.Now().UTC()
	status, verificationMessage, verified := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleStatusAt(&bundle, verificationErr, now)

	receipt, err := s.evaluateStage(ctx, run.request, "intake_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_bundle", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":   strings.TrimSpace(summary.OrganizationID),
		"federation_sponsor_of_record": strings.TrimSpace(summary.SponsorOfRecord),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_key":                     strings.TrimSpace(bundle.Reconciliation.ComparisonKey),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_id":            strings.TrimSpace(bundle.ChallengeSummary.ChallengeID),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":     strings.TrimSpace(bundle.ChallengeAppealSummary.ChallengeAppealID),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_status":        string(bundle.ChallengeSummary.ChallengeStatus),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_status": string(status),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_signer": secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSignerName(&bundle),
		"transition_reason": strings.TrimSpace(intake.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w", ErrPolicyDenied)
	}

	snapshot := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSnapshot{
		SnapshotID:          fmt.Sprintf("%s-federation-counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", strings.TrimSpace(summary.OrganizationID), strings.TrimSpace(bundle.ID), now.Format(time.RFC3339Nano))))),
		OrganizationID:      strings.TrimSpace(summary.OrganizationID),
		Bundle:              bundle,
		Status:              status,
		Verified:            verified,
		VerificationMessage: strings.TrimSpace(verificationMessage),
		Signer:              secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSignerName(&bundle),
		ReceivedBy:          strings.TrimSpace(actorDID),
		ReceivedAt:          now,
		Metadata:            cloneStringMap(intake.Metadata),
	}
	run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppeals = append(run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppeals, snapshot)
	run.result.UpdatedAt = now
	alignmentStatus, matchedLocalChallengeAppealID, divergenceCount := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentForSnapshot(run, snapshot)

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_bundle_ingested", snapshot.SnapshotID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_bundle_ingested",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_bundle",
		TargetDID:        snapshot.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(intake.Reason),
		Metadata: mergeStringMaps(intake.Metadata, map[string]string{
			"federation_organization_id":   strings.TrimSpace(summary.OrganizationID),
			"federation_sponsor_of_record": strings.TrimSpace(summary.SponsorOfRecord),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_snapshot_id":                snapshot.SnapshotID,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_bundle_id":                  strings.TrimSpace(bundle.ID),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_key":                                         strings.TrimSpace(bundle.Reconciliation.ComparisonKey),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_id":                                strings.TrimSpace(bundle.ChallengeSummary.ChallengeID),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                         strings.TrimSpace(bundle.ChallengeAppealSummary.ChallengeAppealID),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_parent_id":                  strings.TrimSpace(bundle.ChallengeAppealSummary.ParentChallengeAppealID),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_generation":                 fmt.Sprintf("%d", bundle.ChallengeAppealSummary.ChallengeAppealGeneration),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":                     string(snapshot.Status),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_verified":                   fmt.Sprintf("%t", snapshot.Verified),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_signer":                     snapshot.Signer,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_generated_at":               bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_expires_at":                 safeTimeString(bundle.ExpiresAt),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_content_hash":               strings.TrimSpace(bundle.ContentHash),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_verification_message":       snapshot.VerificationMessage,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_status":           string(alignmentStatus),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_divergence_count": fmt.Sprintf("%d", divergenceCount),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_matched_local_id":           matchedLocalChallengeAppealID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(_ context.Context, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter) ([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppeals {
			summary := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummaryFromRun(run, snapshot)
			if !matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(summary, filter) {
				continue
			}
			items = append(items, summary)
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

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummaryFromRun(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSnapshot) SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary {
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	alignmentStatus, matchedLocalChallengeAppealID, divergenceCount := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentForSnapshot(run, snapshot)
	summary := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary{
		CellID:                          safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                        safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                      safeSecureCellStatus(run),
		Jurisdiction:                    safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:                  strings.TrimSpace(snapshot.OrganizationID),
		SponsorOfRecord:                 strings.TrimSpace(orgSummary.SponsorOfRecord),
		OrganizationName:                strings.TrimSpace(orgSummary.OrganizationName),
		SnapshotID:                      strings.TrimSpace(snapshot.SnapshotID),
		BundleID:                        strings.TrimSpace(snapshot.Bundle.ID),
		BundleVersion:                   strings.TrimSpace(snapshot.Bundle.Version),
		BundleName:                      strings.TrimSpace(snapshot.Bundle.Name),
		Status:                          snapshot.Status,
		Verified:                        snapshot.Verified,
		Signer:                          strings.TrimSpace(snapshot.Signer),
		IncidentID:                      strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.IncidentID),
		ResponseID:                      strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.ResponseID),
		DirectiveID:                     strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.DirectiveID),
		ExtensionID:                     strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.ExtensionID),
		DisputeID:                       strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.DisputeID),
		AppealID:                        strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.AppealID),
		ComparisonKey:                   strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.ComparisonKey),
		ChallengeID:                     strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.ChallengeID),
		ChallengeAppealID:               strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.ChallengeAppealID),
		ParentChallengeAppealID:         strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.ParentChallengeAppealID),
		ChallengeAppealGeneration:       snapshot.Bundle.ChallengeAppealSummary.ChallengeAppealGeneration,
		ChallengeAppealStatus:           snapshot.Bundle.ChallengeAppealSummary.ChallengeAppealStatus,
		AppealingParty:                  snapshot.Bundle.ChallengeAppealSummary.AppealingParty,
		BoardParty:                      snapshot.Bundle.ChallengeAppealSummary.BoardParty,
		EnforcementAcknowledgementParty: snapshot.Bundle.ChallengeAppealSummary.EnforcementAcknowledgementParty,
		Ruling:                          snapshot.Bundle.ChallengeAppealSummary.Ruling,
		BoardReviewThreshold:            snapshot.Bundle.ChallengeAppealSummary.BoardReviewThreshold,
		BoardDelegationCount:            snapshot.Bundle.ChallengeAppealSummary.BoardDelegationCount,
		BoardRecusalCount:               snapshot.Bundle.ChallengeAppealSummary.BoardRecusalCount,
		BoardCommitteeMemberCount:       snapshot.Bundle.ChallengeAppealSummary.BoardCommitteeMemberCount,
		BoardRecordedVoteCount:          snapshot.Bundle.ChallengeAppealSummary.BoardRecordedVoteCount,
		BoardOutstandingVotes:           snapshot.Bundle.ChallengeAppealSummary.BoardOutstandingVotes,
		BoardMissingQuorumCount:         snapshot.Bundle.ChallengeAppealSummary.BoardMissingQuorumCount,
		BoardThresholdSatisfied:         snapshot.Bundle.ChallengeAppealSummary.BoardThresholdSatisfied,
		RatifyVoteCount:                 snapshot.Bundle.ChallengeAppealSummary.RatifyVoteCount,
		OverturnVoteCount:               snapshot.Bundle.ChallengeAppealSummary.OverturnVoteCount,
		GeneratedAt:                     snapshot.Bundle.GeneratedAt.UTC(),
		ExpiresAt:                       cloneTimePtr(snapshot.Bundle.ExpiresAt),
		ReceivedAt:                      snapshot.ReceivedAt.UTC(),
		ControlLedgerID:                 strings.TrimSpace(snapshot.Bundle.ControlLedgerID),
		ControlLedgerHash:               strings.TrimSpace(snapshot.Bundle.ControlLedgerHash),
		PortablePackageHash:             strings.TrimSpace(snapshot.Bundle.PortablePackageHash),
		PortablePackageSigned:           snapshot.Bundle.PortablePackageSigned,
		PortablePackageAnchored:         snapshot.Bundle.PortablePackageAnchored,
		VerificationMessage:             strings.TrimSpace(snapshot.VerificationMessage),
		MatchedLocalChallengeAppealID:   matchedLocalChallengeAppealID,
		AlignmentStatus:                 alignmentStatus,
		AlignmentDivergenceCount:        divergenceCount,
	}
	if snapshot.Bundle.Signature != nil {
		summary.KeyID = strings.TrimSpace(snapshot.Bundle.Signature.KeyID)
	}
	return summary
}

func matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(item SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter) bool {
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
	if filter.ParentChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ParentChallengeAppealID), strings.TrimSpace(filter.ParentChallengeAppealID)) {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.AlignmentStatus != "" && item.AlignmentStatus != filter.AlignmentStatus {
		return false
	}
	if filter.Signer != "" && !strings.EqualFold(strings.TrimSpace(item.Signer), strings.TrimSpace(filter.Signer)) {
		return false
	}
	return true
}

func secureCellValidateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSemantics(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle, organizationID string) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: bundle is required")
	}
	if strings.TrimSpace(bundle.Organization.OrganizationID) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: bundle organization_id is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.Organization.OrganizationID), strings.TrimSpace(organizationID)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: bundle organization_id %q does not match organization %q", bundle.Organization.OrganizationID, organizationID)
	}
	if strings.TrimSpace(bundle.Reconciliation.OrganizationID) != "" && !strings.EqualFold(strings.TrimSpace(bundle.Reconciliation.OrganizationID), strings.TrimSpace(organizationID)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: reconciliation organization_id %q does not match organization %q", bundle.Reconciliation.OrganizationID, organizationID)
	}
	if strings.TrimSpace(bundle.ChallengeSummary.OrganizationID) != "" && !strings.EqualFold(strings.TrimSpace(bundle.ChallengeSummary.OrganizationID), strings.TrimSpace(organizationID)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: challenge organization_id %q does not match organization %q", bundle.ChallengeSummary.OrganizationID, organizationID)
	}
	if strings.TrimSpace(bundle.ChallengeAppealSummary.OrganizationID) != "" && !strings.EqualFold(strings.TrimSpace(bundle.ChallengeAppealSummary.OrganizationID), strings.TrimSpace(organizationID)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: challenge appeal organization_id %q does not match organization %q", bundle.ChallengeAppealSummary.OrganizationID, organizationID)
	}
	if strings.TrimSpace(bundle.ChallengeAppealSummary.ChallengeAppealID) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: challenge appeal id is required")
	}
	if strings.TrimSpace(bundle.ChallengeAppealSummary.ComparisonKey) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: comparison key is required")
	}
	if strings.TrimSpace(bundle.ChallengeSummary.ChallengeID) == "" || !strings.EqualFold(strings.TrimSpace(bundle.ChallengeSummary.ChallengeID), strings.TrimSpace(bundle.ChallengeAppealSummary.ChallengeID)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: challenge id mismatch")
	}
	if strings.TrimSpace(bundle.Reconciliation.ComparisonKey) != "" && !strings.EqualFold(strings.TrimSpace(bundle.Reconciliation.ComparisonKey), strings.TrimSpace(bundle.ChallengeAppealSummary.ComparisonKey)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: reconciliation comparison key mismatch")
	}
	return nil
}

func secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle(in SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle {
	payload, _ := json.Marshal(in)
	var out SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle
	_ = json.Unmarshal(payload, &out)
	return out
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSignerName(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle) string {
	if bundle == nil || bundle.Signature == nil {
		return ""
	}
	return strings.TrimSpace(bundle.Signature.Signer)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleStatusAt(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle, verificationErr error, now time.Time) (SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus, string, bool) {
	if verificationErr != nil {
		return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusInvalid, verificationErr.Error(), false
	}
	if bundle != nil && bundle.ExpiresAt != nil {
		if bundle.ExpiresAt.Before(now) {
			return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusExpired, "bundle has expired", false
		}
		if bundle.ExpiresAt.Before(now.Add(24 * time.Hour)) {
			return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusStale, "bundle is nearing expiry", true
		}
	}
	return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusVerified, "", true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentForSnapshot(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSnapshot) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus, string, int) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusCounterpartyOnly, "", 0
	}
	var local *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary
	if exact, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealByID(run, strings.TrimSpace(snapshot.Bundle.ChallengeAppealSummary.ChallengeAppealID)); err == nil && exact != nil {
		local = exact
	}
	if local == nil {
		stableKey := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStableKey(snapshot.Bundle.ChallengeAppealSummary)
		for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealsFromRun(run) {
			candidate := item
			if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStableKey(candidate) != stableKey {
				continue
			}
			if local == nil || candidate.CreatedAt.After(local.CreatedAt) {
				local = &candidate
			}
		}
	}
	if local == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusCounterpartyOnly, "", 0
	}
	divergenceCount := 0
	if local.ChallengeAppealStatus != snapshot.Bundle.ChallengeAppealSummary.ChallengeAppealStatus {
		divergenceCount++
	}
	if local.Ruling != snapshot.Bundle.ChallengeAppealSummary.Ruling {
		divergenceCount++
	}
	if local.AppealingParty != snapshot.Bundle.ChallengeAppealSummary.AppealingParty {
		divergenceCount++
	}
	if local.BoardParty != snapshot.Bundle.ChallengeAppealSummary.BoardParty {
		divergenceCount++
	}
	if local.EnforcementAcknowledgementParty != snapshot.Bundle.ChallengeAppealSummary.EnforcementAcknowledgementParty {
		divergenceCount++
	}
	if local.BoardReviewThreshold != snapshot.Bundle.ChallengeAppealSummary.BoardReviewThreshold {
		divergenceCount++
	}
	if local.BoardDelegationCount != snapshot.Bundle.ChallengeAppealSummary.BoardDelegationCount {
		divergenceCount++
	}
	if local.BoardRecusalCount != snapshot.Bundle.ChallengeAppealSummary.BoardRecusalCount {
		divergenceCount++
	}
	if local.BoardRecordedVoteCount != snapshot.Bundle.ChallengeAppealSummary.BoardRecordedVoteCount {
		divergenceCount++
	}
	if local.BoardCommitteeMemberCount != snapshot.Bundle.ChallengeAppealSummary.BoardCommitteeMemberCount {
		divergenceCount++
	}
	if local.BoardThresholdSatisfied != snapshot.Bundle.ChallengeAppealSummary.BoardThresholdSatisfied {
		divergenceCount++
	}
	if divergenceCount == 0 {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusAligned, local.ChallengeAppealID, 0
	}
	return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusDivergent, local.ChallengeAppealID, divergenceCount
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStableKey(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary) string {
	return strings.ToLower(strings.Join([]string{
		strings.TrimSpace(item.ComparisonKey),
		fmt.Sprintf("%d", item.ChallengeAppealGeneration),
		string(item.AppealingParty),
		string(item.BoardParty),
	}, "|"))
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealsByStatus(items []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSnapshot, status SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus) []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSnapshot {
	if status == "" {
		return append([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSnapshot(nil), items...)
	}
	filtered := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSnapshot, 0, len(items))
	for _, item := range items {
		if item.Status == status {
			filtered = append(filtered, item)
		}
	}
	return filtered
}
