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

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus
// tracks verification and freshness posture for one imported appeal bundle.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus string

const (
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusVerified SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus = "verified"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusStale    SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus = "stale"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusExpired  SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus = "expired"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusInvalid  SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus = "invalid"
)

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot
// persists one imported signed appeal bundle in the secure-cell trace.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot struct {
	SnapshotID          string                                                                 `json:"snapshot_id"`
	OrganizationID      string                                                                 `json:"organization_id"`
	ContractIDs         []string                                                               `json:"contract_ids,omitempty"`
	Bundle              SecureCellFederationIncidentDirectiveExtensionAppealBundle             `json:"bundle"`
	Status              SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus `json:"status"`
	Verified            bool                                                                   `json:"verified"`
	VerificationMessage string                                                                 `json:"verification_message,omitempty"`
	Signer              string                                                                 `json:"signer,omitempty"`
	ReceivedBy          string                                                                 `json:"received_by,omitempty"`
	ReceivedAt          time.Time                                                              `json:"received_at"`
	Metadata            map[string]string                                                      `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter
// narrows operator queries across imported counterparty appeal bundles.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter struct {
	CellID               string                                                                   `json:"cell_id,omitempty"`
	OrganizationID       string                                                                   `json:"organization_id,omitempty"`
	ContractID           string                                                                   `json:"contract_id,omitempty"`
	IncidentID           string                                                                   `json:"incident_id,omitempty"`
	ResponseID           string                                                                   `json:"response_id,omitempty"`
	DirectiveID          string                                                                   `json:"directive_id,omitempty"`
	ExtensionID          string                                                                   `json:"extension_id,omitempty"`
	DisputeID            string                                                                   `json:"dispute_id,omitempty"`
	AppealID             string                                                                   `json:"appeal_id,omitempty"`
	Status               SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus   `json:"status,omitempty"`
	ReconciliationStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus `json:"reconciliation_status,omitempty"`
	Signer               string                                                                   `json:"signer,omitempty"`
	Limit                int                                                                      `json:"limit,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummary is
// the operator-facing summary of one imported appeal bundle.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummary struct {
	CellID                          string                                                                   `json:"cell_id"`
	CellName                        string                                                                   `json:"cell_name,omitempty"`
	CellStatus                      SecureCellStatus                                                         `json:"cell_status"`
	Jurisdiction                    string                                                                   `json:"jurisdiction,omitempty"`
	OrganizationID                  string                                                                   `json:"organization_id"`
	SponsorOfRecord                 string                                                                   `json:"sponsor_of_record,omitempty"`
	OrganizationName                string                                                                   `json:"organization_name,omitempty"`
	SnapshotID                      string                                                                   `json:"snapshot_id"`
	BundleID                        string                                                                   `json:"bundle_id,omitempty"`
	BundleVersion                   string                                                                   `json:"bundle_version,omitempty"`
	BundleName                      string                                                                   `json:"bundle_name,omitempty"`
	Status                          SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus   `json:"status"`
	Verified                        bool                                                                     `json:"verified"`
	Signer                          string                                                                   `json:"signer,omitempty"`
	KeyID                           string                                                                   `json:"key_id,omitempty"`
	ContractIDs                     []string                                                                 `json:"contract_ids,omitempty"`
	IncidentID                      string                                                                   `json:"incident_id,omitempty"`
	ResponseID                      string                                                                   `json:"response_id,omitempty"`
	DirectiveID                     string                                                                   `json:"directive_id,omitempty"`
	ExtensionID                     string                                                                   `json:"extension_id,omitempty"`
	DisputeID                       string                                                                   `json:"dispute_id,omitempty"`
	AppealID                        string                                                                   `json:"appeal_id,omitempty"`
	ParentAppealID                  string                                                                   `json:"parent_appeal_id,omitempty"`
	AppealGeneration                int                                                                      `json:"appeal_generation,omitempty"`
	AppealStatus                    SecureCellFederationIncidentDirectiveExtensionAppealStatus               `json:"appeal_status,omitempty"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                                `json:"appealing_party,omitempty"`
	BoardParty                      SecureCellFederationIncidentResponseParty                                `json:"board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                                `json:"enforcement_acknowledgement_party,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling               `json:"ruling,omitempty"`
	BoardReviewThreshold            int                                                                      `json:"board_review_threshold,omitempty"`
	BoardRecusalCount               int                                                                      `json:"board_recusal_count"`
	BoardDelegationCount            int                                                                      `json:"board_delegation_count"`
	BoardRecordedVoteCount          int                                                                      `json:"board_recorded_vote_count"`
	GeneratedAt                     time.Time                                                                `json:"generated_at,omitempty"`
	ExpiresAt                       *time.Time                                                               `json:"expires_at,omitempty"`
	ReceivedAt                      time.Time                                                                `json:"received_at,omitempty"`
	ControlLedgerID                 string                                                                   `json:"control_ledger_id,omitempty"`
	ControlLedgerHash               string                                                                   `json:"control_ledger_hash,omitempty"`
	PortablePackageHash             string                                                                   `json:"portable_package_hash,omitempty"`
	PortablePackageSigned           bool                                                                     `json:"portable_package_signed"`
	PortablePackageAnchored         bool                                                                     `json:"portable_package_anchored"`
	VerificationMessage             string                                                                   `json:"verification_message,omitempty"`
	MatchedLocalAppealID            string                                                                   `json:"matched_local_appeal_id,omitempty"`
	MatchedLocalDisputeID           string                                                                   `json:"matched_local_dispute_id,omitempty"`
	ReconciliationStatus            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus `json:"reconciliation_status,omitempty"`
	ReconciliationDivergenceCount   int                                                                      `json:"reconciliation_divergence_count"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealBundleIntakeRequest
// ingests one signed counterparty appeal bundle into the evidence chain.
type SecureCellFederationIncidentDirectiveExtensionAppealBundleIntakeRequest struct {
	ActorDID string                                                      `json:"actor_did,omitempty"`
	Bundle   *SecureCellFederationIncidentDirectiveExtensionAppealBundle `json:"bundle,omitempty"`
	Reason   string                                                      `json:"reason,omitempty"`
	Metadata map[string]string                                           `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus
// captures bilateral alignment posture between local and imported appeal state.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAligned          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus = "aligned"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusDivergent        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus = "divergent"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusLocalOnly        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus = "local_only"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCounterpartyOnly SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus = "counterparty_only"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter
// narrows operator queries across reciprocal appeal comparisons.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter struct {
	CellID         string                                                                         `json:"cell_id,omitempty"`
	OrganizationID string                                                                         `json:"organization_id,omitempty"`
	IncidentID     string                                                                         `json:"incident_id,omitempty"`
	ResponseID     string                                                                         `json:"response_id,omitempty"`
	DirectiveID    string                                                                         `json:"directive_id,omitempty"`
	ExtensionID    string                                                                         `json:"extension_id,omitempty"`
	DisputeID      string                                                                         `json:"dispute_id,omitempty"`
	AppealID       string                                                                         `json:"appeal_id,omitempty"`
	ComparisonKey  string                                                                         `json:"comparison_key,omitempty"`
	Status         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus       `json:"status,omitempty"`
	ReviewStatus   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus `json:"review_status,omitempty"`
	Limit          int                                                                            `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary
// projects one bilateral appeal comparison for operator review.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary struct {
	CellID                       string                                                                                          `json:"cell_id"`
	CellName                     string                                                                                          `json:"cell_name,omitempty"`
	CellStatus                   SecureCellStatus                                                                                `json:"cell_status"`
	Jurisdiction                 string                                                                                          `json:"jurisdiction,omitempty"`
	OrganizationID               string                                                                                          `json:"organization_id"`
	SponsorOfRecord              string                                                                                          `json:"sponsor_of_record,omitempty"`
	OrganizationName             string                                                                                          `json:"organization_name,omitempty"`
	ComparisonKey                string                                                                                          `json:"comparison_key"`
	IncidentID                   string                                                                                          `json:"incident_id,omitempty"`
	ResponseID                   string                                                                                          `json:"response_id,omitempty"`
	DirectiveID                  string                                                                                          `json:"directive_id,omitempty"`
	DirectiveTitle               string                                                                                          `json:"directive_title,omitempty"`
	ExtensionID                  string                                                                                          `json:"extension_id,omitempty"`
	DisputeID                    string                                                                                          `json:"dispute_id,omitempty"`
	AppealID                     string                                                                                          `json:"appeal_id,omitempty"`
	ParentAppealID               string                                                                                          `json:"parent_appeal_id,omitempty"`
	AppealGeneration             int                                                                                             `json:"appeal_generation,omitempty"`
	AppealingParty               SecureCellFederationIncidentResponseParty                                                       `json:"appealing_party,omitempty"`
	BoardParty                   SecureCellFederationIncidentResponseParty                                                       `json:"board_party,omitempty"`
	Status                       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus                        `json:"status"`
	LocalAppealID                string                                                                                          `json:"local_appeal_id,omitempty"`
	LocalAppealStatus            SecureCellFederationIncidentDirectiveExtensionAppealStatus                                      `json:"local_appeal_status,omitempty"`
	LocalRuling                  SecureCellFederationIncidentDirectiveExtensionAppealRuling                                      `json:"local_ruling,omitempty"`
	LocalRecusalCount            int                                                                                             `json:"local_recusal_count"`
	LocalUpdatedAt               *time.Time                                                                                      `json:"local_updated_at,omitempty"`
	CounterpartySnapshotID       string                                                                                          `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyBundleID         string                                                                                          `json:"counterparty_bundle_id,omitempty"`
	CounterpartyAppealID         string                                                                                          `json:"counterparty_appeal_id,omitempty"`
	CounterpartyAppealStatus     SecureCellFederationIncidentDirectiveExtensionAppealStatus                                      `json:"counterparty_appeal_status,omitempty"`
	CounterpartyRuling           SecureCellFederationIncidentDirectiveExtensionAppealRuling                                      `json:"counterparty_ruling,omitempty"`
	CounterpartyBundleStatus     SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus                          `json:"counterparty_bundle_status,omitempty"`
	CounterpartyRecusalCount     int                                                                                             `json:"counterparty_recusal_count"`
	CounterpartyGeneratedAt      *time.Time                                                                                      `json:"counterparty_generated_at,omitempty"`
	CounterpartyReceivedAt       *time.Time                                                                                      `json:"counterparty_received_at,omitempty"`
	ReviewStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status,omitempty"`
	LastReviewedBy               string                                                                                          `json:"last_reviewed_by,omitempty"`
	LastReviewedAt               *time.Time                                                                                      `json:"last_reviewed_at,omitempty"`
	ReviewActionCount            int                                                                                             `json:"review_action_count"`
	AttestationStatus            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status,omitempty"`
	LastCounterpartyAttestedBy   string                                                                                          `json:"last_counterparty_attested_by,omitempty"`
	LastCounterpartyAttestedAt   *time.Time                                                                                      `json:"last_counterparty_attested_at,omitempty"`
	CounterpartyAttestationCount int                                                                                             `json:"counterparty_attestation_count"`
	ChallengeID                  string                                                                                          `json:"challenge_id,omitempty"`
	ChallengeStatus              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus               `json:"challenge_status,omitempty"`
	ChallengingParty             SecureCellFederationIncidentResponseParty                                                       `json:"challenging_party,omitempty"`
	ChallengeBoardParty          SecureCellFederationIncidentResponseParty                                                       `json:"challenge_board_party,omitempty"`
	ChallengeBoardThreshold      int                                                                                             `json:"challenge_board_threshold,omitempty"`
	ChallengeCommitteeMemberCount int                                                                                            `json:"challenge_committee_member_count,omitempty"`
	ChallengeRecordedVoteCount   int                                                                                             `json:"challenge_recorded_vote_count,omitempty"`
	ChallengeOutstandingVotes    int                                                                                             `json:"challenge_outstanding_votes,omitempty"`
	ChallengeMissingQuorumCount  int                                                                                             `json:"challenge_missing_quorum_count,omitempty"`
	ChallengeQuorumSatisfied     bool                                                                                            `json:"challenge_quorum_satisfied"`
	ChallengeRatifyVoteCount     int                                                                                             `json:"challenge_ratify_vote_count,omitempty"`
	ChallengeOverturnVoteCount   int                                                                                             `json:"challenge_overturn_vote_count,omitempty"`
	ChallengeRuling              SecureCellFederationIncidentDirectiveExtensionAppealRuling                                      `json:"challenge_ruling,omitempty"`
	LastChallengedBy             string                                                                                          `json:"last_challenged_by,omitempty"`
	LastChallengedAt             *time.Time                                                                                      `json:"last_challenged_at,omitempty"`
	LastRuledBy                  string                                                                                          `json:"last_ruled_by,omitempty"`
	LastRuledAt                  *time.Time                                                                                      `json:"last_ruled_at,omitempty"`
	ChallengeCount               int                                                                                             `json:"challenge_count"`
	Divergences                  []string                                                                                        `json:"divergences,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealRef struct {
	Response  *SecureCellFederationIncidentResponse
	Directive *SecureCellFederationIncidentDirective
	Extension *SecureCellFederationIncidentDirectiveExtension
	Dispute   *SecureCellFederationIncidentDirectiveExtensionDispute
	Appeal    *SecureCellFederationIncidentDirectiveExtensionAppeal
}

func (s *Service) IngestFederationIncidentDirectiveExtensionAppealBundle(ctx context.Context, cellID string, organizationID string, intake SecureCellFederationIncidentDirectiveExtensionAppealBundleIntakeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: service is required")
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
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: bundle is required")
	}
	bundle := secureCellCloneFederationIncidentDirectiveExtensionAppealBundle(*intake.Bundle)
	actorDID := firstNonEmpty(strings.TrimSpace(intake.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: actor %q is not permitted to intake appeal bundles", ErrPolicyDenied, actorDID)
	}

	verificationErr := VerifyFederationIncidentDirectiveExtensionAppealBundle(&bundle)
	if verificationErr == nil {
		verificationErr = secureCellValidateFederationIncidentDirectiveExtensionAppealBundleSemantics(&bundle, strings.TrimSpace(summary.OrganizationID))
	}
	now := time.Now().UTC()
	status, verificationMessage, verified := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusAt(&bundle, verificationErr, now)
	contractIDs := uniqueTrimmedStrings(bundle.ResponseSummary.ContractIDs)

	receipt, err := s.evaluateStage(ctx, run.request, "intake_federation_incident_directive_extension_appeal_bundle", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                         strings.TrimSpace(summary.OrganizationID),
		"federation_sponsor_of_record":                                       strings.TrimSpace(summary.SponsorOfRecord),
		"federation_counterparty_incident_directive_extension_appeal_id":     strings.TrimSpace(bundle.Appeal.ID),
		"federation_counterparty_incident_directive_extension_dispute_id":    strings.TrimSpace(bundle.Appeal.DisputeID),
		"federation_counterparty_incident_directive_extension_id":            strings.TrimSpace(bundle.Appeal.ExtensionID),
		"federation_counterparty_incident_directive_id":                      strings.TrimSpace(bundle.Appeal.DirectiveID),
		"federation_counterparty_incident_response_id":                       strings.TrimSpace(bundle.Appeal.ResponseID),
		"federation_counterparty_incident_id":                                strings.TrimSpace(bundle.Appeal.IncidentID),
		"federation_counterparty_incident_directive_extension_appeal_status": string(status),
		"federation_counterparty_incident_directive_extension_appeal_signer": secureCellFederationIncidentDirectiveExtensionAppealBundleSignerName(&bundle),
		"federation_counterparty_incident_directive_extension_contract_ids":  strings.Join(contractIDs, ","),
		"transition_reason": strings.TrimSpace(intake.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w", ErrPolicyDenied)
	}

	snapshot := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot{
		SnapshotID:          fmt.Sprintf("%s-federation-counterparty-incident-directive-extension-appeal-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", strings.TrimSpace(summary.OrganizationID), strings.TrimSpace(bundle.ID), now.Format(time.RFC3339Nano))))),
		OrganizationID:      strings.TrimSpace(summary.OrganizationID),
		ContractIDs:         append([]string(nil), contractIDs...),
		Bundle:              bundle,
		Status:              status,
		Verified:            verified,
		VerificationMessage: strings.TrimSpace(verificationMessage),
		Signer:              secureCellFederationIncidentDirectiveExtensionAppealBundleSignerName(&bundle),
		ReceivedBy:          strings.TrimSpace(actorDID),
		ReceivedAt:          now,
		Metadata:            cloneStringMap(intake.Metadata),
	}
	run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals = append(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals, snapshot)
	run.result.UpdatedAt = now
	reconciliation := secureCellFederationIncidentDirectiveExtensionAppealReconciliationForSnapshot(run, snapshot)

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_bundle_ingested", snapshot.SnapshotID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_bundle_ingested",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_bundle",
		TargetDID:        snapshot.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(intake.Reason),
		Metadata: mergeStringMaps(intake.Metadata, map[string]string{
			"federation_organization_id":   strings.TrimSpace(summary.OrganizationID),
			"federation_sponsor_of_record": strings.TrimSpace(summary.SponsorOfRecord),
			"federation_contract_id":       strings.Join(contractIDs, ","),
			"federation_counterparty_incident_directive_extension_appeal_snapshot_id":          snapshot.SnapshotID,
			"federation_counterparty_incident_directive_extension_appeal_bundle_id":            strings.TrimSpace(bundle.ID),
			"federation_counterparty_incident_directive_extension_appeal_id":                   strings.TrimSpace(bundle.Appeal.ID),
			"federation_counterparty_incident_directive_extension_dispute_id":                  strings.TrimSpace(bundle.Appeal.DisputeID),
			"federation_counterparty_incident_directive_extension_id":                          strings.TrimSpace(bundle.Appeal.ExtensionID),
			"federation_counterparty_incident_directive_id":                                    strings.TrimSpace(bundle.Appeal.DirectiveID),
			"federation_counterparty_incident_response_id":                                     strings.TrimSpace(bundle.Appeal.ResponseID),
			"federation_counterparty_incident_id":                                              strings.TrimSpace(bundle.Appeal.IncidentID),
			"federation_counterparty_incident_directive_extension_appeal_status":               string(snapshot.Status),
			"federation_counterparty_incident_directive_extension_appeal_verified":             fmt.Sprintf("%t", snapshot.Verified),
			"federation_counterparty_incident_directive_extension_appeal_signer":               snapshot.Signer,
			"federation_counterparty_incident_directive_extension_appeal_generated_at":         bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			"federation_counterparty_incident_directive_extension_appeal_expires_at":           safeTimeString(bundle.ExpiresAt),
			"federation_counterparty_incident_directive_extension_appeal_content_hash":         strings.TrimSpace(bundle.ContentHash),
			"federation_counterparty_incident_directive_extension_appeal_verification_message": snapshot.VerificationMessage,
			"federation_incident_directive_extension_appeal_reconciliation_status":             string(reconciliation.Status),
			"federation_incident_directive_extension_appeal_reconciliation_key":                reconciliation.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_local_appeal_id":    reconciliation.LocalAppealID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationCounterpartyIncidentDirectiveExtensionAppeals(_ context.Context, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter) ([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals {
			summary := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummaryFromRun(run, snapshot)
			if !matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter(summary, filter) {
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

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliations(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationsFromRun(run) {
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter(item, filter) {
				continue
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		leftAt := secureCellFederationIncidentDirectiveExtensionAppealReconciliationUpdatedAt(items[i])
		rightAt := secureCellFederationIncidentDirectiveExtensionAppealReconciliationUpdatedAt(items[j])
		if leftAt.Equal(rightAt) {
			return items[i].ComparisonKey < items[j].ComparisonKey
		}
		return leftAt.After(rightAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummaryFromRun(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot) SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummary {
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	reconciliation := secureCellFederationIncidentDirectiveExtensionAppealReconciliationForSnapshot(run, snapshot)
	summary := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummary{
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
		ContractIDs:                     append([]string(nil), uniqueTrimmedStrings(snapshot.ContractIDs)...),
		IncidentID:                      strings.TrimSpace(snapshot.Bundle.Appeal.IncidentID),
		ResponseID:                      strings.TrimSpace(snapshot.Bundle.Appeal.ResponseID),
		DirectiveID:                     strings.TrimSpace(snapshot.Bundle.Appeal.DirectiveID),
		ExtensionID:                     strings.TrimSpace(snapshot.Bundle.Appeal.ExtensionID),
		DisputeID:                       strings.TrimSpace(snapshot.Bundle.Appeal.DisputeID),
		AppealID:                        strings.TrimSpace(snapshot.Bundle.Appeal.ID),
		ParentAppealID:                  strings.TrimSpace(snapshot.Bundle.Appeal.ParentAppealID),
		AppealGeneration:                secureCellFederationIncidentDirectiveExtensionAppealGeneration(snapshot.Bundle.Appeal),
		AppealStatus:                    snapshot.Bundle.Appeal.Status,
		AppealingParty:                  snapshot.Bundle.Appeal.AppealingParty,
		BoardParty:                      snapshot.Bundle.Appeal.BoardParty,
		EnforcementAcknowledgementParty: snapshot.Bundle.Appeal.EnforcementAcknowledgementParty,
		Ruling:                          snapshot.Bundle.Appeal.Ruling,
		BoardReviewThreshold:            snapshot.Bundle.AppealSummary.BoardReviewThreshold,
		BoardRecusalCount:               len(snapshot.Bundle.Appeal.BoardRecusals),
		BoardDelegationCount:            len(snapshot.Bundle.Appeal.BoardDelegations),
		BoardRecordedVoteCount:          len(snapshot.Bundle.Appeal.BoardVotes),
		GeneratedAt:                     snapshot.Bundle.GeneratedAt.UTC(),
		ExpiresAt:                       cloneTimePtr(snapshot.Bundle.ExpiresAt),
		ReceivedAt:                      snapshot.ReceivedAt.UTC(),
		ControlLedgerID:                 strings.TrimSpace(snapshot.Bundle.ControlLedgerID),
		ControlLedgerHash:               strings.TrimSpace(snapshot.Bundle.ControlLedgerHash),
		PortablePackageHash:             strings.TrimSpace(snapshot.Bundle.PortablePackageHash),
		PortablePackageSigned:           snapshot.Bundle.PortablePackageSigned,
		PortablePackageAnchored:         snapshot.Bundle.PortablePackageAnchored,
		VerificationMessage:             strings.TrimSpace(snapshot.VerificationMessage),
		MatchedLocalAppealID:            reconciliation.LocalAppealID,
		MatchedLocalDisputeID:           reconciliation.DisputeID,
		ReconciliationStatus:            reconciliation.Status,
		ReconciliationDivergenceCount:   len(reconciliation.Divergences),
	}
	if snapshot.Bundle.Signature != nil {
		summary.KeyID = strings.TrimSpace(snapshot.Bundle.Signature.KeyID)
	}
	return summary
}

func matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter(item SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummary, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.ContractID != "" {
		match := false
		for _, contractID := range item.ContractIDs {
			if strings.EqualFold(strings.TrimSpace(contractID), strings.TrimSpace(filter.ContractID)) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
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
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.ReconciliationStatus != "" && item.ReconciliationStatus != filter.ReconciliationStatus {
		return false
	}
	if filter.Signer != "" && !strings.EqualFold(strings.TrimSpace(item.Signer), strings.TrimSpace(filter.Signer)) {
		return false
	}
	return true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationsFromRun(run *secureCellRun) []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary {
	if run == nil || run.result == nil {
		return nil
	}
	localByKey := secureCellLatestLocalFederationIncidentDirectiveExtensionAppealsByKey(run)
	counterpartyByKey := secureCellLatestCounterpartyFederationIncidentDirectiveExtensionAppealsByKey(run)
	keys := make(map[string]struct{}, len(localByKey)+len(counterpartyByKey))
	for key := range localByKey {
		keys[key] = struct{}{}
	}
	for key := range counterpartyByKey {
		keys[key] = struct{}{}
	}
	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary, 0, len(keys))
	for key := range keys {
		items = append(items, secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryFromRefs(run, key, localByKey[key], counterpartyByKey[key]))
	}
	return items
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter) bool {
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
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.ReviewStatus != "" && item.ReviewStatus != filter.ReviewStatus {
		return false
	}
	return true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryFromRefs(run *secureCellRun, key string, local *secureCellFederationIncidentDirectiveExtensionAppealRef, counterparty *SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary {
	item := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary{
		CellID:        safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:      safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:    safeSecureCellStatus(run),
		Jurisdiction:  safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		ComparisonKey: strings.TrimSpace(key),
		Status:        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAligned,
	}
	if local != nil && local.Response != nil {
		item.OrganizationID = strings.TrimSpace(local.Response.OrganizationID)
		item.SponsorOfRecord = strings.TrimSpace(local.Response.SponsorOfRecord)
		item.IncidentID = strings.TrimSpace(local.Response.IncidentID)
		item.ResponseID = strings.TrimSpace(local.Response.ID)
	}
	if local != nil && local.Directive != nil {
		item.DirectiveID = strings.TrimSpace(local.Directive.ID)
		item.DirectiveTitle = strings.TrimSpace(local.Directive.Title)
	}
	if local != nil && local.Extension != nil {
		item.ExtensionID = strings.TrimSpace(local.Extension.ID)
	}
	if local != nil && local.Dispute != nil {
		item.DisputeID = strings.TrimSpace(local.Dispute.ID)
	}
	if local != nil && local.Appeal != nil {
		item.AppealID = strings.TrimSpace(local.Appeal.ID)
		item.ParentAppealID = strings.TrimSpace(local.Appeal.ParentAppealID)
		item.AppealGeneration = secureCellFederationIncidentDirectiveExtensionAppealGeneration(*local.Appeal)
		item.AppealingParty = local.Appeal.AppealingParty
		item.BoardParty = local.Appeal.BoardParty
		item.LocalAppealID = strings.TrimSpace(local.Appeal.ID)
		item.LocalAppealStatus = local.Appeal.Status
		item.LocalRuling = local.Appeal.Ruling
		item.LocalRecusalCount = len(local.Appeal.BoardRecusals)
		item.LocalUpdatedAt = cloneTimePtr(&local.Appeal.UpdatedAt)
	}
	if counterparty != nil {
		orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(counterparty.OrganizationID))
		if item.OrganizationID == "" {
			item.OrganizationID = strings.TrimSpace(counterparty.OrganizationID)
		}
		if item.SponsorOfRecord == "" {
			item.SponsorOfRecord = strings.TrimSpace(orgSummary.SponsorOfRecord)
		}
		item.OrganizationName = strings.TrimSpace(orgSummary.OrganizationName)
		if item.IncidentID == "" {
			item.IncidentID = strings.TrimSpace(counterparty.Bundle.Appeal.IncidentID)
		}
		if item.ResponseID == "" {
			item.ResponseID = strings.TrimSpace(counterparty.Bundle.Appeal.ResponseID)
		}
		if item.DirectiveID == "" {
			item.DirectiveID = strings.TrimSpace(counterparty.Bundle.Appeal.DirectiveID)
		}
		if item.DirectiveTitle == "" {
			item.DirectiveTitle = strings.TrimSpace(counterparty.Bundle.DirectiveSummary.Title)
		}
		if item.ExtensionID == "" {
			item.ExtensionID = strings.TrimSpace(counterparty.Bundle.Appeal.ExtensionID)
		}
		if item.DisputeID == "" {
			item.DisputeID = strings.TrimSpace(counterparty.Bundle.Appeal.DisputeID)
		}
		if item.AppealID == "" {
			item.AppealID = strings.TrimSpace(counterparty.Bundle.Appeal.ID)
		}
		if item.ParentAppealID == "" {
			item.ParentAppealID = strings.TrimSpace(counterparty.Bundle.Appeal.ParentAppealID)
		}
		if item.AppealGeneration == 0 {
			item.AppealGeneration = secureCellFederationIncidentDirectiveExtensionAppealGeneration(counterparty.Bundle.Appeal)
		}
		if item.AppealingParty == "" {
			item.AppealingParty = counterparty.Bundle.Appeal.AppealingParty
		}
		if item.BoardParty == "" {
			item.BoardParty = counterparty.Bundle.Appeal.BoardParty
		}
		item.CounterpartySnapshotID = strings.TrimSpace(counterparty.SnapshotID)
		item.CounterpartyBundleID = strings.TrimSpace(counterparty.Bundle.ID)
		item.CounterpartyAppealID = strings.TrimSpace(counterparty.Bundle.Appeal.ID)
		item.CounterpartyAppealStatus = counterparty.Bundle.Appeal.Status
		item.CounterpartyRuling = counterparty.Bundle.Appeal.Ruling
		item.CounterpartyBundleStatus = counterparty.Status
		item.CounterpartyRecusalCount = len(counterparty.Bundle.Appeal.BoardRecusals)
		item.CounterpartyGeneratedAt = cloneTimePtr(&counterparty.Bundle.GeneratedAt)
		item.CounterpartyReceivedAt = cloneTimePtr(&counterparty.ReceivedAt)
	}
	item.Status, item.Divergences = secureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAndDivergences(local, counterparty)
	item.ReviewStatus, item.LastReviewedBy, item.LastReviewedAt, item.ReviewActionCount = secureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewState(run, key)
	item.AttestationStatus, item.LastCounterpartyAttestedBy, item.LastCounterpartyAttestedAt, item.CounterpartyAttestationCount = secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationState(run, key)
	if challenge := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallenge(run, key); challenge != nil {
		item.ChallengeID = challenge.ChallengeID
		item.ChallengeStatus = challenge.ChallengeStatus
		item.ChallengingParty = challenge.ChallengingParty
		item.ChallengeBoardParty = challenge.BoardParty
		item.ChallengeBoardThreshold = challenge.BoardReviewThreshold
		item.ChallengeCommitteeMemberCount = challenge.BoardCommitteeMemberCount
		item.ChallengeRecordedVoteCount = challenge.BoardRecordedVoteCount
		item.ChallengeOutstandingVotes = challenge.BoardOutstandingVotes
		item.ChallengeMissingQuorumCount = challenge.BoardMissingQuorumCount
		item.ChallengeQuorumSatisfied = challenge.BoardQuorumSatisfied
		item.ChallengeRatifyVoteCount = challenge.RatifyVoteCount
		item.ChallengeOverturnVoteCount = challenge.OverturnVoteCount
		item.ChallengeRuling = challenge.Ruling
		item.LastChallengedBy = challenge.CreatedBy
		item.LastChallengedAt = cloneTimePtr(&challenge.CreatedAt)
		item.LastRuledBy = challenge.RuledBy
		item.LastRuledAt = cloneTimePtr(challenge.RuledAt)
	}
	item.ChallengeCount = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeCount(run, key)
	return item
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAndDivergences(local *secureCellFederationIncidentDirectiveExtensionAppealRef, counterparty *SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus, []string) {
	switch {
	case local == nil && counterparty == nil:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAligned, nil
	case local == nil:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCounterpartyOnly, []string{"local appeal is missing"}
	case counterparty == nil:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusLocalOnly, []string{"counterparty appeal bundle is missing"}
	}

	divergences := make([]string, 0)
	if counterparty.Status == SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusInvalid {
		divergences = append(divergences, "counterparty appeal bundle failed verification")
	}
	if counterparty.Status == SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusExpired {
		divergences = append(divergences, "counterparty appeal bundle expired")
	}
	if counterparty.Status == SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusStale {
		divergences = append(divergences, "counterparty appeal bundle is stale")
	}
	if local.Appeal == nil {
		divergences = append(divergences, "local appeal is missing")
	} else {
		appeal := local.Appeal
		bundleAppeal := counterparty.Bundle.Appeal
		if !strings.EqualFold(strings.TrimSpace(appeal.ID), strings.TrimSpace(bundleAppeal.ID)) {
			divergences = append(divergences, "appeal id mismatch")
		}
		if !strings.EqualFold(strings.TrimSpace(appeal.ParentAppealID), strings.TrimSpace(bundleAppeal.ParentAppealID)) {
			divergences = append(divergences, "parent appeal mismatch")
		}
		if secureCellFederationIncidentDirectiveExtensionAppealGeneration(*appeal) != secureCellFederationIncidentDirectiveExtensionAppealGeneration(bundleAppeal) {
			divergences = append(divergences, "appeal generation mismatch")
		}
		if appeal.Status != bundleAppeal.Status {
			divergences = append(divergences, "appeal status mismatch")
		}
		if appeal.Ruling != bundleAppeal.Ruling {
			divergences = append(divergences, "appeal ruling mismatch")
		}
		if appeal.AppealingParty != bundleAppeal.AppealingParty {
			divergences = append(divergences, "appealing party mismatch")
		}
		if appeal.BoardParty != bundleAppeal.BoardParty {
			divergences = append(divergences, "board party mismatch")
		}
		if len(appeal.BoardRecusals) != len(bundleAppeal.BoardRecusals) {
			divergences = append(divergences, "appeal recusal count mismatch")
		}
		if len(appeal.BoardVotes) != len(bundleAppeal.BoardVotes) {
			divergences = append(divergences, "appeal vote count mismatch")
		}
	}
	if len(divergences) > 0 {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusDivergent, divergences
	}
	return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAligned, nil
}

func secureCellLatestLocalFederationIncidentDirectiveExtensionAppealsByKey(run *secureCellRun) map[string]*secureCellFederationIncidentDirectiveExtensionAppealRef {
	out := make(map[string]*secureCellFederationIncidentDirectiveExtensionAppealRef)
	if run == nil || run.result == nil {
		return out
	}
	for responseIdx := range run.result.FederationIncidentResponses {
		response := &run.result.FederationIncidentResponses[responseIdx]
		for directiveIdx := range response.IncidentDirectives {
			directive := &response.IncidentDirectives[directiveIdx]
			for extensionIdx := range directive.Extensions {
				extension := &directive.Extensions[extensionIdx]
				for disputeIdx := range extension.Disputes {
					dispute := &extension.Disputes[disputeIdx]
					for appealIdx := range dispute.Appeals {
						appeal := &dispute.Appeals[appealIdx]
						key := secureCellFederationIncidentDirectiveExtensionAppealComparisonKey(
							strings.TrimSpace(response.OrganizationID),
							strings.TrimSpace(response.IncidentID),
							strings.TrimSpace(response.ID),
							strings.TrimSpace(directive.ID),
							strings.TrimSpace(extension.ID),
							strings.TrimSpace(dispute.ID),
							strings.TrimSpace(appeal.ParentAppealID),
							secureCellFederationIncidentDirectiveExtensionAppealGeneration(*appeal),
							appeal.AppealingParty,
						)
						current, ok := out[key]
						if !ok || current == nil || current.Appeal == nil || appeal.UpdatedAt.After(current.Appeal.UpdatedAt) {
							out[key] = &secureCellFederationIncidentDirectiveExtensionAppealRef{
								Response:  response,
								Directive: directive,
								Extension: extension,
								Dispute:   dispute,
								Appeal:    appeal,
							}
						}
					}
				}
			}
		}
	}
	return out
}

func secureCellLatestCounterpartyFederationIncidentDirectiveExtensionAppealsByKey(run *secureCellRun) map[string]*SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot {
	out := make(map[string]*SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot)
	if run == nil || run.result == nil {
		return out
	}
	for idx := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals {
		snapshot := &run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals[idx]
		key := secureCellFederationIncidentDirectiveExtensionAppealComparisonKey(
			strings.TrimSpace(snapshot.OrganizationID),
			strings.TrimSpace(snapshot.Bundle.Appeal.IncidentID),
			strings.TrimSpace(snapshot.Bundle.Appeal.ResponseID),
			strings.TrimSpace(snapshot.Bundle.Appeal.DirectiveID),
			strings.TrimSpace(snapshot.Bundle.Appeal.ExtensionID),
			strings.TrimSpace(snapshot.Bundle.Appeal.DisputeID),
			strings.TrimSpace(snapshot.Bundle.Appeal.ParentAppealID),
			secureCellFederationIncidentDirectiveExtensionAppealGeneration(snapshot.Bundle.Appeal),
			snapshot.Bundle.Appeal.AppealingParty,
		)
		current, ok := out[key]
		if !ok || current == nil || snapshot.ReceivedAt.After(current.ReceivedAt) {
			out[key] = snapshot
		}
	}
	return out
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationForSnapshot(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary {
	key := secureCellFederationIncidentDirectiveExtensionAppealComparisonKey(
		strings.TrimSpace(snapshot.OrganizationID),
		strings.TrimSpace(snapshot.Bundle.Appeal.IncidentID),
		strings.TrimSpace(snapshot.Bundle.Appeal.ResponseID),
		strings.TrimSpace(snapshot.Bundle.Appeal.DirectiveID),
		strings.TrimSpace(snapshot.Bundle.Appeal.ExtensionID),
		strings.TrimSpace(snapshot.Bundle.Appeal.DisputeID),
		strings.TrimSpace(snapshot.Bundle.Appeal.ParentAppealID),
		secureCellFederationIncidentDirectiveExtensionAppealGeneration(snapshot.Bundle.Appeal),
		snapshot.Bundle.Appeal.AppealingParty,
	)
	return secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryFromRefs(run, key, secureCellLatestLocalFederationIncidentDirectiveExtensionAppealsByKey(run)[key], &snapshot)
}

func secureCellFederationIncidentDirectiveExtensionAppealComparisonKey(organizationID string, incidentID string, responseID string, directiveID string, extensionID string, disputeID string, parentAppealID string, generation int, appealingParty SecureCellFederationIncidentResponseParty) string {
	return strings.ToLower(strings.Join([]string{
		strings.TrimSpace(organizationID),
		strings.TrimSpace(incidentID),
		strings.TrimSpace(responseID),
		strings.TrimSpace(directiveID),
		strings.TrimSpace(extensionID),
		strings.TrimSpace(disputeID),
		strings.TrimSpace(parentAppealID),
		fmt.Sprintf("%d", normalizeSecureCellThreshold(generation)),
		string(appealingParty),
	}, "|"))
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusAt(bundle *SecureCellFederationIncidentDirectiveExtensionAppealBundle, verificationErr error, now time.Time) (SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus, string, bool) {
	switch {
	case verificationErr != nil:
		return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusInvalid, verificationErr.Error(), false
	case bundle == nil:
		return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusInvalid, "bundle is required", false
	case bundle.ExpiresAt != nil && bundle.ExpiresAt.UTC().Before(now.UTC()):
		return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusExpired, "counterparty incident directive extension appeal bundle expired", true
	case now.UTC().Sub(bundle.GeneratedAt.UTC()) > 72*time.Hour:
		return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusStale, "counterparty incident directive extension appeal bundle is stale", true
	default:
		return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusVerified, "counterparty incident directive extension appeal bundle verified", true
	}
}

func secureCellValidateFederationIncidentDirectiveExtensionAppealBundleSemantics(bundle *SecureCellFederationIncidentDirectiveExtensionAppealBundle, organizationID string) error {
	if bundle == nil {
		return fmt.Errorf("bundle is required")
	}
	if strings.TrimSpace(bundle.Organization.OrganizationID) == "" {
		return fmt.Errorf("organization summary is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.Organization.OrganizationID), strings.TrimSpace(organizationID)) {
		return fmt.Errorf("organization summary mismatch")
	}
	if strings.TrimSpace(bundle.ResponseSummary.OrganizationID) != "" && !strings.EqualFold(strings.TrimSpace(bundle.ResponseSummary.OrganizationID), strings.TrimSpace(organizationID)) {
		return fmt.Errorf("response summary organization mismatch")
	}
	if strings.TrimSpace(bundle.AppealSummary.OrganizationID) != "" && !strings.EqualFold(strings.TrimSpace(bundle.AppealSummary.OrganizationID), strings.TrimSpace(organizationID)) {
		return fmt.Errorf("appeal summary organization mismatch")
	}
	if strings.TrimSpace(bundle.AppealSummary.AppealID) != strings.TrimSpace(bundle.Appeal.ID) {
		return fmt.Errorf("appeal summary/appeal mismatch")
	}
	if strings.TrimSpace(bundle.AppealSummary.DisputeID) != strings.TrimSpace(bundle.Appeal.DisputeID) {
		return fmt.Errorf("appeal summary/dispute mismatch")
	}
	if strings.TrimSpace(bundle.AppealSummary.ExtensionID) != strings.TrimSpace(bundle.Appeal.ExtensionID) {
		return fmt.Errorf("appeal summary/extension mismatch")
	}
	if strings.TrimSpace(bundle.AppealSummary.DirectiveID) != strings.TrimSpace(bundle.Appeal.DirectiveID) {
		return fmt.Errorf("appeal summary/directive mismatch")
	}
	if strings.TrimSpace(bundle.AppealSummary.ResponseID) != strings.TrimSpace(bundle.Appeal.ResponseID) {
		return fmt.Errorf("appeal summary/response mismatch")
	}
	if strings.TrimSpace(bundle.AppealSummary.IncidentID) != strings.TrimSpace(bundle.Appeal.IncidentID) {
		return fmt.Errorf("appeal summary/incident mismatch")
	}
	if bundle.AppealSummary.Status != bundle.Appeal.Status {
		return fmt.Errorf("appeal summary/status mismatch")
	}
	if bundle.AppealSummary.Ruling != bundle.Appeal.Ruling {
		return fmt.Errorf("appeal summary/ruling mismatch")
	}
	return nil
}

func secureCellCloneFederationIncidentDirectiveExtensionAppealBundle(in SecureCellFederationIncidentDirectiveExtensionAppealBundle) SecureCellFederationIncidentDirectiveExtensionAppealBundle {
	data, _ := json.Marshal(in)
	var out SecureCellFederationIncidentDirectiveExtensionAppealBundle
	_ = json.Unmarshal(data, &out)
	return out
}

func secureCellFederationIncidentDirectiveExtensionAppealBundleSignerName(bundle *SecureCellFederationIncidentDirectiveExtensionAppealBundle) string {
	if bundle == nil || bundle.Signature == nil {
		return ""
	}
	return strings.TrimSpace(bundle.Signature.Signer)
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealsByStatus(items []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot, status SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus) []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot {
	out := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot, 0, len(items))
	for _, item := range items {
		if item.Status == status {
			out = append(out, item)
		}
	}
	return out
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCount(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary, status SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus) int {
	total := 0
	for _, item := range items {
		if item.Status == status {
			total++
		}
	}
	return total
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationDivergentCount(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary) int {
	total := 0
	for _, item := range items {
		if item.Status == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusDivergent {
			total++
		}
	}
	return total
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationUpdatedAt(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary) time.Time {
	if item.LocalUpdatedAt != nil && !item.LocalUpdatedAt.IsZero() {
		return item.LocalUpdatedAt.UTC()
	}
	if item.CounterpartyReceivedAt != nil && !item.CounterpartyReceivedAt.IsZero() {
		return item.CounterpartyReceivedAt.UTC()
	}
	if item.CounterpartyGeneratedAt != nil && !item.CounterpartyGeneratedAt.IsZero() {
		return item.CounterpartyGeneratedAt.UTC()
	}
	return time.Time{}
}
