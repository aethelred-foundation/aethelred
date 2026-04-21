package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus
// tracks the latest bilateral counterparty coordination posture for one
// directive-extension appeal reconciliation key.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus = "unattested"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus = "acknowledged"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusCorrected    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus = "corrected"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusResolved     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus = "resolved"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType
// captures one evidence-bearing counterparty coordination event over a disputed
// appeal reconciliation.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationAcknowledge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType = "acknowledge_dispute"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationCorrect     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType = "attest_correction"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationResolve     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType = "attest_resolution"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeRequest
// records one counterparty acknowledgement that a bilateral appeal dispute was
// received and is being handled.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestationRequest
// records one counterparty attestation that the challenged appeal posture was
// corrected and links it to the latest reciprocal evidence when available.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestationRequest struct {
	ActorDID               string            `json:"actor_did,omitempty"`
	CounterpartySnapshotID string            `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyReference  string            `json:"counterparty_reference,omitempty"`
	Reason                 string            `json:"reason,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestationRequest
// records one counterparty attestation that a bilateral appeal dispute has
// been resolved.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestationRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter
// narrows operator views across counterparty appeal-dispute coordination.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter struct {
	CellID            string                                                                                          `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                          `json:"organization_id,omitempty"`
	IncidentID        string                                                                                          `json:"incident_id,omitempty"`
	ResponseID        string                                                                                          `json:"response_id,omitempty"`
	DirectiveID       string                                                                                          `json:"directive_id,omitempty"`
	ExtensionID       string                                                                                          `json:"extension_id,omitempty"`
	DisputeID         string                                                                                          `json:"dispute_id,omitempty"`
	AppealID          string                                                                                          `json:"appeal_id,omitempty"`
	ComparisonKey     string                                                                                          `json:"comparison_key,omitempty"`
	Attestation       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType   `json:"attestation,omitempty"`
	AttestationStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status,omitempty"`
	ActorDID          string                                                                                          `json:"actor_did,omitempty"`
	Limit             int                                                                                             `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord
// is the operator-facing evidence record for one counterparty coordination
// attestation against a disputed appeal reconciliation.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord struct {
	CellID                 string                                                                                          `json:"cell_id"`
	CellName               string                                                                                          `json:"cell_name,omitempty"`
	CellStatus             SecureCellStatus                                                                                `json:"cell_status"`
	Jurisdiction           string                                                                                          `json:"jurisdiction,omitempty"`
	OrganizationID         string                                                                                          `json:"organization_id"`
	SponsorOfRecord        string                                                                                          `json:"sponsor_of_record,omitempty"`
	OrganizationName       string                                                                                          `json:"organization_name,omitempty"`
	ComparisonKey          string                                                                                          `json:"comparison_key"`
	IncidentID             string                                                                                          `json:"incident_id,omitempty"`
	ResponseID             string                                                                                          `json:"response_id,omitempty"`
	DirectiveID            string                                                                                          `json:"directive_id,omitempty"`
	ExtensionID            string                                                                                          `json:"extension_id,omitempty"`
	DisputeID              string                                                                                          `json:"dispute_id,omitempty"`
	AppealID               string                                                                                          `json:"appeal_id,omitempty"`
	LocalAppealID          string                                                                                          `json:"local_appeal_id,omitempty"`
	CounterpartySnapshotID string                                                                                          `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyBundleID   string                                                                                          `json:"counterparty_bundle_id,omitempty"`
	CounterpartyAppealID   string                                                                                          `json:"counterparty_appeal_id,omitempty"`
	ReconciliationStatus   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus                        `json:"reconciliation_status"`
	ReviewStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status"`
	Attestation            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType   `json:"attestation"`
	AttestationStatus      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status"`
	TransitionID           string                                                                                          `json:"transition_id,omitempty"`
	PolicyReceiptID        string                                                                                          `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash      string                                                                                          `json:"policy_receipt_hash,omitempty"`
	SealID                 string                                                                                          `json:"seal_id,omitempty"`
	TraceLinkID            string                                                                                          `json:"trace_link_id,omitempty"`
	ActorDID               string                                                                                          `json:"actor_did,omitempty"`
	CounterpartyReference  string                                                                                          `json:"counterparty_reference,omitempty"`
	Reason                 string                                                                                          `json:"reason,omitempty"`
	Metadata               map[string]string                                                                               `json:"metadata,omitempty"`
	OccurredAt             time.Time                                                                                       `json:"occurred_at"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationSpec struct {
	stage                  string
	attestation            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType
	status                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus
	actorDID               string
	reason                 string
	counterpartyReference  string
	counterpartySnapshotID string
	metadata               map[string]string
}

func (s *Service) AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationDispute(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestation(ctx, cellID, comparisonKey, secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationSpec{
		stage:                 "acknowledge_federation_incident_directive_extension_appeal_reconciliation_dispute",
		attestation:           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationAcknowledge,
		status:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusAcknowledged,
		actorDID:              req.ActorDID,
		reason:                req.Reason,
		counterpartyReference: req.CounterpartyReference,
		metadata:              req.Metadata,
	})
}

func (s *Service) AttestFederationIncidentDirectiveExtensionAppealReconciliationCorrection(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestationRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestation(ctx, cellID, comparisonKey, secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationSpec{
		stage:                  "attest_federation_incident_directive_extension_appeal_reconciliation_correction",
		attestation:            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationCorrect,
		status:                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusCorrected,
		actorDID:               req.ActorDID,
		reason:                 req.Reason,
		counterpartyReference:  req.CounterpartyReference,
		counterpartySnapshotID: req.CounterpartySnapshotID,
		metadata:               req.Metadata,
	})
}

func (s *Service) AttestFederationIncidentDirectiveExtensionAppealReconciliationResolution(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestationRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestation(ctx, cellID, comparisonKey, secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationSpec{
		stage:                 "attest_federation_incident_directive_extension_appeal_reconciliation_resolution",
		attestation:           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationResolve,
		status:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusResolved,
		actorDID:              req.ActorDID,
		reason:                req.Reason,
		counterpartyReference: req.CounterpartyReference,
		metadata:              req.Metadata,
	})
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestations(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter(record, filter) {
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

func (s *Service) applyFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestation(ctx context.Context, cellID string, comparisonKey string, spec secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationSpec) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-attestation: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryByKey(run, comparisonKey)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(spec.actorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-attestation: %w: actor %q is not permitted to coordinate reconciliation %q", ErrPolicyDenied, actorDID, comparisonKey)
	}
	reviewStatus := secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveReviewStatus(summary)
	if reviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-attestation: reconciliation %q must be disputed before counterparty coordination can be attested", comparisonKey)
	}
	latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestation(run, summary.ComparisonKey)
	switch spec.attestation {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationAcknowledge:
		if latest != nil && latest.AttestationStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusAcknowledged {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-attestation: reconciliation %q is already acknowledged by the counterparty", comparisonKey)
		}
		if latest != nil && (latest.AttestationStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusCorrected || latest.AttestationStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusResolved) {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-attestation: reconciliation %q already advanced beyond acknowledgement", comparisonKey)
		}
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationCorrect:
		if latest != nil && latest.AttestationStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusResolved {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-attestation: reconciliation %q is already resolved by the counterparty", comparisonKey)
		}
		if strings.TrimSpace(spec.counterpartySnapshotID) == "" {
			spec.counterpartySnapshotID = strings.TrimSpace(summary.CounterpartySnapshotID)
		}
		if strings.TrimSpace(spec.counterpartySnapshotID) == "" {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-attestation: counterparty appeal evidence is required to attest a correction for %q", comparisonKey)
		}
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationResolve:
		if latest == nil || (latest.AttestationStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusAcknowledged && latest.AttestationStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusCorrected) {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-attestation: reconciliation %q must be acknowledged or corrected before resolution is attested", comparisonKey)
		}
		if latest.AttestationStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusResolved {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-attestation: reconciliation %q is already resolved by the counterparty", comparisonKey)
		}
	default:
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-attestation: unsupported attestation %q", spec.attestation)
	}

	counterpartySnapshotID := strings.TrimSpace(spec.counterpartySnapshotID)
	counterpartyBundleID := strings.TrimSpace(summary.CounterpartyBundleID)
	counterpartyAppealID := strings.TrimSpace(summary.CounterpartyAppealID)
	if counterpartySnapshotID != "" {
		if snapshot := secureCellLatestCounterpartyFederationIncidentDirectiveExtensionAppealsByKey(run)[summary.ComparisonKey]; snapshot != nil && strings.EqualFold(strings.TrimSpace(snapshot.SnapshotID), counterpartySnapshotID) {
			counterpartyBundleID = strings.TrimSpace(snapshot.Bundle.ID)
			counterpartyAppealID = strings.TrimSpace(snapshot.Bundle.Appeal.ID)
		}
	}

	receipt, err := s.evaluateStage(ctx, run.request, spec.stage, lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                             summary.OrganizationID,
		"federation_incident_id":                                                                 summary.IncidentID,
		"federation_incident_response_id":                                                        summary.ResponseID,
		"federation_incident_directive_id":                                                       summary.DirectiveID,
		"federation_incident_directive_extension_id":                                             summary.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                     summary.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                      summary.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":                      summary.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_status":                   string(summary.Status),
		"federation_incident_directive_extension_appeal_reconciliation_review":                   string(reviewStatus),
		"federation_incident_directive_extension_appeal_reconciliation_counterparty_attestation": string(spec.attestation),
		"federation_incident_directive_extension_appeal_reconciliation_attestation_status":       string(spec.status),
		"federation_incident_directive_extension_local_appeal_id":                                summary.LocalAppealID,
		"federation_counterparty_incident_directive_extension_appeal_snapshot_id":                counterpartySnapshotID,
		"federation_counterparty_incident_directive_extension_appeal_bundle_id":                  counterpartyBundleID,
		"federation_counterparty_incident_directive_extension_appeal_id":                         counterpartyAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_counterparty_reference":   strings.TrimSpace(spec.counterpartyReference),
		"transition_reason": strings.TrimSpace(spec.reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-attestation: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationTransitionSuffix(spec.attestation), summary.ComparisonKey),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationTransitionSuffix(spec.attestation),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation",
		TargetDID:        summary.ComparisonKey,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(spec.reason),
		Metadata: mergeStringMaps(spec.metadata, map[string]string{
			"federation_organization_id":                                                             summary.OrganizationID,
			"federation_sponsor_of_record":                                                           summary.SponsorOfRecord,
			"federation_organization_name":                                                           summary.OrganizationName,
			"federation_incident_id":                                                                 summary.IncidentID,
			"federation_incident_response_id":                                                        summary.ResponseID,
			"federation_incident_directive_id":                                                       summary.DirectiveID,
			"federation_incident_directive_extension_id":                                             summary.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                     summary.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                      summary.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":                      summary.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_status":                   string(summary.Status),
			"federation_incident_directive_extension_appeal_reconciliation_review":                   string(reviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_counterparty_attestation": string(spec.attestation),
			"federation_incident_directive_extension_appeal_reconciliation_attestation_status":       string(spec.status),
			"federation_incident_directive_extension_local_appeal_id":                                summary.LocalAppealID,
			"federation_counterparty_incident_directive_extension_appeal_snapshot_id":                counterpartySnapshotID,
			"federation_counterparty_incident_directive_extension_appeal_bundle_id":                  counterpartyBundleID,
			"federation_counterparty_incident_directive_extension_appeal_id":                         counterpartyAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_counterparty_reference":   strings.TrimSpace(spec.counterpartyReference),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveReviewStatus(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus {
	if item.ReviewStatus != "" {
		return item.ReviewStatus
	}
	return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusUnreviewed
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord, bool) {
	attestationType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationTypeFromTransitionAction(transition.Action)
	if !ok {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord{}, false
	}
	meta := cloneStringMap(transition.Metadata)
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord{
		CellID:                 safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:               safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		Jurisdiction:           safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		CellStatus:             safeSecureCellStatus(run),
		OrganizationID:         strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:        strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:       strings.TrimSpace(meta["federation_organization_name"]),
		ComparisonKey:          strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_key"]),
		IncidentID:             strings.TrimSpace(meta["federation_incident_id"]),
		ResponseID:             strings.TrimSpace(meta["federation_incident_response_id"]),
		DirectiveID:            strings.TrimSpace(meta["federation_incident_directive_id"]),
		ExtensionID:            strings.TrimSpace(meta["federation_incident_directive_extension_id"]),
		DisputeID:              strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]),
		AppealID:               strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]),
		LocalAppealID:          strings.TrimSpace(meta["federation_incident_directive_extension_local_appeal_id"]),
		CounterpartySnapshotID: strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_snapshot_id"]),
		CounterpartyBundleID:   strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_bundle_id"]),
		CounterpartyAppealID:   strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_id"]),
		ReconciliationStatus:   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_status"])),
		ReviewStatus:           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_review"])),
		Attestation:            attestationType,
		AttestationStatus:      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_attestation_status"])),
		TransitionID:           strings.TrimSpace(transition.ID),
		ActorDID:               strings.TrimSpace(transition.Actor),
		CounterpartyReference:  strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_counterparty_reference"]),
		Reason:                 firstNonEmpty(strings.TrimSpace(transition.Reason), strings.TrimSpace(meta["transition_reason"])),
		Metadata:               meta,
		OccurredAt:             transition.OccurredAt.UTC(),
	}
	if record.AttestationStatus == "" {
		record.AttestationStatus = secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusFromType(attestationType)
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

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter) bool {
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
	if filter.Attestation != "" && item.Attestation != filter.Attestation {
		return false
	}
	if filter.AttestationStatus != "" && item.AttestationStatus != filter.AttestationStatus {
		return false
	}
	if filter.ActorDID != "" && !strings.EqualFold(strings.TrimSpace(item.ActorDID), strings.TrimSpace(filter.ActorDID)) {
		return false
	}
	return true
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestation(run *secureCellRun, comparisonKey string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord {
	if run == nil || run.result == nil {
		return nil
	}
	key := strings.TrimSpace(comparisonKey)
	var latest *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFromTransition(run, transition)
		if !ok || !strings.EqualFold(strings.TrimSpace(record.ComparisonKey), key) {
			continue
		}
		if latest == nil || record.OccurredAt.After(latest.OccurredAt) || (record.OccurredAt.Equal(latest.OccurredAt) && record.TransitionID > latest.TransitionID) {
			copyRecord := record
			latest = &copyRecord
		}
	}
	return latest
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationState(run *secureCellRun, comparisonKey string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus, string, *time.Time, int) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested, "", nil, 0
	}
	key := strings.TrimSpace(comparisonKey)
	status := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested
	lastActor := ""
	var lastAt *time.Time
	count := 0
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFromTransition(run, transition)
		if !ok || !strings.EqualFold(strings.TrimSpace(record.ComparisonKey), key) {
			continue
		}
		count++
		status = record.AttestationStatus
		lastActor = record.ActorDID
		occurred := record.OccurredAt.UTC()
		lastAt = &occurred
	}
	return status, lastActor, cloneTimePtr(lastAt), count
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationTypeFromTransitionAction(action string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType, bool) {
	switch action {
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_dispute_acknowledged":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationAcknowledge, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_correction_attested":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationCorrect, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_resolution_attested":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationResolve, true
	default:
		return "", false
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusFromType(attestation SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus {
	switch attestation {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationAcknowledge:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusAcknowledged
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationCorrect:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusCorrected
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationResolve:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusResolved
	default:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationTransitionSuffix(attestation SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType) string {
	switch attestation {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationAcknowledge:
		return "federation_incident_directive_extension_appeal_reconciliation_dispute_acknowledged"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationCorrect:
		return "federation_incident_directive_extension_appeal_reconciliation_correction_attested"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationResolve:
		return "federation_incident_directive_extension_appeal_reconciliation_resolution_attested"
	default:
		return "federation_incident_directive_extension_appeal_reconciliation_counterparty_attested"
	}
}
