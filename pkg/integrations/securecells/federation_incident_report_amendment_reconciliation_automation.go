package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

const (
	secureCellFederationIncidentReportAmendmentReconciliationReviewSLA          = 6 * time.Hour
	secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAckSLA = 12 * time.Hour
	secureCellFederationIncidentReportAmendmentReconciliationResolutionSLA      = 24 * time.Hour
)

// SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus
// tracks the latest bilateral counterparty coordination posture for one
// amendment reconciliation key.
type SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus string

const (
	SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested   SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus = "unattested"
	SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusAcknowledged SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus = "acknowledged"
	SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusCorrected    SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus = "corrected"
	SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved     SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus = "resolved"
)

// SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType
// captures one evidence-bearing counterparty coordination event over a
// disputed amendment reconciliation.
type SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType string

const (
	SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationAcknowledge SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType = "acknowledge_dispute"
	SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationCorrect     SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType = "attest_correction"
	SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationResolve     SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType = "attest_resolution"
)

// SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAcknowledgeRequest
// records one counterparty acknowledgement that a bilateral amendment dispute
// was received and is being handled.
type SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAcknowledgeRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationCorrectionAttestationRequest
// records one counterparty attestation that the challenged amendment was
// corrected and links it to the latest reciprocal evidence when available.
type SecureCellFederationIncidentReportAmendmentReconciliationCorrectionAttestationRequest struct {
	ActorDID               string            `json:"actor_did,omitempty"`
	CounterpartySnapshotID string            `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyReference  string            `json:"counterparty_reference,omitempty"`
	Reason                 string            `json:"reason,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationResolutionAttestationRequest
// records one counterparty attestation that a bilateral amendment dispute has
// been resolved.
type SecureCellFederationIncidentReportAmendmentReconciliationResolutionAttestationRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter
// narrows operator views across counterparty amendment-dispute coordination.
type SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter struct {
	CellID            string                                                                                 `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                 `json:"organization_id,omitempty"`
	IncidentID        string                                                                                 `json:"incident_id,omitempty"`
	ComparisonKey     string                                                                                 `json:"comparison_key,omitempty"`
	Attestation       SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType   `json:"attestation,omitempty"`
	AttestationStatus SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus `json:"attestation_status,omitempty"`
	ActorDID          string                                                                                 `json:"actor_did,omitempty"`
	Limit             int                                                                                    `json:"limit,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord
// is the operator-facing evidence record for one counterparty coordination
// attestation against a disputed amendment reconciliation.
type SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord struct {
	CellID                  string                                                                                 `json:"cell_id"`
	CellName                string                                                                                 `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                                                                       `json:"cell_status"`
	Jurisdiction            string                                                                                 `json:"jurisdiction,omitempty"`
	OrganizationID          string                                                                                 `json:"organization_id"`
	SponsorOfRecord         string                                                                                 `json:"sponsor_of_record,omitempty"`
	OrganizationName        string                                                                                 `json:"organization_name,omitempty"`
	ComparisonKey           string                                                                                 `json:"comparison_key"`
	IncidentID              string                                                                                 `json:"incident_id,omitempty"`
	LocalReportID           string                                                                                 `json:"local_report_id,omitempty"`
	LocalResponseID         string                                                                                 `json:"local_response_id,omitempty"`
	LocalAmendmentID        string                                                                                 `json:"local_amendment_id,omitempty"`
	CounterpartySnapshotID  string                                                                                 `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyBundleID    string                                                                                 `json:"counterparty_bundle_id,omitempty"`
	CounterpartyReportID    string                                                                                 `json:"counterparty_report_id,omitempty"`
	CounterpartyResponseID  string                                                                                 `json:"counterparty_response_id,omitempty"`
	CounterpartyAmendmentID string                                                                                 `json:"counterparty_amendment_id,omitempty"`
	ReconciliationStatus    SecureCellFederationIncidentReportAmendmentReconciliationStatus                        `json:"reconciliation_status"`
	ReviewStatus            SecureCellFederationIncidentReportReviewStatus                                         `json:"review_status"`
	Attestation             SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType   `json:"attestation"`
	AttestationStatus       SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus `json:"attestation_status"`
	TransitionID            string                                                                                 `json:"transition_id,omitempty"`
	PolicyReceiptID         string                                                                                 `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash       string                                                                                 `json:"policy_receipt_hash,omitempty"`
	SealID                  string                                                                                 `json:"seal_id,omitempty"`
	TraceLinkID             string                                                                                 `json:"trace_link_id,omitempty"`
	ActorDID                string                                                                                 `json:"actor_did,omitempty"`
	CounterpartyReference   string                                                                                 `json:"counterparty_reference,omitempty"`
	Reason                  string                                                                                 `json:"reason,omitempty"`
	Metadata                map[string]string                                                                      `json:"metadata,omitempty"`
	OccurredAt              time.Time                                                                              `json:"occurred_at"`
}

// SecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter narrows
// operator queries across amendment reconciliations whose next governed review
// or counterparty-response milestone is overdue.
type SecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter struct {
	CellID            string                                                                                 `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                 `json:"organization_id,omitempty"`
	IncidentID        string                                                                                 `json:"incident_id,omitempty"`
	ComparisonKey     string                                                                                 `json:"comparison_key,omitempty"`
	Status            SecureCellFederationIncidentReportAmendmentReconciliationStatus                        `json:"status,omitempty"`
	ReviewStatus      SecureCellFederationIncidentReportReviewStatus                                         `json:"review_status,omitempty"`
	AttestationStatus SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus `json:"attestation_status,omitempty"`
	Before            *time.Time                                                                             `json:"before,omitempty"`
	Limit             int                                                                                    `json:"limit,omitempty"`
}

// SecureCellOverdueFederationIncidentReportAmendmentReconciliation projects
// one overdue amendment reconciliation milestone.
type SecureCellOverdueFederationIncidentReportAmendmentReconciliation struct {
	CellID                       string                                                                                 `json:"cell_id"`
	CellName                     string                                                                                 `json:"cell_name,omitempty"`
	Jurisdiction                 string                                                                                 `json:"jurisdiction,omitempty"`
	CellStatus                   SecureCellStatus                                                                       `json:"cell_status"`
	OrganizationID               string                                                                                 `json:"organization_id"`
	SponsorOfRecord              string                                                                                 `json:"sponsor_of_record,omitempty"`
	OrganizationName             string                                                                                 `json:"organization_name,omitempty"`
	ComparisonKey                string                                                                                 `json:"comparison_key"`
	IncidentID                   string                                                                                 `json:"incident_id,omitempty"`
	Regulator                    string                                                                                 `json:"regulator,omitempty"`
	Framework                    string                                                                                 `json:"framework,omitempty"`
	ReportType                   string                                                                                 `json:"report_type,omitempty"`
	ReportingParty               SecureCellFederationIncidentResponseParty                                              `json:"reporting_party,omitempty"`
	Status                       SecureCellFederationIncidentReportAmendmentReconciliationStatus                        `json:"status"`
	ReviewStatus                 SecureCellFederationIncidentReportReviewStatus                                         `json:"review_status"`
	AttestationStatus            SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus `json:"attestation_status"`
	AutomationAction             string                                                                                 `json:"automation_action"`
	OverdueReason                string                                                                                 `json:"overdue_reason"`
	DueAt                        time.Time                                                                              `json:"due_at"`
	OverdueSeconds               int64                                                                                  `json:"overdue_seconds"`
	ReviewDueAt                  *time.Time                                                                             `json:"review_due_at,omitempty"`
	CounterpartyAcknowledgeDueAt *time.Time                                                                             `json:"counterparty_acknowledge_due_at,omitempty"`
	ResolutionDueAt              *time.Time                                                                             `json:"resolution_due_at,omitempty"`
	LocalAmendmentID             string                                                                                 `json:"local_amendment_id,omitempty"`
	CounterpartyAmendmentID      string                                                                                 `json:"counterparty_amendment_id,omitempty"`
	LastReviewedBy               string                                                                                 `json:"last_reviewed_by,omitempty"`
	LastReviewedAt               *time.Time                                                                             `json:"last_reviewed_at,omitempty"`
	LastCounterpartyAttestedBy   string                                                                                 `json:"last_counterparty_attested_by,omitempty"`
	LastCounterpartyAttestedAt   *time.Time                                                                             `json:"last_counterparty_attested_at,omitempty"`
	Divergences                  []string                                                                               `json:"divergences,omitempty"`
	UpdatedAt                    time.Time                                                                              `json:"updated_at"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter
// narrows operator queries over automated amendment-reconciliation actions.
type SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ComparisonKey  string     `json:"comparison_key,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	Action         string     `json:"action,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionRecord
// projects one automated escalation or containment action over a bilateral
// amendment reconciliation.
type SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionRecord struct {
	CellID                  string                                                                                 `json:"cell_id"`
	CellName                string                                                                                 `json:"cell_name,omitempty"`
	Jurisdiction            string                                                                                 `json:"jurisdiction,omitempty"`
	CellStatus              SecureCellStatus                                                                       `json:"cell_status"`
	OrganizationID          string                                                                                 `json:"organization_id,omitempty"`
	SponsorOfRecord         string                                                                                 `json:"sponsor_of_record,omitempty"`
	ComparisonKey           string                                                                                 `json:"comparison_key,omitempty"`
	IncidentID              string                                                                                 `json:"incident_id,omitempty"`
	Regulator               string                                                                                 `json:"regulator,omitempty"`
	ReconciliationStatus    SecureCellFederationIncidentReportAmendmentReconciliationStatus                        `json:"reconciliation_status,omitempty"`
	ReviewStatusBefore      SecureCellFederationIncidentReportReviewStatus                                         `json:"review_status_before,omitempty"`
	ReviewStatusAfter       SecureCellFederationIncidentReportReviewStatus                                         `json:"review_status_after,omitempty"`
	AttestationStatusBefore SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus `json:"attestation_status_before,omitempty"`
	AttestationStatusAfter  SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus `json:"attestation_status_after,omitempty"`
	ContractID              string                                                                                 `json:"contract_id,omitempty"`
	ContractStatusBefore    SecureCellFederationContractStatus                                                     `json:"contract_status_before,omitempty"`
	ContractStatusAfter     SecureCellFederationContractStatus                                                     `json:"contract_status_after,omitempty"`
	Action                  string                                                                                 `json:"action"`
	Trigger                 string                                                                                 `json:"trigger,omitempty"`
	DueAt                   *time.Time                                                                             `json:"due_at,omitempty"`
	Actor                   string                                                                                 `json:"actor"`
	AutomatedActor          string                                                                                 `json:"automated_actor,omitempty"`
	Reason                  string                                                                                 `json:"reason,omitempty"`
	TransitionID            string                                                                                 `json:"transition_id"`
	OccurredAt              time.Time                                                                              `json:"occurred_at"`
	Metadata                map[string]string                                                                      `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationSweepResult summarizes
// one automated amendment-reconciliation sweep.
type SecureCellFederationIncidentReportAmendmentReconciliationSweepResult struct {
	At                          time.Time `json:"at"`
	CellsScanned                int       `json:"cells_scanned"`
	ReconciliationsScanned      int       `json:"reconciliations_scanned"`
	CellsMutated                int       `json:"cells_mutated"`
	ReconciliationsAutoDisputed int       `json:"reconciliations_auto_disputed"`
	ReconciliationsEscalated    int       `json:"reconciliations_escalated"`
	ContractsSuspended          int       `json:"contracts_suspended"`
	CellIDs                     []string  `json:"cell_ids,omitempty"`
}

type secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationSpec struct {
	stage                  string
	attestation            SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType
	status                 SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus
	actorDID               string
	reason                 string
	counterpartyReference  string
	counterpartySnapshotID string
	metadata               map[string]string
}

type secureCellFederationIncidentReportAmendmentReconciliationOverdueState struct {
	reviewStatus         SecureCellFederationIncidentReportReviewStatus
	attestationStatus    SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus
	automationAction     string
	overdueReason        string
	dueAt                time.Time
	reviewDueAt          *time.Time
	counterpartyAckDueAt *time.Time
	resolutionDueAt      *time.Time
}

func (s *Service) AcknowledgeFederationIncidentReportAmendmentReconciliationDispute(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAcknowledgeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentReportAmendmentReconciliationCounterpartyAttestation(ctx, cellID, comparisonKey, secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationSpec{
		stage:                 "acknowledge_federation_incident_report_amendment_reconciliation_dispute",
		attestation:           SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationAcknowledge,
		status:                SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusAcknowledged,
		actorDID:              req.ActorDID,
		reason:                req.Reason,
		counterpartyReference: req.CounterpartyReference,
		metadata:              req.Metadata,
	})
}

func (s *Service) AttestFederationIncidentReportAmendmentReconciliationCorrection(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentReportAmendmentReconciliationCorrectionAttestationRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentReportAmendmentReconciliationCounterpartyAttestation(ctx, cellID, comparisonKey, secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationSpec{
		stage:                  "attest_federation_incident_report_amendment_reconciliation_correction",
		attestation:            SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationCorrect,
		status:                 SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusCorrected,
		actorDID:               req.ActorDID,
		reason:                 req.Reason,
		counterpartyReference:  req.CounterpartyReference,
		counterpartySnapshotID: req.CounterpartySnapshotID,
		metadata:               req.Metadata,
	})
}

func (s *Service) AttestFederationIncidentReportAmendmentReconciliationResolution(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentReportAmendmentReconciliationResolutionAttestationRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentReportAmendmentReconciliationCounterpartyAttestation(ctx, cellID, comparisonKey, secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationSpec{
		stage:                 "attest_federation_incident_report_amendment_reconciliation_resolution",
		attestation:           SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationResolve,
		status:                SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved,
		actorDID:              req.ActorDID,
		reason:                req.Reason,
		counterpartyReference: req.CounterpartyReference,
		metadata:              req.Metadata,
	})
}

func (s *Service) ListFederationIncidentReportAmendmentReconciliationCounterpartyAttestations(_ context.Context, filter SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter) ([]SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter(record, filter) {
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

func (s *Service) applyFederationIncidentReportAmendmentReconciliationCounterpartyAttestation(ctx context.Context, cellID string, comparisonKey string, spec secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationSpec) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-attestation: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationIncidentReportAmendmentReconciliationSummaryByKey(run, comparisonKey)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(spec.actorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-attestation: %w: actor %q is not permitted to coordinate reconciliation %q", ErrPolicyDenied, actorDID, comparisonKey)
	}
	reviewStatus := secureCellFederationIncidentReportAmendmentReconciliationEffectiveReviewStatus(summary)
	if reviewStatus != SecureCellFederationIncidentReportReviewStatusDisputed {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-attestation: reconciliation %q must be disputed before counterparty coordination can be attested", comparisonKey)
	}
	latest := secureCellLatestFederationIncidentReportAmendmentReconciliationCounterpartyAttestation(run, summary.ComparisonKey)
	switch spec.attestation {
	case SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationAcknowledge:
		if latest != nil && latest.AttestationStatus == SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusAcknowledged {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-attestation: reconciliation %q is already acknowledged by the counterparty", comparisonKey)
		}
		if latest != nil && (latest.AttestationStatus == SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusCorrected || latest.AttestationStatus == SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved) {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-attestation: reconciliation %q already advanced beyond acknowledgement", comparisonKey)
		}
	case SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationCorrect:
		if latest != nil && latest.AttestationStatus == SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-attestation: reconciliation %q is already resolved by the counterparty", comparisonKey)
		}
		if strings.TrimSpace(spec.counterpartySnapshotID) == "" {
			spec.counterpartySnapshotID = strings.TrimSpace(summary.CounterpartySnapshotID)
		}
		if strings.TrimSpace(spec.counterpartySnapshotID) == "" {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-attestation: counterparty amendment evidence is required to attest a correction for %q", comparisonKey)
		}
	case SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationResolve:
		if latest == nil || (latest.AttestationStatus != SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusAcknowledged && latest.AttestationStatus != SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusCorrected) {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-attestation: reconciliation %q must be acknowledged or corrected before resolution is attested", comparisonKey)
		}
		if latest.AttestationStatus == SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-attestation: reconciliation %q is already resolved by the counterparty", comparisonKey)
		}
	default:
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-attestation: unsupported attestation %q", spec.attestation)
	}

	counterpartySnapshotID := strings.TrimSpace(spec.counterpartySnapshotID)
	counterpartyBundleID := strings.TrimSpace(summary.CounterpartyBundleID)
	counterpartyReportID := strings.TrimSpace(summary.CounterpartyReportID)
	counterpartyResponseID := strings.TrimSpace(summary.CounterpartyResponseID)
	counterpartyAmendmentID := strings.TrimSpace(summary.CounterpartyAmendmentID)
	if counterpartySnapshotID != "" {
		if snapshot := secureCellLatestCounterpartyFederationIncidentReportAmendmentsByKey(run)[summary.ComparisonKey]; snapshot != nil && strings.EqualFold(strings.TrimSpace(snapshot.SnapshotID), counterpartySnapshotID) {
			counterpartyBundleID = strings.TrimSpace(snapshot.Bundle.ID)
			counterpartyReportID = strings.TrimSpace(snapshot.Bundle.Amendment.ReportID)
			counterpartyResponseID = strings.TrimSpace(snapshot.Bundle.Amendment.ResponseID)
			counterpartyAmendmentID = strings.TrimSpace(snapshot.Bundle.Amendment.ID)
		}
	}

	receipt, err := s.evaluateStage(ctx, run.request, spec.stage, lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                   summary.OrganizationID,
		"federation_incident_id":                                                       summary.IncidentID,
		"federation_incident_report_amendment_reconciliation_key":                      summary.ComparisonKey,
		"federation_incident_report_amendment_reconciliation_status":                   string(summary.Status),
		"federation_incident_report_amendment_reconciliation_review":                   string(reviewStatus),
		"federation_incident_report_amendment_reconciliation_counterparty_attestation": string(spec.attestation),
		"federation_incident_report_amendment_reconciliation_attestation_status":       string(spec.status),
		"federation_incident_report_id":                                                summary.LocalReportID,
		"federation_incident_response_id":                                              summary.LocalResponseID,
		"federation_incident_report_amendment_id":                                      summary.LocalAmendmentID,
		"federation_counterparty_incident_report_amendment_snapshot_id":                counterpartySnapshotID,
		"federation_counterparty_incident_report_amendment_bundle_id":                  counterpartyBundleID,
		"federation_counterparty_incident_report_id":                                   counterpartyReportID,
		"federation_counterparty_incident_response_id":                                 counterpartyResponseID,
		"federation_counterparty_incident_report_amendment_id":                         counterpartyAmendmentID,
		"federation_incident_report_amendment_reconciliation_counterparty_reference":   strings.TrimSpace(spec.counterpartyReference),
		"transition_reason": strings.TrimSpace(spec.reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-attestation: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationTransitionSuffix(spec.attestation), summary.ComparisonKey),
		Action:           "secure_cell." + secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationTransitionSuffix(spec.attestation),
		Actor:            actorDID,
		TargetType:       "federation_incident_report_amendment_reconciliation",
		TargetDID:        summary.ComparisonKey,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(spec.reason),
		Metadata: mergeStringMaps(spec.metadata, map[string]string{
			"federation_organization_id":                                                   summary.OrganizationID,
			"federation_sponsor_of_record":                                                 summary.SponsorOfRecord,
			"federation_organization_name":                                                 summary.OrganizationName,
			"federation_incident_id":                                                       summary.IncidentID,
			"federation_incident_report_amendment_reconciliation_key":                      summary.ComparisonKey,
			"federation_incident_report_amendment_reconciliation_status":                   string(summary.Status),
			"federation_incident_report_amendment_reconciliation_review":                   string(reviewStatus),
			"federation_incident_report_amendment_reconciliation_counterparty_attestation": string(spec.attestation),
			"federation_incident_report_amendment_reconciliation_attestation_status":       string(spec.status),
			"federation_incident_report_id":                                                summary.LocalReportID,
			"federation_incident_response_id":                                              summary.LocalResponseID,
			"federation_incident_report_amendment_id":                                      summary.LocalAmendmentID,
			"federation_counterparty_incident_report_amendment_snapshot_id":                counterpartySnapshotID,
			"federation_counterparty_incident_report_amendment_bundle_id":                  counterpartyBundleID,
			"federation_counterparty_incident_report_id":                                   counterpartyReportID,
			"federation_counterparty_incident_response_id":                                 counterpartyResponseID,
			"federation_counterparty_incident_report_amendment_id":                         counterpartyAmendmentID,
			"federation_incident_report_amendment_reconciliation_counterparty_reference":   strings.TrimSpace(spec.counterpartyReference),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListOverdueFederationIncidentReportAmendmentReconciliations(_ context.Context, filter SecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter) ([]SecureCellOverdueFederationIncidentReportAmendmentReconciliation, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	cellID := strings.TrimSpace(filter.CellID)
	organizationID := strings.TrimSpace(filter.OrganizationID)
	incidentID := strings.TrimSpace(filter.IncidentID)
	comparisonKey := strings.TrimSpace(filter.ComparisonKey)

	items := make([]SecureCellOverdueFederationIncidentReportAmendmentReconciliation, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		for _, reconciliation := range secureCellFederationIncidentReportAmendmentReconciliationsFromRun(run) {
			if organizationID != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.OrganizationID), organizationID) {
				continue
			}
			if incidentID != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.IncidentID), incidentID) {
				continue
			}
			if comparisonKey != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.ComparisonKey), comparisonKey) {
				continue
			}
			if filter.Status != "" && reconciliation.Status != filter.Status {
				continue
			}
			overdue, ok := secureCellFederationIncidentReportAmendmentReconciliationOverdueStateForAt(reconciliation, at)
			if !ok {
				continue
			}
			if filter.ReviewStatus != "" && overdue.reviewStatus != filter.ReviewStatus {
				continue
			}
			if filter.AttestationStatus != "" && overdue.attestationStatus != filter.AttestationStatus {
				continue
			}
			items = append(items, SecureCellOverdueFederationIncidentReportAmendmentReconciliation{
				CellID:                       reconciliation.CellID,
				CellName:                     reconciliation.CellName,
				Jurisdiction:                 reconciliation.Jurisdiction,
				CellStatus:                   reconciliation.CellStatus,
				OrganizationID:               reconciliation.OrganizationID,
				SponsorOfRecord:              reconciliation.SponsorOfRecord,
				OrganizationName:             reconciliation.OrganizationName,
				ComparisonKey:                reconciliation.ComparisonKey,
				IncidentID:                   reconciliation.IncidentID,
				Regulator:                    reconciliation.Regulator,
				Framework:                    reconciliation.Framework,
				ReportType:                   reconciliation.ReportType,
				ReportingParty:               reconciliation.ReportingParty,
				Status:                       reconciliation.Status,
				ReviewStatus:                 overdue.reviewStatus,
				AttestationStatus:            overdue.attestationStatus,
				AutomationAction:             overdue.automationAction,
				OverdueReason:                overdue.overdueReason,
				DueAt:                        overdue.dueAt,
				OverdueSeconds:               int64(at.Sub(overdue.dueAt).Seconds()),
				ReviewDueAt:                  cloneTimePtr(overdue.reviewDueAt),
				CounterpartyAcknowledgeDueAt: cloneTimePtr(overdue.counterpartyAckDueAt),
				ResolutionDueAt:              cloneTimePtr(overdue.resolutionDueAt),
				LocalAmendmentID:             reconciliation.LocalAmendmentID,
				CounterpartyAmendmentID:      reconciliation.CounterpartyAmendmentID,
				LastReviewedBy:               reconciliation.LastReviewedBy,
				LastReviewedAt:               cloneTimePtr(reconciliation.LastReviewedAt),
				LastCounterpartyAttestedBy:   reconciliation.LastCounterpartyAttestedBy,
				LastCounterpartyAttestedAt:   cloneTimePtr(reconciliation.LastCounterpartyAttestedAt),
				Divergences:                  append([]string(nil), reconciliation.Divergences...),
				UpdatedAt:                    secureCellFederationIncidentReportAmendmentReconciliationUpdatedAt(reconciliation),
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt.Equal(items[j].DueAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].ComparisonKey < items[j].ComparisonKey
			}
			return items[i].CellID < items[j].CellID
		}
		return items[i].DueAt.Before(items[j].DueAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListFederationIncidentReportAmendmentReconciliationAutomationActions(_ context.Context, filter SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter) ([]SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	cellID := strings.TrimSpace(filter.CellID)
	organizationID := strings.TrimSpace(filter.OrganizationID)
	incidentID := strings.TrimSpace(filter.IncidentID)
	comparisonKey := strings.TrimSpace(filter.ComparisonKey)
	contractID := strings.TrimSpace(filter.ContractID)
	action := strings.TrimSpace(filter.Action)
	var since time.Time
	if filter.Since != nil && !filter.Since.IsZero() {
		since = filter.Since.UTC()
	}
	var until time.Time
	if filter.Until != nil && !filter.Until.IsZero() {
		until = filter.Until.UTC()
	}

	items := make([]SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		for _, transition := range run.result.Transitions {
			if !secureCellTransitionAutomatedFederationIncidentReportAmendmentReconciliationAction(transition) {
				continue
			}
			if action != "" && !strings.EqualFold(strings.TrimSpace(transition.Action), action) {
				continue
			}
			if organizationID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_organization_id"]), organizationID) {
				continue
			}
			if incidentID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_id"]), incidentID) {
				continue
			}
			if comparisonKey != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_report_amendment_reconciliation_comparison_key"]), comparisonKey) {
				continue
			}
			if contractID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_contract_id"]), contractID) {
				continue
			}
			occurredAt := transition.OccurredAt.UTC()
			if !since.IsZero() && occurredAt.Before(since) {
				continue
			}
			if !until.IsZero() && occurredAt.After(until) {
				continue
			}
			items = append(items, SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionRecord{
				CellID:                  run.result.CellID,
				CellName:                run.result.Name,
				Jurisdiction:            run.request.Jurisdiction,
				CellStatus:              run.result.Status,
				OrganizationID:          strings.TrimSpace(transition.Metadata["federation_organization_id"]),
				SponsorOfRecord:         strings.TrimSpace(transition.Metadata["federation_sponsor_of_record"]),
				ComparisonKey:           strings.TrimSpace(transition.Metadata["federation_incident_report_amendment_reconciliation_comparison_key"]),
				IncidentID:              strings.TrimSpace(transition.Metadata["federation_incident_id"]),
				Regulator:               strings.TrimSpace(transition.Metadata["federation_regulator"]),
				ReconciliationStatus:    SecureCellFederationIncidentReportAmendmentReconciliationStatus(strings.TrimSpace(transition.Metadata["federation_incident_report_amendment_reconciliation_status"])),
				ReviewStatusBefore:      SecureCellFederationIncidentReportReviewStatus(strings.TrimSpace(transition.Metadata["federation_incident_report_amendment_reconciliation_review_status_before"])),
				ReviewStatusAfter:       SecureCellFederationIncidentReportReviewStatus(strings.TrimSpace(transition.Metadata["federation_incident_report_amendment_reconciliation_review_status_after"])),
				AttestationStatusBefore: SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus(strings.TrimSpace(transition.Metadata["federation_incident_report_amendment_reconciliation_attestation_status_before"])),
				AttestationStatusAfter:  SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus(strings.TrimSpace(transition.Metadata["federation_incident_report_amendment_reconciliation_attestation_status_after"])),
				ContractID:              strings.TrimSpace(transition.Metadata["federation_contract_id"]),
				ContractStatusBefore:    SecureCellFederationContractStatus(strings.TrimSpace(transition.Metadata["federation_contract_status_before"])),
				ContractStatusAfter:     SecureCellFederationContractStatus(strings.TrimSpace(transition.Metadata["federation_contract_status_after"])),
				Action:                  transition.Action,
				Trigger:                 strings.TrimSpace(transition.Metadata["federation_incident_report_amendment_reconciliation_trigger"]),
				DueAt:                   parseSecureCellTransitionDueAtWithKey(transition.Metadata, "federation_incident_report_amendment_reconciliation_due_at"),
				Actor:                   transition.Actor,
				AutomatedActor:          strings.TrimSpace(transition.Metadata["automated_actor"]),
				Reason:                  transition.Reason,
				TransitionID:            transition.ID,
				OccurredAt:              occurredAt,
				Metadata:                cloneStringMap(transition.Metadata),
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].TransitionID > items[j].TransitionID
			}
			return items[i].CellID < items[j].CellID
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) SweepFederationIncidentReportAmendmentReconciliations(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationIncidentReportAmendmentReconciliationSweepResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-automation: service is required")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	s.mu.RLock()
	cellIDs := make([]string, 0, len(s.runs))
	for cellID := range s.runs {
		cellIDs = append(cellIDs, cellID)
	}
	s.mu.RUnlock()
	sort.Strings(cellIDs)

	report := &SecureCellFederationIncidentReportAmendmentReconciliationSweepResult{
		At:           at.UTC(),
		CellsScanned: len(cellIDs),
	}
	if len(cellIDs) == 0 {
		return report, nil
	}

	mutated := make(map[string]struct{})
	autoDisputed := make(map[string]struct{})
	escalated := make(map[string]struct{})
	suspendedOrgs := make(map[string]struct{})
	for _, cellID := range cellIDs {
		run, err := s.getRun(cellID)
		if err != nil {
			return nil, err
		}
		reconciliations := secureCellFederationIncidentReportAmendmentReconciliationsFromRun(run)
		report.ReconciliationsScanned += len(reconciliations)
		for _, reconciliation := range reconciliations {
			overdue, ok := secureCellFederationIncidentReportAmendmentReconciliationOverdueStateForAt(reconciliation, at)
			if !ok {
				continue
			}
			baseMetadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
				"federation_incident_report_amendment_reconciliation_sweep_mode":                "automated",
				"federation_incident_report_amendment_reconciliation_action":                    overdue.automationAction,
				"federation_incident_report_amendment_reconciliation_trigger":                   secureCellFederationIncidentReportAmendmentReconciliationTrigger(overdue.automationAction),
				"federation_incident_report_amendment_reconciliation_comparison_key":            reconciliation.ComparisonKey,
				"federation_incident_report_amendment_reconciliation_status":                    string(reconciliation.Status),
				"federation_incident_report_amendment_reconciliation_review_status_before":      string(overdue.reviewStatus),
				"federation_incident_report_amendment_reconciliation_attestation_status_before": string(overdue.attestationStatus),
				"federation_organization_id":                                                    reconciliation.OrganizationID,
				"federation_sponsor_of_record":                                                  reconciliation.SponsorOfRecord,
				"federation_incident_id":                                                        reconciliation.IncidentID,
				"federation_regulator":                                                          reconciliation.Regulator,
				"federation_incident_report_id":                                                 reconciliation.LocalReportID,
				"federation_incident_response_id":                                               reconciliation.LocalResponseID,
				"federation_incident_report_amendment_id":                                       reconciliation.LocalAmendmentID,
				"federation_counterparty_incident_report_amendment_id":                          reconciliation.CounterpartyAmendmentID,
			})
			if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
				baseMetadata["automated_actor"] = automatedActor
			}
			baseMetadata["federation_incident_report_amendment_reconciliation_due_at"] = overdue.dueAt.UTC().Format(time.RFC3339Nano)
			if overdue.reviewDueAt != nil && !overdue.reviewDueAt.IsZero() {
				baseMetadata["federation_incident_report_amendment_reconciliation_review_due_at"] = overdue.reviewDueAt.UTC().Format(time.RFC3339Nano)
			}
			if overdue.counterpartyAckDueAt != nil && !overdue.counterpartyAckDueAt.IsZero() {
				baseMetadata["federation_incident_report_amendment_reconciliation_counterparty_ack_due_at"] = overdue.counterpartyAckDueAt.UTC().Format(time.RFC3339Nano)
			}
			if overdue.resolutionDueAt != nil && !overdue.resolutionDueAt.IsZero() {
				baseMetadata["federation_incident_report_amendment_reconciliation_resolution_due_at"] = overdue.resolutionDueAt.UTC().Format(time.RFC3339Nano)
			}

			switch overdue.automationAction {
			case "auto_dispute":
				key := strings.TrimSpace(reconciliation.CellID) + "|" + strings.TrimSpace(reconciliation.ComparisonKey)
				if _, seen := autoDisputed[key]; seen {
					continue
				}
				if _, err := s.DisputeFederationIncidentReportAmendmentReconciliation(ctx, cellID, reconciliation.ComparisonKey, SecureCellFederationIncidentReportAmendmentReconciliationDisputeRequest{
					ActorDID:    run.request.OwnerIdentity.AgentID(),
					Reason:      firstNonEmpty(strings.TrimSpace(lifecycle.Reason), overdue.overdueReason),
					Divergences: append([]string(nil), reconciliation.Divergences...),
					Metadata: mergeStringMaps(baseMetadata, map[string]string{
						"federation_incident_report_amendment_reconciliation_review_status_after":      string(SecureCellFederationIncidentReportReviewStatusDisputed),
						"federation_incident_report_amendment_reconciliation_attestation_status_after": string(SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested),
					}),
				}); err != nil {
					return nil, err
				}
				autoDisputed[key] = struct{}{}
				report.ReconciliationsAutoDisputed++
				mutated[cellID] = struct{}{}
			case "escalate_counterparty":
				key := strings.TrimSpace(reconciliation.CellID) + "|" + strings.TrimSpace(reconciliation.ComparisonKey)
				if _, seen := escalated[key]; seen {
					continue
				}
				if _, err := s.recordFederationIncidentReportAmendmentReconciliationEscalation(ctx, cellID, reconciliation.ComparisonKey, SecureCellLifecycleRequest{
					ActorDID: run.request.OwnerIdentity.AgentID(),
					Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), overdue.overdueReason),
					Metadata: mergeStringMaps(baseMetadata, map[string]string{
						"federation_incident_report_amendment_reconciliation_review_status_after":      string(SecureCellFederationIncidentReportReviewStatusDisputed),
						"federation_incident_report_amendment_reconciliation_attestation_status_after": string(SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested),
					}),
				}); err != nil {
					return nil, err
				}
				escalated[key] = struct{}{}
				report.ReconciliationsEscalated++
				mutated[cellID] = struct{}{}
			case "suspend_contracts":
				orgKey := strings.TrimSpace(reconciliation.CellID) + "|" + strings.TrimSpace(reconciliation.OrganizationID)
				if _, seen := suspendedOrgs[orgKey]; seen {
					continue
				}
				activeContracts := activeFederationContractsForOrganization(run.result.FederationContracts, reconciliation.OrganizationID)
				if len(activeContracts) == 0 {
					continue
				}
				for _, contract := range activeContracts {
					if _, err := s.SuspendFederationContract(ctx, cellID, contract.ID, SecureCellLifecycleRequest{
						ActorDID: run.request.OwnerIdentity.AgentID(),
						Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), overdue.overdueReason),
						Metadata: mergeStringMaps(baseMetadata, map[string]string{
							"federation_contract_id":                                                       contract.ID,
							"federation_contract_status_before":                                            string(contract.Status),
							"federation_contract_status_after":                                             string(SecureCellFederationContractStatusSuspended),
							"federation_incident_report_amendment_reconciliation_review_status_after":      string(SecureCellFederationIncidentReportReviewStatusDisputed),
							"federation_incident_report_amendment_reconciliation_attestation_status_after": string(overdue.attestationStatus),
						}),
					}); err != nil {
						return nil, err
					}
					report.ContractsSuspended++
				}
				suspendedOrgs[orgKey] = struct{}{}
				mutated[cellID] = struct{}{}
			}
		}
	}
	report.CellsMutated = len(mutated)
	if len(mutated) > 0 {
		report.CellIDs = make([]string, 0, len(mutated))
		for cellID := range mutated {
			report.CellIDs = append(report.CellIDs, cellID)
		}
		sort.Strings(report.CellIDs)
	}
	return report, nil
}

func (s *Service) recordFederationIncidentReportAmendmentReconciliationEscalation(ctx context.Context, cellID string, comparisonKey string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationIncidentReportAmendmentReconciliationSummaryByKey(run, comparisonKey)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-automation: %w: actor %q is not permitted to escalate reconciliation %q", ErrPolicyDenied, actorDID, comparisonKey)
	}
	reviewStatus := secureCellFederationIncidentReportAmendmentReconciliationEffectiveReviewStatus(summary)
	attestationStatus := secureCellFederationIncidentReportAmendmentReconciliationEffectiveCounterpartyAttestationStatus(summary)
	receipt, err := s.evaluateStage(ctx, run.request, "escalate_federation_incident_report_amendment_reconciliation", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                             summary.OrganizationID,
		"federation_incident_id":                                                 summary.IncidentID,
		"federation_incident_report_amendment_reconciliation_key":                summary.ComparisonKey,
		"federation_incident_report_amendment_reconciliation_status":             string(summary.Status),
		"federation_incident_report_amendment_reconciliation_review":             string(reviewStatus),
		"federation_incident_report_amendment_reconciliation_attestation_status": string(attestationStatus),
		"federation_incident_report_id":                                          summary.LocalReportID,
		"federation_incident_response_id":                                        summary.LocalResponseID,
		"federation_incident_report_amendment_id":                                summary.LocalAmendmentID,
		"federation_counterparty_incident_report_amendment_snapshot_id":          summary.CounterpartySnapshotID,
		"federation_counterparty_incident_report_amendment_bundle_id":            summary.CounterpartyBundleID,
		"federation_counterparty_incident_report_id":                             summary.CounterpartyReportID,
		"federation_counterparty_incident_response_id":                           summary.CounterpartyResponseID,
		"federation_counterparty_incident_report_amendment_id":                   summary.CounterpartyAmendmentID,
		"transition_reason":                                                      strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation-automation: %w", ErrPolicyDenied)
	}
	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_report_amendment_reconciliation_escalated", summary.ComparisonKey),
		Action:           "secure_cell.federation_incident_report_amendment_reconciliation_escalated",
		Actor:            actorDID,
		TargetType:       "federation_incident_report_amendment_reconciliation",
		TargetDID:        summary.ComparisonKey,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(lifecycle.Reason),
		Metadata: mergeStringMaps(lifecycle.Metadata, map[string]string{
			"federation_organization_id":                                             summary.OrganizationID,
			"federation_sponsor_of_record":                                           summary.SponsorOfRecord,
			"federation_organization_name":                                           summary.OrganizationName,
			"federation_incident_id":                                                 summary.IncidentID,
			"federation_incident_report_amendment_reconciliation_key":                summary.ComparisonKey,
			"federation_incident_report_amendment_reconciliation_status":             string(summary.Status),
			"federation_incident_report_amendment_reconciliation_review":             string(reviewStatus),
			"federation_incident_report_amendment_reconciliation_attestation_status": string(attestationStatus),
			"federation_incident_report_id":                                          summary.LocalReportID,
			"federation_incident_response_id":                                        summary.LocalResponseID,
			"federation_incident_report_amendment_id":                                summary.LocalAmendmentID,
			"federation_counterparty_incident_report_amendment_snapshot_id":          summary.CounterpartySnapshotID,
			"federation_counterparty_incident_report_amendment_bundle_id":            summary.CounterpartyBundleID,
			"federation_counterparty_incident_report_id":                             summary.CounterpartyReportID,
			"federation_counterparty_incident_response_id":                           summary.CounterpartyResponseID,
			"federation_counterparty_incident_report_amendment_id":                   summary.CounterpartyAmendmentID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationIncidentReportAmendmentReconciliationActionOrAttestationRequiresGovernedReview(item SecureCellFederationIncidentReportAmendmentReconciliationSummary) bool {
	if item.Status != "" && item.Status != SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned {
		return true
	}
	if item.ReviewActionCount > 0 {
		return true
	}
	if item.LastReviewedAt != nil && !item.LastReviewedAt.IsZero() {
		return true
	}
	if item.CounterpartyAttestationCount > 0 {
		return true
	}
	if item.LastCounterpartyAttestedAt != nil && !item.LastCounterpartyAttestedAt.IsZero() {
		return true
	}
	if item.ReviewStatus != "" && item.ReviewStatus != SecureCellFederationIncidentReportReviewStatusUnreviewed {
		return true
	}
	if item.CounterpartyAttestationStatus != "" && item.CounterpartyAttestationStatus != SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested {
		return true
	}
	return false
}

func secureCellFederationIncidentReportAmendmentReconciliationBaselineAt(item SecureCellFederationIncidentReportAmendmentReconciliationSummary) *time.Time {
	var baseline *time.Time
	for _, candidate := range []*time.Time{item.LocalUpdatedAt, item.CounterpartyReceivedAt, item.CounterpartyGeneratedAt} {
		if candidate == nil || candidate.IsZero() {
			continue
		}
		if baseline == nil || candidate.UTC().After(baseline.UTC()) {
			value := candidate.UTC()
			baseline = &value
		}
	}
	return baseline
}

func secureCellFederationIncidentReportAmendmentReconciliationEffectiveReviewStatus(item SecureCellFederationIncidentReportAmendmentReconciliationSummary) SecureCellFederationIncidentReportReviewStatus {
	if !secureCellFederationIncidentReportAmendmentReconciliationActionOrAttestationRequiresGovernedReview(item) {
		return item.ReviewStatus
	}
	baseline := secureCellFederationIncidentReportAmendmentReconciliationBaselineAt(item)
	if baseline != nil && (item.LastReviewedAt == nil || item.LastReviewedAt.Before(*baseline)) {
		return SecureCellFederationIncidentReportReviewStatusUnreviewed
	}
	if item.ReviewStatus != "" {
		return item.ReviewStatus
	}
	return SecureCellFederationIncidentReportReviewStatusUnreviewed
}

func secureCellFederationIncidentReportAmendmentReconciliationEffectiveCounterpartyAttestationStatus(item SecureCellFederationIncidentReportAmendmentReconciliationSummary) SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus {
	if secureCellFederationIncidentReportAmendmentReconciliationEffectiveReviewStatus(item) != SecureCellFederationIncidentReportReviewStatusDisputed {
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested
	}
	if item.LastCounterpartyAttestedAt == nil || item.LastCounterpartyAttestedAt.IsZero() {
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested
	}
	if item.LastReviewedAt != nil && !item.LastReviewedAt.IsZero() && item.LastCounterpartyAttestedAt.Before(*item.LastReviewedAt) {
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested
	}
	if item.CounterpartyAttestationStatus != "" {
		return item.CounterpartyAttestationStatus
	}
	return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested
}

func secureCellFederationIncidentReportAmendmentReconciliationReviewDueAt(item SecureCellFederationIncidentReportAmendmentReconciliationSummary) *time.Time {
	if !secureCellFederationIncidentReportAmendmentReconciliationActionOrAttestationRequiresGovernedReview(item) {
		return nil
	}
	baseline := secureCellFederationIncidentReportAmendmentReconciliationBaselineAt(item)
	if baseline == nil {
		return nil
	}
	dueAt := baseline.Add(secureCellFederationIncidentReportAmendmentReconciliationReviewSLA)
	return &dueAt
}

func secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAcknowledgeDueAt(item SecureCellFederationIncidentReportAmendmentReconciliationSummary) *time.Time {
	if item.LastReviewedAt == nil || item.LastReviewedAt.IsZero() {
		return nil
	}
	if secureCellFederationIncidentReportAmendmentReconciliationEffectiveReviewStatus(item) != SecureCellFederationIncidentReportReviewStatusDisputed {
		return nil
	}
	if secureCellFederationIncidentReportAmendmentReconciliationEffectiveCounterpartyAttestationStatus(item) != SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested {
		return nil
	}
	dueAt := item.LastReviewedAt.Add(secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAckSLA)
	return &dueAt
}

func secureCellFederationIncidentReportAmendmentReconciliationResolutionDueAt(item SecureCellFederationIncidentReportAmendmentReconciliationSummary) *time.Time {
	if secureCellFederationIncidentReportAmendmentReconciliationEffectiveReviewStatus(item) != SecureCellFederationIncidentReportReviewStatusDisputed {
		return nil
	}
	status := secureCellFederationIncidentReportAmendmentReconciliationEffectiveCounterpartyAttestationStatus(item)
	if status == SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved {
		return nil
	}
	if item.LastCounterpartyAttestedAt != nil && !item.LastCounterpartyAttestedAt.IsZero() && (status == SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusAcknowledged || status == SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusCorrected) {
		dueAt := item.LastCounterpartyAttestedAt.Add(secureCellFederationIncidentReportAmendmentReconciliationResolutionSLA)
		return &dueAt
	}
	if item.LastReviewedAt != nil && !item.LastReviewedAt.IsZero() {
		dueAt := item.LastReviewedAt.Add(secureCellFederationIncidentReportAmendmentReconciliationResolutionSLA)
		return &dueAt
	}
	return nil
}

func secureCellFederationIncidentReportAmendmentReconciliationOverdueStateForAt(item SecureCellFederationIncidentReportAmendmentReconciliationSummary, at time.Time) (secureCellFederationIncidentReportAmendmentReconciliationOverdueState, bool) {
	if !secureCellFederationIncidentReportAmendmentReconciliationActionOrAttestationRequiresGovernedReview(item) {
		return secureCellFederationIncidentReportAmendmentReconciliationOverdueState{}, false
	}
	reviewStatus := secureCellFederationIncidentReportAmendmentReconciliationEffectiveReviewStatus(item)
	attestationStatus := secureCellFederationIncidentReportAmendmentReconciliationEffectiveCounterpartyAttestationStatus(item)
	reviewDueAt := secureCellFederationIncidentReportAmendmentReconciliationReviewDueAt(item)
	if reviewStatus == SecureCellFederationIncidentReportReviewStatusUnreviewed && reviewDueAt != nil && !reviewDueAt.After(at) {
		return secureCellFederationIncidentReportAmendmentReconciliationOverdueState{
			reviewStatus:      reviewStatus,
			attestationStatus: attestationStatus,
			automationAction:  "auto_dispute",
			overdueReason:     "incident report amendment reconciliation review deadline reached",
			dueAt:             reviewDueAt.UTC(),
			reviewDueAt:       cloneTimePtr(reviewDueAt),
		}, true
	}
	counterpartyAckDueAt := secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAcknowledgeDueAt(item)
	if reviewStatus == SecureCellFederationIncidentReportReviewStatusDisputed && attestationStatus == SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested && counterpartyAckDueAt != nil && !counterpartyAckDueAt.After(at) {
		return secureCellFederationIncidentReportAmendmentReconciliationOverdueState{
			reviewStatus:         reviewStatus,
			attestationStatus:    attestationStatus,
			automationAction:     "escalate_counterparty",
			overdueReason:        "counterparty amendment dispute acknowledgement deadline reached",
			dueAt:                counterpartyAckDueAt.UTC(),
			reviewDueAt:          cloneTimePtr(reviewDueAt),
			counterpartyAckDueAt: cloneTimePtr(counterpartyAckDueAt),
		}, true
	}
	resolutionDueAt := secureCellFederationIncidentReportAmendmentReconciliationResolutionDueAt(item)
	if reviewStatus == SecureCellFederationIncidentReportReviewStatusDisputed && attestationStatus != SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved && resolutionDueAt != nil && !resolutionDueAt.After(at) {
		return secureCellFederationIncidentReportAmendmentReconciliationOverdueState{
			reviewStatus:         reviewStatus,
			attestationStatus:    attestationStatus,
			automationAction:     "suspend_contracts",
			overdueReason:        "incident report amendment reconciliation resolution deadline reached",
			dueAt:                resolutionDueAt.UTC(),
			reviewDueAt:          cloneTimePtr(reviewDueAt),
			counterpartyAckDueAt: cloneTimePtr(counterpartyAckDueAt),
			resolutionDueAt:      cloneTimePtr(resolutionDueAt),
		}, true
	}
	return secureCellFederationIncidentReportAmendmentReconciliationOverdueState{}, false
}

func secureCellFederationIncidentReportAmendmentReconciliationTrigger(action string) string {
	switch strings.TrimSpace(action) {
	case "auto_dispute":
		return "review_due"
	case "escalate_counterparty":
		return "counterparty_ack_due"
	case "suspend_contracts":
		return "resolution_due"
	default:
		return ""
	}
}

func secureCellTransitionAutomatedFederationIncidentReportAmendmentReconciliationAction(transition SecureCellTransition) bool {
	if strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_report_amendment_reconciliation_sweep_mode"]), "automated") {
		return true
	}
	return false
}

func secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord, bool) {
	attestationType, ok := secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationTypeFromTransitionAction(transition.Action)
	if !ok {
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord{}, false
	}
	meta := cloneStringMap(transition.Metadata)
	record := SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord{
		CellID:                  safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:              safeSecureCellStatus(run),
		Jurisdiction:            safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:          strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:         strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:        strings.TrimSpace(meta["federation_organization_name"]),
		ComparisonKey:           strings.TrimSpace(meta["federation_incident_report_amendment_reconciliation_key"]),
		IncidentID:              strings.TrimSpace(meta["federation_incident_id"]),
		LocalReportID:           strings.TrimSpace(meta["federation_incident_report_id"]),
		LocalResponseID:         strings.TrimSpace(meta["federation_incident_response_id"]),
		LocalAmendmentID:        strings.TrimSpace(meta["federation_incident_report_amendment_id"]),
		CounterpartySnapshotID:  strings.TrimSpace(meta["federation_counterparty_incident_report_amendment_snapshot_id"]),
		CounterpartyBundleID:    strings.TrimSpace(meta["federation_counterparty_incident_report_amendment_bundle_id"]),
		CounterpartyReportID:    strings.TrimSpace(meta["federation_counterparty_incident_report_id"]),
		CounterpartyResponseID:  strings.TrimSpace(meta["federation_counterparty_incident_response_id"]),
		CounterpartyAmendmentID: strings.TrimSpace(meta["federation_counterparty_incident_report_amendment_id"]),
		ReconciliationStatus:    SecureCellFederationIncidentReportAmendmentReconciliationStatus(strings.TrimSpace(meta["federation_incident_report_amendment_reconciliation_status"])),
		ReviewStatus:            SecureCellFederationIncidentReportReviewStatus(strings.TrimSpace(meta["federation_incident_report_amendment_reconciliation_review"])),
		Attestation:             attestationType,
		AttestationStatus:       SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus(strings.TrimSpace(meta["federation_incident_report_amendment_reconciliation_attestation_status"])),
		TransitionID:            strings.TrimSpace(transition.ID),
		ActorDID:                strings.TrimSpace(transition.Actor),
		CounterpartyReference:   strings.TrimSpace(meta["federation_incident_report_amendment_reconciliation_counterparty_reference"]),
		Reason:                  firstNonEmpty(strings.TrimSpace(transition.Reason), strings.TrimSpace(meta["transition_reason"])),
		Metadata:                meta,
		OccurredAt:              transition.OccurredAt.UTC(),
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
	if record.AttestationStatus == "" {
		record.AttestationStatus = secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusFromType(attestationType)
	}
	return record, true
}

func matchesSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter(item SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord, filter SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(item.OrganizationID, strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(item.IncidentID, strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.ComparisonKey != "" && !strings.EqualFold(item.ComparisonKey, strings.TrimSpace(filter.ComparisonKey)) {
		return false
	}
	if filter.Attestation != "" && item.Attestation != filter.Attestation {
		return false
	}
	if filter.AttestationStatus != "" && item.AttestationStatus != filter.AttestationStatus {
		return false
	}
	if filter.ActorDID != "" && !strings.EqualFold(item.ActorDID, strings.TrimSpace(filter.ActorDID)) {
		return false
	}
	return true
}

func secureCellLatestFederationIncidentReportAmendmentReconciliationCounterpartyAttestation(run *secureCellRun, comparisonKey string) *SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord {
	if run == nil || run.result == nil {
		return nil
	}
	comparisonKey = strings.TrimSpace(comparisonKey)
	var latest *SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFromTransition(run, transition)
		if !ok || !strings.EqualFold(record.ComparisonKey, comparisonKey) {
			continue
		}
		recordCopy := record
		if latest == nil || recordCopy.OccurredAt.After(latest.OccurredAt) || (recordCopy.OccurredAt.Equal(latest.OccurredAt) && recordCopy.TransitionID > latest.TransitionID) {
			latest = &recordCopy
		}
	}
	return latest
}

func secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationState(run *secureCellRun, comparisonKey string) (SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus, string, *time.Time, int) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested, "", nil, 0
	}
	status := SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested
	var actor string
	var when *time.Time
	count := 0
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFromTransition(run, transition)
		if !ok || !strings.EqualFold(record.ComparisonKey, comparisonKey) {
			continue
		}
		count++
		status = record.AttestationStatus
		actor = record.ActorDID
		occurredAt := record.OccurredAt.UTC()
		when = &occurredAt
	}
	return status, actor, cloneTimePtr(when), count
}

func secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationTypeFromTransitionAction(action string) (SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_report_amendment_reconciliation_dispute_acknowledged":
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationAcknowledge, true
	case "secure_cell.federation_incident_report_amendment_reconciliation_correction_attested":
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationCorrect, true
	case "secure_cell.federation_incident_report_amendment_reconciliation_resolution_attested":
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationResolve, true
	default:
		return "", false
	}
}

func secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusFromType(attestation SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType) SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus {
	switch attestation {
	case SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationAcknowledge:
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusAcknowledged
	case SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationCorrect:
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusCorrected
	case SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationResolve:
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved
	default:
		return SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested
	}
}

func secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationTransitionSuffix(attestation SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType) string {
	switch attestation {
	case SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationAcknowledge:
		return "federation_incident_report_amendment_reconciliation_dispute_acknowledged"
	case SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationCorrect:
		return "federation_incident_report_amendment_reconciliation_correction_attested"
	case SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationResolve:
		return "federation_incident_report_amendment_reconciliation_resolution_attested"
	default:
		return "federation_incident_report_amendment_reconciliation_counterparty_attested"
	}
}
