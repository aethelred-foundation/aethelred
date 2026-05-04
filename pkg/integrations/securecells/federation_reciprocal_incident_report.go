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

// SecureCellFederationCounterpartyIncidentReportStatus tracks verification and
// freshness posture for one imported counterparty incident report bundle.
type SecureCellFederationCounterpartyIncidentReportStatus string

const (
	SecureCellFederationCounterpartyIncidentReportStatusVerified SecureCellFederationCounterpartyIncidentReportStatus = "verified"
	SecureCellFederationCounterpartyIncidentReportStatusStale    SecureCellFederationCounterpartyIncidentReportStatus = "stale"
	SecureCellFederationCounterpartyIncidentReportStatusExpired  SecureCellFederationCounterpartyIncidentReportStatus = "expired"
	SecureCellFederationCounterpartyIncidentReportStatusInvalid  SecureCellFederationCounterpartyIncidentReportStatus = "invalid"
)

// SecureCellFederationCounterpartyIncidentReportSnapshot persists one imported
// signed counterparty incident report bundle in the secure-cell runtime trace.
type SecureCellFederationCounterpartyIncidentReportSnapshot struct {
	SnapshotID          string                                               `json:"snapshot_id"`
	OrganizationID      string                                               `json:"organization_id"`
	ContractIDs         []string                                             `json:"contract_ids,omitempty"`
	Bundle              SecureCellFederationIncidentReportBundle             `json:"bundle"`
	Status              SecureCellFederationCounterpartyIncidentReportStatus `json:"status"`
	Verified            bool                                                 `json:"verified"`
	VerificationMessage string                                               `json:"verification_message,omitempty"`
	Signer              string                                               `json:"signer,omitempty"`
	ReceivedBy          string                                               `json:"received_by,omitempty"`
	ReceivedAt          time.Time                                            `json:"received_at"`
	Metadata            map[string]string                                    `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyIncidentReportFilter narrows operator
// queries across imported counterparty incident report bundles.
type SecureCellFederationCounterpartyIncidentReportFilter struct {
	CellID               string                                                 `json:"cell_id,omitempty"`
	OrganizationID       string                                                 `json:"organization_id,omitempty"`
	ContractID           string                                                 `json:"contract_id,omitempty"`
	IncidentID           string                                                 `json:"incident_id,omitempty"`
	ResponseID           string                                                 `json:"response_id,omitempty"`
	ReportID             string                                                 `json:"report_id,omitempty"`
	Status               SecureCellFederationCounterpartyIncidentReportStatus   `json:"status,omitempty"`
	ReconciliationStatus SecureCellFederationIncidentReportReconciliationStatus `json:"reconciliation_status,omitempty"`
	Signer               string                                                 `json:"signer,omitempty"`
	Regulator            string                                                 `json:"regulator,omitempty"`
	Limit                int                                                    `json:"limit,omitempty"`
}

// SecureCellFederationCounterpartyIncidentReportSummary is the operator-facing
// summary of one imported counterparty incident report bundle.
type SecureCellFederationCounterpartyIncidentReportSummary struct {
	CellID                        string                                                 `json:"cell_id"`
	CellName                      string                                                 `json:"cell_name,omitempty"`
	CellStatus                    SecureCellStatus                                       `json:"cell_status"`
	Jurisdiction                  string                                                 `json:"jurisdiction,omitempty"`
	OrganizationID                string                                                 `json:"organization_id"`
	SponsorOfRecord               string                                                 `json:"sponsor_of_record,omitempty"`
	OrganizationName              string                                                 `json:"organization_name,omitempty"`
	SnapshotID                    string                                                 `json:"snapshot_id"`
	BundleID                      string                                                 `json:"bundle_id,omitempty"`
	BundleVersion                 string                                                 `json:"bundle_version,omitempty"`
	BundleName                    string                                                 `json:"bundle_name,omitempty"`
	Status                        SecureCellFederationCounterpartyIncidentReportStatus   `json:"status"`
	Verified                      bool                                                   `json:"verified"`
	Signer                        string                                                 `json:"signer,omitempty"`
	KeyID                         string                                                 `json:"key_id,omitempty"`
	ContractIDs                   []string                                               `json:"contract_ids,omitempty"`
	IncidentID                    string                                                 `json:"incident_id,omitempty"`
	ResponseID                    string                                                 `json:"response_id,omitempty"`
	ReportID                      string                                                 `json:"report_id,omitempty"`
	ReportingParty                SecureCellFederationIncidentResponseParty              `json:"reporting_party,omitempty"`
	Regulator                     string                                                 `json:"regulator,omitempty"`
	Framework                     string                                                 `json:"framework,omitempty"`
	ReportType                    string                                                 `json:"report_type,omitempty"`
	ReportStatus                  SecureCellFederationIncidentReportStatus               `json:"report_status,omitempty"`
	DueAt                         *time.Time                                             `json:"due_at,omitempty"`
	SubmissionReference           string                                                 `json:"submission_reference,omitempty"`
	AcknowledgementReference      string                                                 `json:"acknowledgement_reference,omitempty"`
	GeneratedAt                   time.Time                                              `json:"generated_at,omitempty"`
	ExpiresAt                     *time.Time                                             `json:"expires_at,omitempty"`
	ReceivedAt                    time.Time                                              `json:"received_at,omitempty"`
	ControlLedgerID               string                                                 `json:"control_ledger_id,omitempty"`
	ControlLedgerHash             string                                                 `json:"control_ledger_hash,omitempty"`
	PortablePackageHash           string                                                 `json:"portable_package_hash,omitempty"`
	PortablePackageSigned         bool                                                   `json:"portable_package_signed"`
	PortablePackageAnchored       bool                                                   `json:"portable_package_anchored"`
	VerificationMessage           string                                                 `json:"verification_message,omitempty"`
	MatchedLocalReportID          string                                                 `json:"matched_local_report_id,omitempty"`
	MatchedLocalResponseID        string                                                 `json:"matched_local_response_id,omitempty"`
	ReconciliationStatus          SecureCellFederationIncidentReportReconciliationStatus `json:"reconciliation_status,omitempty"`
	ReconciliationDivergenceCount int                                                    `json:"reconciliation_divergence_count"`
}

// SecureCellFederationIncidentReportBundleIntakeRequest ingests one signed
// counterparty incident report bundle into the secure-cell evidence chain.
type SecureCellFederationIncidentReportBundleIntakeRequest struct {
	ActorDID string                                    `json:"actor_did,omitempty"`
	Bundle   *SecureCellFederationIncidentReportBundle `json:"bundle,omitempty"`
	Reason   string                                    `json:"reason,omitempty"`
	Metadata map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportReconciliationStatus captures whether one
// local report obligation aligns with the imported counterparty report state.
type SecureCellFederationIncidentReportReconciliationStatus string

const (
	SecureCellFederationIncidentReportReconciliationStatusAligned             SecureCellFederationIncidentReportReconciliationStatus = "aligned"
	SecureCellFederationIncidentReportReconciliationStatusLocalOnly           SecureCellFederationIncidentReportReconciliationStatus = "local_only"
	SecureCellFederationIncidentReportReconciliationStatusCounterpartyOnly    SecureCellFederationIncidentReportReconciliationStatus = "counterparty_only"
	SecureCellFederationIncidentReportReconciliationStatusDivergent           SecureCellFederationIncidentReportReconciliationStatus = "divergent"
	SecureCellFederationIncidentReportReconciliationStatusCounterpartyInvalid SecureCellFederationIncidentReportReconciliationStatus = "counterparty_invalid"
	SecureCellFederationIncidentReportReconciliationStatusCounterpartyStale   SecureCellFederationIncidentReportReconciliationStatus = "counterparty_stale"
	SecureCellFederationIncidentReportReconciliationStatusCounterpartyExpired SecureCellFederationIncidentReportReconciliationStatus = "counterparty_expired"
)

// SecureCellFederationIncidentReportReconciliationFilter narrows operator
// queries across report-alignment summaries.
type SecureCellFederationIncidentReportReconciliationFilter struct {
	CellID         string                                                 `json:"cell_id,omitempty"`
	OrganizationID string                                                 `json:"organization_id,omitempty"`
	IncidentID     string                                                 `json:"incident_id,omitempty"`
	ComparisonKey  string                                                 `json:"comparison_key,omitempty"`
	Regulator      string                                                 `json:"regulator,omitempty"`
	ReportingParty SecureCellFederationIncidentResponseParty              `json:"reporting_party,omitempty"`
	Status         SecureCellFederationIncidentReportReconciliationStatus `json:"status,omitempty"`
	Limit          int                                                    `json:"limit,omitempty"`
}

// SecureCellFederationIncidentReportReconciliationSummary is the operator-
// facing alignment view across local and imported counterparty report state.
type SecureCellFederationIncidentReportReconciliationSummary struct {
	CellID                               string                                                 `json:"cell_id"`
	CellName                             string                                                 `json:"cell_name,omitempty"`
	Jurisdiction                         string                                                 `json:"jurisdiction,omitempty"`
	CellStatus                           SecureCellStatus                                       `json:"cell_status"`
	OrganizationID                       string                                                 `json:"organization_id"`
	SponsorOfRecord                      string                                                 `json:"sponsor_of_record,omitempty"`
	OrganizationName                     string                                                 `json:"organization_name,omitempty"`
	ComparisonKey                        string                                                 `json:"comparison_key"`
	IncidentID                           string                                                 `json:"incident_id,omitempty"`
	Regulator                            string                                                 `json:"regulator,omitempty"`
	Framework                            string                                                 `json:"framework,omitempty"`
	ReportType                           string                                                 `json:"report_type,omitempty"`
	ReportingParty                       SecureCellFederationIncidentResponseParty              `json:"reporting_party,omitempty"`
	Status                               SecureCellFederationIncidentReportReconciliationStatus `json:"status"`
	LocalReportID                        string                                                 `json:"local_report_id,omitempty"`
	LocalResponseID                      string                                                 `json:"local_response_id,omitempty"`
	LocalReportStatus                    SecureCellFederationIncidentReportStatus               `json:"local_report_status,omitempty"`
	LocalDueAt                           *time.Time                                             `json:"local_due_at,omitempty"`
	LocalUpdatedAt                       *time.Time                                             `json:"local_updated_at,omitempty"`
	LocalSubmissionReference             string                                                 `json:"local_submission_reference,omitempty"`
	LocalAcknowledgementReference        string                                                 `json:"local_acknowledgement_reference,omitempty"`
	CounterpartySnapshotID               string                                                 `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyBundleID                 string                                                 `json:"counterparty_bundle_id,omitempty"`
	CounterpartyReportID                 string                                                 `json:"counterparty_report_id,omitempty"`
	CounterpartyResponseID               string                                                 `json:"counterparty_response_id,omitempty"`
	CounterpartyBundleStatus             SecureCellFederationCounterpartyIncidentReportStatus   `json:"counterparty_bundle_status,omitempty"`
	CounterpartyReportStatus             SecureCellFederationIncidentReportStatus               `json:"counterparty_report_status,omitempty"`
	CounterpartyDueAt                    *time.Time                                             `json:"counterparty_due_at,omitempty"`
	CounterpartyGeneratedAt              *time.Time                                             `json:"counterparty_generated_at,omitempty"`
	CounterpartyReceivedAt               *time.Time                                             `json:"counterparty_received_at,omitempty"`
	CounterpartySubmissionReference      string                                                 `json:"counterparty_submission_reference,omitempty"`
	CounterpartyAcknowledgementReference string                                                 `json:"counterparty_acknowledgement_reference,omitempty"`
	ReviewStatus                         SecureCellFederationIncidentReportReviewStatus         `json:"review_status,omitempty"`
	LastReviewedBy                       string                                                 `json:"last_reviewed_by,omitempty"`
	LastReviewedAt                       *time.Time                                             `json:"last_reviewed_at,omitempty"`
	ReviewActionCount                    int                                                    `json:"review_action_count"`
	Divergences                          []string                                               `json:"divergences,omitempty"`
}

type secureCellFederationIncidentReportRef struct {
	Response *SecureCellFederationIncidentResponse
	Report   *SecureCellFederationIncidentReport
}

func (s *Service) IngestFederationIncidentReportBundle(ctx context.Context, cellID string, organizationID string, intake SecureCellFederationIncidentReportBundleIntakeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report: service is required")
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
		return nil, fmt.Errorf("securecells/federation-incident-report: bundle is required")
	}
	bundle := secureCellCloneFederationIncidentReportBundle(*intake.Bundle)
	actorDID := firstNonEmpty(strings.TrimSpace(intake.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w: actor %q is not permitted to intake incident report bundles", ErrPolicyDenied, actorDID)
	}

	verificationErr := VerifyFederationIncidentReportBundle(&bundle)
	if verificationErr == nil {
		verificationErr = secureCellValidateFederationIncidentReportBundleSemantics(&bundle, strings.TrimSpace(summary.OrganizationID))
	}
	status, verificationMessage, verified := secureCellFederationCounterpartyIncidentReportStatusAt(&bundle, verificationErr, time.Now().UTC())
	contractIDs := secureCellFederationContractIDs(bundle.Contracts)

	receipt, err := s.evaluateStage(ctx, run.request, "intake_federation_incident_report_bundle", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                           strings.TrimSpace(summary.OrganizationID),
		"federation_sponsor_of_record":                         strings.TrimSpace(summary.SponsorOfRecord),
		"federation_counterparty_incident_report_bundle_id":    strings.TrimSpace(bundle.ID),
		"federation_counterparty_incident_report_id":           strings.TrimSpace(bundle.Report.ID),
		"federation_counterparty_incident_response_id":         strings.TrimSpace(bundle.Report.ResponseID),
		"federation_counterparty_incident_id":                  strings.TrimSpace(bundle.Report.IncidentID),
		"federation_counterparty_incident_report_regulator":    strings.TrimSpace(bundle.Report.Regulator),
		"federation_counterparty_incident_report_status":       string(status),
		"federation_counterparty_incident_report_signer":       strings.TrimSpace(secureCellFederationIncidentReportBundleSignerName(&bundle)),
		"federation_counterparty_incident_report_contract_ids": strings.Join(contractIDs, ","),
		"transition_reason":                                    strings.TrimSpace(intake.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	snapshot := SecureCellFederationCounterpartyIncidentReportSnapshot{
		SnapshotID:          fmt.Sprintf("%s-federation-counterparty-incident-report-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", strings.TrimSpace(summary.OrganizationID), strings.TrimSpace(bundle.ID), now.Format(time.RFC3339Nano))))),
		OrganizationID:      strings.TrimSpace(summary.OrganizationID),
		ContractIDs:         append([]string(nil), contractIDs...),
		Bundle:              bundle,
		Status:              status,
		Verified:            verified,
		VerificationMessage: strings.TrimSpace(verificationMessage),
		Signer:              strings.TrimSpace(secureCellFederationIncidentReportBundleSignerName(&bundle)),
		ReceivedBy:          strings.TrimSpace(actorDID),
		ReceivedAt:          now,
		Metadata:            cloneStringMap(intake.Metadata),
	}
	run.result.FederationCounterpartyIncidentReports = append(run.result.FederationCounterpartyIncidentReports, snapshot)
	run.result.UpdatedAt = now
	reconciliation := secureCellFederationIncidentReportReconciliationForSnapshot(run, snapshot)

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_report_bundle_ingested", snapshot.SnapshotID),
		Action:           "secure_cell.federation_incident_report_bundle_ingested",
		Actor:            actorDID,
		TargetType:       "federation_incident_report_bundle",
		TargetDID:        snapshot.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(intake.Reason),
		Metadata: mergeStringMaps(intake.Metadata, map[string]string{
			"federation_organization_id":                                   strings.TrimSpace(summary.OrganizationID),
			"federation_sponsor_of_record":                                 strings.TrimSpace(summary.SponsorOfRecord),
			"federation_contract_id":                                       strings.Join(contractIDs, ","),
			"federation_counterparty_incident_report_snapshot_id":          snapshot.SnapshotID,
			"federation_counterparty_incident_report_bundle_id":            strings.TrimSpace(bundle.ID),
			"federation_counterparty_incident_report_id":                   strings.TrimSpace(bundle.Report.ID),
			"federation_counterparty_incident_response_id":                 strings.TrimSpace(bundle.Report.ResponseID),
			"federation_counterparty_incident_id":                          strings.TrimSpace(bundle.Report.IncidentID),
			"federation_counterparty_incident_report_status":               string(snapshot.Status),
			"federation_counterparty_incident_report_verified":             fmt.Sprintf("%t", snapshot.Verified),
			"federation_counterparty_incident_report_signer":               snapshot.Signer,
			"federation_counterparty_incident_report_generated_at":         bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			"federation_counterparty_incident_report_expires_at":           safeTimeString(bundle.ExpiresAt),
			"federation_counterparty_incident_report_content_hash":         strings.TrimSpace(bundle.ContentHash),
			"federation_counterparty_incident_report_verification_message": snapshot.VerificationMessage,
			"federation_incident_report_reconciliation_status":             string(reconciliation.Status),
			"federation_incident_report_reconciliation_key":                reconciliation.ComparisonKey,
			"federation_incident_report_reconciliation_local_report_id":    reconciliation.LocalReportID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationCounterpartyIncidentReports(_ context.Context, filter SecureCellFederationCounterpartyIncidentReportFilter) ([]SecureCellFederationCounterpartyIncidentReportSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationCounterpartyIncidentReportSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, snapshot := range run.result.FederationCounterpartyIncidentReports {
			summary := secureCellFederationCounterpartyIncidentReportSummaryFromRun(run, snapshot)
			if !matchesSecureCellFederationCounterpartyIncidentReportFilter(summary, filter) {
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

func (s *Service) ListFederationIncidentReportReconciliations(_ context.Context, filter SecureCellFederationIncidentReportReconciliationFilter) ([]SecureCellFederationIncidentReportReconciliationSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentReportReconciliationSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, item := range secureCellFederationIncidentReportReconciliationsFromRun(run) {
			if !matchesSecureCellFederationIncidentReportReconciliationFilter(item, filter) {
				continue
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		leftAt := time.Time{}
		rightAt := time.Time{}
		if left.CounterpartyReceivedAt != nil {
			leftAt = left.CounterpartyReceivedAt.UTC()
		} else if left.LocalUpdatedAt != nil {
			leftAt = left.LocalUpdatedAt.UTC()
		}
		if right.CounterpartyReceivedAt != nil {
			rightAt = right.CounterpartyReceivedAt.UTC()
		} else if right.LocalUpdatedAt != nil {
			rightAt = right.LocalUpdatedAt.UTC()
		}
		if leftAt.Equal(rightAt) {
			return left.ComparisonKey < right.ComparisonKey
		}
		return leftAt.After(rightAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func secureCellFederationCounterpartyIncidentReportSummaryFromRun(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentReportSnapshot) SecureCellFederationCounterpartyIncidentReportSummary {
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	reconciliation := secureCellFederationIncidentReportReconciliationForSnapshot(run, snapshot)
	summary := SecureCellFederationCounterpartyIncidentReportSummary{
		CellID:                        safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                      safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                    safeSecureCellStatus(run),
		Jurisdiction:                  safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:                strings.TrimSpace(snapshot.OrganizationID),
		SponsorOfRecord:               strings.TrimSpace(orgSummary.SponsorOfRecord),
		OrganizationName:              strings.TrimSpace(orgSummary.OrganizationName),
		SnapshotID:                    strings.TrimSpace(snapshot.SnapshotID),
		BundleID:                      strings.TrimSpace(snapshot.Bundle.ID),
		BundleVersion:                 strings.TrimSpace(snapshot.Bundle.Version),
		BundleName:                    strings.TrimSpace(snapshot.Bundle.Name),
		Status:                        snapshot.Status,
		Verified:                      snapshot.Verified,
		Signer:                        strings.TrimSpace(snapshot.Signer),
		ContractIDs:                   append([]string(nil), uniqueTrimmedStrings(snapshot.ContractIDs)...),
		IncidentID:                    strings.TrimSpace(snapshot.Bundle.Report.IncidentID),
		ResponseID:                    strings.TrimSpace(snapshot.Bundle.Report.ResponseID),
		ReportID:                      strings.TrimSpace(snapshot.Bundle.Report.ID),
		ReportingParty:                snapshot.Bundle.Report.ReportingParty,
		Regulator:                     strings.TrimSpace(snapshot.Bundle.Report.Regulator),
		Framework:                     strings.TrimSpace(snapshot.Bundle.Report.Framework),
		ReportType:                    strings.TrimSpace(snapshot.Bundle.Report.ReportType),
		ReportStatus:                  snapshot.Bundle.Report.Status,
		DueAt:                         cloneTimePtr(snapshot.Bundle.Report.DueAt),
		SubmissionReference:           strings.TrimSpace(snapshot.Bundle.Report.SubmissionReference),
		AcknowledgementReference:      strings.TrimSpace(snapshot.Bundle.Report.AcknowledgementReference),
		GeneratedAt:                   snapshot.Bundle.GeneratedAt.UTC(),
		ExpiresAt:                     cloneTimePtr(snapshot.Bundle.ExpiresAt),
		ReceivedAt:                    snapshot.ReceivedAt.UTC(),
		ControlLedgerID:               strings.TrimSpace(snapshot.Bundle.ControlLedgerID),
		ControlLedgerHash:             strings.TrimSpace(snapshot.Bundle.ControlLedgerHash),
		PortablePackageHash:           strings.TrimSpace(snapshot.Bundle.PortablePackageHash),
		PortablePackageSigned:         snapshot.Bundle.PortablePackageSigned,
		PortablePackageAnchored:       snapshot.Bundle.PortablePackageAnchored,
		VerificationMessage:           strings.TrimSpace(snapshot.VerificationMessage),
		MatchedLocalReportID:          reconciliation.LocalReportID,
		MatchedLocalResponseID:        reconciliation.LocalResponseID,
		ReconciliationStatus:          reconciliation.Status,
		ReconciliationDivergenceCount: len(reconciliation.Divergences),
	}
	if snapshot.Bundle.Signature != nil {
		summary.KeyID = strings.TrimSpace(snapshot.Bundle.Signature.KeyID)
	}
	return summary
}

func matchesSecureCellFederationCounterpartyIncidentReportFilter(item SecureCellFederationCounterpartyIncidentReportSummary, filter SecureCellFederationCounterpartyIncidentReportFilter) bool {
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
	if filter.ReportID != "" && !strings.EqualFold(strings.TrimSpace(item.ReportID), strings.TrimSpace(filter.ReportID)) {
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
	if filter.Regulator != "" && !strings.EqualFold(strings.TrimSpace(item.Regulator), strings.TrimSpace(filter.Regulator)) {
		return false
	}
	return true
}

func secureCellFederationIncidentReportReconciliationsFromRun(run *secureCellRun) []SecureCellFederationIncidentReportReconciliationSummary {
	if run == nil || run.result == nil {
		return nil
	}
	localByKey := secureCellLatestLocalFederationIncidentReportsByKey(run)
	counterpartyByKey := secureCellLatestCounterpartyFederationIncidentReportsByKey(run)
	keys := make(map[string]struct{}, len(localByKey)+len(counterpartyByKey))
	for key := range localByKey {
		keys[key] = struct{}{}
	}
	for key := range counterpartyByKey {
		keys[key] = struct{}{}
	}
	items := make([]SecureCellFederationIncidentReportReconciliationSummary, 0, len(keys))
	for key := range keys {
		items = append(items, secureCellFederationIncidentReportReconciliationSummaryFromRefs(run, key, localByKey[key], counterpartyByKey[key]))
	}
	return items
}

func matchesSecureCellFederationIncidentReportReconciliationFilter(item SecureCellFederationIncidentReportReconciliationSummary, filter SecureCellFederationIncidentReportReconciliationFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(item.IncidentID), strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.ComparisonKey != "" && !strings.EqualFold(strings.TrimSpace(item.ComparisonKey), strings.TrimSpace(filter.ComparisonKey)) {
		return false
	}
	if filter.Regulator != "" && !strings.EqualFold(strings.TrimSpace(item.Regulator), strings.TrimSpace(filter.Regulator)) {
		return false
	}
	if filter.ReportingParty != "" && item.ReportingParty != filter.ReportingParty {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	return true
}

func secureCellFederationIncidentReportReconciliationSummaryFromRefs(run *secureCellRun, key string, local *secureCellFederationIncidentReportRef, counterparty *SecureCellFederationCounterpartyIncidentReportSnapshot) SecureCellFederationIncidentReportReconciliationSummary {
	item := SecureCellFederationIncidentReportReconciliationSummary{
		CellID:        safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:      safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		Jurisdiction:  safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		CellStatus:    safeSecureCellStatus(run),
		ComparisonKey: key,
	}
	if local != nil && local.Response != nil && local.Report != nil {
		orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(local.Response.OrganizationID))
		item.OrganizationID = strings.TrimSpace(local.Response.OrganizationID)
		item.SponsorOfRecord = strings.TrimSpace(local.Response.SponsorOfRecord)
		item.OrganizationName = strings.TrimSpace(orgSummary.OrganizationName)
		item.IncidentID = strings.TrimSpace(local.Report.IncidentID)
		item.Regulator = strings.TrimSpace(local.Report.Regulator)
		item.Framework = strings.TrimSpace(local.Report.Framework)
		item.ReportType = strings.TrimSpace(local.Report.ReportType)
		item.ReportingParty = local.Report.ReportingParty
		item.LocalReportID = strings.TrimSpace(local.Report.ID)
		item.LocalResponseID = strings.TrimSpace(local.Response.ID)
		item.LocalReportStatus = local.Report.Status
		item.LocalDueAt = cloneTimePtr(local.Report.DueAt)
		item.LocalUpdatedAt = cloneTimePtr(&local.Report.UpdatedAt)
		item.LocalSubmissionReference = strings.TrimSpace(local.Report.SubmissionReference)
		item.LocalAcknowledgementReference = strings.TrimSpace(local.Report.AcknowledgementReference)
	}
	if counterparty != nil {
		if item.OrganizationID == "" {
			orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(counterparty.OrganizationID))
			item.OrganizationID = strings.TrimSpace(counterparty.OrganizationID)
			item.SponsorOfRecord = strings.TrimSpace(orgSummary.SponsorOfRecord)
			item.OrganizationName = strings.TrimSpace(orgSummary.OrganizationName)
		}
		if item.IncidentID == "" {
			item.IncidentID = strings.TrimSpace(counterparty.Bundle.Report.IncidentID)
		}
		if item.Regulator == "" {
			item.Regulator = strings.TrimSpace(counterparty.Bundle.Report.Regulator)
		}
		if item.Framework == "" {
			item.Framework = strings.TrimSpace(counterparty.Bundle.Report.Framework)
		}
		if item.ReportType == "" {
			item.ReportType = strings.TrimSpace(counterparty.Bundle.Report.ReportType)
		}
		if item.ReportingParty == "" {
			item.ReportingParty = counterparty.Bundle.Report.ReportingParty
		}
		item.CounterpartySnapshotID = strings.TrimSpace(counterparty.SnapshotID)
		item.CounterpartyBundleID = strings.TrimSpace(counterparty.Bundle.ID)
		item.CounterpartyReportID = strings.TrimSpace(counterparty.Bundle.Report.ID)
		item.CounterpartyResponseID = strings.TrimSpace(counterparty.Bundle.Report.ResponseID)
		item.CounterpartyBundleStatus = counterparty.Status
		item.CounterpartyReportStatus = counterparty.Bundle.Report.Status
		item.CounterpartyDueAt = cloneTimePtr(counterparty.Bundle.Report.DueAt)
		item.CounterpartyGeneratedAt = cloneTimePtr(&counterparty.Bundle.GeneratedAt)
		item.CounterpartyReceivedAt = cloneTimePtr(&counterparty.ReceivedAt)
		item.CounterpartySubmissionReference = strings.TrimSpace(counterparty.Bundle.Report.SubmissionReference)
		item.CounterpartyAcknowledgementReference = strings.TrimSpace(counterparty.Bundle.Report.AcknowledgementReference)
	}
	item.Status, item.Divergences = secureCellFederationIncidentReportReconciliationStatusAndDivergences(local, counterparty)
	item.ReviewStatus, item.LastReviewedBy, item.LastReviewedAt, item.ReviewActionCount = secureCellFederationIncidentReportReconciliationReviewState(run, key)
	return item
}

func secureCellFederationIncidentReportReconciliationForSnapshot(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentReportSnapshot) SecureCellFederationIncidentReportReconciliationSummary {
	key := secureCellFederationIncidentReportComparisonKey(
		strings.TrimSpace(snapshot.OrganizationID),
		strings.TrimSpace(snapshot.Bundle.Report.IncidentID),
		snapshot.Bundle.Report.ReportingParty,
		strings.TrimSpace(snapshot.Bundle.Report.Regulator),
		strings.TrimSpace(snapshot.Bundle.Report.Framework),
		strings.TrimSpace(snapshot.Bundle.Report.ReportType),
	)
	return secureCellFederationIncidentReportReconciliationSummaryFromRefs(run, key, secureCellLatestLocalFederationIncidentReportByKey(run, key), &snapshot)
}

func secureCellFederationIncidentReportReconciliationStatusAndDivergences(local *secureCellFederationIncidentReportRef, counterparty *SecureCellFederationCounterpartyIncidentReportSnapshot) (SecureCellFederationIncidentReportReconciliationStatus, []string) {
	if local == nil && counterparty == nil {
		return "", nil
	}
	if counterparty != nil {
		switch counterparty.Status {
		case SecureCellFederationCounterpartyIncidentReportStatusInvalid:
			return SecureCellFederationIncidentReportReconciliationStatusCounterpartyInvalid, nil
		case SecureCellFederationCounterpartyIncidentReportStatusStale:
			return SecureCellFederationIncidentReportReconciliationStatusCounterpartyStale, nil
		case SecureCellFederationCounterpartyIncidentReportStatusExpired:
			return SecureCellFederationIncidentReportReconciliationStatusCounterpartyExpired, nil
		}
	}
	if local == nil {
		return SecureCellFederationIncidentReportReconciliationStatusCounterpartyOnly, nil
	}
	if counterparty == nil {
		return SecureCellFederationIncidentReportReconciliationStatusLocalOnly, nil
	}
	diffs := make([]string, 0, 6)
	if local.Report.Status != counterparty.Bundle.Report.Status {
		diffs = append(diffs, "status")
	}
	if !secureCellEqualOptionalTimes(local.Report.DueAt, counterparty.Bundle.Report.DueAt) {
		diffs = append(diffs, "due_at")
	}
	if !strings.EqualFold(strings.TrimSpace(local.Report.Framework), strings.TrimSpace(counterparty.Bundle.Report.Framework)) {
		diffs = append(diffs, "framework")
	}
	if !strings.EqualFold(strings.TrimSpace(local.Report.ReportType), strings.TrimSpace(counterparty.Bundle.Report.ReportType)) {
		diffs = append(diffs, "report_type")
	}
	if !strings.EqualFold(strings.TrimSpace(local.Report.SubmissionReference), strings.TrimSpace(counterparty.Bundle.Report.SubmissionReference)) {
		diffs = append(diffs, "submission_reference")
	}
	if !strings.EqualFold(strings.TrimSpace(local.Report.AcknowledgementReference), strings.TrimSpace(counterparty.Bundle.Report.AcknowledgementReference)) {
		diffs = append(diffs, "acknowledgement_reference")
	}
	if len(diffs) > 0 {
		return SecureCellFederationIncidentReportReconciliationStatusDivergent, diffs
	}
	return SecureCellFederationIncidentReportReconciliationStatusAligned, nil
}

func secureCellLatestLocalFederationIncidentReportsByKey(run *secureCellRun) map[string]*secureCellFederationIncidentReportRef {
	out := make(map[string]*secureCellFederationIncidentReportRef)
	if run == nil || run.result == nil {
		return out
	}
	for responseIdx := range run.result.FederationIncidentResponses {
		response := &run.result.FederationIncidentResponses[responseIdx]
		for reportIdx := range response.IncidentReports {
			report := &response.IncidentReports[reportIdx]
			key := secureCellFederationIncidentReportComparisonKey(
				strings.TrimSpace(response.OrganizationID),
				strings.TrimSpace(report.IncidentID),
				report.ReportingParty,
				strings.TrimSpace(report.Regulator),
				strings.TrimSpace(report.Framework),
				strings.TrimSpace(report.ReportType),
			)
			current := out[key]
			if current == nil || report.UpdatedAt.After(current.Report.UpdatedAt) {
				out[key] = &secureCellFederationIncidentReportRef{Response: response, Report: report}
			}
		}
	}
	return out
}

func secureCellLatestLocalFederationIncidentReportByKey(run *secureCellRun, key string) *secureCellFederationIncidentReportRef {
	return secureCellLatestLocalFederationIncidentReportsByKey(run)[key]
}

func secureCellLatestCounterpartyFederationIncidentReportsByKey(run *secureCellRun) map[string]*SecureCellFederationCounterpartyIncidentReportSnapshot {
	out := make(map[string]*SecureCellFederationCounterpartyIncidentReportSnapshot)
	if run == nil || run.result == nil {
		return out
	}
	for idx := range run.result.FederationCounterpartyIncidentReports {
		snapshot := &run.result.FederationCounterpartyIncidentReports[idx]
		key := secureCellFederationIncidentReportComparisonKey(
			strings.TrimSpace(snapshot.OrganizationID),
			strings.TrimSpace(snapshot.Bundle.Report.IncidentID),
			snapshot.Bundle.Report.ReportingParty,
			strings.TrimSpace(snapshot.Bundle.Report.Regulator),
			strings.TrimSpace(snapshot.Bundle.Report.Framework),
			strings.TrimSpace(snapshot.Bundle.Report.ReportType),
		)
		current := out[key]
		if current == nil || snapshot.ReceivedAt.After(current.ReceivedAt) {
			out[key] = snapshot
		}
	}
	return out
}

func secureCellFederationIncidentReportComparisonKey(organizationID string, incidentID string, reportingParty SecureCellFederationIncidentResponseParty, regulator string, framework string, reportType string) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(organizationID)),
		strings.ToLower(strings.TrimSpace(incidentID)),
		strings.ToLower(strings.TrimSpace(string(secureCellNormalizedFederationIncidentResponseParty(reportingParty)))),
		strings.ToLower(strings.TrimSpace(regulator)),
		strings.ToLower(strings.TrimSpace(framework)),
		strings.ToLower(strings.TrimSpace(reportType)),
	}
	return strings.Join(parts, "|")
}

func secureCellFederationCounterpartyIncidentReportStatusAt(bundle *SecureCellFederationIncidentReportBundle, verificationErr error, now time.Time) (SecureCellFederationCounterpartyIncidentReportStatus, string, bool) {
	now = now.UTC()
	if verificationErr != nil {
		return SecureCellFederationCounterpartyIncidentReportStatusInvalid, verificationErr.Error(), false
	}
	if bundle == nil {
		return SecureCellFederationCounterpartyIncidentReportStatusInvalid, "bundle is required", false
	}
	if bundle.ExpiresAt != nil && !bundle.ExpiresAt.IsZero() && now.After(bundle.ExpiresAt.UTC()) {
		return SecureCellFederationCounterpartyIncidentReportStatusExpired, "counterparty incident report bundle expired", true
	}
	if secureCellFederationIncidentReportBundleIsStale(bundle, now) {
		return SecureCellFederationCounterpartyIncidentReportStatusStale, "counterparty incident report bundle is stale", true
	}
	return SecureCellFederationCounterpartyIncidentReportStatusVerified, "counterparty incident report bundle verified", true
}

func secureCellFederationIncidentReportBundleIsStale(bundle *SecureCellFederationIncidentReportBundle, now time.Time) bool {
	if bundle == nil || bundle.GeneratedAt.IsZero() {
		return false
	}
	now = now.UTC()
	staleAt := bundle.GeneratedAt.UTC().Add(24 * time.Hour)
	if bundle.ExpiresAt != nil && !bundle.ExpiresAt.IsZero() && bundle.ExpiresAt.UTC().Before(staleAt) {
		staleAt = bundle.ExpiresAt.UTC()
	}
	if bundle.ExpiresAt != nil && !bundle.ExpiresAt.IsZero() && now.After(bundle.ExpiresAt.UTC()) {
		return false
	}
	return now.After(staleAt)
}

func secureCellValidateFederationIncidentReportBundleSemantics(bundle *SecureCellFederationIncidentReportBundle, organizationID string) error {
	if bundle == nil {
		return fmt.Errorf("bundle is required")
	}
	expectedOrgID := strings.TrimSpace(organizationID)
	if expectedOrgID != "" {
		if !strings.EqualFold(strings.TrimSpace(bundle.Organization.OrganizationID), expectedOrgID) {
			return fmt.Errorf("bundle organization %q does not match target organization %q", strings.TrimSpace(bundle.Organization.OrganizationID), expectedOrgID)
		}
		if !strings.EqualFold(strings.TrimSpace(bundle.Report.OrganizationID), expectedOrgID) {
			return fmt.Errorf("report organization %q does not match target organization %q", strings.TrimSpace(bundle.Report.OrganizationID), expectedOrgID)
		}
	}
	if strings.TrimSpace(bundle.ReportSummary.ReportID) != strings.TrimSpace(bundle.Report.ID) {
		return fmt.Errorf("report summary/report mismatch")
	}
	if strings.TrimSpace(bundle.ReportSummary.ResponseID) != strings.TrimSpace(bundle.Report.ResponseID) {
		return fmt.Errorf("response summary/report mismatch")
	}
	if strings.TrimSpace(bundle.ReportSummary.IncidentID) != strings.TrimSpace(bundle.Report.IncidentID) {
		return fmt.Errorf("incident summary/report mismatch")
	}
	if bundle.ReportSummary.ReportingParty != bundle.Report.ReportingParty {
		return fmt.Errorf("reporting party mismatch")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ReportSummary.Regulator), strings.TrimSpace(bundle.Report.Regulator)) {
		return fmt.Errorf("report regulator mismatch")
	}
	if bundle.ReportSummary.Status != bundle.Report.Status {
		return fmt.Errorf("report status mismatch")
	}
	return nil
}

func secureCellCloneFederationIncidentReportBundle(in SecureCellFederationIncidentReportBundle) SecureCellFederationIncidentReportBundle {
	data, _ := json.Marshal(in)
	var out SecureCellFederationIncidentReportBundle
	_ = json.Unmarshal(data, &out)
	return out
}

func secureCellFederationIncidentReportBundleSignerName(bundle *SecureCellFederationIncidentReportBundle) string {
	if bundle == nil || bundle.Signature == nil {
		return ""
	}
	return strings.TrimSpace(bundle.Signature.Signer)
}

func secureCellEqualOptionalTimes(left, right *time.Time) bool {
	switch {
	case left == nil && right == nil:
		return true
	case left == nil || right == nil:
		return false
	default:
		return left.UTC().Equal(right.UTC())
	}
}

func secureCellFederationCounterpartyIncidentReportsByStatus(items []SecureCellFederationCounterpartyIncidentReportSnapshot, status SecureCellFederationCounterpartyIncidentReportStatus) []SecureCellFederationCounterpartyIncidentReportSnapshot {
	if len(items) == 0 {
		return nil
	}
	out := make([]SecureCellFederationCounterpartyIncidentReportSnapshot, 0, len(items))
	for _, item := range items {
		if item.Status == status {
			out = append(out, item)
		}
	}
	return out
}

func secureCellFederationIncidentReportReconciliationStatusCount(items []SecureCellFederationIncidentReportReconciliationSummary, status SecureCellFederationIncidentReportReconciliationStatus) int {
	total := 0
	for _, item := range items {
		if item.Status == status {
			total++
		}
	}
	return total
}

func secureCellFederationIncidentReportReconciliationDivergentCount(items []SecureCellFederationIncidentReportReconciliationSummary) int {
	total := 0
	for _, item := range items {
		switch item.Status {
		case SecureCellFederationIncidentReportReconciliationStatusDivergent,
			SecureCellFederationIncidentReportReconciliationStatusCounterpartyInvalid,
			SecureCellFederationIncidentReportReconciliationStatusCounterpartyStale,
			SecureCellFederationIncidentReportReconciliationStatusCounterpartyExpired:
			total++
		}
	}
	return total
}
