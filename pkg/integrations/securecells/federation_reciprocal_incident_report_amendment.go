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

// SecureCellFederationCounterpartyIncidentReportAmendmentStatus tracks
// verification and freshness posture for one imported amendment bundle.
type SecureCellFederationCounterpartyIncidentReportAmendmentStatus string

const (
	SecureCellFederationCounterpartyIncidentReportAmendmentStatusVerified SecureCellFederationCounterpartyIncidentReportAmendmentStatus = "verified"
	SecureCellFederationCounterpartyIncidentReportAmendmentStatusStale    SecureCellFederationCounterpartyIncidentReportAmendmentStatus = "stale"
	SecureCellFederationCounterpartyIncidentReportAmendmentStatusExpired  SecureCellFederationCounterpartyIncidentReportAmendmentStatus = "expired"
	SecureCellFederationCounterpartyIncidentReportAmendmentStatusInvalid  SecureCellFederationCounterpartyIncidentReportAmendmentStatus = "invalid"
)

// SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot persists
// one imported signed amendment bundle in the secure-cell runtime trace.
type SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot struct {
	SnapshotID          string                                                        `json:"snapshot_id"`
	OrganizationID      string                                                        `json:"organization_id"`
	ContractIDs         []string                                                      `json:"contract_ids,omitempty"`
	Bundle              SecureCellFederationIncidentReportAmendmentBundle             `json:"bundle"`
	Status              SecureCellFederationCounterpartyIncidentReportAmendmentStatus `json:"status"`
	Verified            bool                                                          `json:"verified"`
	VerificationMessage string                                                        `json:"verification_message,omitempty"`
	Signer              string                                                        `json:"signer,omitempty"`
	ReceivedBy          string                                                        `json:"received_by,omitempty"`
	ReceivedAt          time.Time                                                     `json:"received_at"`
	Metadata            map[string]string                                             `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyIncidentReportAmendmentFilter narrows
// operator queries across imported counterparty amendment bundles.
type SecureCellFederationCounterpartyIncidentReportAmendmentFilter struct {
	CellID               string                                                          `json:"cell_id,omitempty"`
	OrganizationID       string                                                          `json:"organization_id,omitempty"`
	ContractID           string                                                          `json:"contract_id,omitempty"`
	IncidentID           string                                                          `json:"incident_id,omitempty"`
	ResponseID           string                                                          `json:"response_id,omitempty"`
	ReportID             string                                                          `json:"report_id,omitempty"`
	AmendmentID          string                                                          `json:"amendment_id,omitempty"`
	Status               SecureCellFederationCounterpartyIncidentReportAmendmentStatus   `json:"status,omitempty"`
	ReconciliationStatus SecureCellFederationIncidentReportAmendmentReconciliationStatus `json:"reconciliation_status,omitempty"`
	Signer               string                                                          `json:"signer,omitempty"`
	Regulator            string                                                          `json:"regulator,omitempty"`
	Limit                int                                                             `json:"limit,omitempty"`
}

// SecureCellFederationCounterpartyIncidentReportAmendmentSummary is the
// operator-facing summary of one imported counterparty amendment bundle.
type SecureCellFederationCounterpartyIncidentReportAmendmentSummary struct {
	CellID                        string                                                          `json:"cell_id"`
	CellName                      string                                                          `json:"cell_name,omitempty"`
	CellStatus                    SecureCellStatus                                                `json:"cell_status"`
	Jurisdiction                  string                                                          `json:"jurisdiction,omitempty"`
	OrganizationID                string                                                          `json:"organization_id"`
	SponsorOfRecord               string                                                          `json:"sponsor_of_record,omitempty"`
	OrganizationName              string                                                          `json:"organization_name,omitempty"`
	SnapshotID                    string                                                          `json:"snapshot_id"`
	BundleID                      string                                                          `json:"bundle_id,omitempty"`
	BundleVersion                 string                                                          `json:"bundle_version,omitempty"`
	BundleName                    string                                                          `json:"bundle_name,omitempty"`
	Status                        SecureCellFederationCounterpartyIncidentReportAmendmentStatus   `json:"status"`
	Verified                      bool                                                            `json:"verified"`
	Signer                        string                                                          `json:"signer,omitempty"`
	KeyID                         string                                                          `json:"key_id,omitempty"`
	ContractIDs                   []string                                                        `json:"contract_ids,omitempty"`
	IncidentID                    string                                                          `json:"incident_id,omitempty"`
	ResponseID                    string                                                          `json:"response_id,omitempty"`
	ReportID                      string                                                          `json:"report_id,omitempty"`
	AmendmentID                   string                                                          `json:"amendment_id,omitempty"`
	Sequence                      int                                                             `json:"sequence"`
	ReportingParty                SecureCellFederationIncidentResponseParty                       `json:"reporting_party,omitempty"`
	Regulator                     string                                                          `json:"regulator,omitempty"`
	Framework                     string                                                          `json:"framework,omitempty"`
	ReportType                    string                                                          `json:"report_type,omitempty"`
	AmendmentStatus               SecureCellFederationIncidentReportAmendmentStatus               `json:"amendment_status,omitempty"`
	ChangedSections               []string                                                        `json:"changed_sections,omitempty"`
	SubmissionReference           string                                                          `json:"submission_reference,omitempty"`
	AcknowledgementReference      string                                                          `json:"acknowledgement_reference,omitempty"`
	GeneratedAt                   time.Time                                                       `json:"generated_at,omitempty"`
	ExpiresAt                     *time.Time                                                      `json:"expires_at,omitempty"`
	ReceivedAt                    time.Time                                                       `json:"received_at,omitempty"`
	ControlLedgerID               string                                                          `json:"control_ledger_id,omitempty"`
	ControlLedgerHash             string                                                          `json:"control_ledger_hash,omitempty"`
	PortablePackageHash           string                                                          `json:"portable_package_hash,omitempty"`
	PortablePackageSigned         bool                                                            `json:"portable_package_signed"`
	PortablePackageAnchored       bool                                                            `json:"portable_package_anchored"`
	VerificationMessage           string                                                          `json:"verification_message,omitempty"`
	MatchedLocalAmendmentID       string                                                          `json:"matched_local_amendment_id,omitempty"`
	MatchedLocalReportID          string                                                          `json:"matched_local_report_id,omitempty"`
	MatchedLocalResponseID        string                                                          `json:"matched_local_response_id,omitempty"`
	ReconciliationStatus          SecureCellFederationIncidentReportAmendmentReconciliationStatus `json:"reconciliation_status,omitempty"`
	ReconciliationDivergenceCount int                                                             `json:"reconciliation_divergence_count"`
}

// SecureCellFederationIncidentReportAmendmentBundleIntakeRequest ingests one
// signed counterparty incident report amendment bundle into the evidence chain.
type SecureCellFederationIncidentReportAmendmentBundleIntakeRequest struct {
	ActorDID string                                             `json:"actor_did,omitempty"`
	Bundle   *SecureCellFederationIncidentReportAmendmentBundle `json:"bundle,omitempty"`
	Reason   string                                             `json:"reason,omitempty"`
	Metadata map[string]string                                  `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationStatus captures
// whether one local amendment aligns with the imported counterparty revision.
type SecureCellFederationIncidentReportAmendmentReconciliationStatus string

const (
	SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned             SecureCellFederationIncidentReportAmendmentReconciliationStatus = "aligned"
	SecureCellFederationIncidentReportAmendmentReconciliationStatusLocalOnly           SecureCellFederationIncidentReportAmendmentReconciliationStatus = "local_only"
	SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyOnly    SecureCellFederationIncidentReportAmendmentReconciliationStatus = "counterparty_only"
	SecureCellFederationIncidentReportAmendmentReconciliationStatusDivergent           SecureCellFederationIncidentReportAmendmentReconciliationStatus = "divergent"
	SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyInvalid SecureCellFederationIncidentReportAmendmentReconciliationStatus = "counterparty_invalid"
	SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyStale   SecureCellFederationIncidentReportAmendmentReconciliationStatus = "counterparty_stale"
	SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyExpired SecureCellFederationIncidentReportAmendmentReconciliationStatus = "counterparty_expired"
)

// SecureCellFederationIncidentReportAmendmentReconciliationFilter narrows
// operator queries across amendment-alignment summaries.
type SecureCellFederationIncidentReportAmendmentReconciliationFilter struct {
	CellID         string                                                          `json:"cell_id,omitempty"`
	OrganizationID string                                                          `json:"organization_id,omitempty"`
	IncidentID     string                                                          `json:"incident_id,omitempty"`
	ComparisonKey  string                                                          `json:"comparison_key,omitempty"`
	Regulator      string                                                          `json:"regulator,omitempty"`
	ReportingParty SecureCellFederationIncidentResponseParty                       `json:"reporting_party,omitempty"`
	Status         SecureCellFederationIncidentReportAmendmentReconciliationStatus `json:"status,omitempty"`
	Limit          int                                                             `json:"limit,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationSummary is the
// operator-facing alignment view across local and imported amendment state.
type SecureCellFederationIncidentReportAmendmentReconciliationSummary struct {
	CellID                               string                                                          `json:"cell_id"`
	CellName                             string                                                          `json:"cell_name,omitempty"`
	Jurisdiction                         string                                                          `json:"jurisdiction,omitempty"`
	CellStatus                           SecureCellStatus                                                `json:"cell_status"`
	OrganizationID                       string                                                          `json:"organization_id"`
	SponsorOfRecord                      string                                                          `json:"sponsor_of_record,omitempty"`
	OrganizationName                     string                                                          `json:"organization_name,omitempty"`
	ComparisonKey                        string                                                          `json:"comparison_key"`
	IncidentID                           string                                                          `json:"incident_id,omitempty"`
	Regulator                            string                                                          `json:"regulator,omitempty"`
	Framework                            string                                                          `json:"framework,omitempty"`
	ReportType                           string                                                          `json:"report_type,omitempty"`
	ReportingParty                       SecureCellFederationIncidentResponseParty                       `json:"reporting_party,omitempty"`
	Status                               SecureCellFederationIncidentReportAmendmentReconciliationStatus `json:"status"`
	LocalReportID                        string                                                          `json:"local_report_id,omitempty"`
	LocalResponseID                      string                                                          `json:"local_response_id,omitempty"`
	LocalAmendmentID                     string                                                          `json:"local_amendment_id,omitempty"`
	LocalAmendmentStatus                 SecureCellFederationIncidentReportAmendmentStatus               `json:"local_amendment_status,omitempty"`
	LocalSequence                        int                                                             `json:"local_sequence"`
	LocalChangedSections                 []string                                                        `json:"local_changed_sections,omitempty"`
	LocalUpdatedAt                       *time.Time                                                      `json:"local_updated_at,omitempty"`
	LocalSubmissionReference             string                                                          `json:"local_submission_reference,omitempty"`
	LocalAcknowledgementReference        string                                                          `json:"local_acknowledgement_reference,omitempty"`
	CounterpartySnapshotID               string                                                          `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyBundleID                 string                                                          `json:"counterparty_bundle_id,omitempty"`
	CounterpartyReportID                 string                                                          `json:"counterparty_report_id,omitempty"`
	CounterpartyResponseID               string                                                          `json:"counterparty_response_id,omitempty"`
	CounterpartyAmendmentID              string                                                          `json:"counterparty_amendment_id,omitempty"`
	CounterpartyBundleStatus             SecureCellFederationCounterpartyIncidentReportAmendmentStatus   `json:"counterparty_bundle_status,omitempty"`
	CounterpartyAmendmentStatus          SecureCellFederationIncidentReportAmendmentStatus               `json:"counterparty_amendment_status,omitempty"`
	CounterpartySequence                 int                                                             `json:"counterparty_sequence"`
	CounterpartyChangedSections          []string                                                        `json:"counterparty_changed_sections,omitempty"`
	CounterpartyGeneratedAt              *time.Time                                                      `json:"counterparty_generated_at,omitempty"`
	CounterpartyReceivedAt               *time.Time                                                      `json:"counterparty_received_at,omitempty"`
	CounterpartySubmissionReference      string                                                          `json:"counterparty_submission_reference,omitempty"`
	CounterpartyAcknowledgementReference string                                                          `json:"counterparty_acknowledgement_reference,omitempty"`
	Divergences                          []string                                                        `json:"divergences,omitempty"`
}

type secureCellFederationIncidentReportAmendmentRef struct {
	Response  *SecureCellFederationIncidentResponse
	Report    *SecureCellFederationIncidentReport
	Amendment *SecureCellFederationIncidentReportAmendment
}

func (s *Service) IngestFederationIncidentReportAmendmentBundle(ctx context.Context, cellID string, organizationID string, intake SecureCellFederationIncidentReportAmendmentBundleIntakeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: service is required")
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
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: bundle is required")
	}
	bundle := secureCellCloneFederationIncidentReportAmendmentBundle(*intake.Bundle)
	actorDID := firstNonEmpty(strings.TrimSpace(intake.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w: actor %q is not permitted to intake amendment bundles", ErrPolicyDenied, actorDID)
	}

	verificationErr := VerifyFederationIncidentReportAmendmentBundle(&bundle)
	if verificationErr == nil {
		verificationErr = secureCellValidateFederationIncidentReportAmendmentBundleSemantics(&bundle, strings.TrimSpace(summary.OrganizationID))
	}
	status, verificationMessage, verified := secureCellFederationCounterpartyIncidentReportAmendmentStatusAt(&bundle, verificationErr, time.Now().UTC())
	contractIDs := secureCellFederationContractIDs(bundle.Contracts)

	receipt, err := s.evaluateStage(ctx, run.request, "intake_federation_incident_report_amendment_bundle", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                     strings.TrimSpace(summary.OrganizationID),
		"federation_sponsor_of_record":                                   strings.TrimSpace(summary.SponsorOfRecord),
		"federation_counterparty_incident_report_amendment_bundle_id":    strings.TrimSpace(bundle.ID),
		"federation_counterparty_incident_report_amendment_id":           strings.TrimSpace(bundle.Amendment.ID),
		"federation_counterparty_incident_report_id":                     strings.TrimSpace(bundle.Amendment.ReportID),
		"federation_counterparty_incident_response_id":                   strings.TrimSpace(bundle.Amendment.ResponseID),
		"federation_counterparty_incident_id":                            strings.TrimSpace(bundle.Amendment.IncidentID),
		"federation_counterparty_incident_report_amendment_status":       string(status),
		"federation_counterparty_incident_report_amendment_signer":       strings.TrimSpace(secureCellFederationIncidentReportAmendmentBundleSignerName(&bundle)),
		"federation_counterparty_incident_report_amendment_contract_ids": strings.Join(contractIDs, ","),
		"transition_reason":                                              strings.TrimSpace(intake.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	snapshot := SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot{
		SnapshotID:          fmt.Sprintf("%s-federation-counterparty-incident-report-amendment-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", strings.TrimSpace(summary.OrganizationID), strings.TrimSpace(bundle.ID), now.Format(time.RFC3339Nano))))),
		OrganizationID:      strings.TrimSpace(summary.OrganizationID),
		ContractIDs:         append([]string(nil), contractIDs...),
		Bundle:              bundle,
		Status:              status,
		Verified:            verified,
		VerificationMessage: strings.TrimSpace(verificationMessage),
		Signer:              strings.TrimSpace(secureCellFederationIncidentReportAmendmentBundleSignerName(&bundle)),
		ReceivedBy:          strings.TrimSpace(actorDID),
		ReceivedAt:          now,
		Metadata:            cloneStringMap(intake.Metadata),
	}
	run.result.FederationCounterpartyIncidentReportAmendments = append(run.result.FederationCounterpartyIncidentReportAmendments, snapshot)
	run.result.UpdatedAt = now
	reconciliation := secureCellFederationIncidentReportAmendmentReconciliationForSnapshot(run, snapshot)

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_report_amendment_bundle_ingested", snapshot.SnapshotID),
		Action:           "secure_cell.federation_incident_report_amendment_bundle_ingested",
		Actor:            actorDID,
		TargetType:       "federation_incident_report_amendment_bundle",
		TargetDID:        snapshot.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(intake.Reason),
		Metadata: mergeStringMaps(intake.Metadata, map[string]string{
			"federation_organization_id":                                             strings.TrimSpace(summary.OrganizationID),
			"federation_sponsor_of_record":                                           strings.TrimSpace(summary.SponsorOfRecord),
			"federation_contract_id":                                                 strings.Join(contractIDs, ","),
			"federation_counterparty_incident_report_amendment_snapshot_id":          snapshot.SnapshotID,
			"federation_counterparty_incident_report_amendment_bundle_id":            strings.TrimSpace(bundle.ID),
			"federation_counterparty_incident_report_amendment_id":                   strings.TrimSpace(bundle.Amendment.ID),
			"federation_counterparty_incident_report_id":                             strings.TrimSpace(bundle.Amendment.ReportID),
			"federation_counterparty_incident_response_id":                           strings.TrimSpace(bundle.Amendment.ResponseID),
			"federation_counterparty_incident_id":                                    strings.TrimSpace(bundle.Amendment.IncidentID),
			"federation_counterparty_incident_report_amendment_status":               string(snapshot.Status),
			"federation_counterparty_incident_report_amendment_verified":             fmt.Sprintf("%t", snapshot.Verified),
			"federation_counterparty_incident_report_amendment_signer":               snapshot.Signer,
			"federation_counterparty_incident_report_amendment_generated_at":         bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			"federation_counterparty_incident_report_amendment_expires_at":           safeTimeString(bundle.ExpiresAt),
			"federation_counterparty_incident_report_amendment_content_hash":         strings.TrimSpace(bundle.ContentHash),
			"federation_counterparty_incident_report_amendment_verification_message": snapshot.VerificationMessage,
			"federation_incident_report_amendment_reconciliation_status":             string(reconciliation.Status),
			"federation_incident_report_amendment_reconciliation_key":                reconciliation.ComparisonKey,
			"federation_incident_report_amendment_reconciliation_local_amendment_id": reconciliation.LocalAmendmentID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationCounterpartyIncidentReportAmendments(_ context.Context, filter SecureCellFederationCounterpartyIncidentReportAmendmentFilter) ([]SecureCellFederationCounterpartyIncidentReportAmendmentSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationCounterpartyIncidentReportAmendmentSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, snapshot := range run.result.FederationCounterpartyIncidentReportAmendments {
			summary := secureCellFederationCounterpartyIncidentReportAmendmentSummaryFromRun(run, snapshot)
			if !matchesSecureCellFederationCounterpartyIncidentReportAmendmentFilter(summary, filter) {
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

func (s *Service) ListFederationIncidentReportAmendmentReconciliations(_ context.Context, filter SecureCellFederationIncidentReportAmendmentReconciliationFilter) ([]SecureCellFederationIncidentReportAmendmentReconciliationSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentReportAmendmentReconciliationSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, item := range secureCellFederationIncidentReportAmendmentReconciliationsFromRun(run) {
			if !matchesSecureCellFederationIncidentReportAmendmentReconciliationFilter(item, filter) {
				continue
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		leftAt := secureCellFederationIncidentReportAmendmentReconciliationUpdatedAt(items[i])
		rightAt := secureCellFederationIncidentReportAmendmentReconciliationUpdatedAt(items[j])
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

func secureCellFederationCounterpartyIncidentReportAmendmentSummaryFromRun(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot) SecureCellFederationCounterpartyIncidentReportAmendmentSummary {
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	reconciliation := secureCellFederationIncidentReportAmendmentReconciliationForSnapshot(run, snapshot)
	summary := SecureCellFederationCounterpartyIncidentReportAmendmentSummary{
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
		IncidentID:                    strings.TrimSpace(snapshot.Bundle.Amendment.IncidentID),
		ResponseID:                    strings.TrimSpace(snapshot.Bundle.Amendment.ResponseID),
		ReportID:                      strings.TrimSpace(snapshot.Bundle.Amendment.ReportID),
		AmendmentID:                   strings.TrimSpace(snapshot.Bundle.Amendment.ID),
		Sequence:                      snapshot.Bundle.Amendment.Sequence,
		ReportingParty:                snapshot.Bundle.ReportSummary.ReportingParty,
		Regulator:                     strings.TrimSpace(snapshot.Bundle.ReportSummary.Regulator),
		Framework:                     strings.TrimSpace(snapshot.Bundle.ReportSummary.Framework),
		ReportType:                    strings.TrimSpace(snapshot.Bundle.ReportSummary.ReportType),
		AmendmentStatus:               snapshot.Bundle.Amendment.Status,
		ChangedSections:               append([]string(nil), snapshot.Bundle.Amendment.ChangedSections...),
		SubmissionReference:           strings.TrimSpace(snapshot.Bundle.Amendment.SubmissionReference),
		AcknowledgementReference:      strings.TrimSpace(snapshot.Bundle.Amendment.AcknowledgementReference),
		GeneratedAt:                   snapshot.Bundle.GeneratedAt.UTC(),
		ExpiresAt:                     cloneTimePtr(snapshot.Bundle.ExpiresAt),
		ReceivedAt:                    snapshot.ReceivedAt.UTC(),
		ControlLedgerID:               strings.TrimSpace(snapshot.Bundle.ControlLedgerID),
		ControlLedgerHash:             strings.TrimSpace(snapshot.Bundle.ControlLedgerHash),
		PortablePackageHash:           strings.TrimSpace(snapshot.Bundle.PortablePackageHash),
		PortablePackageSigned:         snapshot.Bundle.PortablePackageSigned,
		PortablePackageAnchored:       snapshot.Bundle.PortablePackageAnchored,
		VerificationMessage:           strings.TrimSpace(snapshot.VerificationMessage),
		MatchedLocalAmendmentID:       reconciliation.LocalAmendmentID,
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

func matchesSecureCellFederationCounterpartyIncidentReportAmendmentFilter(item SecureCellFederationCounterpartyIncidentReportAmendmentSummary, filter SecureCellFederationCounterpartyIncidentReportAmendmentFilter) bool {
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
	if filter.AmendmentID != "" && !strings.EqualFold(strings.TrimSpace(item.AmendmentID), strings.TrimSpace(filter.AmendmentID)) {
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

func secureCellFederationIncidentReportAmendmentReconciliationsFromRun(run *secureCellRun) []SecureCellFederationIncidentReportAmendmentReconciliationSummary {
	if run == nil || run.result == nil {
		return nil
	}
	localByKey := secureCellLatestLocalFederationIncidentReportAmendmentsByKey(run)
	counterpartyByKey := secureCellLatestCounterpartyFederationIncidentReportAmendmentsByKey(run)
	keys := make(map[string]struct{}, len(localByKey)+len(counterpartyByKey))
	for key := range localByKey {
		keys[key] = struct{}{}
	}
	for key := range counterpartyByKey {
		keys[key] = struct{}{}
	}
	items := make([]SecureCellFederationIncidentReportAmendmentReconciliationSummary, 0, len(keys))
	for key := range keys {
		items = append(items, secureCellFederationIncidentReportAmendmentReconciliationSummaryFromRefs(run, key, localByKey[key], counterpartyByKey[key]))
	}
	return items
}

func matchesSecureCellFederationIncidentReportAmendmentReconciliationFilter(item SecureCellFederationIncidentReportAmendmentReconciliationSummary, filter SecureCellFederationIncidentReportAmendmentReconciliationFilter) bool {
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

func secureCellFederationIncidentReportAmendmentReconciliationSummaryFromRefs(run *secureCellRun, key string, local *secureCellFederationIncidentReportAmendmentRef, counterparty *SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot) SecureCellFederationIncidentReportAmendmentReconciliationSummary {
	item := SecureCellFederationIncidentReportAmendmentReconciliationSummary{
		CellID:        safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:      safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		Jurisdiction:  safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		CellStatus:    safeSecureCellStatus(run),
		ComparisonKey: key,
	}
	if local != nil && local.Response != nil && local.Report != nil && local.Amendment != nil {
		orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(local.Response.OrganizationID))
		item.OrganizationID = strings.TrimSpace(local.Response.OrganizationID)
		item.SponsorOfRecord = strings.TrimSpace(local.Response.SponsorOfRecord)
		item.OrganizationName = strings.TrimSpace(orgSummary.OrganizationName)
		item.IncidentID = strings.TrimSpace(local.Amendment.IncidentID)
		item.Regulator = strings.TrimSpace(local.Report.Regulator)
		item.Framework = strings.TrimSpace(local.Report.Framework)
		item.ReportType = strings.TrimSpace(local.Report.ReportType)
		item.ReportingParty = local.Report.ReportingParty
		item.LocalReportID = strings.TrimSpace(local.Report.ID)
		item.LocalResponseID = strings.TrimSpace(local.Response.ID)
		item.LocalAmendmentID = strings.TrimSpace(local.Amendment.ID)
		item.LocalAmendmentStatus = local.Amendment.Status
		item.LocalSequence = local.Amendment.Sequence
		item.LocalChangedSections = append([]string(nil), local.Amendment.ChangedSections...)
		item.LocalUpdatedAt = cloneTimePtr(&local.Amendment.UpdatedAt)
		item.LocalSubmissionReference = strings.TrimSpace(local.Amendment.SubmissionReference)
		item.LocalAcknowledgementReference = strings.TrimSpace(local.Amendment.AcknowledgementReference)
	}
	if counterparty != nil {
		if item.OrganizationID == "" {
			orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(counterparty.OrganizationID))
			item.OrganizationID = strings.TrimSpace(counterparty.OrganizationID)
			item.SponsorOfRecord = strings.TrimSpace(orgSummary.SponsorOfRecord)
			item.OrganizationName = strings.TrimSpace(orgSummary.OrganizationName)
		}
		if item.IncidentID == "" {
			item.IncidentID = strings.TrimSpace(counterparty.Bundle.Amendment.IncidentID)
		}
		if item.Regulator == "" {
			item.Regulator = strings.TrimSpace(counterparty.Bundle.ReportSummary.Regulator)
		}
		if item.Framework == "" {
			item.Framework = strings.TrimSpace(counterparty.Bundle.ReportSummary.Framework)
		}
		if item.ReportType == "" {
			item.ReportType = strings.TrimSpace(counterparty.Bundle.ReportSummary.ReportType)
		}
		if item.ReportingParty == "" {
			item.ReportingParty = counterparty.Bundle.ReportSummary.ReportingParty
		}
		item.CounterpartySnapshotID = strings.TrimSpace(counterparty.SnapshotID)
		item.CounterpartyBundleID = strings.TrimSpace(counterparty.Bundle.ID)
		item.CounterpartyReportID = strings.TrimSpace(counterparty.Bundle.Amendment.ReportID)
		item.CounterpartyResponseID = strings.TrimSpace(counterparty.Bundle.Amendment.ResponseID)
		item.CounterpartyAmendmentID = strings.TrimSpace(counterparty.Bundle.Amendment.ID)
		item.CounterpartyBundleStatus = counterparty.Status
		item.CounterpartyAmendmentStatus = counterparty.Bundle.Amendment.Status
		item.CounterpartySequence = counterparty.Bundle.Amendment.Sequence
		item.CounterpartyChangedSections = append([]string(nil), counterparty.Bundle.Amendment.ChangedSections...)
		item.CounterpartyGeneratedAt = cloneTimePtr(&counterparty.Bundle.GeneratedAt)
		item.CounterpartyReceivedAt = cloneTimePtr(&counterparty.ReceivedAt)
		item.CounterpartySubmissionReference = strings.TrimSpace(counterparty.Bundle.Amendment.SubmissionReference)
		item.CounterpartyAcknowledgementReference = strings.TrimSpace(counterparty.Bundle.Amendment.AcknowledgementReference)
	}
	item.Status, item.Divergences = secureCellFederationIncidentReportAmendmentReconciliationStatusAndDivergences(local, counterparty)
	return item
}

func secureCellFederationIncidentReportAmendmentReconciliationForSnapshot(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot) SecureCellFederationIncidentReportAmendmentReconciliationSummary {
	key := secureCellFederationIncidentReportAmendmentComparisonKey(
		strings.TrimSpace(snapshot.OrganizationID),
		strings.TrimSpace(snapshot.Bundle.Amendment.IncidentID),
		snapshot.Bundle.ReportSummary.ReportingParty,
		strings.TrimSpace(snapshot.Bundle.ReportSummary.Regulator),
		strings.TrimSpace(snapshot.Bundle.ReportSummary.Framework),
		strings.TrimSpace(snapshot.Bundle.ReportSummary.ReportType),
		snapshot.Bundle.Amendment.Sequence,
	)
	return secureCellFederationIncidentReportAmendmentReconciliationSummaryFromRefs(run, key, secureCellLatestLocalFederationIncidentReportAmendmentByKey(run, key), &snapshot)
}

func secureCellFederationIncidentReportAmendmentReconciliationStatusAndDivergences(local *secureCellFederationIncidentReportAmendmentRef, counterparty *SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot) (SecureCellFederationIncidentReportAmendmentReconciliationStatus, []string) {
	if local == nil && counterparty == nil {
		return "", nil
	}
	if counterparty != nil {
		switch counterparty.Status {
		case SecureCellFederationCounterpartyIncidentReportAmendmentStatusInvalid:
			return SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyInvalid, nil
		case SecureCellFederationCounterpartyIncidentReportAmendmentStatusStale:
			return SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyStale, nil
		case SecureCellFederationCounterpartyIncidentReportAmendmentStatusExpired:
			return SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyExpired, nil
		}
	}
	if local == nil {
		return SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyOnly, nil
	}
	if counterparty == nil {
		return SecureCellFederationIncidentReportAmendmentReconciliationStatusLocalOnly, nil
	}
	diffs := make([]string, 0, 6)
	if local.Amendment.Status != counterparty.Bundle.Amendment.Status {
		diffs = append(diffs, "status")
	}
	if !equalTrimmedStringSets(local.Amendment.ChangedSections, counterparty.Bundle.Amendment.ChangedSections) {
		diffs = append(diffs, "changed_sections")
	}
	if !strings.EqualFold(strings.TrimSpace(local.Amendment.SubmissionReference), strings.TrimSpace(counterparty.Bundle.Amendment.SubmissionReference)) {
		diffs = append(diffs, "submission_reference")
	}
	if !strings.EqualFold(strings.TrimSpace(local.Amendment.AcknowledgementReference), strings.TrimSpace(counterparty.Bundle.Amendment.AcknowledgementReference)) {
		diffs = append(diffs, "acknowledgement_reference")
	}
	if (strings.TrimSpace(local.Amendment.SupersedesAmendmentID) == "") != (strings.TrimSpace(counterparty.Bundle.Amendment.SupersedesAmendmentID) == "") {
		diffs = append(diffs, "supersedes_state")
	}
	if len(diffs) > 0 {
		return SecureCellFederationIncidentReportAmendmentReconciliationStatusDivergent, diffs
	}
	return SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned, nil
}

func secureCellLatestLocalFederationIncidentReportAmendmentsByKey(run *secureCellRun) map[string]*secureCellFederationIncidentReportAmendmentRef {
	out := make(map[string]*secureCellFederationIncidentReportAmendmentRef)
	if run == nil || run.result == nil {
		return out
	}
	for responseIdx := range run.result.FederationIncidentResponses {
		response := &run.result.FederationIncidentResponses[responseIdx]
		for reportIdx := range response.IncidentReports {
			report := &response.IncidentReports[reportIdx]
			for amendmentIdx := range report.Amendments {
				amendment := &report.Amendments[amendmentIdx]
				key := secureCellFederationIncidentReportAmendmentComparisonKey(
					strings.TrimSpace(response.OrganizationID),
					strings.TrimSpace(amendment.IncidentID),
					report.ReportingParty,
					strings.TrimSpace(report.Regulator),
					strings.TrimSpace(report.Framework),
					strings.TrimSpace(report.ReportType),
					amendment.Sequence,
				)
				current := out[key]
				if current == nil || amendment.UpdatedAt.After(current.Amendment.UpdatedAt) {
					out[key] = &secureCellFederationIncidentReportAmendmentRef{
						Response:  response,
						Report:    report,
						Amendment: amendment,
					}
				}
			}
		}
	}
	return out
}

func secureCellLatestLocalFederationIncidentReportAmendmentByKey(run *secureCellRun, key string) *secureCellFederationIncidentReportAmendmentRef {
	return secureCellLatestLocalFederationIncidentReportAmendmentsByKey(run)[key]
}

func secureCellLatestCounterpartyFederationIncidentReportAmendmentsByKey(run *secureCellRun) map[string]*SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot {
	out := make(map[string]*SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot)
	if run == nil || run.result == nil {
		return out
	}
	for idx := range run.result.FederationCounterpartyIncidentReportAmendments {
		snapshot := &run.result.FederationCounterpartyIncidentReportAmendments[idx]
		key := secureCellFederationIncidentReportAmendmentComparisonKey(
			strings.TrimSpace(snapshot.OrganizationID),
			strings.TrimSpace(snapshot.Bundle.Amendment.IncidentID),
			snapshot.Bundle.ReportSummary.ReportingParty,
			strings.TrimSpace(snapshot.Bundle.ReportSummary.Regulator),
			strings.TrimSpace(snapshot.Bundle.ReportSummary.Framework),
			strings.TrimSpace(snapshot.Bundle.ReportSummary.ReportType),
			snapshot.Bundle.Amendment.Sequence,
		)
		current := out[key]
		if current == nil || snapshot.ReceivedAt.After(current.ReceivedAt) {
			out[key] = snapshot
		}
	}
	return out
}

func secureCellFederationIncidentReportAmendmentComparisonKey(organizationID string, incidentID string, reportingParty SecureCellFederationIncidentResponseParty, regulator string, framework string, reportType string, sequence int) string {
	return fmt.Sprintf("%s|%d", secureCellFederationIncidentReportComparisonKey(organizationID, incidentID, reportingParty, regulator, framework, reportType), sequence)
}

func secureCellFederationCounterpartyIncidentReportAmendmentStatusAt(bundle *SecureCellFederationIncidentReportAmendmentBundle, verificationErr error, now time.Time) (SecureCellFederationCounterpartyIncidentReportAmendmentStatus, string, bool) {
	now = now.UTC()
	if verificationErr != nil {
		return SecureCellFederationCounterpartyIncidentReportAmendmentStatusInvalid, verificationErr.Error(), false
	}
	if bundle == nil {
		return SecureCellFederationCounterpartyIncidentReportAmendmentStatusInvalid, "bundle is required", false
	}
	if bundle.ExpiresAt != nil && !bundle.ExpiresAt.IsZero() && now.After(bundle.ExpiresAt.UTC()) {
		return SecureCellFederationCounterpartyIncidentReportAmendmentStatusExpired, "counterparty incident report amendment bundle expired", true
	}
	if secureCellFederationIncidentReportAmendmentBundleIsStale(bundle, now) {
		return SecureCellFederationCounterpartyIncidentReportAmendmentStatusStale, "counterparty incident report amendment bundle is stale", true
	}
	return SecureCellFederationCounterpartyIncidentReportAmendmentStatusVerified, "counterparty incident report amendment bundle verified", true
}

func secureCellFederationIncidentReportAmendmentBundleIsStale(bundle *SecureCellFederationIncidentReportAmendmentBundle, now time.Time) bool {
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

func secureCellValidateFederationIncidentReportAmendmentBundleSemantics(bundle *SecureCellFederationIncidentReportAmendmentBundle, organizationID string) error {
	if bundle == nil {
		return fmt.Errorf("bundle is required")
	}
	expectedOrgID := strings.TrimSpace(organizationID)
	if expectedOrgID != "" {
		if !strings.EqualFold(strings.TrimSpace(bundle.Organization.OrganizationID), expectedOrgID) {
			return fmt.Errorf("bundle organization %q does not match target organization %q", strings.TrimSpace(bundle.Organization.OrganizationID), expectedOrgID)
		}
		if !strings.EqualFold(strings.TrimSpace(bundle.Amendment.OrganizationID), expectedOrgID) {
			return fmt.Errorf("amendment organization %q does not match target organization %q", strings.TrimSpace(bundle.Amendment.OrganizationID), expectedOrgID)
		}
	}
	if strings.TrimSpace(bundle.ReportSummary.ReportID) != strings.TrimSpace(bundle.Amendment.ReportID) {
		return fmt.Errorf("report summary/amendment report mismatch")
	}
	if strings.TrimSpace(bundle.ResponseSummary.ResponseID) != strings.TrimSpace(bundle.Amendment.ResponseID) {
		return fmt.Errorf("response summary/amendment response mismatch")
	}
	if strings.TrimSpace(bundle.AmendmentSummary.AmendmentID) != strings.TrimSpace(bundle.Amendment.ID) {
		return fmt.Errorf("amendment summary/amendment mismatch")
	}
	if strings.TrimSpace(bundle.AmendmentSummary.ReportID) != strings.TrimSpace(bundle.Amendment.ReportID) {
		return fmt.Errorf("amendment summary/report mismatch")
	}
	if strings.TrimSpace(bundle.AmendmentSummary.ResponseID) != strings.TrimSpace(bundle.Amendment.ResponseID) {
		return fmt.Errorf("amendment summary/response mismatch")
	}
	if strings.TrimSpace(bundle.AmendmentSummary.IncidentID) != strings.TrimSpace(bundle.Amendment.IncidentID) {
		return fmt.Errorf("amendment summary/incident mismatch")
	}
	if bundle.AmendmentSummary.Sequence != bundle.Amendment.Sequence {
		return fmt.Errorf("amendment summary/sequence mismatch")
	}
	if bundle.AmendmentSummary.Status != bundle.Amendment.Status {
		return fmt.Errorf("amendment summary/status mismatch")
	}
	return nil
}

func secureCellCloneFederationIncidentReportAmendmentBundle(in SecureCellFederationIncidentReportAmendmentBundle) SecureCellFederationIncidentReportAmendmentBundle {
	data, _ := json.Marshal(in)
	var out SecureCellFederationIncidentReportAmendmentBundle
	_ = json.Unmarshal(data, &out)
	return out
}

func secureCellFederationIncidentReportAmendmentBundleSignerName(bundle *SecureCellFederationIncidentReportAmendmentBundle) string {
	if bundle == nil || bundle.Signature == nil {
		return ""
	}
	return strings.TrimSpace(bundle.Signature.Signer)
}

func equalTrimmedStringSets(left, right []string) bool {
	lv := uniqueTrimmedStrings(left)
	rv := uniqueTrimmedStrings(right)
	if len(lv) != len(rv) {
		return false
	}
	sort.Strings(lv)
	sort.Strings(rv)
	for idx := range lv {
		if !strings.EqualFold(lv[idx], rv[idx]) {
			return false
		}
	}
	return true
}

func secureCellFederationCounterpartyIncidentReportAmendmentsByStatus(items []SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot, status SecureCellFederationCounterpartyIncidentReportAmendmentStatus) []SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot {
	if len(items) == 0 {
		return nil
	}
	out := make([]SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot, 0, len(items))
	for _, item := range items {
		if item.Status == status {
			out = append(out, item)
		}
	}
	return out
}

func secureCellFederationIncidentReportAmendmentReconciliationStatusCount(items []SecureCellFederationIncidentReportAmendmentReconciliationSummary, status SecureCellFederationIncidentReportAmendmentReconciliationStatus) int {
	total := 0
	for _, item := range items {
		if item.Status == status {
			total++
		}
	}
	return total
}

func secureCellFederationIncidentReportAmendmentReconciliationDivergentCount(items []SecureCellFederationIncidentReportAmendmentReconciliationSummary) int {
	total := 0
	for _, item := range items {
		switch item.Status {
		case SecureCellFederationIncidentReportAmendmentReconciliationStatusDivergent,
			SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyInvalid,
			SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyStale,
			SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyExpired:
			total++
		}
	}
	return total
}

func secureCellFederationIncidentReportAmendmentReconciliationUpdatedAt(item SecureCellFederationIncidentReportAmendmentReconciliationSummary) time.Time {
	if item.CounterpartyReceivedAt != nil {
		return item.CounterpartyReceivedAt.UTC()
	}
	if item.LocalUpdatedAt != nil {
		return item.LocalUpdatedAt.UTC()
	}
	return time.Time{}
}

func secureCellFederationIncidentReportAmendmentTotal(items []SecureCellFederationIncidentReport) int {
	total := 0
	for _, item := range items {
		total += len(item.Amendments)
	}
	return total
}

func secureCellFederationIncidentResponseReportAmendmentTotal(items []SecureCellFederationIncidentResponse) int {
	total := 0
	for _, item := range items {
		total += secureCellFederationIncidentReportAmendmentTotal(item.IncidentReports)
	}
	return total
}
