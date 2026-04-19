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

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

const secureCellFederationIncidentReportBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentReportStatus tracks one duty-to-notify
// obligation across its planning, submission, and acknowledgement lifecycle.
type SecureCellFederationIncidentReportStatus string

const (
	SecureCellFederationIncidentReportStatusPendingSubmission SecureCellFederationIncidentReportStatus = "pending_submission"
	SecureCellFederationIncidentReportStatusSubmitted         SecureCellFederationIncidentReportStatus = "submitted"
	SecureCellFederationIncidentReportStatusAcknowledged      SecureCellFederationIncidentReportStatus = "acknowledged"
)

// SecureCellFederationIncidentReport captures one governed regulatory or
// contractual notification obligation tied to a bilateral incident response.
type SecureCellFederationIncidentReport struct {
	ID                         string                                    `json:"id"`
	ResponseID                 string                                    `json:"response_id"`
	OrganizationID             string                                    `json:"organization_id"`
	SponsorOfRecord            string                                    `json:"sponsor_of_record,omitempty"`
	IncidentID                 string                                    `json:"incident_id"`
	ReportingParty             SecureCellFederationIncidentResponseParty `json:"reporting_party"`
	Regulator                  string                                    `json:"regulator"`
	Jurisdiction               string                                    `json:"jurisdiction,omitempty"`
	Framework                  string                                    `json:"framework,omitempty"`
	ReportType                 string                                    `json:"report_type,omitempty"`
	Status                     SecureCellFederationIncidentReportStatus  `json:"status"`
	Summary                    string                                    `json:"summary"`
	Description                string                                    `json:"description,omitempty"`
	RequiredSections           []string                                  `json:"required_sections,omitempty"`
	EvidenceIDs                []string                                  `json:"evidence_ids,omitempty"`
	DueAt                      *time.Time                                `json:"due_at,omitempty"`
	SubmissionReference        string                                    `json:"submission_reference,omitempty"`
	SubmissionReceiptID        string                                    `json:"submission_receipt_id,omitempty"`
	SubmissionReceiptHash      string                                    `json:"submission_receipt_hash,omitempty"`
	SubmissionSealID           string                                    `json:"submission_seal_id,omitempty"`
	SubmissionTraceLinkID      string                                    `json:"submission_trace_link_id,omitempty"`
	SubmittedBy                string                                    `json:"submitted_by,omitempty"`
	SubmittedAt                *time.Time                                `json:"submitted_at,omitempty"`
	AcknowledgementReference   string                                    `json:"acknowledgement_reference,omitempty"`
	AcknowledgementReceiptID   string                                    `json:"acknowledgement_receipt_id,omitempty"`
	AcknowledgementReceiptHash string                                    `json:"acknowledgement_receipt_hash,omitempty"`
	AcknowledgementSealID      string                                    `json:"acknowledgement_seal_id,omitempty"`
	AcknowledgementTraceLinkID string                                    `json:"acknowledgement_trace_link_id,omitempty"`
	AcknowledgedBy             string                                    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt             *time.Time                                `json:"acknowledged_at,omitempty"`
	CreatedBy                  string                                    `json:"created_by,omitempty"`
	CreatedAt                  time.Time                                 `json:"created_at"`
	UpdatedAt                  time.Time                                 `json:"updated_at"`
	Metadata                   map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportPlanRequest creates one pending reporting
// obligation that can later be submitted and acknowledged.
type SecureCellFederationIncidentReportPlanRequest struct {
	ActorDID         string                                    `json:"actor_did,omitempty"`
	ReportingParty   SecureCellFederationIncidentResponseParty `json:"reporting_party,omitempty"`
	Regulator        string                                    `json:"regulator,omitempty"`
	Jurisdiction     string                                    `json:"jurisdiction,omitempty"`
	Framework        string                                    `json:"framework,omitempty"`
	ReportType       string                                    `json:"report_type,omitempty"`
	Summary          string                                    `json:"summary,omitempty"`
	Description      string                                    `json:"description,omitempty"`
	RequiredSections []string                                  `json:"required_sections,omitempty"`
	EvidenceIDs      []string                                  `json:"evidence_ids,omitempty"`
	DueAt            *time.Time                                `json:"due_at,omitempty"`
	Reason           string                                    `json:"reason,omitempty"`
	Metadata         map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportSubmitRequest records one submitted
// regulator-ready report package for a previously planned obligation.
type SecureCellFederationIncidentReportSubmitRequest struct {
	ActorDID            string            `json:"actor_did,omitempty"`
	SubmissionReference string            `json:"submission_reference,omitempty"`
	Summary             string            `json:"summary,omitempty"`
	Description         string            `json:"description,omitempty"`
	EvidenceIDs         []string          `json:"evidence_ids,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAcknowledgeRequest records the receiving
// side's acknowledgement for one submitted obligation.
type SecureCellFederationIncidentReportAcknowledgeRequest struct {
	ActorDID                 string                                    `json:"actor_did,omitempty"`
	AcknowledgingParty       SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	AcknowledgementReference string                                    `json:"acknowledgement_reference,omitempty"`
	Reason                   string                                    `json:"reason,omitempty"`
	Metadata                 map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportFilter narrows operator queries across
// reporting obligations.
type SecureCellFederationIncidentReportFilter struct {
	CellID         string                                    `json:"cell_id,omitempty"`
	OrganizationID string                                    `json:"organization_id,omitempty"`
	IncidentID     string                                    `json:"incident_id,omitempty"`
	ResponseID     string                                    `json:"response_id,omitempty"`
	ReportID       string                                    `json:"report_id,omitempty"`
	ReportingParty SecureCellFederationIncidentResponseParty `json:"reporting_party,omitempty"`
	Status         SecureCellFederationIncidentReportStatus  `json:"status,omitempty"`
	Regulator      string                                    `json:"regulator,omitempty"`
	Since          *time.Time                                `json:"since,omitempty"`
	Until          *time.Time                                `json:"until,omitempty"`
	Limit          int                                       `json:"limit,omitempty"`
}

// SecureCellFederationIncidentReportSummary projects one reporting obligation
// for operator and auditor use.
type SecureCellFederationIncidentReportSummary struct {
	CellID                   string                                    `json:"cell_id"`
	CellName                 string                                    `json:"cell_name,omitempty"`
	Jurisdiction             string                                    `json:"jurisdiction,omitempty"`
	CellStatus               SecureCellStatus                          `json:"cell_status"`
	ResponseID               string                                    `json:"response_id"`
	OrganizationID           string                                    `json:"organization_id"`
	SponsorOfRecord          string                                    `json:"sponsor_of_record,omitempty"`
	IncidentID               string                                    `json:"incident_id"`
	ReportID                 string                                    `json:"report_id"`
	ReportingParty           SecureCellFederationIncidentResponseParty `json:"reporting_party"`
	Regulator                string                                    `json:"regulator"`
	Framework                string                                    `json:"framework,omitempty"`
	ReportType               string                                    `json:"report_type,omitempty"`
	Status                   SecureCellFederationIncidentReportStatus  `json:"status"`
	Summary                  string                                    `json:"summary"`
	Description              string                                    `json:"description,omitempty"`
	RequiredSections         []string                                  `json:"required_sections,omitempty"`
	EvidenceIDs              []string                                  `json:"evidence_ids,omitempty"`
	DueAt                    *time.Time                                `json:"due_at,omitempty"`
	Overdue                  bool                                      `json:"overdue"`
	SubmissionReference      string                                    `json:"submission_reference,omitempty"`
	SubmittedBy              string                                    `json:"submitted_by,omitempty"`
	SubmittedAt              *time.Time                                `json:"submitted_at,omitempty"`
	AcknowledgementReference string                                    `json:"acknowledgement_reference,omitempty"`
	AcknowledgedBy           string                                    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt           *time.Time                                `json:"acknowledged_at,omitempty"`
	CreatedBy                string                                    `json:"created_by,omitempty"`
	CreatedAt                time.Time                                 `json:"created_at"`
	UpdatedAt                time.Time                                 `json:"updated_at"`
	Metadata                 map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellOverdueFederationIncidentReportFilter narrows operator views over
// report obligations that crossed their submission deadline.
type SecureCellOverdueFederationIncidentReportFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ResponseID     string     `json:"response_id,omitempty"`
	Regulator      string     `json:"regulator,omitempty"`
	Before         *time.Time `json:"before,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellOverdueFederationIncidentReport projects one pending report that
// has crossed its due time.
type SecureCellOverdueFederationIncidentReport struct {
	CellID          string                                    `json:"cell_id"`
	CellName        string                                    `json:"cell_name,omitempty"`
	Jurisdiction    string                                    `json:"jurisdiction,omitempty"`
	CellStatus      SecureCellStatus                          `json:"cell_status"`
	ResponseID      string                                    `json:"response_id"`
	OrganizationID  string                                    `json:"organization_id"`
	SponsorOfRecord string                                    `json:"sponsor_of_record,omitempty"`
	IncidentID      string                                    `json:"incident_id"`
	ReportID        string                                    `json:"report_id"`
	ReportingParty  SecureCellFederationIncidentResponseParty `json:"reporting_party"`
	Regulator       string                                    `json:"regulator"`
	Framework       string                                    `json:"framework,omitempty"`
	ReportType      string                                    `json:"report_type,omitempty"`
	Status          SecureCellFederationIncidentReportStatus  `json:"status"`
	Summary         string                                    `json:"summary"`
	DueAt           time.Time                                 `json:"due_at"`
	OverdueSeconds  int64                                     `json:"overdue_seconds"`
	UpdatedAt       time.Time                                 `json:"updated_at"`
}

// SecureCellFederationIncidentReportBundleSignature captures detached signer
// metadata for one portable incident report bundle.
type SecureCellFederationIncidentReportBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentReportBundle is the signed portable auditor and
// regulator-facing bundle for one incident reporting obligation.
type SecureCellFederationIncidentReportBundle struct {
	ID                      string                                             `json:"id"`
	Version                 string                                             `json:"version"`
	Name                    string                                             `json:"name"`
	GeneratedAt             time.Time                                          `json:"generated_at"`
	ExpiresAt               *time.Time                                         `json:"expires_at,omitempty"`
	CellID                  string                                             `json:"cell_id"`
	CellName                string                                             `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                                   `json:"cell_status"`
	Jurisdiction            string                                             `json:"jurisdiction,omitempty"`
	Framework               string                                             `json:"framework,omitempty"`
	Organization            SecureCellFederationOrganizationSummary            `json:"organization"`
	ResponseSummary         SecureCellFederationIncidentResponseSummary        `json:"response_summary"`
	ReportSummary           SecureCellFederationIncidentReportSummary          `json:"report_summary"`
	Report                  SecureCellFederationIncidentReport                 `json:"report"`
	ResponseBundleHash      string                                             `json:"response_bundle_hash,omitempty"`
	Contracts               []SecureCellFederationContractSummary              `json:"contracts,omitempty"`
	Controls                []SecureCellFederationTrustPackControl             `json:"controls,omitempty"`
	OperatorSurfaces        []SecureCellFederationOperatorSurface              `json:"operator_surfaces,omitempty"`
	ControlLedgerID         string                                             `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                             `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                             `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                               `json:"portable_package_signed"`
	PortablePackageAnchored bool                                               `json:"portable_package_anchored"`
	ContentHash             string                                             `json:"content_hash,omitempty"`
	Signature               *SecureCellFederationIncidentReportBundleSignature `json:"signature,omitempty"`
	Metadata                map[string]string                                  `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportBundleOptions lets callers tune bundle
// identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentReportBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

func (s *Service) CreateFederationIncidentReport(ctx context.Context, cellID string, responseID string, req SecureCellFederationIncidentReportPlanRequest) (*SecureCellResult, error) {
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
	idx, response := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, responseID)
	if response == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w: %q", ErrFederationIncidentResponseNotFound, responseID)
	}
	if strings.TrimSpace(req.Summary) == "" {
		return nil, fmt.Errorf("securecells/federation-incident-report: report summary is required")
	}
	regulator := strings.TrimSpace(req.Regulator)
	if regulator == "" {
		return nil, fmt.Errorf("securecells/federation-incident-report: regulator is required")
	}
	party := secureCellNormalizedFederationIncidentResponseParty(req.ReportingParty)
	if party == "" {
		party = secureCellFederationIncidentReportDefaultParty(*response)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, party) {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w: actor %q is not permitted to plan reports for response %q", ErrPolicyDenied, actorDID, responseID)
	}
	dueAt := secureCellFederationIncidentReportDueAt(*response, req.DueAt)
	receipt, err := s.evaluateStage(ctx, run.request, "plan_federation_incident_report", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":      response.ID,
		"federation_organization_id":           response.OrganizationID,
		"federation_sponsor_of_record":         response.SponsorOfRecord,
		"federation_incident_id":               response.IncidentID,
		"federation_incident_report_party":     string(party),
		"federation_incident_report_regulator": regulator,
		"federation_incident_report_due_at":    dueAt.UTC().Format(time.RFC3339Nano),
		"transition_reason":                    firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	report := SecureCellFederationIncidentReport{
		ID:               secureCellFederationIncidentReportID(*response, actorDID, regulator, now, len(run.result.FederationIncidentResponses[idx].IncidentReports)),
		ResponseID:       response.ID,
		OrganizationID:   response.OrganizationID,
		SponsorOfRecord:  response.SponsorOfRecord,
		IncidentID:       response.IncidentID,
		ReportingParty:   party,
		Regulator:        regulator,
		Jurisdiction:     firstNonEmpty(strings.TrimSpace(req.Jurisdiction), run.request.Jurisdiction),
		Framework:        firstNonEmpty(strings.TrimSpace(req.Framework), strings.TrimSpace(s.config.Framework)),
		ReportType:       strings.TrimSpace(req.ReportType),
		Status:           SecureCellFederationIncidentReportStatusPendingSubmission,
		Summary:          strings.TrimSpace(req.Summary),
		Description:      strings.TrimSpace(req.Description),
		RequiredSections: append([]string(nil), uniqueTrimmedStrings(req.RequiredSections)...),
		EvidenceIDs:      append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...),
		DueAt:            cloneTimePtr(&dueAt),
		CreatedBy:        actorDID,
		CreatedAt:        now,
		UpdatedAt:        now,
		Metadata:         cloneStringMap(req.Metadata),
	}
	run.result.FederationIncidentResponses[idx].IncidentReports = append(run.result.FederationIncidentResponses[idx].IncidentReports, report)
	run.result.FederationIncidentResponses[idx].UpdatedAt = now
	run.result.FederationIncidentResponses[idx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[idx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_report_planned", report.ID),
		Action:           "secure_cell.federation_incident_report_planned",
		Actor:            actorDID,
		TargetType:       "federation_incident_report",
		TargetDID:        report.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":      response.ID,
			"federation_organization_id":           response.OrganizationID,
			"federation_sponsor_of_record":         response.SponsorOfRecord,
			"federation_incident_id":               response.IncidentID,
			"federation_incident_report_id":        report.ID,
			"federation_incident_report_party":     string(report.ReportingParty),
			"federation_incident_report_regulator": report.Regulator,
			"federation_incident_report_framework": report.Framework,
			"federation_incident_report_type":      report.ReportType,
			"federation_incident_report_status":    string(report.Status),
			"federation_incident_report_due_at":    dueAt.UTC().Format(time.RFC3339Nano),
			"federation_contract_ids":              strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) SubmitFederationIncidentReport(ctx context.Context, cellID string, reportID string, req SecureCellFederationIncidentReportSubmitRequest) (*SecureCellResult, error) {
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
	responseIdx, reportIdx, response, report := findSecureCellFederationIncidentReport(run.result.FederationIncidentResponses, reportID)
	if response == nil || report == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w: %q", ErrFederationIncidentResponseNotFound, reportID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, report.ReportingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w: actor %q is not permitted to submit report %q", ErrPolicyDenied, actorDID, reportID)
	}
	if report.Status == SecureCellFederationIncidentReportStatusAcknowledged {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w: report %q is already acknowledged", ErrFederationIncidentResponseImmutable, reportID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "submit_federation_incident_report", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":      response.ID,
		"federation_organization_id":           response.OrganizationID,
		"federation_sponsor_of_record":         response.SponsorOfRecord,
		"federation_incident_id":               response.IncidentID,
		"federation_incident_report_id":        report.ID,
		"federation_incident_report_party":     string(report.ReportingParty),
		"federation_incident_report_regulator": report.Regulator,
		"federation_incident_report_status":    string(report.Status),
		"federation_incident_report_reference": strings.TrimSpace(req.SubmissionReference),
		"transition_reason":                    firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary), report.Summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w", ErrPolicyDenied)
	}
	now := time.Now().UTC()
	updated := run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx]
	updated.Status = SecureCellFederationIncidentReportStatusSubmitted
	updated.SubmissionReference = firstNonEmpty(strings.TrimSpace(req.SubmissionReference), updated.SubmissionReference)
	if strings.TrimSpace(req.Summary) != "" {
		updated.Summary = strings.TrimSpace(req.Summary)
	}
	if strings.TrimSpace(req.Description) != "" {
		updated.Description = strings.TrimSpace(req.Description)
	}
	if len(req.EvidenceIDs) > 0 {
		updated.EvidenceIDs = append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...)
	}
	updated.SubmissionReceiptID = receipt.ID
	updated.SubmissionReceiptHash = receipt.ContentHash
	updated.SubmittedBy = actorDID
	updated.SubmittedAt = cloneTimePtr(&now)
	updated.UpdatedAt = now
	updated.Metadata = mergeStringMaps(updated.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx] = updated
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_report_submitted", report.ID),
		Action:           "secure_cell.federation_incident_report_submitted",
		Actor:            actorDID,
		TargetType:       "federation_incident_report",
		TargetDID:        report.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary), updated.Summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":      response.ID,
			"federation_organization_id":           response.OrganizationID,
			"federation_sponsor_of_record":         response.SponsorOfRecord,
			"federation_incident_id":               response.IncidentID,
			"federation_incident_report_id":        updated.ID,
			"federation_incident_report_party":     string(updated.ReportingParty),
			"federation_incident_report_regulator": updated.Regulator,
			"federation_incident_report_framework": updated.Framework,
			"federation_incident_report_type":      updated.ReportType,
			"federation_incident_report_status":    string(updated.Status),
			"federation_incident_report_reference": updated.SubmissionReference,
			"federation_contract_ids":              strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) AcknowledgeFederationIncidentReport(ctx context.Context, cellID string, reportID string, req SecureCellFederationIncidentReportAcknowledgeRequest) (*SecureCellResult, error) {
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
	responseIdx, reportIdx, response, report := findSecureCellFederationIncidentReport(run.result.FederationIncidentResponses, reportID)
	if response == nil || report == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w: %q", ErrFederationIncidentResponseNotFound, reportID)
	}
	party := secureCellNormalizedFederationIncidentResponseParty(req.AcknowledgingParty)
	if party == "" {
		party = secureCellFederationIncidentReportAcknowledgingParty(*report)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, party) {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w: actor %q is not permitted to acknowledge report %q", ErrPolicyDenied, actorDID, reportID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "acknowledge_federation_incident_report", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":      response.ID,
		"federation_organization_id":           response.OrganizationID,
		"federation_sponsor_of_record":         response.SponsorOfRecord,
		"federation_incident_id":               response.IncidentID,
		"federation_incident_report_id":        report.ID,
		"federation_incident_report_party":     string(report.ReportingParty),
		"federation_incident_report_regulator": report.Regulator,
		"federation_incident_report_status":    string(report.Status),
		"federation_incident_report_ack_party": string(party),
		"transition_reason":                    firstNonEmpty(strings.TrimSpace(req.Reason), report.Summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report: %w", ErrPolicyDenied)
	}
	now := time.Now().UTC()
	updated := run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx]
	updated.Status = SecureCellFederationIncidentReportStatusAcknowledged
	updated.AcknowledgementReference = firstNonEmpty(strings.TrimSpace(req.AcknowledgementReference), updated.AcknowledgementReference)
	updated.AcknowledgementReceiptID = receipt.ID
	updated.AcknowledgementReceiptHash = receipt.ContentHash
	updated.AcknowledgedBy = actorDID
	updated.AcknowledgedAt = cloneTimePtr(&now)
	updated.UpdatedAt = now
	updated.Metadata = mergeStringMaps(updated.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx] = updated
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_report_acknowledged", report.ID),
		Action:           "secure_cell.federation_incident_report_acknowledged",
		Actor:            actorDID,
		TargetType:       "federation_incident_report",
		TargetDID:        report.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), updated.Summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":      response.ID,
			"federation_organization_id":           response.OrganizationID,
			"federation_sponsor_of_record":         response.SponsorOfRecord,
			"federation_incident_id":               response.IncidentID,
			"federation_incident_report_id":        updated.ID,
			"federation_incident_report_party":     string(updated.ReportingParty),
			"federation_incident_report_regulator": updated.Regulator,
			"federation_incident_report_status":    string(updated.Status),
			"federation_incident_report_ack_party": string(party),
			"federation_incident_report_ack_ref":   updated.AcknowledgementReference,
			"federation_contract_ids":              strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationIncidentReports(_ context.Context, filter SecureCellFederationIncidentReportFilter) ([]SecureCellFederationIncidentReportSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentReportSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, response := range run.result.FederationIncidentResponses {
			if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(response.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
				continue
			}
			if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(response.IncidentID), strings.TrimSpace(filter.IncidentID)) {
				continue
			}
			if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(response.ID), strings.TrimSpace(filter.ResponseID)) {
				continue
			}
			for _, report := range response.IncidentReports {
				summary := secureCellFederationIncidentReportSummaryFromRun(run, response, report)
				if !matchesSecureCellFederationIncidentReportFilter(summary, filter) {
					continue
				}
				items = append(items, summary)
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListOverdueFederationIncidentReports(_ context.Context, filter SecureCellOverdueFederationIncidentReportFilter) ([]SecureCellOverdueFederationIncidentReport, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	items := make([]SecureCellOverdueFederationIncidentReport, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, response := range run.result.FederationIncidentResponses {
			if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(response.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
				continue
			}
			if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(response.IncidentID), strings.TrimSpace(filter.IncidentID)) {
				continue
			}
			if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(response.ID), strings.TrimSpace(filter.ResponseID)) {
				continue
			}
			for _, report := range response.IncidentReports {
				if !secureCellFederationIncidentReportIsOverdue(report, at) {
					continue
				}
				if filter.Regulator != "" && !strings.EqualFold(strings.TrimSpace(report.Regulator), strings.TrimSpace(filter.Regulator)) {
					continue
				}
				dueAt := report.CreatedAt
				if report.DueAt != nil {
					dueAt = report.DueAt.UTC()
				}
				items = append(items, SecureCellOverdueFederationIncidentReport{
					CellID:          run.result.CellID,
					CellName:        run.result.Name,
					Jurisdiction:    run.request.Jurisdiction,
					CellStatus:      run.result.Status,
					ResponseID:      response.ID,
					OrganizationID:  response.OrganizationID,
					SponsorOfRecord: response.SponsorOfRecord,
					IncidentID:      response.IncidentID,
					ReportID:        report.ID,
					ReportingParty:  report.ReportingParty,
					Regulator:       report.Regulator,
					Framework:       report.Framework,
					ReportType:      report.ReportType,
					Status:          report.Status,
					Summary:         report.Summary,
					DueAt:           dueAt,
					OverdueSeconds:  int64(at.Sub(dueAt).Seconds()),
					UpdatedAt:       report.UpdatedAt,
				})
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt.Equal(items[j].DueAt) {
			return items[i].UpdatedAt.After(items[j].UpdatedAt)
		}
		return items[i].DueAt.Before(items[j].DueAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) BuildFederationIncidentReportBundle(ctx context.Context, cellID string, reportID string, options SecureCellFederationIncidentReportBundleOptions) (*SecureCellFederationIncidentReportBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	responseSummary, reportSummary, response, report, err := secureCellFederationIncidentReportSummaryAndRefs(run, reportID)
	if err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, response.OrganizationID)
	if err != nil {
		return nil, err
	}
	cloned, err := cloneResult(&SecureCellResult{FederationIncidentResponses: []SecureCellFederationIncidentResponse{*response}})
	if err != nil {
		return nil, err
	}
	if cloned == nil || len(cloned.FederationIncidentResponses) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-report: failed to clone report %q", reportID)
	}
	clonedReport := *report
	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	responseBundle, err := s.BuildFederationIncidentResponseBundle(ctx, cellID, response.ID, SecureCellFederationIncidentResponseBundleOptions{
		OperatorSurfaces: cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:         cloneStringMap(options.Metadata),
	})
	if err != nil {
		return nil, err
	}
	bundle := &SecureCellFederationIncidentReportBundle{
		ID:                 firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-report-bundle", run.result.CellID, clonedReport.ID)),
		Version:            firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:               firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Incident Report Bundle %s", clonedReport.ID)),
		GeneratedAt:        now,
		ExpiresAt:          cloneTimePtr(&expiresAt),
		CellID:             run.result.CellID,
		CellName:           run.result.Name,
		CellStatus:         run.result.Status,
		Jurisdiction:       run.request.Jurisdiction,
		Framework:          firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:       orgSummary,
		ResponseSummary:    responseSummary,
		ReportSummary:      reportSummary,
		Report:             clonedReport,
		ResponseBundleHash: strings.TrimSpace(responseBundle.ContentHash),
		Contracts:          secureCellFederationContractSummariesForResponse(run, *response),
		Controls:           secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:   cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:           cloneStringMap(options.Metadata),
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
	if s.config.FederationIncidentReportBundleSigner != nil {
		if err := s.config.FederationIncidentReportBundleSigner(ctx, bundle); err != nil {
			return nil, err
		}
	} else if err := SignFederationIncidentReportBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

func VerifyFederationIncidentReportBundle(bundle *SecureCellFederationIncidentReportBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-report: bundle is required")
	}
	digest := secureCellFederationIncidentReportBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-report: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-report: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-report: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentReportBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-report: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-report: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-report: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-report: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-report: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-report: signature verification failed")
	}
	return nil
}

func SignFederationIncidentReportBundleEd25519(bundle *SecureCellFederationIncidentReportBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-report: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-report: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentReportBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])
	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentReportBundleSignature{
		Algorithm: secureCellFederationIncidentReportBundleSignatureAlgorithmED25519,
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

func secureCellFederationIncidentReportBundleDigest(bundle *SecureCellFederationIncidentReportBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}

func findSecureCellFederationIncidentReport(items []SecureCellFederationIncidentResponse, reportID string) (int, int, *SecureCellFederationIncidentResponse, *SecureCellFederationIncidentReport) {
	reportID = strings.TrimSpace(reportID)
	for responseIdx := range items {
		for reportIdx := range items[responseIdx].IncidentReports {
			if strings.TrimSpace(items[responseIdx].IncidentReports[reportIdx].ID) == reportID {
				return responseIdx, reportIdx, &items[responseIdx], &items[responseIdx].IncidentReports[reportIdx]
			}
		}
	}
	return -1, -1, nil, nil
}

func secureCellFederationIncidentReportID(response SecureCellFederationIncidentResponse, actorDID string, regulator string, at time.Time, ordinal int) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{response.ID, actorDID, strings.ToLower(strings.TrimSpace(regulator)), at.UTC().Format(time.RFC3339Nano), fmt.Sprintf("%d", ordinal)}, "|")))
	return fmt.Sprintf("federation-report-%x", sum[:10])
}

func secureCellFederationIncidentReportDefaultParty(response SecureCellFederationIncidentResponse) SecureCellFederationIncidentResponseParty {
	if response.SourceType == SecureCellFederationIncidentResponseSourceCounterpartyIncident {
		return SecureCellFederationIncidentResponsePartyCounterpartyOrg
	}
	return SecureCellFederationIncidentResponsePartyLocalOrg
}

func secureCellFederationIncidentReportAcknowledgingParty(report SecureCellFederationIncidentReport) SecureCellFederationIncidentResponseParty {
	if report.ReportingParty == SecureCellFederationIncidentResponsePartyCounterpartyOrg {
		return SecureCellFederationIncidentResponsePartyLocalOrg
	}
	return SecureCellFederationIncidentResponsePartyCounterpartyOrg
}

func secureCellFederationIncidentReportDueAt(response SecureCellFederationIncidentResponse, requested *time.Time) time.Time {
	if requested != nil && !requested.IsZero() {
		return requested.UTC()
	}
	base := time.Now().UTC()
	switch response.IncidentSeverity {
	case SecureCellFederationIncidentSeverityCritical:
		return base.Add(24 * time.Hour)
	case SecureCellFederationIncidentSeverityHigh:
		return base.Add(48 * time.Hour)
	default:
		return base.Add(72 * time.Hour)
	}
}

func secureCellFederationIncidentReportIsOverdue(report SecureCellFederationIncidentReport, at time.Time) bool {
	if report.Status != SecureCellFederationIncidentReportStatusPendingSubmission {
		return false
	}
	if report.DueAt == nil || report.DueAt.IsZero() {
		return false
	}
	return at.After(report.DueAt.UTC())
}

func secureCellFederationIncidentReportSummaryAndRefs(run *secureCellRun, reportID string) (SecureCellFederationIncidentResponseSummary, SecureCellFederationIncidentReportSummary, *SecureCellFederationIncidentResponse, *SecureCellFederationIncidentReport, error) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentResponseSummary{}, SecureCellFederationIncidentReportSummary{}, nil, nil, fmt.Errorf("securecells/federation-incident-report: secure cell result is required")
	}
	_, _, response, report := findSecureCellFederationIncidentReport(run.result.FederationIncidentResponses, reportID)
	if response == nil || report == nil {
		return SecureCellFederationIncidentResponseSummary{}, SecureCellFederationIncidentReportSummary{}, nil, nil, fmt.Errorf("securecells/federation-incident-report: %w: %q", ErrFederationIncidentResponseNotFound, reportID)
	}
	return secureCellFederationIncidentResponseSummaryFromRun(run, *response), secureCellFederationIncidentReportSummaryFromRun(run, *response, *report), response, report, nil
}

func secureCellFederationIncidentReportSummaryFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, report SecureCellFederationIncidentReport) SecureCellFederationIncidentReportSummary {
	summary := SecureCellFederationIncidentReportSummary{
		CellID:                   run.result.CellID,
		CellName:                 run.result.Name,
		Jurisdiction:             run.request.Jurisdiction,
		CellStatus:               run.result.Status,
		ResponseID:               response.ID,
		OrganizationID:           response.OrganizationID,
		SponsorOfRecord:          response.SponsorOfRecord,
		IncidentID:               response.IncidentID,
		ReportID:                 report.ID,
		ReportingParty:           report.ReportingParty,
		Regulator:                report.Regulator,
		Framework:                report.Framework,
		ReportType:               report.ReportType,
		Status:                   report.Status,
		Summary:                  report.Summary,
		Description:              report.Description,
		RequiredSections:         append([]string(nil), report.RequiredSections...),
		EvidenceIDs:              append([]string(nil), report.EvidenceIDs...),
		DueAt:                    cloneTimePtr(report.DueAt),
		SubmissionReference:      report.SubmissionReference,
		SubmittedBy:              report.SubmittedBy,
		SubmittedAt:              cloneTimePtr(report.SubmittedAt),
		AcknowledgementReference: report.AcknowledgementReference,
		AcknowledgedBy:           report.AcknowledgedBy,
		AcknowledgedAt:           cloneTimePtr(report.AcknowledgedAt),
		CreatedBy:                report.CreatedBy,
		CreatedAt:                report.CreatedAt,
		UpdatedAt:                report.UpdatedAt,
		Metadata:                 cloneStringMap(report.Metadata),
	}
	summary.Overdue = secureCellFederationIncidentReportIsOverdue(report, time.Now().UTC())
	return summary
}

func matchesSecureCellFederationIncidentReportFilter(summary SecureCellFederationIncidentReportSummary, filter SecureCellFederationIncidentReportFilter) bool {
	if filter.ReportID != "" && !strings.EqualFold(summary.ReportID, strings.TrimSpace(filter.ReportID)) {
		return false
	}
	if filter.ReportingParty != "" && summary.ReportingParty != filter.ReportingParty {
		return false
	}
	if filter.Status != "" && summary.Status != filter.Status {
		return false
	}
	if filter.Regulator != "" && !strings.EqualFold(summary.Regulator, strings.TrimSpace(filter.Regulator)) {
		return false
	}
	if filter.Since != nil && summary.CreatedAt.Before(filter.Since.UTC()) {
		return false
	}
	if filter.Until != nil && summary.CreatedAt.After(filter.Until.UTC()) {
		return false
	}
	return true
}

func secureCellFederationIncidentReportCountByStatus(items []SecureCellFederationIncidentReport, status SecureCellFederationIncidentReportStatus) int {
	total := 0
	for _, item := range items {
		if item.Status == status {
			total++
		}
	}
	return total
}

func secureCellFederationIncidentReportOverdueCount(items []SecureCellFederationIncidentReport, at time.Time) int {
	total := 0
	for _, item := range items {
		if secureCellFederationIncidentReportIsOverdue(item, at) {
			total++
		}
	}
	return total
}

func secureCellFederationIncidentReportNextDueAt(items []SecureCellFederationIncidentReport, at time.Time) *time.Time {
	var next *time.Time
	for _, item := range items {
		if item.Status != SecureCellFederationIncidentReportStatusPendingSubmission || item.DueAt == nil || item.DueAt.IsZero() {
			continue
		}
		dueAt := item.DueAt.UTC()
		if dueAt.Before(at) {
			return cloneTimePtr(&dueAt)
		}
		if next == nil || dueAt.Before(next.UTC()) {
			next = cloneTimePtr(&dueAt)
		}
	}
	return next
}

func secureCellFederationIncidentResponseReportTotal(items []SecureCellFederationIncidentResponse) int {
	total := 0
	for _, item := range items {
		total += len(item.IncidentReports)
	}
	return total
}
