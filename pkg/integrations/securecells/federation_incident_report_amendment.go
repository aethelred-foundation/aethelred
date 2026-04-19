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

const secureCellFederationIncidentReportAmendmentBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentReportAmendmentStatus tracks one governed
// amendment over an existing incident report.
type SecureCellFederationIncidentReportAmendmentStatus string

const (
	SecureCellFederationIncidentReportAmendmentStatusPendingSubmission SecureCellFederationIncidentReportAmendmentStatus = "pending_submission"
	SecureCellFederationIncidentReportAmendmentStatusSubmitted         SecureCellFederationIncidentReportAmendmentStatus = "submitted"
	SecureCellFederationIncidentReportAmendmentStatusAcknowledged      SecureCellFederationIncidentReportAmendmentStatus = "acknowledged"
)

// SecureCellFederationIncidentReportAmendment captures one governed revision
// over a previously planned or submitted incident report.
type SecureCellFederationIncidentReportAmendment struct {
	ID                         string                                            `json:"id"`
	ReportID                   string                                            `json:"report_id"`
	ResponseID                 string                                            `json:"response_id"`
	OrganizationID             string                                            `json:"organization_id"`
	SponsorOfRecord            string                                            `json:"sponsor_of_record,omitempty"`
	IncidentID                 string                                            `json:"incident_id"`
	Sequence                   int                                               `json:"sequence"`
	SupersedesAmendmentID      string                                            `json:"supersedes_amendment_id,omitempty"`
	Status                     SecureCellFederationIncidentReportAmendmentStatus `json:"status"`
	Summary                    string                                            `json:"summary"`
	Description                string                                            `json:"description,omitempty"`
	ChangedSections            []string                                          `json:"changed_sections,omitempty"`
	EvidenceIDs                []string                                          `json:"evidence_ids,omitempty"`
	SubmissionReference        string                                            `json:"submission_reference,omitempty"`
	SubmissionReceiptID        string                                            `json:"submission_receipt_id,omitempty"`
	SubmissionReceiptHash      string                                            `json:"submission_receipt_hash,omitempty"`
	SubmittedBy                string                                            `json:"submitted_by,omitempty"`
	SubmittedAt                *time.Time                                        `json:"submitted_at,omitempty"`
	AcknowledgementReference   string                                            `json:"acknowledgement_reference,omitempty"`
	AcknowledgementReceiptID   string                                            `json:"acknowledgement_receipt_id,omitempty"`
	AcknowledgementReceiptHash string                                            `json:"acknowledgement_receipt_hash,omitempty"`
	AcknowledgedBy             string                                            `json:"acknowledged_by,omitempty"`
	AcknowledgedAt             *time.Time                                        `json:"acknowledged_at,omitempty"`
	CreatedBy                  string                                            `json:"created_by,omitempty"`
	CreatedAt                  time.Time                                         `json:"created_at"`
	UpdatedAt                  time.Time                                         `json:"updated_at"`
	Metadata                   map[string]string                                 `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendRequest creates one pending report
// amendment that can later be submitted and acknowledged.
type SecureCellFederationIncidentReportAmendRequest struct {
	ActorDID        string            `json:"actor_did,omitempty"`
	Summary         string            `json:"summary,omitempty"`
	Description     string            `json:"description,omitempty"`
	ChangedSections []string          `json:"changed_sections,omitempty"`
	EvidenceIDs     []string          `json:"evidence_ids,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentSubmitRequest records one
// submitted amendment package for a planned amendment.
type SecureCellFederationIncidentReportAmendmentSubmitRequest struct {
	ActorDID            string            `json:"actor_did,omitempty"`
	SubmissionReference string            `json:"submission_reference,omitempty"`
	Summary             string            `json:"summary,omitempty"`
	Description         string            `json:"description,omitempty"`
	EvidenceIDs         []string          `json:"evidence_ids,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentAcknowledgeRequest records the
// receiving side's acknowledgement for one submitted amendment.
type SecureCellFederationIncidentReportAmendmentAcknowledgeRequest struct {
	ActorDID                 string                                    `json:"actor_did,omitempty"`
	AcknowledgingParty       SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	AcknowledgementReference string                                    `json:"acknowledgement_reference,omitempty"`
	Reason                   string                                    `json:"reason,omitempty"`
	Metadata                 map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentFilter narrows operator queries
// over report amendments.
type SecureCellFederationIncidentReportAmendmentFilter struct {
	CellID         string                                            `json:"cell_id,omitempty"`
	OrganizationID string                                            `json:"organization_id,omitempty"`
	IncidentID     string                                            `json:"incident_id,omitempty"`
	ResponseID     string                                            `json:"response_id,omitempty"`
	ReportID       string                                            `json:"report_id,omitempty"`
	AmendmentID    string                                            `json:"amendment_id,omitempty"`
	Status         SecureCellFederationIncidentReportAmendmentStatus `json:"status,omitempty"`
	Regulator      string                                            `json:"regulator,omitempty"`
	Since          *time.Time                                        `json:"since,omitempty"`
	Until          *time.Time                                        `json:"until,omitempty"`
	Limit          int                                               `json:"limit,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentSummary projects one amendment
// for operator and auditor use.
type SecureCellFederationIncidentReportAmendmentSummary struct {
	CellID                   string                                            `json:"cell_id"`
	CellName                 string                                            `json:"cell_name,omitempty"`
	Jurisdiction             string                                            `json:"jurisdiction,omitempty"`
	CellStatus               SecureCellStatus                                  `json:"cell_status"`
	ResponseID               string                                            `json:"response_id"`
	OrganizationID           string                                            `json:"organization_id"`
	SponsorOfRecord          string                                            `json:"sponsor_of_record,omitempty"`
	IncidentID               string                                            `json:"incident_id"`
	ReportID                 string                                            `json:"report_id"`
	ReportRegulator          string                                            `json:"report_regulator,omitempty"`
	ReportFramework          string                                            `json:"report_framework,omitempty"`
	ReportType               string                                            `json:"report_type,omitempty"`
	ReportStatus             SecureCellFederationIncidentReportStatus          `json:"report_status"`
	AmendmentID              string                                            `json:"amendment_id"`
	Sequence                 int                                               `json:"sequence"`
	SupersedesAmendmentID    string                                            `json:"supersedes_amendment_id,omitempty"`
	Status                   SecureCellFederationIncidentReportAmendmentStatus `json:"status"`
	Summary                  string                                            `json:"summary"`
	Description              string                                            `json:"description,omitempty"`
	ChangedSections          []string                                          `json:"changed_sections,omitempty"`
	EvidenceIDs              []string                                          `json:"evidence_ids,omitempty"`
	SubmissionReference      string                                            `json:"submission_reference,omitempty"`
	SubmittedBy              string                                            `json:"submitted_by,omitempty"`
	SubmittedAt              *time.Time                                        `json:"submitted_at,omitempty"`
	AcknowledgementReference string                                            `json:"acknowledgement_reference,omitempty"`
	AcknowledgedBy           string                                            `json:"acknowledged_by,omitempty"`
	AcknowledgedAt           *time.Time                                        `json:"acknowledged_at,omitempty"`
	CreatedBy                string                                            `json:"created_by,omitempty"`
	CreatedAt                time.Time                                         `json:"created_at"`
	UpdatedAt                time.Time                                         `json:"updated_at"`
	Metadata                 map[string]string                                 `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentBundleSignature captures detached
// signer metadata for one portable amendment bundle.
type SecureCellFederationIncidentReportAmendmentBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentReportAmendmentBundle is the signed portable
// auditor and regulator-facing bundle for one report amendment.
type SecureCellFederationIncidentReportAmendmentBundle struct {
	ID                      string                                                      `json:"id"`
	Version                 string                                                      `json:"version"`
	Name                    string                                                      `json:"name"`
	GeneratedAt             time.Time                                                   `json:"generated_at"`
	ExpiresAt               *time.Time                                                  `json:"expires_at,omitempty"`
	CellID                  string                                                      `json:"cell_id"`
	CellName                string                                                      `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                                            `json:"cell_status"`
	Jurisdiction            string                                                      `json:"jurisdiction,omitempty"`
	Framework               string                                                      `json:"framework,omitempty"`
	Organization            SecureCellFederationOrganizationSummary                     `json:"organization"`
	ResponseSummary         SecureCellFederationIncidentResponseSummary                 `json:"response_summary"`
	ReportSummary           SecureCellFederationIncidentReportSummary                   `json:"report_summary"`
	AmendmentSummary        SecureCellFederationIncidentReportAmendmentSummary          `json:"amendment_summary"`
	Amendment               SecureCellFederationIncidentReportAmendment                 `json:"amendment"`
	ReportBundleHash        string                                                      `json:"report_bundle_hash,omitempty"`
	Contracts               []SecureCellFederationContractSummary                       `json:"contracts,omitempty"`
	Controls                []SecureCellFederationTrustPackControl                      `json:"controls,omitempty"`
	OperatorSurfaces        []SecureCellFederationOperatorSurface                       `json:"operator_surfaces,omitempty"`
	ControlLedgerID         string                                                      `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                                      `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                                      `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                                        `json:"portable_package_signed"`
	PortablePackageAnchored bool                                                        `json:"portable_package_anchored"`
	ContentHash             string                                                      `json:"content_hash,omitempty"`
	Signature               *SecureCellFederationIncidentReportAmendmentBundleSignature `json:"signature,omitempty"`
	Metadata                map[string]string                                           `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentBundleOptions lets callers tune
// bundle identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentReportAmendmentBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

func (s *Service) AmendFederationIncidentReport(ctx context.Context, cellID string, reportID string, req SecureCellFederationIncidentReportAmendRequest) (*SecureCellResult, error) {
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
	responseIdx, reportIdx, response, report := findSecureCellFederationIncidentReport(run.result.FederationIncidentResponses, reportID)
	if response == nil || report == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w: %q", ErrFederationIncidentResponseNotFound, reportID)
	}
	if report.Status == SecureCellFederationIncidentReportStatusPendingSubmission {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w: report %q must be submitted before it can be amended", ErrFederationIncidentResponseImmutable, reportID)
	}
	if strings.TrimSpace(req.Summary) == "" {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: amendment summary is required")
	}
	if pending := secureCellActiveFederationIncidentReportAmendment(*report); pending != nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w: amendment %q is still active", ErrFederationIncidentResponseImmutable, pending.ID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, report.ReportingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w: actor %q is not permitted to amend report %q", ErrPolicyDenied, actorDID, reportID)
	}
	nextSequence := len(report.Amendments) + 1
	latest := secureCellLatestFederationIncidentReportAmendment(report.Amendments)
	receipt, err := s.evaluateStage(ctx, run.request, "amend_federation_incident_report", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":           response.ID,
		"federation_organization_id":                response.OrganizationID,
		"federation_sponsor_of_record":              response.SponsorOfRecord,
		"federation_incident_id":                    response.IncidentID,
		"federation_incident_report_id":             report.ID,
		"federation_incident_report_regulator":      report.Regulator,
		"federation_incident_report_amend_sequence": fmt.Sprintf("%d", nextSequence),
		"transition_reason":                         firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	amendment := SecureCellFederationIncidentReportAmendment{
		ID:              secureCellFederationIncidentReportAmendmentID(*report, actorDID, now, nextSequence),
		ReportID:        report.ID,
		ResponseID:      response.ID,
		OrganizationID:  response.OrganizationID,
		SponsorOfRecord: response.SponsorOfRecord,
		IncidentID:      response.IncidentID,
		Sequence:        nextSequence,
		Status:          SecureCellFederationIncidentReportAmendmentStatusPendingSubmission,
		Summary:         strings.TrimSpace(req.Summary),
		Description:     strings.TrimSpace(req.Description),
		ChangedSections: append([]string(nil), uniqueTrimmedStrings(req.ChangedSections)...),
		EvidenceIDs:     append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...),
		CreatedBy:       actorDID,
		CreatedAt:       now,
		UpdatedAt:       now,
		Metadata:        cloneStringMap(req.Metadata),
	}
	if latest != nil {
		amendment.SupersedesAmendmentID = latest.ID
	}
	updatedReport := run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx]
	updatedReport.Amendments = append(updatedReport.Amendments, amendment)
	updatedReport.UpdatedAt = now
	updatedReport.Metadata = mergeStringMaps(updatedReport.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx] = updatedReport
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_report_amendment_created", amendment.ID),
		Action:           "secure_cell.federation_incident_report_amendment_created",
		Actor:            actorDID,
		TargetType:       "federation_incident_report_amendment",
		TargetDID:        amendment.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), amendment.Summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":           response.ID,
			"federation_organization_id":                response.OrganizationID,
			"federation_sponsor_of_record":              response.SponsorOfRecord,
			"federation_incident_id":                    response.IncidentID,
			"federation_incident_report_id":             report.ID,
			"federation_incident_report_amendment_id":   amendment.ID,
			"federation_incident_report_amend_sequence": fmt.Sprintf("%d", amendment.Sequence),
			"federation_incident_report_amend_status":   string(amendment.Status),
			"federation_incident_report_regulator":      report.Regulator,
			"federation_contract_ids":                   strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) SubmitFederationIncidentReportAmendment(ctx context.Context, cellID string, amendmentID string, req SecureCellFederationIncidentReportAmendmentSubmitRequest) (*SecureCellResult, error) {
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
	responseIdx, reportIdx, amendmentIdx, response, report, amendment := findSecureCellFederationIncidentReportAmendment(run.result.FederationIncidentResponses, amendmentID)
	if response == nil || report == nil || amendment == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w: %q", ErrFederationIncidentResponseNotFound, amendmentID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, report.ReportingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w: actor %q is not permitted to submit amendment %q", ErrPolicyDenied, actorDID, amendmentID)
	}
	if amendment.Status == SecureCellFederationIncidentReportAmendmentStatusAcknowledged {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w: amendment %q is already acknowledged", ErrFederationIncidentResponseImmutable, amendmentID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "submit_federation_incident_report_amendment", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":            response.ID,
		"federation_organization_id":                 response.OrganizationID,
		"federation_sponsor_of_record":               response.SponsorOfRecord,
		"federation_incident_id":                     response.IncidentID,
		"federation_incident_report_id":              report.ID,
		"federation_incident_report_amendment_id":    amendment.ID,
		"federation_incident_report_amend_sequence":  fmt.Sprintf("%d", amendment.Sequence),
		"federation_incident_report_amend_status":    string(amendment.Status),
		"federation_incident_report_amend_reference": strings.TrimSpace(req.SubmissionReference),
		"transition_reason":                          firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary), amendment.Summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w", ErrPolicyDenied)
	}
	now := time.Now().UTC()
	updated := run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx].Amendments[amendmentIdx]
	updated.Status = SecureCellFederationIncidentReportAmendmentStatusSubmitted
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
	run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx].Amendments[amendmentIdx] = updated
	run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_report_amendment_submitted", updated.ID),
		Action:           "secure_cell.federation_incident_report_amendment_submitted",
		Actor:            actorDID,
		TargetType:       "federation_incident_report_amendment",
		TargetDID:        updated.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary), updated.Summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":            response.ID,
			"federation_organization_id":                 response.OrganizationID,
			"federation_sponsor_of_record":               response.SponsorOfRecord,
			"federation_incident_id":                     response.IncidentID,
			"federation_incident_report_id":              report.ID,
			"federation_incident_report_amendment_id":    updated.ID,
			"federation_incident_report_amend_sequence":  fmt.Sprintf("%d", updated.Sequence),
			"federation_incident_report_amend_status":    string(updated.Status),
			"federation_incident_report_amend_reference": updated.SubmissionReference,
			"federation_contract_ids":                    strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) AcknowledgeFederationIncidentReportAmendment(ctx context.Context, cellID string, amendmentID string, req SecureCellFederationIncidentReportAmendmentAcknowledgeRequest) (*SecureCellResult, error) {
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
	responseIdx, reportIdx, amendmentIdx, response, report, amendment := findSecureCellFederationIncidentReportAmendment(run.result.FederationIncidentResponses, amendmentID)
	if response == nil || report == nil || amendment == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w: %q", ErrFederationIncidentResponseNotFound, amendmentID)
	}
	party := secureCellNormalizedFederationIncidentResponseParty(req.AcknowledgingParty)
	if party == "" {
		party = secureCellFederationIncidentReportAcknowledgingParty(*report)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, party) {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w: actor %q is not permitted to acknowledge amendment %q", ErrPolicyDenied, actorDID, amendmentID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "acknowledge_federation_incident_report_amendment", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":            response.ID,
		"federation_organization_id":                 response.OrganizationID,
		"federation_sponsor_of_record":               response.SponsorOfRecord,
		"federation_incident_id":                     response.IncidentID,
		"federation_incident_report_id":              report.ID,
		"federation_incident_report_amendment_id":    amendment.ID,
		"federation_incident_report_amend_sequence":  fmt.Sprintf("%d", amendment.Sequence),
		"federation_incident_report_amend_status":    string(amendment.Status),
		"federation_incident_report_amend_ack_party": string(party),
		"transition_reason":                          firstNonEmpty(strings.TrimSpace(req.Reason), amendment.Summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w", ErrPolicyDenied)
	}
	now := time.Now().UTC()
	updated := run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx].Amendments[amendmentIdx]
	updated.Status = SecureCellFederationIncidentReportAmendmentStatusAcknowledged
	updated.AcknowledgementReference = firstNonEmpty(strings.TrimSpace(req.AcknowledgementReference), updated.AcknowledgementReference)
	updated.AcknowledgementReceiptID = receipt.ID
	updated.AcknowledgementReceiptHash = receipt.ContentHash
	updated.AcknowledgedBy = actorDID
	updated.AcknowledgedAt = cloneTimePtr(&now)
	updated.UpdatedAt = now
	updated.Metadata = mergeStringMaps(updated.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx].Amendments[amendmentIdx] = updated
	run.result.FederationIncidentResponses[responseIdx].IncidentReports[reportIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_report_amendment_acknowledged", updated.ID),
		Action:           "secure_cell.federation_incident_report_amendment_acknowledged",
		Actor:            actorDID,
		TargetType:       "federation_incident_report_amendment",
		TargetDID:        updated.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), updated.Summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":            response.ID,
			"federation_organization_id":                 response.OrganizationID,
			"federation_sponsor_of_record":               response.SponsorOfRecord,
			"federation_incident_id":                     response.IncidentID,
			"federation_incident_report_id":              report.ID,
			"federation_incident_report_amendment_id":    updated.ID,
			"federation_incident_report_amend_sequence":  fmt.Sprintf("%d", updated.Sequence),
			"federation_incident_report_amend_status":    string(updated.Status),
			"federation_incident_report_amend_ack_ref":   updated.AcknowledgementReference,
			"federation_incident_report_amend_ack_party": string(party),
			"federation_contract_ids":                    strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationIncidentReportAmendments(_ context.Context, filter SecureCellFederationIncidentReportAmendmentFilter) ([]SecureCellFederationIncidentReportAmendmentSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentReportAmendmentSummary, 0)
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
				if filter.ReportID != "" && !strings.EqualFold(strings.TrimSpace(report.ID), strings.TrimSpace(filter.ReportID)) {
					continue
				}
				if filter.Regulator != "" && !strings.EqualFold(strings.TrimSpace(report.Regulator), strings.TrimSpace(filter.Regulator)) {
					continue
				}
				for _, amendment := range report.Amendments {
					summary := secureCellFederationIncidentReportAmendmentSummaryFromRun(run, response, report, amendment)
					if !matchesSecureCellFederationIncidentReportAmendmentFilter(summary, filter) {
						continue
					}
					items = append(items, summary)
				}
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

func (s *Service) BuildFederationIncidentReportAmendmentBundle(ctx context.Context, cellID string, amendmentID string, options SecureCellFederationIncidentReportAmendmentBundleOptions) (*SecureCellFederationIncidentReportAmendmentBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	responseSummary, reportSummary, amendmentSummary, response, report, amendment, err := secureCellFederationIncidentReportAmendmentSummaryAndRefs(run, amendmentID)
	if err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, response.OrganizationID)
	if err != nil {
		return nil, err
	}
	reportBundle, err := s.BuildFederationIncidentReportBundle(ctx, cellID, report.ID, SecureCellFederationIncidentReportBundleOptions{
		OperatorSurfaces: cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:         cloneStringMap(options.Metadata),
	})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationIncidentReportAmendmentBundle{
		ID:               firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-report-amendment-bundle", run.result.CellID, amendment.ID)),
		Version:          firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:             firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Incident Report Amendment Bundle %s", amendment.ID)),
		GeneratedAt:      now,
		ExpiresAt:        cloneTimePtr(&expiresAt),
		CellID:           run.result.CellID,
		CellName:         run.result.Name,
		CellStatus:       run.result.Status,
		Jurisdiction:     run.request.Jurisdiction,
		Framework:        firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:     orgSummary,
		ResponseSummary:  responseSummary,
		ReportSummary:    reportSummary,
		AmendmentSummary: amendmentSummary,
		Amendment:        *amendment,
		ReportBundleHash: strings.TrimSpace(reportBundle.ContentHash),
		Contracts:        secureCellFederationContractSummariesForResponse(run, *response),
		Controls:         secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces: cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:         cloneStringMap(options.Metadata),
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
	if s.config.FederationIncidentReportAmendmentBundleSigner != nil {
		if err := s.config.FederationIncidentReportAmendmentBundleSigner(ctx, bundle); err != nil {
			return nil, err
		}
	} else if err := SignFederationIncidentReportAmendmentBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

func VerifyFederationIncidentReportAmendmentBundle(bundle *SecureCellFederationIncidentReportAmendmentBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-report-amendment: bundle is required")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-report-amendment: bundle signature is required")
	}
	digest := secureCellFederationIncidentReportAmendmentBundleDigest(bundle)
	if bundle.ContentHash != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("securecells/federation-incident-report-amendment: bundle content hash mismatch")
	}
	signature, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-report-amendment: invalid bundle signature: %w", err)
	}
	publicKey, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-report-amendment: invalid bundle public key: %w", err)
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentReportAmendmentBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-report-amendment: unsupported bundle signature algorithm %q", bundle.Signature.Algorithm)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), digest[:], signature) {
		return fmt.Errorf("securecells/federation-incident-report-amendment: bundle signature verification failed")
	}
	return nil
}

func SignFederationIncidentReportAmendmentBundleEd25519(bundle *SecureCellFederationIncidentReportAmendmentBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-report-amendment: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-report-amendment: package signing key is invalid")
	}
	digest := secureCellFederationIncidentReportAmendmentBundleDigest(bundle)
	signature := ed25519.Sign(privateKey, digest[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentReportAmendmentBundleSignature{
		Algorithm: secureCellFederationIncidentReportAmendmentBundleSignatureAlgorithmED25519,
		Signer:    strings.TrimSpace(signer),
		KeyID:     fmt.Sprintf("ed25519:%x", sha256.Sum256(publicKey)),
		Signature: hex.EncodeToString(signature),
		SignedAt:  time.Now().UTC(),
	}
	if includeVerificationKeys {
		bundle.Signature.PublicKey = hex.EncodeToString(publicKey)
	}
	return nil
}

func secureCellFederationIncidentReportAmendmentBundleDigest(bundle *SecureCellFederationIncidentReportAmendmentBundle) [32]byte {
	type alias SecureCellFederationIncidentReportAmendmentBundle
	cloned := *bundle
	cloned.Signature = nil
	cloned.ContentHash = ""
	raw, _ := json.Marshal(alias(cloned))
	return sha256.Sum256(raw)
}

func findSecureCellFederationIncidentReportAmendment(items []SecureCellFederationIncidentResponse, amendmentID string) (int, int, int, *SecureCellFederationIncidentResponse, *SecureCellFederationIncidentReport, *SecureCellFederationIncidentReportAmendment) {
	amendmentID = strings.TrimSpace(amendmentID)
	for responseIdx := range items {
		for reportIdx := range items[responseIdx].IncidentReports {
			for amendmentIdx := range items[responseIdx].IncidentReports[reportIdx].Amendments {
				if strings.TrimSpace(items[responseIdx].IncidentReports[reportIdx].Amendments[amendmentIdx].ID) == amendmentID {
					return responseIdx, reportIdx, amendmentIdx, &items[responseIdx], &items[responseIdx].IncidentReports[reportIdx], &items[responseIdx].IncidentReports[reportIdx].Amendments[amendmentIdx]
				}
			}
		}
	}
	return -1, -1, -1, nil, nil, nil
}

func secureCellFederationIncidentReportAmendmentID(report SecureCellFederationIncidentReport, actorDID string, at time.Time, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d", report.ID, strings.TrimSpace(actorDID), at.UTC().Format(time.RFC3339Nano), ordinal)
	return fmt.Sprintf("%s-amendment-%x", report.ID, sha256.Sum256([]byte(seed)))
}

func secureCellActiveFederationIncidentReportAmendment(report SecureCellFederationIncidentReport) *SecureCellFederationIncidentReportAmendment {
	for idx := len(report.Amendments) - 1; idx >= 0; idx-- {
		switch report.Amendments[idx].Status {
		case SecureCellFederationIncidentReportAmendmentStatusPendingSubmission, SecureCellFederationIncidentReportAmendmentStatusSubmitted:
			return &report.Amendments[idx]
		}
	}
	return nil
}

func secureCellLatestFederationIncidentReportAmendment(items []SecureCellFederationIncidentReportAmendment) *SecureCellFederationIncidentReportAmendment {
	if len(items) == 0 {
		return nil
	}
	return &items[len(items)-1]
}

func secureCellFederationIncidentReportAmendmentSummaryAndRefs(run *secureCellRun, amendmentID string) (SecureCellFederationIncidentResponseSummary, SecureCellFederationIncidentReportSummary, SecureCellFederationIncidentReportAmendmentSummary, *SecureCellFederationIncidentResponse, *SecureCellFederationIncidentReport, *SecureCellFederationIncidentReportAmendment, error) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentResponseSummary{}, SecureCellFederationIncidentReportSummary{}, SecureCellFederationIncidentReportAmendmentSummary{}, nil, nil, nil, fmt.Errorf("securecells/federation-incident-report-amendment: secure cell result is required")
	}
	_, _, _, response, report, amendment := findSecureCellFederationIncidentReportAmendment(run.result.FederationIncidentResponses, amendmentID)
	if response == nil || report == nil || amendment == nil {
		return SecureCellFederationIncidentResponseSummary{}, SecureCellFederationIncidentReportSummary{}, SecureCellFederationIncidentReportAmendmentSummary{}, nil, nil, nil, fmt.Errorf("securecells/federation-incident-report-amendment: %w: %q", ErrFederationIncidentResponseNotFound, amendmentID)
	}
	return secureCellFederationIncidentResponseSummaryFromRun(run, *response), secureCellFederationIncidentReportSummaryFromRun(run, *response, *report), secureCellFederationIncidentReportAmendmentSummaryFromRun(run, *response, *report, *amendment), response, report, amendment, nil
}

func secureCellFederationIncidentReportAmendmentSummaryFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, report SecureCellFederationIncidentReport, amendment SecureCellFederationIncidentReportAmendment) SecureCellFederationIncidentReportAmendmentSummary {
	return SecureCellFederationIncidentReportAmendmentSummary{
		CellID:                   run.result.CellID,
		CellName:                 run.result.Name,
		Jurisdiction:             run.request.Jurisdiction,
		CellStatus:               run.result.Status,
		ResponseID:               response.ID,
		OrganizationID:           response.OrganizationID,
		SponsorOfRecord:          response.SponsorOfRecord,
		IncidentID:               response.IncidentID,
		ReportID:                 report.ID,
		ReportRegulator:          report.Regulator,
		ReportFramework:          report.Framework,
		ReportType:               report.ReportType,
		ReportStatus:             report.Status,
		AmendmentID:              amendment.ID,
		Sequence:                 amendment.Sequence,
		SupersedesAmendmentID:    amendment.SupersedesAmendmentID,
		Status:                   amendment.Status,
		Summary:                  amendment.Summary,
		Description:              amendment.Description,
		ChangedSections:          append([]string(nil), amendment.ChangedSections...),
		EvidenceIDs:              append([]string(nil), amendment.EvidenceIDs...),
		SubmissionReference:      amendment.SubmissionReference,
		SubmittedBy:              amendment.SubmittedBy,
		SubmittedAt:              cloneTimePtr(amendment.SubmittedAt),
		AcknowledgementReference: amendment.AcknowledgementReference,
		AcknowledgedBy:           amendment.AcknowledgedBy,
		AcknowledgedAt:           cloneTimePtr(amendment.AcknowledgedAt),
		CreatedBy:                amendment.CreatedBy,
		CreatedAt:                amendment.CreatedAt,
		UpdatedAt:                amendment.UpdatedAt,
		Metadata:                 cloneStringMap(amendment.Metadata),
	}
}

func matchesSecureCellFederationIncidentReportAmendmentFilter(summary SecureCellFederationIncidentReportAmendmentSummary, filter SecureCellFederationIncidentReportAmendmentFilter) bool {
	if filter.AmendmentID != "" && !strings.EqualFold(summary.AmendmentID, strings.TrimSpace(filter.AmendmentID)) {
		return false
	}
	if filter.Status != "" && summary.Status != filter.Status {
		return false
	}
	if filter.Since != nil && summary.UpdatedAt.Before(filter.Since.UTC()) {
		return false
	}
	if filter.Until != nil && summary.UpdatedAt.After(filter.Until.UTC()) {
		return false
	}
	return true
}
