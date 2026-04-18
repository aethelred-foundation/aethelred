package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/evidence"
)

// SecureCellFederationOrganizationFilter narrows operator queries across
// federated organizations.
type SecureCellFederationOrganizationFilter struct {
	CellID          string                                 `json:"cell_id,omitempty"`
	Status          SecureCellFederationOrganizationStatus `json:"status,omitempty"`
	Jurisdiction    string                                 `json:"jurisdiction,omitempty"`
	SponsorOfRecord string                                 `json:"sponsor_of_record,omitempty"`
	ParticipantDID  string                                 `json:"participant_did,omitempty"`
	UpdatedAfter    *time.Time                             `json:"updated_after,omitempty"`
	UpdatedBefore   *time.Time                             `json:"updated_before,omitempty"`
	Limit           int                                    `json:"limit,omitempty"`
}

// SecureCellFederationInvitationFilter narrows operator queries across
// federation invitations.
type SecureCellFederationInvitationFilter struct {
	CellID          string                               `json:"cell_id,omitempty"`
	OrganizationID  string                               `json:"organization_id,omitempty"`
	Status          SecureCellFederationInvitationStatus `json:"status,omitempty"`
	Jurisdiction    string                               `json:"jurisdiction,omitempty"`
	SponsorOfRecord string                               `json:"sponsor_of_record,omitempty"`
	ExpectedDID     string                               `json:"expected_did,omitempty"`
	UpdatedAfter    *time.Time                           `json:"updated_after,omitempty"`
	UpdatedBefore   *time.Time                           `json:"updated_before,omitempty"`
	Limit           int                                  `json:"limit,omitempty"`
}

// SecureCellFederationOrganizationSummary is the operator-facing summary of one
// federated organization inside one secure cell.
type SecureCellFederationOrganizationSummary struct {
	CellID                  string                                 `json:"cell_id"`
	CellName                string                                 `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                       `json:"cell_status"`
	Jurisdiction            string                                 `json:"jurisdiction,omitempty"`
	OrganizationID          string                                 `json:"organization_id"`
	SponsorOfRecord         string                                 `json:"sponsor_of_record,omitempty"`
	OrganizationName        string                                 `json:"organization_name,omitempty"`
	Status                  SecureCellFederationOrganizationStatus `json:"status"`
	ParticipantDIDs         []string                               `json:"participant_dids,omitempty"`
	ParticipantCount        int                                    `json:"participant_count"`
	ActiveParticipantCount  int                                    `json:"active_participant_count"`
	InvitationCount         int                                    `json:"invitation_count"`
	PendingInvitationCount  int                                    `json:"pending_invitation_count"`
	AcceptedInvitationCount int                                    `json:"accepted_invitation_count"`
	RevokedInvitationCount  int                                    `json:"revoked_invitation_count"`
	ContractCount           int                                    `json:"contract_count"`
	ActiveContractCount     int                                    `json:"active_contract_count"`
	RevokedContractCount    int                                    `json:"revoked_contract_count"`
	ControlLedgerID         string                                 `json:"control_ledger_id,omitempty"`
	PortablePackageHash     string                                 `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                   `json:"portable_package_signed"`
	PortablePackageAnchored bool                                   `json:"portable_package_anchored"`
	CreatedAt               time.Time                              `json:"created_at,omitempty"`
	UpdatedAt               time.Time                              `json:"updated_at,omitempty"`
}

// SecureCellFederationInvitationSummary is the operator-facing summary of one
// federation invitation.
type SecureCellFederationInvitationSummary struct {
	CellID                  string                               `json:"cell_id"`
	CellName                string                               `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                     `json:"cell_status"`
	Jurisdiction            string                               `json:"jurisdiction,omitempty"`
	InvitationID            string                               `json:"invitation_id"`
	OrganizationID          string                               `json:"organization_id"`
	SponsorOfRecord         string                               `json:"sponsor_of_record,omitempty"`
	OrganizationName        string                               `json:"organization_name,omitempty"`
	Status                  SecureCellFederationInvitationStatus `json:"status"`
	ExpectedDID             string                               `json:"expected_did,omitempty"`
	Role                    string                               `json:"role,omitempty"`
	SessionScopeCount       int                                  `json:"session_scope_count"`
	DataClassCount          int                                  `json:"data_class_count"`
	ComputeZoneCount        int                                  `json:"compute_zone_count"`
	Resource                string                               `json:"resource,omitempty"`
	CreatedBy               string                               `json:"created_by,omitempty"`
	AcceptedBy              string                               `json:"accepted_by,omitempty"`
	RevokedBy               string                               `json:"revoked_by,omitempty"`
	Reason                  string                               `json:"reason,omitempty"`
	ControlLedgerID         string                               `json:"control_ledger_id,omitempty"`
	PortablePackageHash     string                               `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                 `json:"portable_package_signed"`
	PortablePackageAnchored bool                                 `json:"portable_package_anchored"`
	CreatedAt               time.Time                            `json:"created_at,omitempty"`
	AcceptedAt              *time.Time                           `json:"accepted_at,omitempty"`
	RevokedAt               *time.Time                           `json:"revoked_at,omitempty"`
	UpdatedAt               time.Time                            `json:"updated_at,omitempty"`
}

// SecureCellFederationOperatorSurface documents one buyer- or operator-facing
// federation runtime surface.
type SecureCellFederationOperatorSurface struct {
	ID          string   `json:"id"`
	Method      string   `json:"method,omitempty"`
	Path        string   `json:"path,omitempty"`
	Description string   `json:"description,omitempty"`
	Formats     []string `json:"formats,omitempty"`
}

// SecureCellFederationTrustPackControl captures one federation-facing control
// included in a trust pack or invitation bundle.
type SecureCellFederationTrustPackControl struct {
	ControlID     string   `json:"control_id"`
	ControlName   string   `json:"control_name"`
	Description   string   `json:"description,omitempty"`
	EvidenceTypes []string `json:"evidence_types,omitempty"`
}

// SecureCellFederationOrganizationRuntime summarizes current runtime posture
// for one participating organization.
type SecureCellFederationOrganizationRuntime struct {
	ParticipantCount        int       `json:"participant_count"`
	ActiveParticipantCount  int       `json:"active_participant_count"`
	QuarantinedParticipants int       `json:"quarantined_participants"`
	RevokedParticipants     int       `json:"revoked_participants"`
	InvitationCount         int       `json:"invitation_count"`
	PendingInvitations      int       `json:"pending_invitations"`
	AcceptedInvitations     int       `json:"accepted_invitations"`
	RevokedInvitations      int       `json:"revoked_invitations"`
	ContractCount           int       `json:"contract_count"`
	ActiveContracts         int       `json:"active_contracts"`
	RevokedContracts        int       `json:"revoked_contracts"`
	LastUpdatedAt           time.Time `json:"last_updated_at,omitempty"`
}

// SecureCellFederationOrganizationTrustPack is the buyer- and operator-facing
// trust-pack summary for one collaborating organization inside one secure cell.
type SecureCellFederationOrganizationTrustPack struct {
	ID                      string                                  `json:"id"`
	Version                 string                                  `json:"version"`
	Name                    string                                  `json:"name"`
	Sector                  string                                  `json:"sector"`
	GeneratedAt             time.Time                               `json:"generated_at"`
	CellID                  string                                  `json:"cell_id"`
	CellName                string                                  `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                        `json:"cell_status"`
	Jurisdiction            string                                  `json:"jurisdiction,omitempty"`
	Framework               string                                  `json:"framework,omitempty"`
	PolicySetID             string                                  `json:"policy_set_id,omitempty"`
	PolicySetName           string                                  `json:"policy_set_name,omitempty"`
	RequiredTool            string                                  `json:"required_tool,omitempty"`
	Organization            SecureCellFederationOrganizationSummary `json:"organization"`
	Participants            []SecureCellParticipantState            `json:"participants,omitempty"`
	Invitations             []SecureCellFederationInvitationSummary `json:"invitations,omitempty"`
	Contracts               []SecureCellFederationContractSummary   `json:"contracts,omitempty"`
	Runtime                 SecureCellFederationOrganizationRuntime `json:"runtime"`
	Controls                []SecureCellFederationTrustPackControl  `json:"controls,omitempty"`
	OperatorSurfaces        []SecureCellFederationOperatorSurface   `json:"operator_surfaces,omitempty"`
	ControlLedgerID         string                                  `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                  `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                  `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                    `json:"portable_package_signed"`
	PortablePackageAnchored bool                                    `json:"portable_package_anchored"`
}

// SecureCellFederationOrganizationTrustPackOptions lets callers enrich pack
// generation with runtime-specific operator surfaces or custom identifiers.
type SecureCellFederationOrganizationTrustPackOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
}

// SecureCellFederationInvitationBundle is the portable onboarding summary for
// one federation invitation.
type SecureCellFederationInvitationBundle struct {
	ID                      string                                  `json:"id"`
	Version                 string                                  `json:"version"`
	Name                    string                                  `json:"name"`
	GeneratedAt             time.Time                               `json:"generated_at"`
	CellID                  string                                  `json:"cell_id"`
	CellName                string                                  `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                        `json:"cell_status"`
	Jurisdiction            string                                  `json:"jurisdiction,omitempty"`
	Framework               string                                  `json:"framework,omitempty"`
	Organization            SecureCellFederationOrganizationSummary `json:"organization"`
	Invitation              SecureCellFederationInvitationSummary   `json:"invitation"`
	Contract                *SecureCellFederationContractSummary    `json:"contract,omitempty"`
	Controls                []SecureCellFederationTrustPackControl  `json:"controls,omitempty"`
	ControlLedgerID         string                                  `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                  `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                  `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                    `json:"portable_package_signed"`
	PortablePackageAnchored bool                                    `json:"portable_package_anchored"`
}

// ListFederationOrganizations returns operator-facing federation organization
// summaries across the current secure-cell set.
func (s *Service) ListFederationOrganizations(_ context.Context, filter SecureCellFederationOrganizationFilter) ([]SecureCellFederationOrganizationSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var items []SecureCellFederationOrganizationSummary
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, org := range run.result.FederationOrganizations {
			summary := secureCellFederationOrganizationSummaryFromRun(run, org)
			if !matchesSecureCellFederationOrganizationFilter(summary, filter) {
				continue
			}
			items = append(items, summary)
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

// ListFederationInvitations returns operator-facing federation invitation
// summaries across the current secure-cell set.
func (s *Service) ListFederationInvitations(_ context.Context, filter SecureCellFederationInvitationFilter) ([]SecureCellFederationInvitationSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var items []SecureCellFederationInvitationSummary
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, invitation := range run.result.FederationInvitations {
			summary := secureCellFederationInvitationSummaryFromRun(run, invitation)
			if !matchesSecureCellFederationInvitationFilter(summary, filter) {
				continue
			}
			items = append(items, summary)
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

// BuildFederationOrganizationTrustPack returns the buyer- and operator-facing
// federation trust pack for one organization in one secure cell.
func (s *Service) BuildFederationOrganizationTrustPack(_ context.Context, cellID string, organizationID string, options SecureCellFederationOrganizationTrustPackOptions) (*SecureCellFederationOrganizationTrustPack, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	orgSummary, org, err := secureCellFederationOrganizationSummaryAndRef(run, organizationID)
	if err != nil {
		return nil, err
	}
	invitations := secureCellFederationInvitationSummariesForOrganization(run, org.OrganizationID)
	contracts := secureCellFederationContractsForOrganization(run, org.OrganizationID)
	participants := secureCellFederationParticipantsForOrganization(run, *org)
	runtime := secureCellFederationRuntimeForOrganization(run, *org)

	pack := &SecureCellFederationOrganizationTrustPack{
		ID:               firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-trust-pack", run.result.CellID, org.OrganizationID)),
		Version:          firstNonEmpty(strings.TrimSpace(options.Version), "1.0"),
		Name:             firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("%s Federation Trust Pack", firstNonEmpty(orgSummary.OrganizationName, orgSummary.SponsorOfRecord, orgSummary.OrganizationID))),
		Sector:           "regulated_collaboration",
		GeneratedAt:      time.Now().UTC(),
		CellID:           run.result.CellID,
		CellName:         run.result.Name,
		CellStatus:       run.result.Status,
		Jurisdiction:     run.request.Jurisdiction,
		Framework:        s.config.Framework,
		RequiredTool:     secureCellTool,
		Organization:     orgSummary,
		Participants:     participants,
		Invitations:      invitations,
		Contracts:        contracts,
		Runtime:          runtime,
		Controls:         secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces: cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
	}
	if s.config.PolicySet != nil {
		pack.PolicySetID = strings.TrimSpace(s.config.PolicySet.ID)
		pack.PolicySetName = strings.TrimSpace(s.config.PolicySet.Name)
	}
	if run.result.ControlLedger != nil {
		pack.ControlLedgerID = strings.TrimSpace(run.result.ControlLedger.Bundle.ID)
		pack.ControlLedgerHash = strings.TrimSpace(run.result.ControlLedger.Bundle.ContentHash)
	}
	if run.result.PortablePackage != nil {
		pack.PortablePackageHash = strings.TrimSpace(run.result.PortablePackage.PackageHash)
		pack.PortablePackageSigned = run.result.PortablePackage.Signature != nil
		pack.PortablePackageAnchored = run.result.PortablePackage.AuditAnchor != nil
	}
	return pack, nil
}

// BuildFederationInvitationBundle returns a portable onboarding bundle for one
// federation invitation.
func (s *Service) BuildFederationInvitationBundle(_ context.Context, cellID string, invitationID string) (*SecureCellFederationInvitationBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	invitationSummary, invitation, err := secureCellFederationInvitationSummaryAndRef(run, invitationID)
	if err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, invitation.OrganizationID)
	if err != nil {
		return nil, err
	}
	bundle := &SecureCellFederationInvitationBundle{
		ID:           fmt.Sprintf("%s-%s-bundle", run.result.CellID, invitation.ID),
		Version:      "1.0",
		Name:         fmt.Sprintf("Federation Invitation Bundle %s", invitation.ID),
		GeneratedAt:  time.Now().UTC(),
		CellID:       run.result.CellID,
		CellName:     run.result.Name,
		CellStatus:   run.result.Status,
		Jurisdiction: run.request.Jurisdiction,
		Framework:    s.config.Framework,
		Organization: orgSummary,
		Invitation:   invitationSummary,
		Contract:     secureCellFederationContractForInvitation(run, invitation.ID),
		Controls:     secureCellFederationControlsFromLedger(run.result.ControlLedger),
	}
	if run.result.ControlLedger != nil {
		bundle.ControlLedgerID = strings.TrimSpace(run.result.ControlLedger.Bundle.ID)
		bundle.ControlLedgerHash = strings.TrimSpace(run.result.ControlLedger.Bundle.ContentHash)
	}
	if run.result.PortablePackage != nil {
		bundle.PortablePackageHash = strings.TrimSpace(run.result.PortablePackage.PackageHash)
		bundle.PortablePackageSigned = run.result.PortablePackage.Signature != nil
		bundle.PortablePackageAnchored = run.result.PortablePackage.AuditAnchor != nil
	}
	return bundle, nil
}

func secureCellFederationRunMatchesCellFilter(run *secureCellRun, cellID string) bool {
	cellID = strings.TrimSpace(cellID)
	if cellID == "" {
		return true
	}
	if run == nil || run.result == nil {
		return false
	}
	return strings.TrimSpace(run.result.CellID) == cellID
}

func secureCellFederationOrganizationSummaryAndRef(run *secureCellRun, organizationID string) (SecureCellFederationOrganizationSummary, *SecureCellFederationOrganization, error) {
	if run == nil || run.result == nil {
		return SecureCellFederationOrganizationSummary{}, nil, fmt.Errorf("securecells/federation: secure cell result is required")
	}
	_, org := findSecureCellFederationOrganization(run.result.FederationOrganizations, organizationID)
	if org == nil {
		return SecureCellFederationOrganizationSummary{}, nil, fmt.Errorf("securecells/federation: %w: %q", ErrFederationOrganizationNotFound, organizationID)
	}
	return secureCellFederationOrganizationSummaryFromRun(run, *org), org, nil
}

func secureCellFederationInvitationSummaryAndRef(run *secureCellRun, invitationID string) (SecureCellFederationInvitationSummary, *SecureCellFederationInvitation, error) {
	if run == nil || run.result == nil {
		return SecureCellFederationInvitationSummary{}, nil, fmt.Errorf("securecells/federation: secure cell result is required")
	}
	_, invitation := findSecureCellFederationInvitation(run.result.FederationInvitations, invitationID)
	if invitation == nil {
		return SecureCellFederationInvitationSummary{}, nil, fmt.Errorf("securecells/federation: %w: %q", ErrFederationInvitationNotFound, invitationID)
	}
	return secureCellFederationInvitationSummaryFromRun(run, *invitation), invitation, nil
}

func secureCellFederationOrganizationSummaryFromRun(run *secureCellRun, org SecureCellFederationOrganization) SecureCellFederationOrganizationSummary {
	summary := SecureCellFederationOrganizationSummary{
		CellID:           safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:         safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:       safeSecureCellStatus(run),
		Jurisdiction:     safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:   strings.TrimSpace(org.OrganizationID),
		SponsorOfRecord:  strings.TrimSpace(org.SponsorOfRecord),
		OrganizationName: strings.TrimSpace(org.OrganizationName),
		Status:           org.Status,
		ParticipantDIDs:  uniqueTrimmedStrings(org.ParticipantDIDs),
		CreatedAt:        org.CreatedAt.UTC(),
		UpdatedAt:        org.UpdatedAt.UTC(),
	}
	for _, participantDID := range summary.ParticipantDIDs {
		state, ok := participantStateForResult(run.result, participantDID)
		if !ok {
			continue
		}
		summary.ParticipantCount++
		switch state.Status {
		case SecureCellParticipantStatusActive:
			summary.ActiveParticipantCount++
		}
	}
	for _, invitation := range run.result.FederationInvitations {
		if strings.TrimSpace(invitation.OrganizationID) != summary.OrganizationID {
			continue
		}
		summary.InvitationCount++
		switch invitation.Status {
		case SecureCellFederationInvitationStatusPending:
			summary.PendingInvitationCount++
		case SecureCellFederationInvitationStatusAccepted:
			summary.AcceptedInvitationCount++
		case SecureCellFederationInvitationStatusRevoked:
			summary.RevokedInvitationCount++
		}
	}
	for _, contract := range run.result.FederationContracts {
		if strings.TrimSpace(contract.OrganizationID) != summary.OrganizationID {
			continue
		}
		summary.ContractCount++
		switch contract.Status {
		case SecureCellFederationContractStatusActive:
			summary.ActiveContractCount++
		case SecureCellFederationContractStatusRevoked:
			summary.RevokedContractCount++
		}
	}
	if run.result.ControlLedger != nil {
		summary.ControlLedgerID = strings.TrimSpace(run.result.ControlLedger.Bundle.ID)
	}
	if run.result.PortablePackage != nil {
		summary.PortablePackageHash = strings.TrimSpace(run.result.PortablePackage.PackageHash)
		summary.PortablePackageSigned = run.result.PortablePackage.Signature != nil
		summary.PortablePackageAnchored = run.result.PortablePackage.AuditAnchor != nil
	}
	return summary
}

func secureCellFederationInvitationSummaryFromRun(run *secureCellRun, invitation SecureCellFederationInvitation) SecureCellFederationInvitationSummary {
	summary := SecureCellFederationInvitationSummary{
		CellID:            safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:          safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:        safeSecureCellStatus(run),
		Jurisdiction:      firstNonEmpty(strings.TrimSpace(invitation.Jurisdiction), safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) })),
		InvitationID:      strings.TrimSpace(invitation.ID),
		OrganizationID:    strings.TrimSpace(invitation.OrganizationID),
		SponsorOfRecord:   strings.TrimSpace(invitation.SponsorOfRecord),
		OrganizationName:  strings.TrimSpace(invitation.OrganizationName),
		Status:            invitation.Status,
		ExpectedDID:       strings.TrimSpace(invitation.ExpectedDID),
		Role:              strings.TrimSpace(invitation.Role),
		SessionScopeCount: len(uniqueTrimmedStrings(invitation.SessionScopeIDs)),
		DataClassCount:    len(uniqueTrimmedStrings(invitation.DataClasses)),
		ComputeZoneCount:  len(uniqueTrimmedStrings(invitation.ComputeZones)),
		Resource:          strings.TrimSpace(invitation.Resource),
		CreatedBy:         strings.TrimSpace(invitation.CreatedBy),
		AcceptedBy:        strings.TrimSpace(invitation.AcceptedBy),
		RevokedBy:         strings.TrimSpace(invitation.RevokedBy),
		Reason:            strings.TrimSpace(invitation.Reason),
		CreatedAt:         invitation.CreatedAt.UTC(),
		AcceptedAt:        cloneTimePtr(invitation.AcceptedAt),
		RevokedAt:         cloneTimePtr(invitation.RevokedAt),
		UpdatedAt:         secureCellFederationInvitationUpdatedAt(invitation),
	}
	if run.result.ControlLedger != nil {
		summary.ControlLedgerID = strings.TrimSpace(run.result.ControlLedger.Bundle.ID)
	}
	if run.result.PortablePackage != nil {
		summary.PortablePackageHash = strings.TrimSpace(run.result.PortablePackage.PackageHash)
		summary.PortablePackageSigned = run.result.PortablePackage.Signature != nil
		summary.PortablePackageAnchored = run.result.PortablePackage.AuditAnchor != nil
	}
	return summary
}

func secureCellFederationInvitationUpdatedAt(invitation SecureCellFederationInvitation) time.Time {
	switch {
	case invitation.RevokedAt != nil && !invitation.RevokedAt.IsZero():
		return invitation.RevokedAt.UTC()
	case invitation.AcceptedAt != nil && !invitation.AcceptedAt.IsZero():
		return invitation.AcceptedAt.UTC()
	default:
		return invitation.CreatedAt.UTC()
	}
}

func matchesSecureCellFederationOrganizationFilter(summary SecureCellFederationOrganizationSummary, filter SecureCellFederationOrganizationFilter) bool {
	if filter.Status != "" && summary.Status != filter.Status {
		return false
	}
	if filter.Jurisdiction != "" && !strings.EqualFold(summary.Jurisdiction, strings.TrimSpace(filter.Jurisdiction)) {
		return false
	}
	if filter.SponsorOfRecord != "" && !strings.EqualFold(summary.SponsorOfRecord, strings.TrimSpace(filter.SponsorOfRecord)) {
		return false
	}
	if filter.ParticipantDID != "" && !secureCellFederationSummaryHasParticipant(summary, strings.TrimSpace(filter.ParticipantDID)) {
		return false
	}
	if filter.UpdatedAfter != nil && summary.UpdatedAt.Before(filter.UpdatedAfter.UTC()) {
		return false
	}
	if filter.UpdatedBefore != nil && summary.UpdatedAt.After(filter.UpdatedBefore.UTC()) {
		return false
	}
	return true
}

func matchesSecureCellFederationInvitationFilter(summary SecureCellFederationInvitationSummary, filter SecureCellFederationInvitationFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(summary.OrganizationID, strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.Status != "" && summary.Status != filter.Status {
		return false
	}
	if filter.Jurisdiction != "" && !strings.EqualFold(summary.Jurisdiction, strings.TrimSpace(filter.Jurisdiction)) {
		return false
	}
	if filter.SponsorOfRecord != "" && !strings.EqualFold(summary.SponsorOfRecord, strings.TrimSpace(filter.SponsorOfRecord)) {
		return false
	}
	if filter.ExpectedDID != "" && !strings.EqualFold(summary.ExpectedDID, strings.TrimSpace(filter.ExpectedDID)) {
		return false
	}
	if filter.UpdatedAfter != nil && summary.UpdatedAt.Before(filter.UpdatedAfter.UTC()) {
		return false
	}
	if filter.UpdatedBefore != nil && summary.UpdatedAt.After(filter.UpdatedBefore.UTC()) {
		return false
	}
	return true
}

func secureCellFederationSummaryHasParticipant(summary SecureCellFederationOrganizationSummary, participantDID string) bool {
	participantDID = strings.TrimSpace(participantDID)
	if participantDID == "" {
		return true
	}
	for _, candidate := range summary.ParticipantDIDs {
		if strings.TrimSpace(candidate) == participantDID {
			return true
		}
	}
	return false
}

func secureCellFederationParticipantsForOrganization(run *secureCellRun, org SecureCellFederationOrganization) []SecureCellParticipantState {
	if run == nil || run.result == nil {
		return nil
	}
	items := make([]SecureCellParticipantState, 0, len(org.ParticipantDIDs))
	for _, participantDID := range uniqueTrimmedStrings(org.ParticipantDIDs) {
		state, ok := participantStateForResult(run.result, participantDID)
		if !ok {
			continue
		}
		items = append(items, state)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].AddedAt.After(items[j].AddedAt)
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	return items
}

func secureCellFederationInvitationSummariesForOrganization(run *secureCellRun, organizationID string) []SecureCellFederationInvitationSummary {
	if run == nil || run.result == nil {
		return nil
	}
	items := make([]SecureCellFederationInvitationSummary, 0)
	for _, invitation := range run.result.FederationInvitations {
		if strings.TrimSpace(invitation.OrganizationID) != strings.TrimSpace(organizationID) {
			continue
		}
		items = append(items, secureCellFederationInvitationSummaryFromRun(run, invitation))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	return items
}

func secureCellFederationRuntimeForOrganization(run *secureCellRun, org SecureCellFederationOrganization) SecureCellFederationOrganizationRuntime {
	runtime := SecureCellFederationOrganizationRuntime{}
	for _, participant := range secureCellFederationParticipantsForOrganization(run, org) {
		runtime.ParticipantCount++
		switch participant.Status {
		case SecureCellParticipantStatusActive:
			runtime.ActiveParticipantCount++
		case SecureCellParticipantStatusQuarantined:
			runtime.QuarantinedParticipants++
		case SecureCellParticipantStatusRevoked:
			runtime.RevokedParticipants++
		}
		if participant.UpdatedAt.After(runtime.LastUpdatedAt) {
			runtime.LastUpdatedAt = participant.UpdatedAt.UTC()
		}
	}
	for _, invitation := range run.result.FederationInvitations {
		if strings.TrimSpace(invitation.OrganizationID) != strings.TrimSpace(org.OrganizationID) {
			continue
		}
		runtime.InvitationCount++
		switch invitation.Status {
		case SecureCellFederationInvitationStatusPending:
			runtime.PendingInvitations++
		case SecureCellFederationInvitationStatusAccepted:
			runtime.AcceptedInvitations++
		case SecureCellFederationInvitationStatusRevoked:
			runtime.RevokedInvitations++
		}
		if updatedAt := secureCellFederationInvitationUpdatedAt(invitation); updatedAt.After(runtime.LastUpdatedAt) {
			runtime.LastUpdatedAt = updatedAt
		}
	}
	for _, contract := range run.result.FederationContracts {
		if strings.TrimSpace(contract.OrganizationID) != strings.TrimSpace(org.OrganizationID) {
			continue
		}
		runtime.ContractCount++
		switch contract.Status {
		case SecureCellFederationContractStatusActive:
			runtime.ActiveContracts++
		case SecureCellFederationContractStatusRevoked:
			runtime.RevokedContracts++
		}
		if updatedAt := secureCellFederationContractUpdatedAt(contract); updatedAt.After(runtime.LastUpdatedAt) {
			runtime.LastUpdatedAt = updatedAt
		}
	}
	if org.UpdatedAt.After(runtime.LastUpdatedAt) {
		runtime.LastUpdatedAt = org.UpdatedAt.UTC()
	}
	return runtime
}

func secureCellFederationControlsFromLedger(ledger *evidence.ControlLedger) []SecureCellFederationTrustPackControl {
	if ledger == nil {
		return nil
	}
	items := make([]SecureCellFederationTrustPackControl, 0, len(ledger.Controls))
	for _, control := range ledger.Controls {
		if strings.TrimSpace(control.ControlID) == "" {
			continue
		}
		if !secureCellFederationControlRelevant(control) {
			continue
		}
		items = append(items, SecureCellFederationTrustPackControl{
			ControlID:     strings.TrimSpace(control.ControlID),
			ControlName:   strings.TrimSpace(control.ControlName),
			Description:   strings.TrimSpace(control.Description),
			EvidenceTypes: secureCellFederationControlEvidenceTypes(control.EvidenceRefs),
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].ControlID < items[j].ControlID
	})
	return items
}

func secureCellFederationControlRelevant(control evidence.LedgerControl) bool {
	if strings.HasPrefix(strings.TrimSpace(control.ControlID), "CELL-FED-") {
		return true
	}
	for key, value := range control.Metadata {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		normalizedValue := strings.ToLower(strings.TrimSpace(value))
		if strings.Contains(normalizedKey, "federation") || strings.Contains(normalizedValue, "federation") {
			return true
		}
	}
	return false
}

func secureCellFederationControlEvidenceTypes(refs evidence.ControlEvidenceRefs) []string {
	types := make([]string, 0, 7)
	if len(refs.RecordIDs) > 0 {
		types = append(types, "record")
	}
	if len(refs.AttestationIDs) > 0 {
		types = append(types, "attestation")
	}
	if len(refs.PolicyReceiptIDs) > 0 {
		types = append(types, "policy_receipt")
	}
	if len(refs.SealIDs) > 0 {
		types = append(types, "seal")
	}
	if len(refs.TraceLinkIDs) > 0 {
		types = append(types, "trace_link")
	}
	if len(refs.TrustCompliancePackageIDs) > 0 {
		types = append(types, "trust_compliance_package")
	}
	if len(refs.ApproverAttestationIDs) > 0 {
		types = append(types, "approver_attestation")
	}
	return types
}

func safeSecureCellStatus(run *secureCellRun) SecureCellStatus {
	if run == nil || run.result == nil {
		return ""
	}
	return run.result.Status
}

func cloneSecureCellFederationOperatorSurfaces(in []SecureCellFederationOperatorSurface) []SecureCellFederationOperatorSurface {
	if len(in) == 0 {
		return nil
	}
	out := make([]SecureCellFederationOperatorSurface, 0, len(in))
	for _, item := range in {
		out = append(out, SecureCellFederationOperatorSurface{
			ID:          strings.TrimSpace(item.ID),
			Method:      strings.TrimSpace(item.Method),
			Path:        strings.TrimSpace(item.Path),
			Description: strings.TrimSpace(item.Description),
			Formats:     append([]string(nil), item.Formats...),
		})
	}
	return out
}
