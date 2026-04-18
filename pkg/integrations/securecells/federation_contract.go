package securecells

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// SecureCellFederationContractStatus tracks the lifecycle posture of one
// replayable federation contract inside a secure cell.
type SecureCellFederationContractStatus string

const (
	SecureCellFederationContractStatusActive  SecureCellFederationContractStatus = "active"
	SecureCellFederationContractStatusRevoked SecureCellFederationContractStatus = "revoked"
)

const (
	secureCellFederationContractActionShareOutput     = "share_output"
	secureCellFederationContractActionSessionExchange = "session_exchange"
	secureCellFederationContractActionThreadMessage   = "thread_message"
)

// SecureCellFederationContract captures the negotiated, replayable contract
// binding one accepted federation invitation to the live collaboration state.
type SecureCellFederationContract struct {
	ID                string                             `json:"id"`
	OrganizationID    string                             `json:"organization_id"`
	InvitationID      string                             `json:"invitation_id"`
	SponsorOfRecord   string                             `json:"sponsor_of_record,omitempty"`
	OrganizationName  string                             `json:"organization_name,omitempty"`
	Jurisdiction      string                             `json:"jurisdiction,omitempty"`
	Status            SecureCellFederationContractStatus `json:"status"`
	ParticipantDIDs   []string                           `json:"participant_dids,omitempty"`
	SessionScopeIDs   []string                           `json:"session_scope_ids,omitempty"`
	DataClasses       []string                           `json:"data_classes,omitempty"`
	ComputeZones      []string                           `json:"compute_zones,omitempty"`
	AllowedActions    []string                           `json:"allowed_actions,omitempty"`
	Resource          string                             `json:"resource,omitempty"`
	NegotiationID     string                             `json:"negotiation_id,omitempty"`
	CredentialID      string                             `json:"credential_id,omitempty"`
	PolicyReceiptID   string                             `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                             `json:"policy_receipt_hash,omitempty"`
	CreatedBy         string                             `json:"created_by,omitempty"`
	ActivatedBy       string                             `json:"activated_by,omitempty"`
	RevokedBy         string                             `json:"revoked_by,omitempty"`
	Reason            string                             `json:"reason,omitempty"`
	CreatedAt         time.Time                          `json:"created_at,omitempty"`
	ActivatedAt       *time.Time                         `json:"activated_at,omitempty"`
	RevokedAt         *time.Time                         `json:"revoked_at,omitempty"`
	UpdatedAt         time.Time                          `json:"updated_at,omitempty"`
	Metadata          map[string]string                  `json:"metadata,omitempty"`
}

// SecureCellFederationContractFilter narrows operator queries across live
// federation contracts.
type SecureCellFederationContractFilter struct {
	CellID          string                             `json:"cell_id,omitempty"`
	OrganizationID  string                             `json:"organization_id,omitempty"`
	Status          SecureCellFederationContractStatus `json:"status,omitempty"`
	SponsorOfRecord string                             `json:"sponsor_of_record,omitempty"`
	ParticipantDID  string                             `json:"participant_did,omitempty"`
	SessionID       string                             `json:"session_id,omitempty"`
	Action          string                             `json:"action,omitempty"`
	Classification  string                             `json:"classification,omitempty"`
	UpdatedAfter    *time.Time                         `json:"updated_after,omitempty"`
	UpdatedBefore   *time.Time                         `json:"updated_before,omitempty"`
	Limit           int                                `json:"limit,omitempty"`
}

// SecureCellFederationContractSummary is the operator-facing summary of one
// active or historical federation contract.
type SecureCellFederationContractSummary struct {
	CellID                  string                             `json:"cell_id"`
	CellName                string                             `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                   `json:"cell_status"`
	Jurisdiction            string                             `json:"jurisdiction,omitempty"`
	ContractID              string                             `json:"contract_id"`
	OrganizationID          string                             `json:"organization_id"`
	InvitationID            string                             `json:"invitation_id,omitempty"`
	SponsorOfRecord         string                             `json:"sponsor_of_record,omitempty"`
	OrganizationName        string                             `json:"organization_name,omitempty"`
	Status                  SecureCellFederationContractStatus `json:"status"`
	ParticipantDIDs         []string                           `json:"participant_dids,omitempty"`
	ParticipantCount        int                                `json:"participant_count"`
	SessionScopeIDs         []string                           `json:"session_scope_ids,omitempty"`
	SessionScopeCount       int                                `json:"session_scope_count"`
	DataClasses             []string                           `json:"data_classes,omitempty"`
	DataClassCount          int                                `json:"data_class_count"`
	ComputeZones            []string                           `json:"compute_zones,omitempty"`
	ComputeZoneCount        int                                `json:"compute_zone_count"`
	AllowedActions          []string                           `json:"allowed_actions,omitempty"`
	Resource                string                             `json:"resource,omitempty"`
	NegotiationID           string                             `json:"negotiation_id,omitempty"`
	CredentialID            string                             `json:"credential_id,omitempty"`
	PolicyReceiptID         string                             `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash       string                             `json:"policy_receipt_hash,omitempty"`
	ControlLedgerID         string                             `json:"control_ledger_id,omitempty"`
	PortablePackageHash     string                             `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                               `json:"portable_package_signed"`
	PortablePackageAnchored bool                               `json:"portable_package_anchored"`
	CreatedAt               time.Time                          `json:"created_at,omitempty"`
	ActivatedAt             *time.Time                         `json:"activated_at,omitempty"`
	RevokedAt               *time.Time                         `json:"revoked_at,omitempty"`
	UpdatedAt               time.Time                          `json:"updated_at,omitempty"`
}

// SecureCellFederationContractBundle is the operator-facing portable detail
// view for one federation contract.
type SecureCellFederationContractBundle struct {
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
	Invitation              *SecureCellFederationInvitationSummary  `json:"invitation,omitempty"`
	Contract                SecureCellFederationContractSummary     `json:"contract"`
	Controls                []SecureCellFederationTrustPackControl  `json:"controls,omitempty"`
	OperatorSurfaces        []SecureCellFederationOperatorSurface   `json:"operator_surfaces,omitempty"`
	ControlLedgerID         string                                  `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                  `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                  `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                    `json:"portable_package_signed"`
	PortablePackageAnchored bool                                    `json:"portable_package_anchored"`
}

// SecureCellFederationContractBundleOptions lets callers enrich contract
// bundles with custom identifiers or operator surfaces.
type SecureCellFederationContractBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
}

type secureCellFederationExchangeAuthorization struct {
	ContractIDs     []string
	OrganizationIDs []string
}

func (auth secureCellFederationExchangeAuthorization) metadata() map[string]string {
	if len(auth.ContractIDs) == 0 && len(auth.OrganizationIDs) == 0 {
		return nil
	}
	return map[string]string{
		"federation_contract_ids": strings.Join(uniqueTrimmedStrings(auth.ContractIDs), ","),
		"federation_org_ids":      strings.Join(uniqueTrimmedStrings(auth.OrganizationIDs), ","),
	}
}

// ListFederationContracts returns operator-facing federation contract summaries
// across the current secure-cell set.
func (s *Service) ListFederationContracts(_ context.Context, filter SecureCellFederationContractFilter) ([]SecureCellFederationContractSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var items []SecureCellFederationContractSummary
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, contract := range run.result.FederationContracts {
			summary := secureCellFederationContractSummaryFromRun(run, contract)
			if !matchesSecureCellFederationContractFilter(summary, filter) {
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

// BuildFederationContractBundle returns the portable operator bundle for one
// federation contract in one secure cell.
func (s *Service) BuildFederationContractBundle(_ context.Context, cellID string, contractID string, options SecureCellFederationContractBundleOptions) (*SecureCellFederationContractBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	contractSummary, contract, err := secureCellFederationContractSummaryAndRef(run, contractID)
	if err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, contract.OrganizationID)
	if err != nil {
		return nil, err
	}
	var invitationSummary *SecureCellFederationInvitationSummary
	if _, invitation := findSecureCellFederationInvitation(run.result.FederationInvitations, contract.InvitationID); invitation != nil {
		summary := secureCellFederationInvitationSummaryFromRun(run, *invitation)
		invitationSummary = &summary
	}

	bundle := &SecureCellFederationContractBundle{
		ID:               firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-contract-bundle", run.result.CellID, contract.ID)),
		Version:          firstNonEmpty(strings.TrimSpace(options.Version), "1.0"),
		Name:             firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Contract Bundle %s", contract.ID)),
		GeneratedAt:      time.Now().UTC(),
		CellID:           run.result.CellID,
		CellName:         run.result.Name,
		CellStatus:       run.result.Status,
		Jurisdiction:     run.request.Jurisdiction,
		Framework:        s.config.Framework,
		Organization:     orgSummary,
		Invitation:       invitationSummary,
		Contract:         contractSummary,
		Controls:         secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces: cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
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

func newActivatedFederationContract(req SecureCellRequest, invitation SecureCellFederationInvitation, participant SecureCellParticipantState, receipt *policy.SignedPolicyReceipt, actorDID string, reason string, metadata map[string]string) SecureCellFederationContract {
	activatedAt := time.Now().UTC()
	contract := SecureCellFederationContract{
		ID:                secureCellFederationContractID(req, invitation, participant.ParticipantDID),
		OrganizationID:    strings.TrimSpace(invitation.OrganizationID),
		InvitationID:      strings.TrimSpace(invitation.ID),
		SponsorOfRecord:   strings.TrimSpace(invitation.SponsorOfRecord),
		OrganizationName:  strings.TrimSpace(invitation.OrganizationName),
		Jurisdiction:      firstNonEmpty(strings.TrimSpace(invitation.Jurisdiction), req.Jurisdiction),
		Status:            SecureCellFederationContractStatusActive,
		ParticipantDIDs:   uniqueTrimmedStrings([]string{participant.ParticipantDID}),
		SessionScopeIDs:   uniqueTrimmedStrings(invitation.SessionScopeIDs),
		DataClasses:       uniqueTrimmedStrings(invitation.DataClasses),
		ComputeZones:      uniqueTrimmedStrings(invitation.ComputeZones),
		AllowedActions:    secureCellDefaultFederationContractActions(),
		Resource:          strings.TrimSpace(invitation.Resource),
		NegotiationID:     strings.TrimSpace(participant.NegotiationID),
		CredentialID:      strings.TrimSpace(participant.CredentialID),
		PolicyReceiptID:   safeString(receipt, func(in *policy.SignedPolicyReceipt) string { return strings.TrimSpace(in.ID) }),
		PolicyReceiptHash: safeString(receipt, func(in *policy.SignedPolicyReceipt) string { return strings.TrimSpace(in.ContentHash) }),
		CreatedBy:         strings.TrimSpace(invitation.CreatedBy),
		ActivatedBy:       strings.TrimSpace(actorDID),
		Reason:            strings.TrimSpace(reason),
		CreatedAt:         invitation.CreatedAt.UTC(),
		ActivatedAt:       &activatedAt,
		UpdatedAt:         activatedAt,
		Metadata:          mergeStringMaps(invitation.Metadata, metadata),
	}
	if contract.Resource == "" {
		contract.Resource = fmt.Sprintf("secure-cell:%s:federation-contract:%s", cellID(req), contract.ID)
	}
	if contract.CreatedAt.IsZero() {
		contract.CreatedAt = activatedAt
	}
	return contract
}

func secureCellFederationContractID(req SecureCellRequest, invitation SecureCellFederationInvitation, participantDID string) string {
	seed := fmt.Sprintf("%s|%s|%s|%s|%s", cellID(req), invitation.ID, invitation.OrganizationID, strings.TrimSpace(participantDID), strings.Join(uniqueTrimmedStrings(invitation.SessionScopeIDs), ","))
	return fmt.Sprintf("%s-federation-contract-%x", cellID(req), sha256.Sum256([]byte(seed)))
}

func secureCellDefaultFederationContractActions() []string {
	return []string{
		secureCellFederationContractActionShareOutput,
		secureCellFederationContractActionSessionExchange,
		secureCellFederationContractActionThreadMessage,
	}
}

func secureCellFederationContractUpdatedAt(contract SecureCellFederationContract) time.Time {
	switch {
	case contract.RevokedAt != nil && !contract.RevokedAt.IsZero():
		return contract.RevokedAt.UTC()
	case contract.ActivatedAt != nil && !contract.ActivatedAt.IsZero():
		return contract.ActivatedAt.UTC()
	case !contract.UpdatedAt.IsZero():
		return contract.UpdatedAt.UTC()
	default:
		return contract.CreatedAt.UTC()
	}
}

func findSecureCellFederationContract(contracts []SecureCellFederationContract, contractID string) (int, *SecureCellFederationContract) {
	contractID = strings.TrimSpace(contractID)
	for idx := range contracts {
		if strings.TrimSpace(contracts[idx].ID) == contractID {
			return idx, &contracts[idx]
		}
	}
	return -1, nil
}

func secureCellFederationContractSummaryAndRef(run *secureCellRun, contractID string) (SecureCellFederationContractSummary, *SecureCellFederationContract, error) {
	if run == nil || run.result == nil {
		return SecureCellFederationContractSummary{}, nil, fmt.Errorf("securecells/federation: secure cell result is required")
	}
	_, contract := findSecureCellFederationContract(run.result.FederationContracts, contractID)
	if contract == nil {
		return SecureCellFederationContractSummary{}, nil, fmt.Errorf("securecells/service: %w: %q", ErrFederationContractNotFound, contractID)
	}
	return secureCellFederationContractSummaryFromRun(run, *contract), contract, nil
}

func secureCellFederationContractSummaryFromRun(run *secureCellRun, contract SecureCellFederationContract) SecureCellFederationContractSummary {
	summary := SecureCellFederationContractSummary{
		CellID:            safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:          safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:        safeSecureCellStatus(run),
		Jurisdiction:      firstNonEmpty(strings.TrimSpace(contract.Jurisdiction), safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) })),
		ContractID:        strings.TrimSpace(contract.ID),
		OrganizationID:    strings.TrimSpace(contract.OrganizationID),
		InvitationID:      strings.TrimSpace(contract.InvitationID),
		SponsorOfRecord:   strings.TrimSpace(contract.SponsorOfRecord),
		OrganizationName:  strings.TrimSpace(contract.OrganizationName),
		Status:            contract.Status,
		ParticipantDIDs:   uniqueTrimmedStrings(contract.ParticipantDIDs),
		SessionScopeIDs:   uniqueTrimmedStrings(contract.SessionScopeIDs),
		SessionScopeCount: len(uniqueTrimmedStrings(contract.SessionScopeIDs)),
		DataClasses:       uniqueTrimmedStrings(contract.DataClasses),
		DataClassCount:    len(uniqueTrimmedStrings(contract.DataClasses)),
		ComputeZones:      uniqueTrimmedStrings(contract.ComputeZones),
		ComputeZoneCount:  len(uniqueTrimmedStrings(contract.ComputeZones)),
		AllowedActions:    append([]string(nil), uniqueTrimmedStrings(contract.AllowedActions)...),
		Resource:          strings.TrimSpace(contract.Resource),
		NegotiationID:     strings.TrimSpace(contract.NegotiationID),
		CredentialID:      strings.TrimSpace(contract.CredentialID),
		PolicyReceiptID:   strings.TrimSpace(contract.PolicyReceiptID),
		PolicyReceiptHash: strings.TrimSpace(contract.PolicyReceiptHash),
		CreatedAt:         contract.CreatedAt.UTC(),
		ActivatedAt:       cloneTimePtr(contract.ActivatedAt),
		RevokedAt:         cloneTimePtr(contract.RevokedAt),
		UpdatedAt:         secureCellFederationContractUpdatedAt(contract),
	}
	for _, participantDID := range summary.ParticipantDIDs {
		if _, ok := participantStateForResult(run.result, participantDID); ok {
			summary.ParticipantCount++
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

func secureCellFederationContractsForOrganization(run *secureCellRun, organizationID string) []SecureCellFederationContractSummary {
	if run == nil || run.result == nil {
		return nil
	}
	items := make([]SecureCellFederationContractSummary, 0)
	for _, contract := range run.result.FederationContracts {
		if strings.TrimSpace(contract.OrganizationID) != strings.TrimSpace(organizationID) {
			continue
		}
		items = append(items, secureCellFederationContractSummaryFromRun(run, contract))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	return items
}

func secureCellFederationContractForInvitation(run *secureCellRun, invitationID string) *SecureCellFederationContractSummary {
	if run == nil || run.result == nil {
		return nil
	}
	var best *SecureCellFederationContractSummary
	for _, contract := range run.result.FederationContracts {
		if strings.TrimSpace(contract.InvitationID) != strings.TrimSpace(invitationID) {
			continue
		}
		summary := secureCellFederationContractSummaryFromRun(run, contract)
		if best == nil || summary.UpdatedAt.After(best.UpdatedAt) {
			best = &summary
		}
	}
	return best
}

func matchesSecureCellFederationContractFilter(summary SecureCellFederationContractSummary, filter SecureCellFederationContractFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(summary.OrganizationID, strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.Status != "" && summary.Status != filter.Status {
		return false
	}
	if filter.SponsorOfRecord != "" && !strings.EqualFold(summary.SponsorOfRecord, strings.TrimSpace(filter.SponsorOfRecord)) {
		return false
	}
	if filter.ParticipantDID != "" && !secureCellFederationContractHasParticipant(summary, strings.TrimSpace(filter.ParticipantDID)) {
		return false
	}
	if filter.SessionID != "" && summary.SessionScopeCount > 0 {
		// Only filter session-scoped contracts when they explicitly list scopes.
		if !secureCellFederationContractHasSession(runSummaryContract(summary), strings.TrimSpace(filter.SessionID)) {
			return false
		}
	}
	if filter.Action != "" && !secureCellFederationContractAllowsAction(runSummaryContract(summary), strings.TrimSpace(filter.Action)) {
		return false
	}
	if filter.Classification != "" && !secureCellFederationContractAllowsClassification(runSummaryContract(summary), strings.TrimSpace(filter.Classification)) {
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

func secureCellFederationContractHasParticipant(summary SecureCellFederationContractSummary, participantDID string) bool {
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

func runSummaryContract(summary SecureCellFederationContractSummary) SecureCellFederationContract {
	return SecureCellFederationContract{
		SessionScopeIDs: uniqueTrimmedStrings(summary.SessionScopeIDs),
		DataClasses:     uniqueTrimmedStrings(summary.DataClasses),
		ComputeZones:    uniqueTrimmedStrings(summary.ComputeZones),
		AllowedActions:  append([]string(nil), summary.AllowedActions...),
	}
}

func secureCellAuthorizeFederatedExchange(run *secureCellRun, actorDID string, recipients []string, sessionID string, classification string, action string) (secureCellFederationExchangeAuthorization, error) {
	if run == nil || run.result == nil {
		return secureCellFederationExchangeAuthorization{}, nil
	}
	ownerOrgID, _, _, _ := secureCellFederationIdentity(run.request.OwnerIdentity)
	involved := make(map[string]struct{})
	for _, did := range append([]string{strings.TrimSpace(actorDID)}, uniqueTrimmedStrings(recipients)...) {
		orgID, governed := secureCellFederationGovernedOrganizationForParticipant(run.result, did)
		if !governed || orgID == "" || orgID == ownerOrgID {
			continue
		}
		involved[orgID] = struct{}{}
	}
	if len(involved) == 0 {
		return secureCellFederationExchangeAuthorization{}, nil
	}

	organizationIDs := make([]string, 0, len(involved))
	for orgID := range involved {
		organizationIDs = append(organizationIDs, orgID)
	}
	sort.Strings(organizationIDs)

	auth := secureCellFederationExchangeAuthorization{
		OrganizationIDs: organizationIDs,
	}
	for _, orgID := range organizationIDs {
		contract, err := secureCellMatchingFederationContract(run, orgID, sessionID, classification, action)
		if err != nil {
			return secureCellFederationExchangeAuthorization{}, err
		}
		auth.ContractIDs = append(auth.ContractIDs, contract.ID)
	}
	auth.ContractIDs = uniqueTrimmedStrings(auth.ContractIDs)
	return auth, nil
}

func secureCellMatchingFederationContract(run *secureCellRun, organizationID string, sessionID string, classification string, action string) (*SecureCellFederationContract, error) {
	if run == nil || run.result == nil {
		return nil, fmt.Errorf("securecells/service: %w", ErrFederationContractRequired)
	}
	var activeCount int
	var match *SecureCellFederationContract
	for idx := range run.result.FederationContracts {
		contract := &run.result.FederationContracts[idx]
		if strings.TrimSpace(contract.OrganizationID) != strings.TrimSpace(organizationID) {
			continue
		}
		if contract.Status != SecureCellFederationContractStatusActive {
			continue
		}
		activeCount++
		if !secureCellFederationContractHasSession(*contract, sessionID) {
			continue
		}
		if !secureCellFederationContractAllowsClassification(*contract, classification) {
			continue
		}
		if !secureCellFederationContractAllowsAction(*contract, action) {
			continue
		}
		if !secureCellFederationContractAllowsComputeZones(*contract, run.request.Policy.ComputeZones) {
			continue
		}
		if match == nil || secureCellFederationContractUpdatedAt(*contract).After(secureCellFederationContractUpdatedAt(*match)) {
			match = contract
		}
	}
	if activeCount == 0 {
		return nil, fmt.Errorf("securecells/service: %w: no active federation contract for organization %q", ErrFederationContractRequired, organizationID)
	}
	if match == nil {
		return nil, fmt.Errorf("securecells/service: %w: organization %q does not permit %s in session %q for %q", ErrFederationExchangePolicyDenied, organizationID, strings.TrimSpace(action), strings.TrimSpace(sessionID), strings.TrimSpace(classification))
	}
	return match, nil
}

func secureCellFederationGovernedOrganizationForParticipant(result *SecureCellResult, participantDID string) (string, bool) {
	if result == nil {
		return "", false
	}
	participantDID = strings.TrimSpace(participantDID)
	if participantDID == "" {
		return "", false
	}
	var best *SecureCellFederationContract
	for idx := range result.FederationContracts {
		contract := &result.FederationContracts[idx]
		for _, candidate := range contract.ParticipantDIDs {
			if strings.TrimSpace(candidate) != participantDID {
				continue
			}
			if best == nil || secureCellFederationContractUpdatedAt(*contract).After(secureCellFederationContractUpdatedAt(*best)) {
				best = contract
			}
			break
		}
	}
	if best == nil {
		return "", false
	}
	return strings.TrimSpace(best.OrganizationID), true
}

func secureCellFederationContractHasSession(contract SecureCellFederationContract, sessionID string) bool {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return true
	}
	scopes := uniqueTrimmedStrings(contract.SessionScopeIDs)
	if len(scopes) == 0 {
		return true
	}
	for _, candidate := range scopes {
		if strings.TrimSpace(candidate) == sessionID {
			return true
		}
	}
	return false
}

func secureCellFederationContractAllowsClassification(contract SecureCellFederationContract, classification string) bool {
	classification = strings.TrimSpace(classification)
	if classification == "" {
		return true
	}
	allowed := uniqueTrimmedStrings(contract.DataClasses)
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(candidate), classification) {
			return true
		}
	}
	return false
}

func secureCellFederationContractAllowsAction(contract SecureCellFederationContract, action string) bool {
	action = strings.TrimSpace(action)
	if action == "" {
		return true
	}
	allowed := uniqueTrimmedStrings(contract.AllowedActions)
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(candidate), action) {
			return true
		}
	}
	return false
}

func secureCellFederationContractAllowsComputeZones(contract SecureCellFederationContract, cellZones []string) bool {
	allowed := uniqueTrimmedStrings(contract.ComputeZones)
	if len(allowed) == 0 {
		return true
	}
	for _, zone := range uniqueTrimmedStrings(cellZones) {
		for _, candidate := range allowed {
			if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(zone)) {
				return true
			}
		}
	}
	return false
}

func secureCellFederationContractsByStatus(contracts []SecureCellFederationContract, status SecureCellFederationContractStatus) []SecureCellFederationContract {
	if len(contracts) == 0 {
		return nil
	}
	items := make([]SecureCellFederationContract, 0, len(contracts))
	for _, contract := range contracts {
		if contract.Status == status {
			items = append(items, contract)
		}
	}
	return items
}
