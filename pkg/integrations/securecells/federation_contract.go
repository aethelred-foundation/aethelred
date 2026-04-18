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

// SecureCellFederationPolicyDiff captures how the owner-authored federation
// terms and counterparty-offered terms resolved into one replayable contract.
type SecureCellFederationPolicyDiff struct {
	Field            string   `json:"field"`
	InvitationValues []string `json:"invitation_values,omitempty"`
	OfferedValues    []string `json:"offered_values,omitempty"`
	NegotiatedValues []string `json:"negotiated_values,omitempty"`
	Effect           string   `json:"effect,omitempty"`
	Summary          string   `json:"summary,omitempty"`
}

type secureCellFederationTerms struct {
	SessionScopeIDs []string
	DataClasses     []string
	ComputeZones    []string
	AllowedActions  []string
}

// SecureCellFederationContractRenewRequest renews an active federation
// contract with owner-authored policy terms and optional counterparty-offered
// narrowing terms.
type SecureCellFederationContractRenewRequest struct {
	ActorDID               string            `json:"actor_did,omitempty"`
	SessionScopeIDs        []string          `json:"session_scope_ids,omitempty"`
	DataClasses            []string          `json:"data_classes,omitempty"`
	ComputeZones           []string          `json:"compute_zones,omitempty"`
	AllowedActions         []string          `json:"allowed_actions,omitempty"`
	OfferedSessionScopeIDs []string          `json:"offered_session_scope_ids,omitempty"`
	OfferedDataClasses     []string          `json:"offered_data_classes,omitempty"`
	OfferedComputeZones    []string          `json:"offered_compute_zones,omitempty"`
	OfferedActions         []string          `json:"offered_actions,omitempty"`
	Resource               string            `json:"resource,omitempty"`
	Reason                 string            `json:"reason,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationContract captures the negotiated, replayable contract
// binding one accepted federation invitation to the live collaboration state.
type SecureCellFederationContract struct {
	ID                     string                             `json:"id"`
	OrganizationID         string                             `json:"organization_id"`
	InvitationID           string                             `json:"invitation_id"`
	SponsorOfRecord        string                             `json:"sponsor_of_record,omitempty"`
	OrganizationName       string                             `json:"organization_name,omitempty"`
	Jurisdiction           string                             `json:"jurisdiction,omitempty"`
	Status                 SecureCellFederationContractStatus `json:"status"`
	ParticipantDIDs        []string                           `json:"participant_dids,omitempty"`
	SessionScopeIDs        []string                           `json:"session_scope_ids,omitempty"`
	DataClasses            []string                           `json:"data_classes,omitempty"`
	ComputeZones           []string                           `json:"compute_zones,omitempty"`
	AllowedActions         []string                           `json:"allowed_actions,omitempty"`
	OfferedSessionScopeIDs []string                           `json:"offered_session_scope_ids,omitempty"`
	OfferedDataClasses     []string                           `json:"offered_data_classes,omitempty"`
	OfferedComputeZones    []string                           `json:"offered_compute_zones,omitempty"`
	OfferedActions         []string                           `json:"offered_actions,omitempty"`
	NegotiationDiffs       []SecureCellFederationPolicyDiff   `json:"negotiation_diffs,omitempty"`
	Resource               string                             `json:"resource,omitempty"`
	NegotiationID          string                             `json:"negotiation_id,omitempty"`
	CredentialID           string                             `json:"credential_id,omitempty"`
	PolicyReceiptID        string                             `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash      string                             `json:"policy_receipt_hash,omitempty"`
	Revision               int                                `json:"revision,omitempty"`
	SupersedesContractID   string                             `json:"supersedes_contract_id,omitempty"`
	ReplacedByContractID   string                             `json:"replaced_by_contract_id,omitempty"`
	CreatedBy              string                             `json:"created_by,omitempty"`
	ActivatedBy            string                             `json:"activated_by,omitempty"`
	RevokedBy              string                             `json:"revoked_by,omitempty"`
	Reason                 string                             `json:"reason,omitempty"`
	CreatedAt              time.Time                          `json:"created_at,omitempty"`
	ActivatedAt            *time.Time                         `json:"activated_at,omitempty"`
	RevokedAt              *time.Time                         `json:"revoked_at,omitempty"`
	UpdatedAt              time.Time                          `json:"updated_at,omitempty"`
	Metadata               map[string]string                  `json:"metadata,omitempty"`
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
	OfferedSessionScopeIDs  []string                           `json:"offered_session_scope_ids,omitempty"`
	OfferedDataClasses      []string                           `json:"offered_data_classes,omitempty"`
	OfferedComputeZones     []string                           `json:"offered_compute_zones,omitempty"`
	OfferedActions          []string                           `json:"offered_actions,omitempty"`
	NegotiationDiffs        []SecureCellFederationPolicyDiff   `json:"negotiation_diffs,omitempty"`
	NegotiationDiffCount    int                                `json:"negotiation_diff_count"`
	Resource                string                             `json:"resource,omitempty"`
	NegotiationID           string                             `json:"negotiation_id,omitempty"`
	CredentialID            string                             `json:"credential_id,omitempty"`
	PolicyReceiptID         string                             `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash       string                             `json:"policy_receipt_hash,omitempty"`
	Revision                int                                `json:"revision,omitempty"`
	SupersedesContractID    string                             `json:"supersedes_contract_id,omitempty"`
	ReplacedByContractID    string                             `json:"replaced_by_contract_id,omitempty"`
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

// RevokeFederationContract revokes one active federation contract while
// leaving the collaborating participant enrolled in the cell.
func (s *Service) RevokeFederationContract(ctx context.Context, cellID string, contractID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}

	contractIdx, contract := findSecureCellFederationContract(run.result.FederationContracts, contractID)
	if contract == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrFederationContractNotFound, contractID)
	}
	if contract.Status != SecureCellFederationContractStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: federation contract %q is %s", ErrFederationContractImmutable, contractID, contract.Status)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to revoke federation contracts", ErrPolicyDenied, actorDID)
	}

	receipt, err := s.evaluateStage(ctx, run.request, "revoke_federation_contract", lastReceiptHash(run.result), map[string]string{
		"federation_contract_id":       contract.ID,
		"federation_organization_id":   contract.OrganizationID,
		"federation_invitation_id":     contract.InvitationID,
		"federation_sponsor_of_record": contract.SponsorOfRecord,
		"federation_allowed_actions":   strings.Join(uniqueTrimmedStrings(contract.AllowedActions), ","),
		"federation_session_scopes":    strings.Join(uniqueTrimmedStrings(contract.SessionScopeIDs), ","),
		"cell_status_before":           string(run.result.Status),
		"transition_reason":            strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	revokedAt := time.Now().UTC()
	revoked := revokeFederationContract(&run.result.FederationContracts[contractIdx], actorDID, strings.TrimSpace(lifecycle.Reason), revokedAt, lifecycle.Metadata, "")
	run.result.UpdatedAt = revokedAt

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_contract_revoked", revoked.ID),
		Action:           "secure_cell.federation_contract_revoked",
		Actor:            actorDID,
		TargetType:       "federation_contract",
		TargetDID:        revoked.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(lifecycle.Reason),
		Metadata: mergeStringMaps(lifecycle.Metadata, map[string]string{
			"federation_contract_id":       revoked.ID,
			"federation_organization_id":   revoked.OrganizationID,
			"federation_invitation_id":     revoked.InvitationID,
			"federation_sponsor_of_record": revoked.SponsorOfRecord,
			"federation_contract_revision": fmt.Sprintf("%d", revoked.Revision),
			"federation_allowed_actions":   strings.Join(uniqueTrimmedStrings(revoked.AllowedActions), ","),
			"federation_session_scopes":    strings.Join(uniqueTrimmedStrings(revoked.SessionScopeIDs), ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// RenewFederationContract supersedes one active federation contract with a new
// negotiated revision.
func (s *Service) RenewFederationContract(ctx context.Context, cellID string, contractID string, renewal SecureCellFederationContractRenewRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}

	contractIdx, contract := findSecureCellFederationContract(run.result.FederationContracts, contractID)
	if contract == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrFederationContractNotFound, contractID)
	}
	if contract.Status != SecureCellFederationContractStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: federation contract %q is %s", ErrFederationContractImmutable, contractID, contract.Status)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(renewal.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to renew federation contracts", ErrPolicyDenied, actorDID)
	}

	participantState, err := secureCellPrimaryFederationContractParticipant(run.result, *contract)
	if err != nil {
		return nil, err
	}
	invitation := secureCellFederationInvitationForContract(run.result.FederationInvitations, *contract)
	ownerTerms, offeredTerms, resource, err := secureCellRenewalTerms(run, *contract, renewal)
	if err != nil {
		return nil, err
	}
	negotiatedTerms, diffs, err := secureCellNegotiateFederationTerms(ownerTerms, offeredTerms)
	if err != nil {
		return nil, err
	}
	if err := secureCellValidateNegotiatedFederationTerms(run.request.Policy, negotiatedTerms); err != nil {
		return nil, err
	}

	receipt, err := s.evaluateStage(ctx, run.request, "renew_federation_contract", lastReceiptHash(run.result), map[string]string{
		"federation_contract_id":            contract.ID,
		"federation_contract_revision":      fmt.Sprintf("%d", contract.Revision),
		"federation_organization_id":        contract.OrganizationID,
		"federation_invitation_id":          contract.InvitationID,
		"federation_sponsor_of_record":      contract.SponsorOfRecord,
		"federation_contract_supersedes":    contract.ID,
		"federation_session_scopes":         strings.Join(uniqueTrimmedStrings(negotiatedTerms.SessionScopeIDs), ","),
		"federation_data_classes":           strings.Join(uniqueTrimmedStrings(negotiatedTerms.DataClasses), ","),
		"federation_compute_zones":          strings.Join(uniqueTrimmedStrings(negotiatedTerms.ComputeZones), ","),
		"federation_allowed_actions":        strings.Join(uniqueTrimmedStrings(negotiatedTerms.AllowedActions), ","),
		"federation_offered_session_scopes": strings.Join(uniqueTrimmedStrings(offeredTerms.SessionScopeIDs), ","),
		"federation_offered_data_classes":   strings.Join(uniqueTrimmedStrings(offeredTerms.DataClasses), ","),
		"federation_offered_compute_zones":  strings.Join(uniqueTrimmedStrings(offeredTerms.ComputeZones), ","),
		"federation_offered_actions":        strings.Join(uniqueTrimmedStrings(offeredTerms.AllowedActions), ","),
		"federation_policy_diffs":           secureCellFederationPolicyDiffsSummary(diffs),
		"target_participant_did":            participantState.ParticipantDID,
		"cell_status_before":                string(run.result.Status),
		"transition_reason":                 strings.TrimSpace(renewal.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	revokedAt := time.Now().UTC()
	revoked := revokeFederationContract(&run.result.FederationContracts[contractIdx], actorDID, firstNonEmpty(strings.TrimSpace(renewal.Reason), contract.Reason), revokedAt, renewal.Metadata, "")
	newContract := newActivatedFederationContract(run.request, invitation, participantState, negotiatedTerms, offeredTerms, diffs, resource, receipt, actorDID, strings.TrimSpace(renewal.Reason), renewal.Metadata, &revoked)
	run.result.FederationContracts[contractIdx].ReplacedByContractID = newContract.ID
	run.result.FederationContracts = append(run.result.FederationContracts, newContract)
	run.result.UpdatedAt = revokedAt

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_contract_renewed", newContract.ID),
		Action:           "secure_cell.federation_contract_renewed",
		Actor:            actorDID,
		TargetType:       "federation_contract",
		TargetDID:        newContract.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(renewal.Reason),
		Metadata: mergeStringMaps(renewal.Metadata, map[string]string{
			"federation_contract_id":            newContract.ID,
			"federation_contract_previous_id":   revoked.ID,
			"federation_contract_revision":      fmt.Sprintf("%d", newContract.Revision),
			"federation_contract_supersedes":    revoked.ID,
			"federation_organization_id":        newContract.OrganizationID,
			"federation_invitation_id":          newContract.InvitationID,
			"federation_sponsor_of_record":      newContract.SponsorOfRecord,
			"federation_session_scopes":         strings.Join(uniqueTrimmedStrings(newContract.SessionScopeIDs), ","),
			"federation_data_classes":           strings.Join(uniqueTrimmedStrings(newContract.DataClasses), ","),
			"federation_compute_zones":          strings.Join(uniqueTrimmedStrings(newContract.ComputeZones), ","),
			"federation_allowed_actions":        strings.Join(uniqueTrimmedStrings(newContract.AllowedActions), ","),
			"federation_offered_session_scopes": strings.Join(uniqueTrimmedStrings(newContract.OfferedSessionScopeIDs), ","),
			"federation_offered_data_classes":   strings.Join(uniqueTrimmedStrings(newContract.OfferedDataClasses), ","),
			"federation_offered_compute_zones":  strings.Join(uniqueTrimmedStrings(newContract.OfferedComputeZones), ","),
			"federation_offered_actions":        strings.Join(uniqueTrimmedStrings(newContract.OfferedActions), ","),
			"federation_policy_diffs":           secureCellFederationPolicyDiffsSummary(newContract.NegotiationDiffs),
			"target_participant_did":            participantState.ParticipantDID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func newActivatedFederationContract(req SecureCellRequest, invitation SecureCellFederationInvitation, participant SecureCellParticipantState, negotiatedTerms secureCellFederationTerms, offeredTerms secureCellFederationTerms, diffs []SecureCellFederationPolicyDiff, resource string, receipt *policy.SignedPolicyReceipt, actorDID string, reason string, metadata map[string]string, prior *SecureCellFederationContract) SecureCellFederationContract {
	activatedAt := time.Now().UTC()
	revision := 1
	supersedesContractID := ""
	createdBy := strings.TrimSpace(invitation.CreatedBy)
	createdAt := invitation.CreatedAt.UTC()
	if prior != nil {
		revision = secureCellMaxInt(1, prior.Revision) + 1
		supersedesContractID = strings.TrimSpace(prior.ID)
		createdBy = strings.TrimSpace(actorDID)
		createdAt = activatedAt
	}
	contract := SecureCellFederationContract{
		ID:                     secureCellFederationContractID(req, invitation, participant.ParticipantDID, revision, resource, negotiatedTerms),
		OrganizationID:         strings.TrimSpace(invitation.OrganizationID),
		InvitationID:           strings.TrimSpace(invitation.ID),
		SponsorOfRecord:        strings.TrimSpace(invitation.SponsorOfRecord),
		OrganizationName:       strings.TrimSpace(invitation.OrganizationName),
		Jurisdiction:           firstNonEmpty(strings.TrimSpace(invitation.Jurisdiction), req.Jurisdiction),
		Status:                 SecureCellFederationContractStatusActive,
		ParticipantDIDs:        uniqueTrimmedStrings([]string{participant.ParticipantDID}),
		SessionScopeIDs:        uniqueTrimmedStrings(negotiatedTerms.SessionScopeIDs),
		DataClasses:            uniqueTrimmedStrings(negotiatedTerms.DataClasses),
		ComputeZones:           uniqueTrimmedStrings(negotiatedTerms.ComputeZones),
		AllowedActions:         uniqueTrimmedStrings(negotiatedTerms.AllowedActions),
		OfferedSessionScopeIDs: uniqueTrimmedStrings(offeredTerms.SessionScopeIDs),
		OfferedDataClasses:     uniqueTrimmedStrings(offeredTerms.DataClasses),
		OfferedComputeZones:    uniqueTrimmedStrings(offeredTerms.ComputeZones),
		OfferedActions:         uniqueTrimmedStrings(offeredTerms.AllowedActions),
		NegotiationDiffs:       cloneSecureCellFederationPolicyDiffs(diffs),
		Resource:               strings.TrimSpace(resource),
		NegotiationID:          strings.TrimSpace(participant.NegotiationID),
		CredentialID:           strings.TrimSpace(participant.CredentialID),
		PolicyReceiptID:        safeString(receipt, func(in *policy.SignedPolicyReceipt) string { return strings.TrimSpace(in.ID) }),
		PolicyReceiptHash:      safeString(receipt, func(in *policy.SignedPolicyReceipt) string { return strings.TrimSpace(in.ContentHash) }),
		Revision:               revision,
		SupersedesContractID:   supersedesContractID,
		CreatedBy:              createdBy,
		ActivatedBy:            strings.TrimSpace(actorDID),
		Reason:                 strings.TrimSpace(reason),
		CreatedAt:              createdAt,
		ActivatedAt:            &activatedAt,
		UpdatedAt:              activatedAt,
		Metadata:               mergeStringMaps(invitation.Metadata, metadata),
	}
	if contract.Resource == "" {
		contract.Resource = fmt.Sprintf("secure-cell:%s:federation-contract:%s", cellID(req), contract.ID)
	}
	if contract.CreatedAt.IsZero() {
		contract.CreatedAt = activatedAt
	}
	return contract
}

func secureCellFederationContractID(req SecureCellRequest, invitation SecureCellFederationInvitation, participantDID string, revision int, resource string, terms secureCellFederationTerms) string {
	seed := fmt.Sprintf(
		"%s|%s|%s|%s|%d|%s|%s|%s|%s|%s",
		cellID(req),
		invitation.ID,
		invitation.OrganizationID,
		strings.TrimSpace(participantDID),
		secureCellMaxInt(1, revision),
		strings.TrimSpace(resource),
		strings.Join(uniqueTrimmedStrings(terms.SessionScopeIDs), ","),
		strings.Join(uniqueTrimmedStrings(terms.DataClasses), ","),
		strings.Join(uniqueTrimmedStrings(terms.ComputeZones), ","),
		strings.Join(uniqueTrimmedStrings(terms.AllowedActions), ","),
	)
	return fmt.Sprintf("%s-federation-contract-%x", cellID(req), sha256.Sum256([]byte(seed)))
}

func secureCellDefaultFederationContractActions() []string {
	return []string{
		secureCellFederationContractActionShareOutput,
		secureCellFederationContractActionSessionExchange,
		secureCellFederationContractActionThreadMessage,
	}
}

func revokeFederationContract(contract *SecureCellFederationContract, actorDID string, reason string, revokedAt time.Time, metadata map[string]string, replacedByContractID string) SecureCellFederationContract {
	if contract == nil {
		return SecureCellFederationContract{}
	}
	contract.Status = SecureCellFederationContractStatusRevoked
	contract.RevokedBy = strings.TrimSpace(actorDID)
	contract.Reason = firstNonEmpty(strings.TrimSpace(reason), contract.Reason)
	contract.RevokedAt = cloneTimePtr(&revokedAt)
	contract.UpdatedAt = revokedAt.UTC()
	contract.ReplacedByContractID = firstNonEmpty(strings.TrimSpace(replacedByContractID), strings.TrimSpace(contract.ReplacedByContractID))
	contract.Metadata = mergeStringMaps(contract.Metadata, metadata)
	return *contract
}

func secureCellPrimaryFederationContractParticipant(result *SecureCellResult, contract SecureCellFederationContract) (SecureCellParticipantState, error) {
	if result == nil {
		return SecureCellParticipantState{}, fmt.Errorf("securecells/service: secure cell result is required")
	}
	for _, participantDID := range uniqueTrimmedStrings(contract.ParticipantDIDs) {
		state, ok := participantStateForResult(result, participantDID)
		if !ok {
			continue
		}
		if state.Status == SecureCellParticipantStatusActive {
			return state, nil
		}
	}
	return SecureCellParticipantState{}, fmt.Errorf("securecells/service: %w: federation contract %q has no active participant", ErrFederationContractImmutable, strings.TrimSpace(contract.ID))
}

func secureCellFederationInvitationForContract(invitations []SecureCellFederationInvitation, contract SecureCellFederationContract) SecureCellFederationInvitation {
	if _, invitation := findSecureCellFederationInvitation(invitations, contract.InvitationID); invitation != nil {
		return *invitation
	}
	return SecureCellFederationInvitation{
		ID:               strings.TrimSpace(contract.InvitationID),
		OrganizationID:   strings.TrimSpace(contract.OrganizationID),
		SponsorOfRecord:  strings.TrimSpace(contract.SponsorOfRecord),
		OrganizationName: strings.TrimSpace(contract.OrganizationName),
		Jurisdiction:     strings.TrimSpace(contract.Jurisdiction),
		SessionScopeIDs:  uniqueTrimmedStrings(contract.SessionScopeIDs),
		DataClasses:      uniqueTrimmedStrings(contract.DataClasses),
		ComputeZones:     uniqueTrimmedStrings(contract.ComputeZones),
		AllowedActions:   uniqueTrimmedStrings(contract.AllowedActions),
		Resource:         strings.TrimSpace(contract.Resource),
		CreatedBy:        strings.TrimSpace(contract.CreatedBy),
		CreatedAt:        contract.CreatedAt.UTC(),
		Metadata:         cloneStringMap(contract.Metadata),
	}
}

func secureCellRenewalTerms(run *secureCellRun, contract SecureCellFederationContract, renewal SecureCellFederationContractRenewRequest) (secureCellFederationTerms, secureCellFederationTerms, string, error) {
	if run == nil || run.result == nil {
		return secureCellFederationTerms{}, secureCellFederationTerms{}, "", fmt.Errorf("securecells/service: secure cell result is required")
	}

	sessionScopes := uniqueTrimmedStrings(contract.SessionScopeIDs)
	if renewal.SessionScopeIDs != nil {
		resolved, err := secureCellResolveFederationSessionScopes(run.result.Sessions, renewal.SessionScopeIDs)
		if err != nil {
			return secureCellFederationTerms{}, secureCellFederationTerms{}, "", err
		}
		sessionScopes = resolved
	}
	dataClasses := uniqueTrimmedStrings(contract.DataClasses)
	if renewal.DataClasses != nil {
		dataClasses = uniqueTrimmedStrings(renewal.DataClasses)
	}
	computeZones := uniqueTrimmedStrings(contract.ComputeZones)
	if renewal.ComputeZones != nil {
		computeZones = uniqueTrimmedStrings(renewal.ComputeZones)
	}
	allowedActions := uniqueTrimmedStrings(contract.AllowedActions)
	if renewal.AllowedActions != nil {
		var err error
		allowedActions, err = secureCellNormalizeFederationActions(renewal.AllowedActions)
		if err != nil {
			return secureCellFederationTerms{}, secureCellFederationTerms{}, "", err
		}
	}

	ownerTerms := secureCellFederationTerms{
		SessionScopeIDs: sessionScopes,
		DataClasses:     dataClasses,
		ComputeZones:    computeZones,
		AllowedActions:  allowedActions,
	}
	offeredTerms, err := secureCellFederationOfferedTerms(run.result.Sessions, renewal.OfferedSessionScopeIDs, renewal.OfferedDataClasses, renewal.OfferedComputeZones, renewal.OfferedActions)
	if err != nil {
		return secureCellFederationTerms{}, secureCellFederationTerms{}, "", err
	}
	return ownerTerms, offeredTerms, firstNonEmpty(strings.TrimSpace(renewal.Resource), strings.TrimSpace(contract.Resource)), nil
}

func secureCellInvitationTerms(invitation SecureCellFederationInvitation) secureCellFederationTerms {
	allowedActions := uniqueTrimmedStrings(invitation.AllowedActions)
	if len(allowedActions) == 0 {
		allowedActions = secureCellDefaultFederationContractActions()
	}
	return secureCellFederationTerms{
		SessionScopeIDs: uniqueTrimmedStrings(invitation.SessionScopeIDs),
		DataClasses:     uniqueTrimmedStrings(invitation.DataClasses),
		ComputeZones:    uniqueTrimmedStrings(invitation.ComputeZones),
		AllowedActions:  allowedActions,
	}
}

func secureCellContractTerms(contract SecureCellFederationContract) secureCellFederationTerms {
	return secureCellFederationTerms{
		SessionScopeIDs: uniqueTrimmedStrings(contract.SessionScopeIDs),
		DataClasses:     uniqueTrimmedStrings(contract.DataClasses),
		ComputeZones:    uniqueTrimmedStrings(contract.ComputeZones),
		AllowedActions:  uniqueTrimmedStrings(contract.AllowedActions),
	}
}

func secureCellFederationOfferedTerms(sessions []SecureCellSession, sessionScopeIDs, dataClasses, computeZones, allowedActions []string) (secureCellFederationTerms, error) {
	resolvedSessionScopes := uniqueTrimmedStrings(sessionScopeIDs)
	if len(resolvedSessionScopes) > 0 {
		var err error
		resolvedSessionScopes, err = secureCellResolveFederationSessionScopes(sessions, sessionScopeIDs)
		if err != nil {
			return secureCellFederationTerms{}, err
		}
	}
	normalizedActions, err := secureCellNormalizeFederationActions(allowedActions)
	if err != nil {
		return secureCellFederationTerms{}, err
	}
	return secureCellFederationTerms{
		SessionScopeIDs: resolvedSessionScopes,
		DataClasses:     uniqueTrimmedStrings(dataClasses),
		ComputeZones:    uniqueTrimmedStrings(computeZones),
		AllowedActions:  normalizedActions,
	}, nil
}

func secureCellNegotiateFederationTerms(invitationTerms secureCellFederationTerms, offeredTerms secureCellFederationTerms) (secureCellFederationTerms, []SecureCellFederationPolicyDiff, error) {
	negotiatedSessionScopes, sessionDiff, err := secureCellNegotiateFederationField("session_scope_ids", invitationTerms.SessionScopeIDs, offeredTerms.SessionScopeIDs)
	if err != nil {
		return secureCellFederationTerms{}, nil, err
	}
	negotiatedDataClasses, dataClassDiff, err := secureCellNegotiateFederationField("data_classes", invitationTerms.DataClasses, offeredTerms.DataClasses)
	if err != nil {
		return secureCellFederationTerms{}, nil, err
	}
	negotiatedComputeZones, computeZoneDiff, err := secureCellNegotiateFederationField("compute_zones", invitationTerms.ComputeZones, offeredTerms.ComputeZones)
	if err != nil {
		return secureCellFederationTerms{}, nil, err
	}
	negotiatedActions, actionDiff, err := secureCellNegotiateFederationField("allowed_actions", invitationTerms.AllowedActions, offeredTerms.AllowedActions)
	if err != nil {
		return secureCellFederationTerms{}, nil, err
	}
	return secureCellFederationTerms{
			SessionScopeIDs: negotiatedSessionScopes,
			DataClasses:     negotiatedDataClasses,
			ComputeZones:    negotiatedComputeZones,
			AllowedActions:  negotiatedActions,
		},
		compactSecureCellFederationPolicyDiffs(sessionDiff, dataClassDiff, computeZoneDiff, actionDiff),
		nil
}

func secureCellValidateNegotiatedFederationTerms(policy SecureCellPolicy, terms secureCellFederationTerms) error {
	if len(uniqueTrimmedStrings(terms.AllowedActions)) == 0 {
		return fmt.Errorf("securecells/service: %w: negotiated federation actions are required", ErrFederationNegotiationConflict)
	}
	if len(policy.DataClasses) > 0 && len(terms.DataClasses) > 0 && len(intersectSecureCellFederationValues(policy.DataClasses, terms.DataClasses)) == 0 {
		return fmt.Errorf("securecells/service: %w: negotiated federation data classes do not align with the secure cell policy", ErrFederationNegotiationConflict)
	}
	if len(policy.ComputeZones) > 0 && len(terms.ComputeZones) > 0 && len(intersectSecureCellFederationValues(policy.ComputeZones, terms.ComputeZones)) == 0 {
		return fmt.Errorf("securecells/service: %w: negotiated federation compute zones do not align with the secure cell policy", ErrFederationNegotiationConflict)
	}
	return nil
}

func secureCellNegotiateFederationField(field string, invitationValues []string, offeredValues []string) ([]string, SecureCellFederationPolicyDiff, error) {
	invitationValues = uniqueTrimmedStrings(invitationValues)
	offeredValues = uniqueTrimmedStrings(offeredValues)
	diff := SecureCellFederationPolicyDiff{
		Field:            strings.TrimSpace(field),
		InvitationValues: append([]string(nil), invitationValues...),
		OfferedValues:    append([]string(nil), offeredValues...),
	}

	switch {
	case len(invitationValues) == 0 && len(offeredValues) == 0:
		return nil, diff, nil
	case len(offeredValues) == 0:
		diff.Effect = "owner_terms_applied"
		diff.NegotiatedValues = append([]string(nil), invitationValues...)
		diff.Summary = "counterparty accepted owner terms"
		return invitationValues, diff, nil
	case len(invitationValues) == 0:
		diff.Effect = "counterparty_narrowed_open_scope"
		diff.NegotiatedValues = append([]string(nil), offeredValues...)
		diff.Summary = "counterparty narrowed an otherwise open federation scope"
		return offeredValues, diff, nil
	default:
		negotiated := intersectSecureCellFederationValues(invitationValues, offeredValues)
		if len(negotiated) == 0 {
			return nil, SecureCellFederationPolicyDiff{}, fmt.Errorf("securecells/service: %w: no mutually permitted %s values", ErrFederationNegotiationConflict, strings.TrimSpace(field))
		}
		diff.NegotiatedValues = append([]string(nil), negotiated...)
		if equalFoldStringSlices(invitationValues, negotiated) && equalFoldStringSlices(offeredValues, negotiated) {
			diff.Effect = "unchanged"
			diff.Summary = "counterparty accepted the owner-authored federation terms"
		} else {
			diff.Effect = "narrowed"
			diff.Summary = "negotiated federation scope narrowed relative to one or both proposed term sets"
		}
		return negotiated, diff, nil
	}
}

func intersectSecureCellFederationValues(left []string, right []string) []string {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	rightIndex := make(map[string]string, len(right))
	for _, value := range uniqueTrimmedStrings(right) {
		rightIndex[strings.ToLower(strings.TrimSpace(value))] = strings.TrimSpace(value)
	}
	out := make([]string, 0, len(left))
	for _, candidate := range uniqueTrimmedStrings(left) {
		if matched, ok := rightIndex[strings.ToLower(strings.TrimSpace(candidate))]; ok {
			out = append(out, firstNonEmpty(strings.TrimSpace(candidate), matched))
		}
	}
	return uniqueTrimmedStrings(out)
}

func equalFoldStringSlices(left []string, right []string) bool {
	left = uniqueTrimmedStrings(left)
	right = uniqueTrimmedStrings(right)
	if len(left) != len(right) {
		return false
	}
	for idx := range left {
		if !strings.EqualFold(strings.TrimSpace(left[idx]), strings.TrimSpace(right[idx])) {
			return false
		}
	}
	return true
}

func compactSecureCellFederationPolicyDiffs(diffs ...SecureCellFederationPolicyDiff) []SecureCellFederationPolicyDiff {
	out := make([]SecureCellFederationPolicyDiff, 0, len(diffs))
	for _, diff := range diffs {
		if strings.TrimSpace(diff.Field) == "" {
			continue
		}
		if len(diff.InvitationValues) == 0 && len(diff.OfferedValues) == 0 && len(diff.NegotiatedValues) == 0 {
			continue
		}
		out = append(out, diff)
	}
	return out
}

func cloneSecureCellFederationPolicyDiffs(in []SecureCellFederationPolicyDiff) []SecureCellFederationPolicyDiff {
	if len(in) == 0 {
		return nil
	}
	out := make([]SecureCellFederationPolicyDiff, 0, len(in))
	for _, diff := range in {
		out = append(out, SecureCellFederationPolicyDiff{
			Field:            strings.TrimSpace(diff.Field),
			InvitationValues: append([]string(nil), uniqueTrimmedStrings(diff.InvitationValues)...),
			OfferedValues:    append([]string(nil), uniqueTrimmedStrings(diff.OfferedValues)...),
			NegotiatedValues: append([]string(nil), uniqueTrimmedStrings(diff.NegotiatedValues)...),
			Effect:           strings.TrimSpace(diff.Effect),
			Summary:          strings.TrimSpace(diff.Summary),
		})
	}
	return out
}

func secureCellFederationPolicyDiffsSummary(diffs []SecureCellFederationPolicyDiff) string {
	items := make([]string, 0, len(diffs))
	for _, diff := range diffs {
		field := strings.TrimSpace(diff.Field)
		if field == "" {
			continue
		}
		negotiated := strings.Join(uniqueTrimmedStrings(diff.NegotiatedValues), "|")
		if negotiated == "" {
			negotiated = "open"
		}
		effect := firstNonEmpty(strings.TrimSpace(diff.Effect), "resolved")
		items = append(items, fmt.Sprintf("%s:%s:%s", field, effect, negotiated))
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

func secureCellNormalizeFederationActions(values []string) ([]string, error) {
	normalized := uniqueTrimmedStrings(values)
	if len(normalized) == 0 {
		return nil, nil
	}
	allowed := make(map[string]struct{}, len(secureCellDefaultFederationContractActions()))
	for _, action := range secureCellDefaultFederationContractActions() {
		allowed[strings.ToLower(strings.TrimSpace(action))] = struct{}{}
	}
	for _, value := range normalized {
		if _, ok := allowed[strings.ToLower(strings.TrimSpace(value))]; !ok {
			return nil, fmt.Errorf("securecells/service: %w: unsupported federation action %q", ErrFederationNegotiationConflict, strings.TrimSpace(value))
		}
	}
	return normalized, nil
}

func secureCellMaxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
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
		CellID:                 safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:               safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:             safeSecureCellStatus(run),
		Jurisdiction:           firstNonEmpty(strings.TrimSpace(contract.Jurisdiction), safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) })),
		ContractID:             strings.TrimSpace(contract.ID),
		OrganizationID:         strings.TrimSpace(contract.OrganizationID),
		InvitationID:           strings.TrimSpace(contract.InvitationID),
		SponsorOfRecord:        strings.TrimSpace(contract.SponsorOfRecord),
		OrganizationName:       strings.TrimSpace(contract.OrganizationName),
		Status:                 contract.Status,
		ParticipantDIDs:        uniqueTrimmedStrings(contract.ParticipantDIDs),
		SessionScopeIDs:        uniqueTrimmedStrings(contract.SessionScopeIDs),
		SessionScopeCount:      len(uniqueTrimmedStrings(contract.SessionScopeIDs)),
		DataClasses:            uniqueTrimmedStrings(contract.DataClasses),
		DataClassCount:         len(uniqueTrimmedStrings(contract.DataClasses)),
		ComputeZones:           uniqueTrimmedStrings(contract.ComputeZones),
		ComputeZoneCount:       len(uniqueTrimmedStrings(contract.ComputeZones)),
		AllowedActions:         append([]string(nil), uniqueTrimmedStrings(contract.AllowedActions)...),
		OfferedSessionScopeIDs: append([]string(nil), uniqueTrimmedStrings(contract.OfferedSessionScopeIDs)...),
		OfferedDataClasses:     append([]string(nil), uniqueTrimmedStrings(contract.OfferedDataClasses)...),
		OfferedComputeZones:    append([]string(nil), uniqueTrimmedStrings(contract.OfferedComputeZones)...),
		OfferedActions:         append([]string(nil), uniqueTrimmedStrings(contract.OfferedActions)...),
		NegotiationDiffs:       cloneSecureCellFederationPolicyDiffs(contract.NegotiationDiffs),
		NegotiationDiffCount:   len(contract.NegotiationDiffs),
		Resource:               strings.TrimSpace(contract.Resource),
		NegotiationID:          strings.TrimSpace(contract.NegotiationID),
		CredentialID:           strings.TrimSpace(contract.CredentialID),
		PolicyReceiptID:        strings.TrimSpace(contract.PolicyReceiptID),
		PolicyReceiptHash:      strings.TrimSpace(contract.PolicyReceiptHash),
		Revision:               secureCellMaxInt(1, contract.Revision),
		SupersedesContractID:   strings.TrimSpace(contract.SupersedesContractID),
		ReplacedByContractID:   strings.TrimSpace(contract.ReplacedByContractID),
		CreatedAt:              contract.CreatedAt.UTC(),
		ActivatedAt:            cloneTimePtr(contract.ActivatedAt),
		RevokedAt:              cloneTimePtr(contract.RevokedAt),
		UpdatedAt:              secureCellFederationContractUpdatedAt(contract),
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
	var bestActive *SecureCellFederationContract
	for idx := range result.FederationContracts {
		contract := &result.FederationContracts[idx]
		for _, candidate := range contract.ParticipantDIDs {
			if strings.TrimSpace(candidate) != participantDID {
				continue
			}
			if best == nil || secureCellFederationContractUpdatedAt(*contract).After(secureCellFederationContractUpdatedAt(*best)) {
				best = contract
			}
			if contract.Status == SecureCellFederationContractStatusActive && (bestActive == nil || secureCellFederationContractUpdatedAt(*contract).After(secureCellFederationContractUpdatedAt(*bestActive))) {
				bestActive = contract
			}
			break
		}
	}
	if bestActive != nil {
		return strings.TrimSpace(bestActive.OrganizationID), true
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
