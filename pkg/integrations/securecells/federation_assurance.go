package securecells

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellFederationAssuranceSeverity ranks the urgency of one live
// federation posture finding.
type SecureCellFederationAssuranceSeverity string

const (
	SecureCellFederationAssuranceSeverityInfo     SecureCellFederationAssuranceSeverity = "info"
	SecureCellFederationAssuranceSeverityWarning  SecureCellFederationAssuranceSeverity = "warning"
	SecureCellFederationAssuranceSeverityCritical SecureCellFederationAssuranceSeverity = "critical"
)

// SecureCellFederationAssuranceCategory groups live federation posture
// findings into operator-facing buckets.
type SecureCellFederationAssuranceCategory string

const (
	SecureCellFederationAssuranceCategoryContractCoverage              SecureCellFederationAssuranceCategory = "contract_coverage"
	SecureCellFederationAssuranceCategoryParticipantContinuity         SecureCellFederationAssuranceCategory = "participant_continuity"
	SecureCellFederationAssuranceCategoryExpectedIdentityDrift         SecureCellFederationAssuranceCategory = "expected_identity_drift"
	SecureCellFederationAssuranceCategoryCredentialContinuity          SecureCellFederationAssuranceCategory = "credential_continuity"
	SecureCellFederationAssuranceCategorySessionScopeDrift             SecureCellFederationAssuranceCategory = "session_scope_drift"
	SecureCellFederationAssuranceCategoryPolicyDrift                   SecureCellFederationAssuranceCategory = "policy_drift"
	SecureCellFederationAssuranceCategoryConfidentialComputeDrift      SecureCellFederationAssuranceCategory = "confidential_compute_drift"
	SecureCellFederationAssuranceCategoryArtifactExposure              SecureCellFederationAssuranceCategory = "artifact_exposure"
	SecureCellFederationAssuranceCategoryConcurrentRevision            SecureCellFederationAssuranceCategory = "concurrent_revision_drift"
	SecureCellFederationAssuranceCategoryCounterpartyAssuranceMissing  SecureCellFederationAssuranceCategory = "counterparty_assurance_missing"
	SecureCellFederationAssuranceCategoryCounterpartyAssuranceInvalid  SecureCellFederationAssuranceCategory = "counterparty_assurance_invalid"
	SecureCellFederationAssuranceCategoryCounterpartyAssuranceExpired  SecureCellFederationAssuranceCategory = "counterparty_assurance_expired"
	SecureCellFederationAssuranceCategoryCounterpartyAssuranceStale    SecureCellFederationAssuranceCategory = "counterparty_assurance_stale"
	SecureCellFederationAssuranceCategoryCounterpartyAssuranceCritical SecureCellFederationAssuranceCategory = "counterparty_assurance_critical"
	SecureCellFederationAssuranceCategoryCounterpartyScopeDrift        SecureCellFederationAssuranceCategory = "counterparty_scope_drift"
	SecureCellFederationAssuranceCategoryCounterpartyConfidentialDrift SecureCellFederationAssuranceCategory = "counterparty_confidential_drift"
)

// SecureCellFederationAssuranceFinding captures one live cross-organization
// posture issue derived from current secure-cell runtime state.
type SecureCellFederationAssuranceFinding struct {
	ID                      string                                `json:"id"`
	CellID                  string                                `json:"cell_id"`
	CellName                string                                `json:"cell_name,omitempty"`
	Jurisdiction            string                                `json:"jurisdiction,omitempty"`
	CellStatus              SecureCellStatus                      `json:"cell_status"`
	OrganizationID          string                                `json:"organization_id,omitempty"`
	SponsorOfRecord         string                                `json:"sponsor_of_record,omitempty"`
	OrganizationName        string                                `json:"organization_name,omitempty"`
	InvitationID            string                                `json:"invitation_id,omitempty"`
	ContractID              string                                `json:"contract_id,omitempty"`
	ContractRevision        int                                   `json:"contract_revision,omitempty"`
	ContractStatus          SecureCellFederationContractStatus    `json:"contract_status,omitempty"`
	ParticipantDID          string                                `json:"participant_did,omitempty"`
	ExpectedDID             string                                `json:"expected_did,omitempty"`
	CredentialID            string                                `json:"credential_id,omitempty"`
	SessionIDs              []string                              `json:"session_ids,omitempty"`
	ArtifactIDs             []string                              `json:"artifact_ids,omitempty"`
	ArtifactType            string                                `json:"artifact_type,omitempty"`
	Severity                SecureCellFederationAssuranceSeverity `json:"severity"`
	Category                SecureCellFederationAssuranceCategory `json:"category"`
	Summary                 string                                `json:"summary"`
	Reason                  string                                `json:"reason,omitempty"`
	SuggestedAction         string                                `json:"suggested_action,omitempty"`
	AutoContainmentEligible bool                                  `json:"auto_containment_eligible"`
	DetectedAt              time.Time                             `json:"detected_at"`
	Metadata                map[string]string                     `json:"metadata,omitempty"`
}

// SecureCellFederationAssuranceFilter narrows operator queries across live
// federation posture findings.
type SecureCellFederationAssuranceFilter struct {
	CellID          string                                `json:"cell_id,omitempty"`
	OrganizationID  string                                `json:"organization_id,omitempty"`
	ContractID      string                                `json:"contract_id,omitempty"`
	SponsorOfRecord string                                `json:"sponsor_of_record,omitempty"`
	ParticipantDID  string                                `json:"participant_did,omitempty"`
	Severity        SecureCellFederationAssuranceSeverity `json:"severity,omitempty"`
	Category        SecureCellFederationAssuranceCategory `json:"category,omitempty"`
	Limit           int                                   `json:"limit,omitempty"`
}

// SecureCellFederationAssuranceActionFilter narrows operator queries over
// automated containment actions already applied by the assurance runtime.
type SecureCellFederationAssuranceActionFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	FindingID      string     `json:"finding_id,omitempty"`
	Category       string     `json:"category,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationAssuranceActionRecord projects one automated contract
// containment action executed by the federation assurance runtime.
type SecureCellFederationAssuranceActionRecord struct {
	CellID          string                                `json:"cell_id"`
	CellName        string                                `json:"cell_name,omitempty"`
	Jurisdiction    string                                `json:"jurisdiction,omitempty"`
	CellStatus      SecureCellStatus                      `json:"cell_status"`
	OrganizationID  string                                `json:"organization_id,omitempty"`
	SponsorOfRecord string                                `json:"sponsor_of_record,omitempty"`
	ContractID      string                                `json:"contract_id,omitempty"`
	InvitationID    string                                `json:"invitation_id,omitempty"`
	FindingID       string                                `json:"finding_id,omitempty"`
	Category        SecureCellFederationAssuranceCategory `json:"category,omitempty"`
	Severity        SecureCellFederationAssuranceSeverity `json:"severity,omitempty"`
	Action          string                                `json:"action"`
	Trigger         string                                `json:"trigger,omitempty"`
	Actor           string                                `json:"actor"`
	AutomatedActor  string                                `json:"automated_actor,omitempty"`
	Reason          string                                `json:"reason,omitempty"`
	TransitionID    string                                `json:"transition_id"`
	OccurredAt      time.Time                             `json:"occurred_at"`
	Metadata        map[string]string                     `json:"metadata,omitempty"`
}

// SecureCellFederationAssuranceReport is the operator-facing continuous
// assurance package for one federated organization inside one secure cell.
type SecureCellFederationAssuranceReport struct {
	ID                               string                                      `json:"id"`
	Version                          string                                      `json:"version"`
	Name                             string                                      `json:"name"`
	GeneratedAt                      time.Time                                   `json:"generated_at"`
	CellID                           string                                      `json:"cell_id"`
	CellName                         string                                      `json:"cell_name,omitempty"`
	CellStatus                       SecureCellStatus                            `json:"cell_status"`
	Jurisdiction                     string                                      `json:"jurisdiction,omitempty"`
	Framework                        string                                      `json:"framework,omitempty"`
	Organization                     SecureCellFederationOrganizationSummary     `json:"organization"`
	Runtime                          SecureCellFederationOrganizationRuntime     `json:"runtime"`
	Contracts                        []SecureCellFederationContractSummary       `json:"contracts,omitempty"`
	Findings                         []SecureCellFederationAssuranceFinding      `json:"findings,omitempty"`
	AutomationActions                []SecureCellFederationAssuranceActionRecord `json:"automation_actions,omitempty"`
	FindingCount                     int                                         `json:"finding_count"`
	CriticalFindingCount             int                                         `json:"critical_finding_count"`
	WarningFindingCount              int                                         `json:"warning_finding_count"`
	InfoFindingCount                 int                                         `json:"info_finding_count"`
	AutoContainmentEligibleCount     int                                         `json:"auto_containment_eligible_count"`
	RequireConfidentialCompute       bool                                        `json:"require_confidential_compute"`
	ConfidentialExecutionVerified    bool                                        `json:"confidential_execution_verified"`
	ConfidentialExecutionPresent     int                                         `json:"confidential_execution_present,omitempty"`
	ConfidentialExecutionValid       int                                         `json:"confidential_execution_valid,omitempty"`
	ConfidentialExecutionBindingHash string                                      `json:"confidential_execution_binding_hash,omitempty"`
	OperatorSurfaces                 []SecureCellFederationOperatorSurface       `json:"operator_surfaces,omitempty"`
	ControlLedgerID                  string                                      `json:"control_ledger_id,omitempty"`
	ControlLedgerHash                string                                      `json:"control_ledger_hash,omitempty"`
	PortablePackageHash              string                                      `json:"portable_package_hash,omitempty"`
	PortablePackageSigned            bool                                        `json:"portable_package_signed"`
	PortablePackageAnchored          bool                                        `json:"portable_package_anchored"`
}

// SecureCellFederationAssuranceReportOptions lets callers enrich assurance
// reports with custom identifiers or operator surfaces.
type SecureCellFederationAssuranceReportOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
}

// SecureCellFederationAssuranceSweepResult summarizes one automated
// federation-assurance pass across all secure cells.
type SecureCellFederationAssuranceSweepResult struct {
	At                     time.Time                                   `json:"at"`
	CellsScanned           int                                         `json:"cells_scanned"`
	OrganizationsScanned   int                                         `json:"organizations_scanned"`
	ActiveContractsScanned int                                         `json:"active_contracts_scanned"`
	FindingsDetected       int                                         `json:"findings_detected"`
	CriticalFindings       int                                         `json:"critical_findings"`
	ContractsSuspended     int                                         `json:"contracts_suspended"`
	CellIDs                []string                                    `json:"cell_ids,omitempty"`
	Actions                []SecureCellFederationAssuranceActionRecord `json:"actions,omitempty"`
}

// ListFederationAssuranceFindings returns operator-facing live federation
// posture findings across the current secure-cell set.
func (s *Service) ListFederationAssuranceFindings(_ context.Context, filter SecureCellFederationAssuranceFilter) ([]SecureCellFederationAssuranceFinding, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var items []SecureCellFederationAssuranceFinding
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		items = append(items, secureCellFederationAssuranceFindingsForRun(run)...)
	}

	filtered := make([]SecureCellFederationAssuranceFinding, 0, len(items))
	for _, item := range items {
		if !matchesSecureCellFederationAssuranceFindingFilter(item, filter) {
			continue
		}
		filtered = append(filtered, item)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if secureCellFederationAssuranceSeverityRank(filtered[i].Severity) == secureCellFederationAssuranceSeverityRank(filtered[j].Severity) {
			if filtered[i].DetectedAt.Equal(filtered[j].DetectedAt) {
				if filtered[i].CellID == filtered[j].CellID {
					return filtered[i].ID < filtered[j].ID
				}
				return filtered[i].CellID < filtered[j].CellID
			}
			return filtered[i].DetectedAt.After(filtered[j].DetectedAt)
		}
		return secureCellFederationAssuranceSeverityRank(filtered[i].Severity) > secureCellFederationAssuranceSeverityRank(filtered[j].Severity)
	})
	if filter.Limit > 0 && len(filtered) > filter.Limit {
		filtered = filtered[:filter.Limit]
	}
	return filtered, nil
}

// ListFederationAssuranceActions returns automated containment actions already
// applied by the federation assurance runtime.
func (s *Service) ListFederationAssuranceActions(_ context.Context, filter SecureCellFederationAssuranceActionFilter) ([]SecureCellFederationAssuranceActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var items []SecureCellFederationAssuranceActionRecord
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationAssuranceActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationAssuranceActionFilter(record, filter) {
				continue
			}
			items = append(items, record)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

// BuildFederationAssuranceReport returns a continuous-assurance package for
// one collaborating organization inside one secure cell.
func (s *Service) BuildFederationAssuranceReport(ctx context.Context, cellID string, organizationID string, options SecureCellFederationAssuranceReportOptions) (*SecureCellFederationAssuranceReport, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/assurance: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	orgSummary, org, err := secureCellFederationOrganizationSummaryAndRef(run, organizationID)
	if err != nil {
		return nil, err
	}
	contracts := secureCellFederationContractsForOrganization(run, org.OrganizationID)
	runtime := secureCellFederationRuntimeForOrganization(run, *org)
	findings, err := s.ListFederationAssuranceFindings(ctx, SecureCellFederationAssuranceFilter{
		CellID:         cellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		return nil, err
	}
	actions, err := s.ListFederationAssuranceActions(ctx, SecureCellFederationAssuranceActionFilter{
		CellID:         cellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		return nil, err
	}

	report := &SecureCellFederationAssuranceReport{
		ID:                         firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-assurance", strings.TrimSpace(run.result.CellID), strings.TrimSpace(org.OrganizationID))),
		Version:                    firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:                       firstNonEmpty(strings.TrimSpace(options.Name), "secure-cell-federation-assurance"),
		GeneratedAt:                time.Now().UTC(),
		CellID:                     strings.TrimSpace(run.result.CellID),
		CellName:                   strings.TrimSpace(run.result.Name),
		CellStatus:                 run.result.Status,
		Jurisdiction:               strings.TrimSpace(run.request.Jurisdiction),
		Framework:                  strings.TrimSpace(s.config.Framework),
		Organization:               orgSummary,
		Runtime:                    runtime,
		Contracts:                  contracts,
		Findings:                   findings,
		AutomationActions:          actions,
		OperatorSurfaces:           append([]SecureCellFederationOperatorSurface(nil), options.OperatorSurfaces...),
		RequireConfidentialCompute: run.request.Policy.RequireConfidentialCompute != nil && *run.request.Policy.RequireConfidentialCompute,
	}
	for _, finding := range findings {
		report.FindingCount++
		if finding.AutoContainmentEligible {
			report.AutoContainmentEligibleCount++
		}
		switch finding.Severity {
		case SecureCellFederationAssuranceSeverityCritical:
			report.CriticalFindingCount++
		case SecureCellFederationAssuranceSeverityWarning:
			report.WarningFindingCount++
		default:
			report.InfoFindingCount++
		}
	}
	if run.result.ConfidentialExecution != nil {
		report.ConfidentialExecutionVerified = run.result.ConfidentialExecution.Verified
		report.ConfidentialExecutionPresent = run.result.ConfidentialExecution.Present
		report.ConfidentialExecutionValid = run.result.ConfidentialExecution.Valid
		report.ConfidentialExecutionBindingHash = strings.TrimSpace(run.result.ConfidentialExecution.BindingHash)
	}
	if run.result.ControlLedger != nil {
		report.ControlLedgerID = strings.TrimSpace(run.result.ControlLedger.Bundle.ID)
		report.ControlLedgerHash = strings.TrimSpace(run.result.ControlLedger.Bundle.ContentHash)
	}
	if run.result.PortablePackage != nil {
		report.PortablePackageHash = strings.TrimSpace(run.result.PortablePackage.PackageHash)
		report.PortablePackageSigned = run.result.PortablePackage.Signature != nil
		report.PortablePackageAnchored = run.result.PortablePackage.AuditAnchor != nil
	}
	return report, nil
}

// SweepFederationAssurance applies automated containment to active federation
// contracts whose current runtime posture has drifted into critical exposure.
func (s *Service) SweepFederationAssurance(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationAssuranceSweepResult, error) {
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

	report := &SecureCellFederationAssuranceSweepResult{
		At:           at.UTC(),
		CellsScanned: len(cellIDs),
	}
	if len(cellIDs) == 0 {
		return report, nil
	}

	findings, err := s.ListFederationAssuranceFindings(ctx, SecureCellFederationAssuranceFilter{})
	if err != nil {
		return nil, err
	}
	report.FindingsDetected = len(findings)
	cellSet := make(map[string]struct{}, len(cellIDs))
	orgSet := make(map[string]struct{})
	activeContractSet := make(map[string]struct{})
	for _, finding := range findings {
		if finding.CellID != "" {
			cellSet[finding.CellID] = struct{}{}
		}
		if finding.OrganizationID != "" {
			orgSet[finding.CellID+"|"+finding.OrganizationID] = struct{}{}
		}
		if finding.ContractID != "" && finding.ContractStatus == SecureCellFederationContractStatusActive {
			activeContractSet[finding.CellID+"|"+finding.ContractID] = struct{}{}
		}
		if finding.Severity == SecureCellFederationAssuranceSeverityCritical {
			report.CriticalFindings++
		}
	}
	report.OrganizationsScanned = len(orgSet)
	report.ActiveContractsScanned = len(activeContractSet)

	suspended := make(map[string]struct{})
	mutatedCells := make(map[string]struct{})
	for _, finding := range findings {
		if finding.Severity != SecureCellFederationAssuranceSeverityCritical || !finding.AutoContainmentEligible {
			continue
		}
		if finding.CellID == "" || finding.ContractID == "" || finding.ContractStatus != SecureCellFederationContractStatusActive {
			continue
		}
		key := finding.CellID + "|" + finding.ContractID
		if _, ok := suspended[key]; ok {
			continue
		}

		run, err := s.getRun(finding.CellID)
		if err != nil {
			return nil, err
		}
		metadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
			"workflow":                          "secure_cell",
			"automation_mode":                   "federation_assurance",
			"federation_assurance_mode":         "automated",
			"federation_assurance_trigger":      string(finding.Category),
			"federation_assurance_finding_id":   finding.ID,
			"federation_assurance_severity":     string(finding.Severity),
			"federation_assurance_category":     string(finding.Category),
			"federation_organization_id":        finding.OrganizationID,
			"federation_contract_id":            finding.ContractID,
			"federation_sponsor_of_record":      finding.SponsorOfRecord,
			"federation_contract_status_before": string(finding.ContractStatus),
			"federation_contract_status_after":  string(SecureCellFederationContractStatusSuspended),
		})
		if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
			metadata["automated_actor"] = automatedActor
		}
		result, err := s.SuspendFederationContract(ctx, finding.CellID, finding.ContractID, SecureCellLifecycleRequest{
			ActorDID: run.request.OwnerIdentity.AgentID(),
			Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), "automated federation assurance containment") + ": " + finding.Summary,
			Metadata: metadata,
		})
		if err != nil {
			return nil, err
		}
		report.ContractsSuspended++
		suspended[key] = struct{}{}
		mutatedCells[finding.CellID] = struct{}{}
		if result != nil && len(result.Transitions) > 0 {
			if action, ok := secureCellFederationAssuranceActionFromTransition(&secureCellRun{request: run.request, result: result}, result.Transitions[len(result.Transitions)-1]); ok {
				report.Actions = append(report.Actions, action)
			}
		}
	}
	if len(mutatedCells) > 0 {
		report.CellIDs = make([]string, 0, len(mutatedCells))
		for cellID := range mutatedCells {
			report.CellIDs = append(report.CellIDs, cellID)
		}
		sort.Strings(report.CellIDs)
	}
	return report, nil
}

func secureCellFederationAssuranceFindingsForRun(run *secureCellRun) []SecureCellFederationAssuranceFinding {
	if run == nil || run.result == nil {
		return nil
	}
	sessionByID := make(map[string]SecureCellSession, len(run.result.Sessions))
	for _, session := range run.result.Sessions {
		sessionByID[strings.TrimSpace(session.ID)] = session
	}
	participantByDID := make(map[string]SecureCellParticipantState, len(run.result.Participants))
	for _, participant := range run.result.Participants {
		participantByDID[strings.TrimSpace(participant.ParticipantDID)] = participant
	}
	invitationsByID := make(map[string]SecureCellFederationInvitation, len(run.result.FederationInvitations))
	for _, invitation := range run.result.FederationInvitations {
		invitationsByID[strings.TrimSpace(invitation.ID)] = invitation
	}
	contractsByID := make(map[string]SecureCellFederationContract, len(run.result.FederationContracts))
	activeContractsByOrg := make(map[string][]SecureCellFederationContract)
	for _, contract := range run.result.FederationContracts {
		contractsByID[strings.TrimSpace(contract.ID)] = contract
		if contract.Status == SecureCellFederationContractStatusActive {
			orgID := strings.TrimSpace(contract.OrganizationID)
			activeContractsByOrg[orgID] = append(activeContractsByOrg[orgID], contract)
		}
	}

	findings := make([]SecureCellFederationAssuranceFinding, 0)
	appendFinding := func(item SecureCellFederationAssuranceFinding) {
		if item.CellID == "" {
			item.CellID = strings.TrimSpace(run.result.CellID)
		}
		if item.CellName == "" {
			item.CellName = strings.TrimSpace(run.result.Name)
		}
		if item.Jurisdiction == "" {
			item.Jurisdiction = strings.TrimSpace(run.request.Jurisdiction)
		}
		if item.DetectedAt.IsZero() {
			item.DetectedAt = run.result.UpdatedAt.UTC()
		}
		item.Metadata = cloneStringMap(item.Metadata)
		item.ID = secureCellFederationAssuranceFindingID(item)
		findings = append(findings, item)
	}
	appendCounterpartyContractFinding := func(contractSummary SecureCellFederationContractSummary, severity SecureCellFederationAssuranceSeverity, category SecureCellFederationAssuranceCategory, summary, reason, suggestedAction string, autoContainment bool, detectedAt time.Time, metadata map[string]string) {
		appendFinding(SecureCellFederationAssuranceFinding{
			OrganizationID:          contractSummary.OrganizationID,
			SponsorOfRecord:         contractSummary.SponsorOfRecord,
			OrganizationName:        contractSummary.OrganizationName,
			InvitationID:            contractSummary.InvitationID,
			ContractID:              contractSummary.ContractID,
			ContractRevision:        contractSummary.Revision,
			ContractStatus:          contractSummary.Status,
			Severity:                severity,
			Category:                category,
			Summary:                 summary,
			Reason:                  reason,
			SuggestedAction:         suggestedAction,
			AutoContainmentEligible: autoContainment,
			DetectedAt:              detectedAt,
			Metadata:                metadata,
		})
	}

	for _, org := range run.result.FederationOrganizations {
		summary := secureCellFederationOrganizationSummaryFromRun(run, org)
		runtime := secureCellFederationRuntimeForOrganization(run, org)
		activeContracts := activeContractsByOrg[strings.TrimSpace(org.OrganizationID)]
		latestCounterpartyAssurance := secureCellLatestFederationCounterpartyAssurance(run.result, org.OrganizationID)
		if summary.Status == SecureCellFederationOrganizationStatusActive && runtime.ActiveParticipantCount > 0 && len(activeContracts) == 0 {
			appendFinding(SecureCellFederationAssuranceFinding{
				OrganizationID:          summary.OrganizationID,
				SponsorOfRecord:         summary.SponsorOfRecord,
				OrganizationName:        summary.OrganizationName,
				Severity:                SecureCellFederationAssuranceSeverityCritical,
				Category:                SecureCellFederationAssuranceCategoryContractCoverage,
				Summary:                 "Federated organization has active participants without an active contract",
				Reason:                  "Cross-organization participants remain active in the secure cell, but no active federation contract covers their current collaboration posture.",
				SuggestedAction:         "Issue or renew an active federation contract before continuing collaboration.",
				AutoContainmentEligible: false,
				DetectedAt:              maxTime(summary.UpdatedAt, runtime.LastUpdatedAt),
				Metadata: map[string]string{
					"active_participant_count": fmt.Sprintf("%d", runtime.ActiveParticipantCount),
					"contract_count":           fmt.Sprintf("%d", runtime.ActiveContracts),
				},
			})
		}
		if len(activeContracts) > 1 {
			contractIDs := make([]string, 0, len(activeContracts))
			for _, contract := range activeContracts {
				contractIDs = append(contractIDs, contract.ID)
			}
			appendFinding(SecureCellFederationAssuranceFinding{
				OrganizationID:          summary.OrganizationID,
				SponsorOfRecord:         summary.SponsorOfRecord,
				OrganizationName:        summary.OrganizationName,
				Severity:                SecureCellFederationAssuranceSeverityWarning,
				Category:                SecureCellFederationAssuranceCategoryConcurrentRevision,
				Summary:                 "Organization has multiple active federation contract revisions",
				Reason:                  "More than one active contract revision is attached to the same federation organization, which can create ambiguous exchange scope.",
				SuggestedAction:         "Review contract lineage and revoke superseded active revisions.",
				AutoContainmentEligible: false,
				DetectedAt:              runtime.LastUpdatedAt,
				Metadata: map[string]string{
					"contract_ids": strings.Join(uniqueTrimmedStrings(contractIDs), ","),
				},
			})
		}
		if run.request.Policy.RequireConfidentialCompute != nil && *run.request.Policy.RequireConfidentialCompute && len(activeContracts) > 0 {
			if run.result.ConfidentialExecution == nil || !run.result.ConfidentialExecution.Verified {
				appendFinding(SecureCellFederationAssuranceFinding{
					OrganizationID:          summary.OrganizationID,
					SponsorOfRecord:         summary.SponsorOfRecord,
					OrganizationName:        summary.OrganizationName,
					Severity:                SecureCellFederationAssuranceSeverityCritical,
					Category:                SecureCellFederationAssuranceCategoryConfidentialComputeDrift,
					Summary:                 "Confidential execution assurance is unavailable for an active federated organization",
					Reason:                  "The secure cell policy requires confidential compute, but the latest execution bundle is missing a verified confidential execution summary.",
					SuggestedAction:         "Suspend exposed federation contracts until confidential execution verification is restored.",
					AutoContainmentEligible: true,
					DetectedAt:              runtime.LastUpdatedAt,
				})
			}
		}
		if len(activeContracts) > 0 {
			if latestCounterpartyAssurance == nil {
				for _, contract := range activeContracts {
					contractSummary := secureCellFederationContractSummaryFromRun(run, contract)
					appendCounterpartyContractFinding(
						contractSummary,
						SecureCellFederationAssuranceSeverityCritical,
						SecureCellFederationAssuranceCategoryCounterpartyAssuranceMissing,
						"Active federation contract has no imported counterparty assurance bundle",
						"The local secure cell still has an active federation contract, but no reciprocal assurance bundle has been imported for the counterparty organization.",
						"Require a fresh signed counterparty assurance bundle before continuing governed cross-organization exchange.",
						true,
						maxTime(runtime.LastUpdatedAt, secureCellFederationContractUpdatedAt(contract)),
						map[string]string{
							"organization_id": summary.OrganizationID,
						},
					)
				}
				continue
			}

			counterpartyMetadata := map[string]string{
				"federation_counterparty_assurance_snapshot_id":  latestCounterpartyAssurance.SnapshotID,
				"federation_counterparty_assurance_bundle_id":    latestCounterpartyAssurance.Bundle.ID,
				"federation_counterparty_assurance_status":       string(latestCounterpartyAssurance.Status),
				"federation_counterparty_assurance_signer":       latestCounterpartyAssurance.Signer,
				"federation_counterparty_assurance_contract_ids": strings.Join(uniqueTrimmedStrings(latestCounterpartyAssurance.ContractIDs), ","),
				"federation_counterparty_assurance_content_hash": strings.TrimSpace(latestCounterpartyAssurance.Bundle.ContentHash),
				"federation_counterparty_assurance_expires_at":   safeTimeString(latestCounterpartyAssurance.Bundle.ExpiresAt),
			}
			if message := strings.TrimSpace(latestCounterpartyAssurance.VerificationMessage); message != "" {
				counterpartyMetadata["federation_counterparty_assurance_verification_message"] = message
			}
			detectedAt := maxTime(runtime.LastUpdatedAt, latestCounterpartyAssurance.ReceivedAt)

			for _, contract := range activeContracts {
				contractSummary := secureCellFederationContractSummaryFromRun(run, contract)
				switch latestCounterpartyAssurance.Status {
				case SecureCellFederationCounterpartyAssuranceStatusInvalid:
					appendCounterpartyContractFinding(
						contractSummary,
						SecureCellFederationAssuranceSeverityCritical,
						SecureCellFederationAssuranceCategoryCounterpartyAssuranceInvalid,
						"Imported counterparty assurance bundle failed verification",
						firstNonEmpty(strings.TrimSpace(latestCounterpartyAssurance.VerificationMessage), "The latest imported counterparty assurance bundle does not pass signature or content-hash verification."),
						"Suspend the contract and require the counterparty to resend a valid signed assurance bundle.",
						true,
						maxTime(detectedAt, secureCellFederationContractUpdatedAt(contract)),
						cloneStringMap(counterpartyMetadata),
					)
				case SecureCellFederationCounterpartyAssuranceStatusExpired:
					appendCounterpartyContractFinding(
						contractSummary,
						SecureCellFederationAssuranceSeverityCritical,
						SecureCellFederationAssuranceCategoryCounterpartyAssuranceExpired,
						"Imported counterparty assurance bundle is expired",
						"The latest imported counterparty assurance bundle has passed its expiry boundary and no longer proves current cross-organization posture.",
						"Suspend the contract until the counterparty provides a fresh signed assurance bundle.",
						true,
						maxTime(detectedAt, secureCellFederationContractUpdatedAt(contract)),
						cloneStringMap(counterpartyMetadata),
					)
				case SecureCellFederationCounterpartyAssuranceStatusStale:
					appendCounterpartyContractFinding(
						contractSummary,
						SecureCellFederationAssuranceSeverityWarning,
						SecureCellFederationAssuranceCategoryCounterpartyAssuranceStale,
						"Imported counterparty assurance bundle is stale",
						"The latest imported counterparty assurance bundle is older than the expected freshness window and may no longer reflect the current counterparty posture.",
						"Request a fresh counterparty assurance bundle before this contract drifts into expired posture.",
						false,
						maxTime(detectedAt, secureCellFederationContractUpdatedAt(contract)),
						cloneStringMap(counterpartyMetadata),
					)
				}
				if latestCounterpartyAssurance.Bundle.Assurance.CriticalFindingCount > 0 {
					metadata := cloneStringMap(counterpartyMetadata)
					metadata["federation_counterparty_assurance_critical_findings"] = fmt.Sprintf("%d", latestCounterpartyAssurance.Bundle.Assurance.CriticalFindingCount)
					appendCounterpartyContractFinding(
						contractSummary,
						SecureCellFederationAssuranceSeverityCritical,
						SecureCellFederationAssuranceCategoryCounterpartyAssuranceCritical,
						"Counterparty assurance bundle reports critical posture findings",
						"The imported counterparty assurance bundle declares critical findings in the counterparty's own continuous-assurance report.",
						"Suspend the contract and require remediation or explicit re-onboarding before exchange continues.",
						true,
						maxTime(detectedAt, secureCellFederationContractUpdatedAt(contract)),
						metadata,
					)
				}
				if latestCounterpartyAssurance.Bundle.CellStatus != SecureCellStatusActive || latestCounterpartyAssurance.Bundle.Runtime.ActiveContracts == 0 {
					metadata := cloneStringMap(counterpartyMetadata)
					metadata["counterparty_cell_status"] = string(latestCounterpartyAssurance.Bundle.CellStatus)
					metadata["counterparty_active_contracts"] = fmt.Sprintf("%d", latestCounterpartyAssurance.Bundle.Runtime.ActiveContracts)
					appendCounterpartyContractFinding(
						contractSummary,
						SecureCellFederationAssuranceSeverityCritical,
						SecureCellFederationAssuranceCategoryCounterpartyScopeDrift,
						"Counterparty assurance bundle no longer reports active collaboration scope",
						"The imported counterparty assurance bundle does not show an active collaboration posture even though the local federation contract remains active.",
						"Suspend the contract and renegotiate scope after the counterparty restores active governed collaboration posture.",
						true,
						maxTime(detectedAt, secureCellFederationContractUpdatedAt(contract)),
						metadata,
					)
				}
				if run.request.Policy.RequireConfidentialCompute != nil && *run.request.Policy.RequireConfidentialCompute && !latestCounterpartyAssurance.Bundle.Assurance.ConfidentialExecutionVerified {
					metadata := cloneStringMap(counterpartyMetadata)
					metadata["counterparty_confidential_execution_verified"] = fmt.Sprintf("%t", latestCounterpartyAssurance.Bundle.Assurance.ConfidentialExecutionVerified)
					metadata["counterparty_confidential_execution_present"] = fmt.Sprintf("%d", latestCounterpartyAssurance.Bundle.Assurance.ConfidentialExecutionPresent)
					appendCounterpartyContractFinding(
						contractSummary,
						SecureCellFederationAssuranceSeverityCritical,
						SecureCellFederationAssuranceCategoryCounterpartyConfidentialDrift,
						"Counterparty assurance bundle is missing verified confidential execution",
						"The local secure cell requires confidential compute, but the imported counterparty assurance bundle does not prove verified confidential execution posture.",
						"Suspend the contract until the counterparty restores verified confidential execution assurance.",
						true,
						maxTime(detectedAt, secureCellFederationContractUpdatedAt(contract)),
						metadata,
					)
				}
			}
		}
	}

	for _, contract := range run.result.FederationContracts {
		contractSummary := secureCellFederationContractSummaryFromRun(run, contract)
		invitation := invitationsByID[strings.TrimSpace(contract.InvitationID)]
		participantStates := secureCellFederationContractParticipantStates(participantByDID, contract)
		activeParticipants := secureCellFederationActiveContractParticipants(participantStates)
		if contract.Status == SecureCellFederationContractStatusActive && len(activeParticipants) == 0 {
			appendFinding(SecureCellFederationAssuranceFinding{
				OrganizationID:          contractSummary.OrganizationID,
				SponsorOfRecord:         contractSummary.SponsorOfRecord,
				OrganizationName:        contractSummary.OrganizationName,
				InvitationID:            contractSummary.InvitationID,
				ContractID:              contractSummary.ContractID,
				ContractRevision:        contractSummary.Revision,
				ContractStatus:          contractSummary.Status,
				Severity:                SecureCellFederationAssuranceSeverityCritical,
				Category:                SecureCellFederationAssuranceCategoryParticipantContinuity,
				Summary:                 "Active federation contract has no active participant continuity",
				Reason:                  "The active contract still exists, but every bound participant is missing or no longer active in the secure cell.",
				SuggestedAction:         "Suspend the contract until a valid active participant is re-established.",
				AutoContainmentEligible: true,
				DetectedAt:              secureCellFederationContractUpdatedAt(contract),
				Metadata: map[string]string{
					"participant_dids": strings.Join(uniqueTrimmedStrings(contract.ParticipantDIDs), ","),
				},
			})
		}
		if expectedDID := strings.TrimSpace(invitation.ExpectedDID); contract.Status == SecureCellFederationContractStatusActive && expectedDID != "" {
			if len(activeParticipants) == 0 || !secureCellFederationParticipantStateMatches(activeParticipants, expectedDID) {
				appendFinding(SecureCellFederationAssuranceFinding{
					OrganizationID:          contractSummary.OrganizationID,
					SponsorOfRecord:         contractSummary.SponsorOfRecord,
					OrganizationName:        contractSummary.OrganizationName,
					InvitationID:            contractSummary.InvitationID,
					ContractID:              contractSummary.ContractID,
					ContractRevision:        contractSummary.Revision,
					ContractStatus:          contractSummary.Status,
					ExpectedDID:             expectedDID,
					Severity:                SecureCellFederationAssuranceSeverityCritical,
					Category:                SecureCellFederationAssuranceCategoryExpectedIdentityDrift,
					Summary:                 "Active federation contract no longer matches the invited counterparty identity",
					Reason:                  "The active contract was negotiated for a specific expected DID, but that identity is not the current active participant bound to the contract.",
					SuggestedAction:         "Suspend the contract and re-onboard the counterparty through a fresh federation acceptance flow.",
					AutoContainmentEligible: true,
					DetectedAt:              maxTime(secureCellFederationContractUpdatedAt(contract), secureCellFederationInvitationUpdatedAt(invitation)),
					Metadata: map[string]string{
						"expected_did":        expectedDID,
						"active_participants": strings.Join(secureCellParticipantDIDs(activeParticipants), ","),
					},
				})
			}
		}
		if contract.Status == SecureCellFederationContractStatusActive && strings.TrimSpace(contract.CredentialID) == "" {
			appendFinding(SecureCellFederationAssuranceFinding{
				OrganizationID:          contractSummary.OrganizationID,
				SponsorOfRecord:         contractSummary.SponsorOfRecord,
				OrganizationName:        contractSummary.OrganizationName,
				InvitationID:            contractSummary.InvitationID,
				ContractID:              contractSummary.ContractID,
				ContractRevision:        contractSummary.Revision,
				ContractStatus:          contractSummary.Status,
				Severity:                SecureCellFederationAssuranceSeverityWarning,
				Category:                SecureCellFederationAssuranceCategoryCredentialContinuity,
				Summary:                 "Active federation contract is missing credential continuity metadata",
				Reason:                  "The contract is active, but no credential ID was preserved from the participant state that activated it.",
				SuggestedAction:         "Renew the contract after reissuing or confirming the counterparty credential trace.",
				AutoContainmentEligible: false,
				DetectedAt:              secureCellFederationContractUpdatedAt(contract),
			})
		}
		if len(contract.SessionScopeIDs) > 0 {
			missingScopes := make([]string, 0)
			inactiveScopes := make([]string, 0)
			activeScopeCount := 0
			for _, sessionID := range uniqueTrimmedStrings(contract.SessionScopeIDs) {
				session, ok := sessionByID[sessionID]
				if !ok {
					missingScopes = append(missingScopes, sessionID)
					continue
				}
				if session.Status != SecureCellSessionStatusActive {
					inactiveScopes = append(inactiveScopes, sessionID+":"+string(session.Status))
					continue
				}
				activeScopeCount++
			}
			if len(missingScopes) > 0 {
				appendFinding(SecureCellFederationAssuranceFinding{
					OrganizationID:          contractSummary.OrganizationID,
					SponsorOfRecord:         contractSummary.SponsorOfRecord,
					OrganizationName:        contractSummary.OrganizationName,
					InvitationID:            contractSummary.InvitationID,
					ContractID:              contractSummary.ContractID,
					ContractRevision:        contractSummary.Revision,
					ContractStatus:          contractSummary.Status,
					SessionIDs:              missingScopes,
					Severity:                SecureCellFederationAssuranceSeverityCritical,
					Category:                SecureCellFederationAssuranceCategorySessionScopeDrift,
					Summary:                 "Federation contract scope references missing sessions",
					Reason:                  "The active contract still references session scopes that are no longer present in the secure cell runtime.",
					SuggestedAction:         "Suspend the contract and renew it against current live session scopes.",
					AutoContainmentEligible: contract.Status == SecureCellFederationContractStatusActive,
					DetectedAt:              secureCellFederationContractUpdatedAt(contract),
				})
			}
			if contract.Status == SecureCellFederationContractStatusActive && activeScopeCount == 0 {
				appendFinding(SecureCellFederationAssuranceFinding{
					OrganizationID:          contractSummary.OrganizationID,
					SponsorOfRecord:         contractSummary.SponsorOfRecord,
					OrganizationName:        contractSummary.OrganizationName,
					InvitationID:            contractSummary.InvitationID,
					ContractID:              contractSummary.ContractID,
					ContractRevision:        contractSummary.Revision,
					ContractStatus:          contractSummary.Status,
					SessionIDs:              uniqueTrimmedStrings(contract.SessionScopeIDs),
					Severity:                SecureCellFederationAssuranceSeverityCritical,
					Category:                SecureCellFederationAssuranceCategorySessionScopeDrift,
					Summary:                 "Active federation contract has no active scoped session remaining",
					Reason:                  "Every scoped session for the active contract is paused, quarantined, closed, or missing.",
					SuggestedAction:         "Suspend the contract until a valid active scoped session is restored or the contract is renewed.",
					AutoContainmentEligible: true,
					DetectedAt:              secureCellFederationContractUpdatedAt(contract),
					Metadata: map[string]string{
						"inactive_scopes": strings.Join(uniqueTrimmedStrings(inactiveScopes), ","),
					},
				})
			} else if len(inactiveScopes) > 0 {
				appendFinding(SecureCellFederationAssuranceFinding{
					OrganizationID:          contractSummary.OrganizationID,
					SponsorOfRecord:         contractSummary.SponsorOfRecord,
					OrganizationName:        contractSummary.OrganizationName,
					InvitationID:            contractSummary.InvitationID,
					ContractID:              contractSummary.ContractID,
					ContractRevision:        contractSummary.Revision,
					ContractStatus:          contractSummary.Status,
					SessionIDs:              uniqueTrimmedStrings(contract.SessionScopeIDs),
					Severity:                SecureCellFederationAssuranceSeverityWarning,
					Category:                SecureCellFederationAssuranceCategorySessionScopeDrift,
					Summary:                 "Federation contract still carries inactive session scopes",
					Reason:                  "Some scoped sessions referenced by the contract are no longer active, even though at least one active scope remains.",
					SuggestedAction:         "Review whether the contract should be renewed to remove inactive scope.",
					AutoContainmentEligible: false,
					DetectedAt:              secureCellFederationContractUpdatedAt(contract),
					Metadata: map[string]string{
						"inactive_scopes": strings.Join(uniqueTrimmedStrings(inactiveScopes), ","),
					},
				})
			}
		}
		terms := secureCellFederationTerms{
			SessionScopeIDs: append([]string(nil), contract.SessionScopeIDs...),
			DataClasses:     append([]string(nil), contract.DataClasses...),
			ComputeZones:    append([]string(nil), contract.ComputeZones...),
			AllowedActions:  append([]string(nil), contract.AllowedActions...),
		}
		if err := secureCellValidateNegotiatedFederationTerms(run.request.Policy, terms); err != nil {
			appendFinding(SecureCellFederationAssuranceFinding{
				OrganizationID:          contractSummary.OrganizationID,
				SponsorOfRecord:         contractSummary.SponsorOfRecord,
				OrganizationName:        contractSummary.OrganizationName,
				InvitationID:            contractSummary.InvitationID,
				ContractID:              contractSummary.ContractID,
				ContractRevision:        contractSummary.Revision,
				ContractStatus:          contractSummary.Status,
				Severity:                SecureCellFederationAssuranceSeverityCritical,
				Category:                SecureCellFederationAssuranceCategoryPolicyDrift,
				Summary:                 "Federation contract terms drifted beyond current secure-cell policy",
				Reason:                  err.Error(),
				SuggestedAction:         "Suspend the contract and renew it against the current secure-cell policy boundary.",
				AutoContainmentEligible: contract.Status == SecureCellFederationContractStatusActive,
				DetectedAt:              secureCellFederationContractUpdatedAt(contract),
			})
		}
	}

	for _, item := range run.result.SharedOutputs {
		findings = append(findings, secureCellFederationArtifactExposureFindings(run, contractsByID, item.FederationContractIDs, item.FederationOrgIDs, item.ContainmentStatus, item.ID, item.SessionID, "shared_output")...)
	}
	for _, item := range run.result.SessionExchanges {
		findings = append(findings, secureCellFederationArtifactExposureFindings(run, contractsByID, item.FederationContractIDs, item.FederationOrgIDs, item.ContainmentStatus, item.ID, item.SessionID, "session_exchange")...)
	}
	return findings
}

func secureCellFederationArtifactExposureFindings(run *secureCellRun, contractsByID map[string]SecureCellFederationContract, contractIDs []string, orgIDs []string, containmentStatus SecureCellArtifactContainmentStatus, artifactID string, sessionID string, artifactType string) []SecureCellFederationAssuranceFinding {
	if run == nil || run.result == nil || containmentStatus != SecureCellArtifactContainmentStatusActive {
		return nil
	}
	items := make([]SecureCellFederationAssuranceFinding, 0)
	for _, contractID := range uniqueTrimmedStrings(contractIDs) {
		contract, ok := contractsByID[contractID]
		if !ok || contract.Status == SecureCellFederationContractStatusActive {
			continue
		}
		summary := secureCellFederationContractSummaryFromRun(run, contract)
		items = append(items, SecureCellFederationAssuranceFinding{
			ID:                      "",
			CellID:                  strings.TrimSpace(run.result.CellID),
			CellName:                strings.TrimSpace(run.result.Name),
			Jurisdiction:            strings.TrimSpace(run.request.Jurisdiction),
			CellStatus:              run.result.Status,
			OrganizationID:          summary.OrganizationID,
			SponsorOfRecord:         summary.SponsorOfRecord,
			OrganizationName:        summary.OrganizationName,
			InvitationID:            summary.InvitationID,
			ContractID:              summary.ContractID,
			ContractRevision:        summary.Revision,
			ContractStatus:          summary.Status,
			SessionIDs:              uniqueTrimmedStrings([]string{sessionID}),
			ArtifactIDs:             uniqueTrimmedStrings([]string{artifactID}),
			ArtifactType:            artifactType,
			Severity:                SecureCellFederationAssuranceSeverityCritical,
			Category:                SecureCellFederationAssuranceCategoryArtifactExposure,
			Summary:                 "Active cross-organization artifact remains available under a non-active federation contract",
			Reason:                  "A shared artifact still has active containment posture even though its bound federation contract is suspended or revoked.",
			SuggestedAction:         "Contain or reissue the artifact under an active contract before continuing exchange.",
			AutoContainmentEligible: false,
			DetectedAt:              maxTime(secureCellFederationContractUpdatedAt(contract), run.result.UpdatedAt),
			Metadata: map[string]string{
				"federation_org_ids": strings.Join(uniqueTrimmedStrings(orgIDs), ","),
			},
		})
	}
	return items
}

func secureCellFederationAssuranceActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationAssuranceActionRecord, bool) {
	if run == nil || run.result == nil {
		return SecureCellFederationAssuranceActionRecord{}, false
	}
	if transition.Action != "secure_cell.federation_contract_suspended" {
		return SecureCellFederationAssuranceActionRecord{}, false
	}
	if !strings.EqualFold(strings.TrimSpace(transition.Metadata["automation_mode"]), "federation_assurance") {
		return SecureCellFederationAssuranceActionRecord{}, false
	}
	record := SecureCellFederationAssuranceActionRecord{
		CellID:          strings.TrimSpace(run.result.CellID),
		CellName:        strings.TrimSpace(run.result.Name),
		Jurisdiction:    strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:      run.result.Status,
		OrganizationID:  strings.TrimSpace(transition.Metadata["federation_organization_id"]),
		SponsorOfRecord: strings.TrimSpace(transition.Metadata["federation_sponsor_of_record"]),
		ContractID:      firstNonEmpty(strings.TrimSpace(transition.Metadata["federation_contract_id"]), strings.TrimSpace(transition.TargetDID)),
		InvitationID:    strings.TrimSpace(transition.Metadata["federation_invitation_id"]),
		FindingID:       strings.TrimSpace(transition.Metadata["federation_assurance_finding_id"]),
		Category:        SecureCellFederationAssuranceCategory(strings.TrimSpace(transition.Metadata["federation_assurance_category"])),
		Severity:        SecureCellFederationAssuranceSeverity(strings.TrimSpace(transition.Metadata["federation_assurance_severity"])),
		Action:          "suspend_contract",
		Trigger:         strings.TrimSpace(transition.Metadata["federation_assurance_trigger"]),
		Actor:           strings.TrimSpace(transition.Actor),
		AutomatedActor:  strings.TrimSpace(transition.Metadata["automated_actor"]),
		Reason:          strings.TrimSpace(transition.Reason),
		TransitionID:    strings.TrimSpace(transition.ID),
		OccurredAt:      transition.OccurredAt.UTC(),
		Metadata:        cloneStringMap(transition.Metadata),
	}
	return record, true
}

func secureCellFederationAssuranceFindingID(item SecureCellFederationAssuranceFinding) string {
	seed := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		strings.TrimSpace(item.CellID),
		strings.TrimSpace(item.OrganizationID),
		strings.TrimSpace(item.ContractID),
		strings.TrimSpace(item.InvitationID),
		strings.TrimSpace(item.ParticipantDID),
		string(item.Severity),
		string(item.Category),
		strings.TrimSpace(item.ArtifactType),
		strings.Join(uniqueTrimmedStrings(item.SessionIDs), ","),
		strings.Join(uniqueTrimmedStrings(item.ArtifactIDs), ","),
	)
	return fmt.Sprintf("%s-federation-assurance-%x", strings.TrimSpace(item.CellID), sha256.Sum256([]byte(seed)))
}

func matchesSecureCellFederationAssuranceFindingFilter(item SecureCellFederationAssuranceFinding, filter SecureCellFederationAssuranceFilter) bool {
	if filter.CellID != "" && !strings.EqualFold(strings.TrimSpace(item.CellID), strings.TrimSpace(filter.CellID)) {
		return false
	}
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.ContractID != "" && !strings.EqualFold(strings.TrimSpace(item.ContractID), strings.TrimSpace(filter.ContractID)) {
		return false
	}
	if filter.SponsorOfRecord != "" && !strings.EqualFold(strings.TrimSpace(item.SponsorOfRecord), strings.TrimSpace(filter.SponsorOfRecord)) {
		return false
	}
	if filter.ParticipantDID != "" && !strings.EqualFold(strings.TrimSpace(item.ParticipantDID), strings.TrimSpace(filter.ParticipantDID)) && !strings.EqualFold(strings.TrimSpace(item.ExpectedDID), strings.TrimSpace(filter.ParticipantDID)) {
		return false
	}
	if filter.Severity != "" && item.Severity != filter.Severity {
		return false
	}
	if filter.Category != "" && item.Category != filter.Category {
		return false
	}
	return true
}

func matchesSecureCellFederationAssuranceActionFilter(item SecureCellFederationAssuranceActionRecord, filter SecureCellFederationAssuranceActionFilter) bool {
	if filter.CellID != "" && !strings.EqualFold(strings.TrimSpace(item.CellID), strings.TrimSpace(filter.CellID)) {
		return false
	}
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.ContractID != "" && !strings.EqualFold(strings.TrimSpace(item.ContractID), strings.TrimSpace(filter.ContractID)) {
		return false
	}
	if filter.FindingID != "" && !strings.EqualFold(strings.TrimSpace(item.FindingID), strings.TrimSpace(filter.FindingID)) {
		return false
	}
	if filter.Category != "" && !strings.EqualFold(strings.TrimSpace(string(item.Category)), strings.TrimSpace(filter.Category)) {
		return false
	}
	if filter.Since != nil && item.OccurredAt.Before(filter.Since.UTC()) {
		return false
	}
	if filter.Until != nil && item.OccurredAt.After(filter.Until.UTC()) {
		return false
	}
	return true
}

func secureCellFederationAssuranceSeverityRank(severity SecureCellFederationAssuranceSeverity) int {
	switch severity {
	case SecureCellFederationAssuranceSeverityCritical:
		return 3
	case SecureCellFederationAssuranceSeverityWarning:
		return 2
	default:
		return 1
	}
}

func secureCellFederationContractParticipantStates(states map[string]SecureCellParticipantState, contract SecureCellFederationContract) []SecureCellParticipantState {
	if len(contract.ParticipantDIDs) == 0 {
		return nil
	}
	out := make([]SecureCellParticipantState, 0, len(contract.ParticipantDIDs))
	for _, did := range uniqueTrimmedStrings(contract.ParticipantDIDs) {
		if state, ok := states[did]; ok {
			out = append(out, state)
		}
	}
	return out
}

func secureCellFederationActiveContractParticipants(items []SecureCellParticipantState) []SecureCellParticipantState {
	out := make([]SecureCellParticipantState, 0, len(items))
	for _, item := range items {
		if item.Status == SecureCellParticipantStatusActive {
			out = append(out, item)
		}
	}
	return out
}

func secureCellFederationParticipantStateMatches(items []SecureCellParticipantState, participantDID string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.ParticipantDID), strings.TrimSpace(participantDID)) {
			return true
		}
	}
	return false
}

func secureCellParticipantDIDs(items []SecureCellParticipantState) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if did := strings.TrimSpace(item.ParticipantDID); did != "" {
			out = append(out, did)
		}
	}
	return uniqueTrimmedStrings(out)
}

func maxTime(left, right time.Time) time.Time {
	switch {
	case left.IsZero():
		return right.UTC()
	case right.IsZero():
		return left.UTC()
	case right.After(left):
		return right.UTC()
	default:
		return left.UTC()
	}
}
