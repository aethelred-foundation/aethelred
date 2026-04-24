package securecells

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SecureCellGovernmentAgentReadinessLevel describes whether a secure cell is
// operationally ready for government-service AI agent execution.
type SecureCellGovernmentAgentReadinessLevel string

const (
	SecureCellGovernmentAgentReadinessBlocked         SecureCellGovernmentAgentReadinessLevel = "blocked"
	SecureCellGovernmentAgentReadinessFoundationReady SecureCellGovernmentAgentReadinessLevel = "foundation_ready"
	SecureCellGovernmentAgentReadinessSupervisedReady SecureCellGovernmentAgentReadinessLevel = "supervised_ready"
	SecureCellGovernmentAgentReadinessAutonomyReady   SecureCellGovernmentAgentReadinessLevel = "autonomy_ready"
)

// SecureCellGovernmentAgentReadinessSeverity captures how strongly a finding
// blocks autonomous service execution.
type SecureCellGovernmentAgentReadinessSeverity string

const (
	SecureCellGovernmentAgentReadinessSeverityCritical SecureCellGovernmentAgentReadinessSeverity = "critical"
	SecureCellGovernmentAgentReadinessSeverityWarning  SecureCellGovernmentAgentReadinessSeverity = "warning"
	SecureCellGovernmentAgentReadinessSeverityInfo     SecureCellGovernmentAgentReadinessSeverity = "info"
)

// SecureCellGovernmentAgentReadinessFilter narrows operator readiness views.
type SecureCellGovernmentAgentReadinessFilter struct {
	CellID              string
	Jurisdiction        string
	ReadinessLevel      SecureCellGovernmentAgentReadinessLevel
	MinimumOverallScore int
	Limit               int
}

// SecureCellGovernmentAgentReadinessScorecard is the buyer-facing score model.
type SecureCellGovernmentAgentReadinessScorecard struct {
	Overall               int `json:"overall"`
	WorkflowLegibility    int `json:"workflow_legibility"`
	EvidenceReadiness     int `json:"evidence_readiness"`
	AuthorityControls     int `json:"authority_controls"`
	IntegrationReadiness  int `json:"integration_readiness"`
	SLAAutomation         int `json:"sla_automation"`
	HumanOversight        int `json:"human_oversight"`
	LocalizationReadiness int `json:"localization_readiness"`
}

// SecureCellGovernmentAgentReadinessFinding explains a concrete readiness gap.
type SecureCellGovernmentAgentReadinessFinding struct {
	Severity       SecureCellGovernmentAgentReadinessSeverity `json:"severity"`
	Code           string                                     `json:"code"`
	Category       string                                     `json:"category"`
	Title          string                                     `json:"title"`
	Detail         string                                     `json:"detail,omitempty"`
	Recommendation string                                     `json:"recommendation,omitempty"`
}

// SecureCellGovernmentAgentReadinessNextAction turns findings into an operator
// execution checklist.
type SecureCellGovernmentAgentReadinessNextAction struct {
	Priority       int    `json:"priority"`
	Owner          string `json:"owner,omitempty"`
	Action         string `json:"action"`
	Rationale      string `json:"rationale,omitempty"`
	BlocksAutonomy bool   `json:"blocks_autonomy"`
}

// SecureCellGovernmentAgentWorkflowSignals expose the workflow artifacts the
// readiness score was derived from.
type SecureCellGovernmentAgentWorkflowSignals struct {
	SessionCount                int `json:"session_count"`
	ThreadCount                 int `json:"thread_count"`
	DecisionCount               int `json:"decision_count"`
	GovernedDecisionCount       int `json:"governed_decision_count"`
	TimedDecisionCount          int `json:"timed_decision_count"`
	ApprovalGateCount           int `json:"approval_gate_count"`
	EscalationLadderCount       int `json:"escalation_ladder_count"`
	FederationOrganizationCount int `json:"federation_organization_count"`
	FederationContractCount     int `json:"federation_contract_count"`
	FederationIncidentCount     int `json:"federation_incident_count"`
	AutomationActionCount       int `json:"automation_action_count"`
	TransitionCount             int `json:"transition_count"`
	EvidenceTransitionCount     int `json:"evidence_transition_count"`
}

// SecureCellGovernmentAgentEvidenceState captures the evidence fabric backing
// a readiness decision.
type SecureCellGovernmentAgentEvidenceState struct {
	PolicyReceiptChainHash     string `json:"policy_receipt_chain_hash,omitempty"`
	ControlLedgerID            string `json:"control_ledger_id,omitempty"`
	ControlLedgerHash          string `json:"control_ledger_hash,omitempty"`
	PortablePackageHash        string `json:"portable_package_hash,omitempty"`
	PortablePackageSigned      bool   `json:"portable_package_signed"`
	PortablePackageAnchored    bool   `json:"portable_package_anchored"`
	ExecutionSealID            string `json:"execution_seal_id,omitempty"`
	ConfidentialVerified       bool   `json:"confidential_verified"`
	PolicyReceiptCount         int    `json:"policy_receipt_count"`
	SealedTransitionCount      int    `json:"sealed_transition_count"`
	TraceLinkedTransitionCount int    `json:"trace_linked_transition_count"`
}

// SecureCellGovernmentAgentReadinessAssessment is a live operator projection
// for national-scale agentic workflow adoption.
type SecureCellGovernmentAgentReadinessAssessment struct {
	AssessmentID          string                                         `json:"assessment_id"`
	CellID                string                                         `json:"cell_id"`
	Name                  string                                         `json:"name"`
	Purpose               string                                         `json:"purpose"`
	Resource              string                                         `json:"resource,omitempty"`
	Jurisdiction          string                                         `json:"jurisdiction,omitempty"`
	CellStatus            SecureCellStatus                               `json:"cell_status"`
	ReadinessLevel        SecureCellGovernmentAgentReadinessLevel        `json:"readiness_level"`
	ReadyForSupervisedRun bool                                           `json:"ready_for_supervised_run"`
	ReadyForAutonomousRun bool                                           `json:"ready_for_autonomous_run"`
	ServiceCode           string                                         `json:"service_code,omitempty"`
	ServiceTier           string                                         `json:"service_tier,omitempty"`
	IdentityProviders     []string                                       `json:"identity_providers,omitempty"`
	Languages             []string                                       `json:"languages,omitempty"`
	Scorecard             SecureCellGovernmentAgentReadinessScorecard    `json:"scorecard"`
	Signals               SecureCellGovernmentAgentWorkflowSignals       `json:"signals"`
	Evidence              SecureCellGovernmentAgentEvidenceState         `json:"evidence"`
	Findings              []SecureCellGovernmentAgentReadinessFinding    `json:"findings,omitempty"`
	NextActions           []SecureCellGovernmentAgentReadinessNextAction `json:"next_actions,omitempty"`
	WorkflowDigest        string                                         `json:"workflow_digest"`
	AssessedAt            time.Time                                      `json:"assessed_at"`
	UpdatedAt             time.Time                                      `json:"updated_at"`
}

// GetGovernmentAgentReadinessAssessment returns the live readiness projection
// for one secure cell.
func (s *Service) GetGovernmentAgentReadinessAssessment(ctx context.Context, cellID string) (*SecureCellGovernmentAgentReadinessAssessment, error) {
	items, err := s.ListGovernmentAgentReadinessAssessments(ctx, SecureCellGovernmentAgentReadinessFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-readiness: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentReadinessAssessments returns operator-facing readiness
// projections for AI-agent executable government workflows.
func (s *Service) ListGovernmentAgentReadinessAssessments(_ context.Context, filter SecureCellGovernmentAgentReadinessFilter) ([]SecureCellGovernmentAgentReadinessAssessment, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-readiness: service is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cellID := strings.TrimSpace(filter.CellID)
	jurisdiction := strings.TrimSpace(filter.Jurisdiction)
	level := filter.ReadinessLevel
	items := make([]SecureCellGovernmentAgentReadinessAssessment, 0, len(s.runs))
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		if jurisdiction != "" && !strings.EqualFold(strings.TrimSpace(run.request.Jurisdiction), jurisdiction) {
			continue
		}
		assessment := secureCellGovernmentAgentReadinessAssessment(run, len(s.decisionSLATemplates))
		if level != "" && assessment.ReadinessLevel != level {
			continue
		}
		if filter.MinimumOverallScore > 0 && assessment.Scorecard.Overall < filter.MinimumOverallScore {
			continue
		}
		items = append(items, assessment)
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Scorecard.Overall == items[j].Scorecard.Overall {
			if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
				return items[i].CellID < items[j].CellID
			}
			return items[i].UpdatedAt.After(items[j].UpdatedAt)
		}
		return items[i].Scorecard.Overall < items[j].Scorecard.Overall
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func secureCellGovernmentAgentReadinessAssessment(run *secureCellRun, configuredSLATemplateCount int) SecureCellGovernmentAgentReadinessAssessment {
	now := time.Now().UTC()
	result := run.result
	metadata := mergeStringMaps(run.request.Metadata, secureCellGovernmentAgentPolicyMetadata(result))
	serviceCode := firstNonEmpty(
		metadataValue(metadata, "government_service_code"),
		metadataValue(metadata, "service_code"),
		metadataValue(metadata, "service_catalog_id"),
	)
	serviceTier := firstNonEmpty(
		metadataValue(metadata, "service_tier"),
		metadataValue(metadata, "sla_tier"),
		metadataValue(metadata, "priority_tier"),
	)
	identityProviders := normalizedMetadataList(metadata, "identity_provider", "identity_providers", "digital_identity_provider")
	languages := normalizedMetadataList(metadata, "languages", "supported_languages", "locales", "locale")
	signals := secureCellGovernmentAgentWorkflowSignals(result)
	evidenceState := secureCellGovernmentAgentEvidenceState(result)

	scorecard := SecureCellGovernmentAgentReadinessScorecard{
		WorkflowLegibility:    secureCellGovernmentAgentWorkflowLegibilityScore(run, signals, serviceCode),
		EvidenceReadiness:     secureCellGovernmentAgentEvidenceScore(run, signals, evidenceState),
		AuthorityControls:     secureCellGovernmentAgentAuthorityScore(run, signals),
		IntegrationReadiness:  secureCellGovernmentAgentIntegrationScore(run, identityProviders, metadata),
		SLAAutomation:         secureCellGovernmentAgentSLAScore(run, signals, configuredSLATemplateCount),
		HumanOversight:        secureCellGovernmentAgentOversightScore(run, signals, metadata),
		LocalizationReadiness: secureCellGovernmentAgentLocalizationScore(run, identityProviders, languages, metadata, serviceCode),
	}
	scorecard.Overall = secureCellGovernmentAgentOverallScore(scorecard)

	findings := secureCellGovernmentAgentReadinessFindings(run, scorecard, signals, evidenceState, identityProviders, languages, metadata, serviceCode)
	level := secureCellGovernmentAgentReadinessLevel(scorecard.Overall, findings)
	assessmentCore := struct {
		CellID            string                                      `json:"cell_id"`
		UpdatedAt         time.Time                                   `json:"updated_at"`
		ServiceCode       string                                      `json:"service_code,omitempty"`
		ServiceTier       string                                      `json:"service_tier,omitempty"`
		IdentityProviders []string                                    `json:"identity_providers,omitempty"`
		Languages         []string                                    `json:"languages,omitempty"`
		Scorecard         SecureCellGovernmentAgentReadinessScorecard `json:"scorecard"`
		Signals           SecureCellGovernmentAgentWorkflowSignals    `json:"signals"`
		Evidence          SecureCellGovernmentAgentEvidenceState      `json:"evidence"`
	}{
		CellID:            result.CellID,
		UpdatedAt:         result.UpdatedAt.UTC(),
		ServiceCode:       serviceCode,
		ServiceTier:       serviceTier,
		IdentityProviders: identityProviders,
		Languages:         languages,
		Scorecard:         scorecard,
		Signals:           signals,
		Evidence:          evidenceState,
	}
	workflowDigest := EvidenceHash(assessmentCore)
	return SecureCellGovernmentAgentReadinessAssessment{
		AssessmentID:          "government-agent-readiness:" + result.CellID + ":" + workflowDigest[:12],
		CellID:                result.CellID,
		Name:                  result.Name,
		Purpose:               result.Purpose,
		Resource:              run.request.Resource,
		Jurisdiction:          run.request.Jurisdiction,
		CellStatus:            result.Status,
		ReadinessLevel:        level,
		ReadyForSupervisedRun: level == SecureCellGovernmentAgentReadinessSupervisedReady || level == SecureCellGovernmentAgentReadinessAutonomyReady,
		ReadyForAutonomousRun: level == SecureCellGovernmentAgentReadinessAutonomyReady,
		ServiceCode:           serviceCode,
		ServiceTier:           serviceTier,
		IdentityProviders:     identityProviders,
		Languages:             languages,
		Scorecard:             scorecard,
		Signals:               signals,
		Evidence:              evidenceState,
		Findings:              findings,
		NextActions:           secureCellGovernmentAgentNextActions(findings),
		WorkflowDigest:        workflowDigest,
		AssessedAt:            now,
		UpdatedAt:             result.UpdatedAt.UTC(),
	}
}

func secureCellGovernmentAgentPolicyMetadata(result *SecureCellResult) map[string]string {
	if result == nil {
		return nil
	}
	out := map[string]string{}
	if len(result.Policy.AllowedActions) > 0 {
		out["policy_allowed_actions_count"] = strconv.Itoa(len(result.Policy.AllowedActions))
	}
	if len(result.Policy.AllowedTools) > 0 {
		out["policy_allowed_tools_count"] = strconv.Itoa(len(result.Policy.AllowedTools))
	}
	if len(result.Policy.DataClasses) > 0 {
		out["policy_data_classes_count"] = strconv.Itoa(len(result.Policy.DataClasses))
	}
	if len(result.Policy.ComputeZones) > 0 {
		out["policy_compute_zones_count"] = strconv.Itoa(len(result.Policy.ComputeZones))
	}
	return out
}

func secureCellGovernmentAgentWorkflowSignals(result *SecureCellResult) SecureCellGovernmentAgentWorkflowSignals {
	if result == nil {
		return SecureCellGovernmentAgentWorkflowSignals{}
	}
	signals := SecureCellGovernmentAgentWorkflowSignals{
		SessionCount:                len(result.Sessions),
		ThreadCount:                 len(result.Threads),
		DecisionCount:               len(result.Decisions),
		FederationOrganizationCount: len(result.FederationOrganizations),
		FederationContractCount:     len(result.FederationContracts),
		FederationIncidentCount:     len(result.FederationIncidents) + len(result.FederationCounterpartyIncidents),
		TransitionCount:             len(result.Transitions),
	}
	for _, decision := range result.Decisions {
		if strings.TrimSpace(decision.GovernanceTemplate) != "" || decision.ApprovalThreshold > 0 || len(decision.RequiredApproverRoles) > 0 || len(decision.EligibleApproverDIDs) > 0 {
			signals.GovernedDecisionCount++
		}
		if strings.TrimSpace(decision.SLATemplate) != "" || decision.EscalationDueAt != nil || decision.ResolutionDueAt != nil {
			signals.TimedDecisionCount++
		}
		if decision.ApprovalThreshold > 0 || len(decision.RequiredApproverRoles) > 0 || len(decision.EligibleApproverDIDs) > 0 {
			signals.ApprovalGateCount++
		}
		if len(decision.EscalationLadder) > 0 || strings.TrimSpace(decision.AutoEscalateToDID) != "" {
			signals.EscalationLadderCount++
		}
	}
	for _, transition := range result.Transitions {
		if transition.PolicyReceipt != nil && transition.ExecutionSeal != nil && transition.TraceLink != nil {
			signals.EvidenceTransitionCount++
		}
		if secureCellTransitionAutomatedDecisionAction(transition) ||
			strings.Contains(strings.ToLower(transition.Action), "automation") ||
			strings.Contains(strings.ToLower(transition.Actor), "automation") {
			signals.AutomationActionCount++
		}
	}
	return signals
}

func secureCellGovernmentAgentEvidenceState(result *SecureCellResult) SecureCellGovernmentAgentEvidenceState {
	if result == nil {
		return SecureCellGovernmentAgentEvidenceState{}
	}
	state := SecureCellGovernmentAgentEvidenceState{
		PolicyReceiptChainHash: safeChainHash(result.ReceiptChain),
		PolicyReceiptCount:     len(orderedReceipts(result, nil)),
		ConfidentialVerified:   result.ConfidentialExecution != nil && result.ConfidentialExecution.Verified,
	}
	if result.ControlLedger != nil {
		state.ControlLedgerID = result.ControlLedger.Bundle.ID
		state.ControlLedgerHash = result.ControlLedger.Bundle.ContentHash
	}
	if result.PortablePackage != nil {
		state.PortablePackageHash = result.PortablePackage.PackageHash
		state.PortablePackageSigned = result.PortablePackage.Signature != nil
		state.PortablePackageAnchored = result.PortablePackage.AuditAnchor != nil
	}
	if result.ExecutionSeal != nil {
		state.ExecutionSealID = result.ExecutionSeal.SealID
	}
	for _, transition := range result.Transitions {
		if transition.ExecutionSeal != nil {
			state.SealedTransitionCount++
		}
		if transition.TraceLink != nil {
			state.TraceLinkedTransitionCount++
		}
	}
	return state
}

func secureCellGovernmentAgentWorkflowLegibilityScore(run *secureCellRun, signals SecureCellGovernmentAgentWorkflowSignals, serviceCode string) int {
	score := 0
	if strings.TrimSpace(run.result.Name) != "" {
		score += 8
	}
	if strings.TrimSpace(run.result.Purpose) != "" {
		score += 12
	}
	if strings.TrimSpace(run.request.Resource) != "" {
		score += 10
	}
	if strings.TrimSpace(serviceCode) != "" {
		score += 15
	}
	if signals.SessionCount > 0 {
		score += 10
	}
	if signals.ThreadCount > 0 {
		score += 10
	}
	if signals.DecisionCount > 0 {
		score += 10
	}
	if signals.GovernedDecisionCount > 0 {
		score += 15
	}
	if signals.TimedDecisionCount > 0 {
		score += 10
	}
	return clampSecureCellGovernmentAgentScore(score)
}

func secureCellGovernmentAgentEvidenceScore(run *secureCellRun, signals SecureCellGovernmentAgentWorkflowSignals, evidenceState SecureCellGovernmentAgentEvidenceState) int {
	score := 0
	if evidenceState.PolicyReceiptChainHash != "" {
		score += 18
	}
	if evidenceState.ControlLedgerHash != "" {
		score += 18
	}
	if evidenceState.PortablePackageHash != "" {
		score += 14
	}
	if evidenceState.PortablePackageSigned {
		score += 10
	}
	if evidenceState.PortablePackageAnchored {
		score += 10
	}
	if signals.TransitionCount > 0 && signals.EvidenceTransitionCount == signals.TransitionCount {
		score += 15
	} else if signals.EvidenceTransitionCount > 0 {
		score += 8
	}
	if evidenceState.ConfidentialVerified || !confidentialComputeRequired(run.result.Policy) {
		score += 10
	}
	if len(run.result.Policy.DataClasses) > 0 && strings.TrimSpace(run.result.Policy.RetentionPolicy) != "" {
		score += 5
	}
	return clampSecureCellGovernmentAgentScore(score)
}

func secureCellGovernmentAgentAuthorityScore(run *secureCellRun, signals SecureCellGovernmentAgentWorkflowSignals) int {
	score := 0
	if len(run.result.Policy.AllowedActions) > 0 {
		score += 18
	}
	if len(run.result.Policy.AllowedTools) > 0 {
		score += 12
	}
	if signals.ApprovalGateCount > 0 {
		score += 24
	}
	if signals.GovernedDecisionCount > 0 {
		score += 14
	}
	if signals.EscalationLadderCount > 0 {
		score += 14
	}
	if len(run.result.Participants) > 1 {
		score += 8
	}
	if len(run.result.FederationContracts) > 0 || len(run.result.FederationOrganizations) > 1 {
		score += 10
	}
	return clampSecureCellGovernmentAgentScore(score)
}

func secureCellGovernmentAgentIntegrationScore(run *secureCellRun, identityProviders []string, metadata map[string]string) int {
	score := 0
	if strings.TrimSpace(run.request.Resource) != "" {
		score += 15
	}
	if len(run.result.Policy.DataClasses) > 0 {
		score += 18
	}
	if len(run.result.Policy.ComputeZones) > 0 {
		score += 14
	}
	if len(identityProviders) > 0 {
		score += 16
	}
	if metadataTruth(metadata, "digital_records_policy", "official_digital_records", "government_services_digital_records_policy") {
		score += 14
	}
	if metadataTruth(metadata, "data_sharing_policy", "collect_once_share_securely", "government_services_data_sharing_policy") {
		score += 14
	}
	if strings.TrimSpace(firstNonEmpty(metadataValue(metadata, "system_of_record"), metadataValue(metadata, "source_system"), metadataValue(metadata, "integration_systems"))) != "" {
		score += 9
	}
	return clampSecureCellGovernmentAgentScore(score)
}

func secureCellGovernmentAgentSLAScore(run *secureCellRun, signals SecureCellGovernmentAgentWorkflowSignals, configuredSLATemplateCount int) int {
	score := 0
	if configuredSLATemplateCount > 0 {
		score += 15
	}
	if signals.TimedDecisionCount > 0 && signals.DecisionCount > 0 {
		score += 25 * signals.TimedDecisionCount / signals.DecisionCount
	}
	if signals.EscalationLadderCount > 0 {
		score += 20
	}
	if signals.AutomationActionCount > 0 {
		score += 15
	}
	for _, decision := range run.result.Decisions {
		if decision.EscalationDueAt != nil {
			score += 5
			break
		}
	}
	for _, decision := range run.result.Decisions {
		if decision.ResolutionDueAt != nil {
			score += 10
			break
		}
	}
	if signals.FederationIncidentCount > 0 || len(run.result.FederationIncidentResponses) > 0 {
		score += 10
	}
	return clampSecureCellGovernmentAgentScore(score)
}

func secureCellGovernmentAgentOversightScore(run *secureCellRun, signals SecureCellGovernmentAgentWorkflowSignals, metadata map[string]string) int {
	score := 0
	if signals.ApprovalGateCount > 0 {
		score += 25
	}
	if secureCellAnyDecisionHasVote(run.result.Decisions) {
		score += 10
	}
	if secureCellAnyDecisionHasDelegation(run.result.Decisions) {
		score += 10
	}
	if metadataTruth(metadata, "human_override", "human_in_the_loop", "emergency_stop", "operator_override") {
		score += 20
	}
	if secureCellHasTransitionAction(run.result.Transitions, "quarantined", "revoked", "contained", "disputed", "reconciliation") {
		score += 20
	}
	if len(run.result.FederationIncidentResponses) > 0 || signals.FederationIncidentCount > 0 {
		score += 15
	}
	return clampSecureCellGovernmentAgentScore(score)
}

func secureCellGovernmentAgentLocalizationScore(run *secureCellRun, identityProviders []string, languages []string, metadata map[string]string, serviceCode string) int {
	score := 0
	if !strings.EqualFold(strings.TrimSpace(run.request.Jurisdiction), "UAE") {
		if len(languages) > 0 {
			score += 35
		}
		if len(identityProviders) > 0 {
			score += 25
		}
		if strings.TrimSpace(serviceCode) != "" {
			score += 20
		}
		if metadataTruth(metadata, "data_residency", "sovereign_data_residency") || len(run.result.Policy.ComputeZones) > 0 {
			score += 20
		}
		return clampSecureCellGovernmentAgentScore(score)
	}
	if metadataListContainsLanguage(languages, "ar") && metadataListContainsLanguage(languages, "en") {
		score += 35
	}
	if metadataListContainsIdentityProvider(identityProviders, "uae_pass") {
		score += 25
	}
	if secureCellComputeZoneContains(run.result.Policy.ComputeZones, "uae") {
		score += 15
	}
	if strings.TrimSpace(serviceCode) != "" {
		score += 15
	}
	if metadataTruth(metadata, "data_sharing_policy", "government_services_data_sharing_policy") {
		score += 5
	}
	if metadataTruth(metadata, "digital_records_policy", "government_services_digital_records_policy") {
		score += 5
	}
	return clampSecureCellGovernmentAgentScore(score)
}

func secureCellGovernmentAgentOverallScore(scorecard SecureCellGovernmentAgentReadinessScorecard) int {
	total := scorecard.WorkflowLegibility*20 +
		scorecard.EvidenceReadiness*25 +
		scorecard.AuthorityControls*15 +
		scorecard.IntegrationReadiness*15 +
		scorecard.SLAAutomation*10 +
		scorecard.HumanOversight*10 +
		scorecard.LocalizationReadiness*5
	return clampSecureCellGovernmentAgentScore(total / 100)
}

func secureCellGovernmentAgentReadinessFindings(
	run *secureCellRun,
	scorecard SecureCellGovernmentAgentReadinessScorecard,
	signals SecureCellGovernmentAgentWorkflowSignals,
	evidenceState SecureCellGovernmentAgentEvidenceState,
	identityProviders []string,
	languages []string,
	metadata map[string]string,
	serviceCode string,
) []SecureCellGovernmentAgentReadinessFinding {
	findings := make([]SecureCellGovernmentAgentReadinessFinding, 0)
	add := func(severity SecureCellGovernmentAgentReadinessSeverity, code, category, title, detail, recommendation string) {
		findings = append(findings, SecureCellGovernmentAgentReadinessFinding{
			Severity:       severity,
			Code:           code,
			Category:       category,
			Title:          title,
			Detail:         detail,
			Recommendation: recommendation,
		})
	}
	if evidenceState.PolicyReceiptChainHash == "" || evidenceState.ControlLedgerHash == "" || evidenceState.PortablePackageHash == "" {
		add(SecureCellGovernmentAgentReadinessSeverityCritical, "GOVAGENT_EVIDENCE_FABRIC_INCOMPLETE", "evidence", "Evidence fabric is incomplete", "A government agent workflow must carry receipt-chain, control-ledger, and portable-package evidence.", "Regenerate the secure-cell lifecycle artifact package before agent execution.")
	}
	if signals.DecisionCount == 0 {
		add(SecureCellGovernmentAgentReadinessSeverityCritical, "GOVAGENT_NO_GOVERNED_DECISIONS", "workflow", "No governed decisions are modeled", "The process still lacks explicit approval, denial, exception, or escalation decision objects.", "Create governed decision nodes for every tacit approval or service outcome.")
	}
	if signals.ApprovalGateCount == 0 {
		add(SecureCellGovernmentAgentReadinessSeverityCritical, "GOVAGENT_NO_AUTHORITY_BOUNDARY", "authority", "No authority boundary is defined", "Agent actions must be separated from human-only approvals and non-delegable decisions.", "Attach approval thresholds, eligible approvers, and required roles to decision objects.")
	}
	if signals.TimedDecisionCount == 0 {
		add(SecureCellGovernmentAgentReadinessSeverityWarning, "GOVAGENT_NO_DECISION_SLA", "sla", "No decision timer is attached", "The workflow cannot prove overdue decisions or automatic escalation timing.", "Bind each decision to an SLA template or explicit escalation/resolution deadlines.")
	}
	if signals.EscalationLadderCount == 0 {
		add(SecureCellGovernmentAgentReadinessSeverityWarning, "GOVAGENT_NO_ESCALATION_LADDER", "sla", "No escalation ladder is attached", "Agent execution needs deterministic next actors when service work becomes overdue.", "Add escalation tiers with target DIDs, modes, due times, and evidence-bearing reasons.")
	}
	if len(run.result.Policy.DataClasses) == 0 {
		add(SecureCellGovernmentAgentReadinessSeverityCritical, "GOVAGENT_DATA_CLASSES_UNMAPPED", "integration", "Data classes are not mapped", "Government-service agents need explicit data boundaries before they fetch, infer, or share records.", "Map every workflow step to data classes and retention requirements.")
	}
	if len(run.result.Policy.AllowedActions) == 0 || len(run.result.Policy.AllowedTools) == 0 {
		add(SecureCellGovernmentAgentReadinessSeverityWarning, "GOVAGENT_TOOL_SCOPE_UNMAPPED", "authority", "Agent tool/action scope is not explicit", "Allowed tools and actions are part of the execution contract for safe autonomous operation.", "Declare the exact secure-cell actions and tools the government-service agent may use.")
	}
	if strings.TrimSpace(serviceCode) == "" {
		add(SecureCellGovernmentAgentReadinessSeverityWarning, "GOVAGENT_SERVICE_CODE_MISSING", "workflow", "Government service code is missing", "Operator dashboards need a stable service catalog key for rollout measurement.", "Add government_service_code or service_catalog_id metadata.")
	}
	if strings.EqualFold(strings.TrimSpace(run.request.Jurisdiction), "UAE") {
		if !metadataListContainsIdentityProvider(identityProviders, "uae_pass") {
			add(SecureCellGovernmentAgentReadinessSeverityWarning, "GOVAGENT_UAE_PASS_MISSING", "integration", "UAE Pass binding is not declared", "UAE-scale services need a first-class identity-provider boundary.", "Set identity_provider metadata to UAE Pass or attach an equivalent eID adapter contract.")
		}
		if !metadataListContainsLanguage(languages, "ar") || !metadataListContainsLanguage(languages, "en") {
			add(SecureCellGovernmentAgentReadinessSeverityWarning, "GOVAGENT_BILINGUAL_SURFACE_MISSING", "localization", "Arabic/English service surface is not declared", "Federal service automation should be operable and auditable in Arabic and English.", "Set supported languages to Arabic and English for the workflow pack.")
		}
		if !metadataTruth(metadata, "digital_records_policy", "government_services_digital_records_policy") {
			add(SecureCellGovernmentAgentReadinessSeverityWarning, "GOVAGENT_DIGITAL_RECORDS_POLICY_MISSING", "integration", "Digital records policy binding is missing", "Government agents need an official-source-of-record rule for service data.", "Attach the digital records policy reference for the service workflow.")
		}
		if !metadataTruth(metadata, "data_sharing_policy", "government_services_data_sharing_policy") {
			add(SecureCellGovernmentAgentReadinessSeverityWarning, "GOVAGENT_DATA_SHARING_POLICY_MISSING", "integration", "Data sharing policy binding is missing", "Collect-once, securely reused records are core to agentic government delivery.", "Attach the government service data-sharing policy and cross-entity sharing constraints.")
		}
	}
	if scorecard.EvidenceReadiness >= 90 && scorecard.AuthorityControls >= 80 && scorecard.WorkflowLegibility >= 80 {
		add(SecureCellGovernmentAgentReadinessSeverityInfo, "GOVAGENT_CORE_FABRIC_STRONG", "moat", "Core workflow trust fabric is strong", "The cell has evidence-bearing transitions, governed decisions, and authority controls.", "Continue closing localization, integration, and SLA automation gaps for autonomous rollout.")
	}
	return findings
}

func secureCellGovernmentAgentReadinessLevel(overall int, findings []SecureCellGovernmentAgentReadinessFinding) SecureCellGovernmentAgentReadinessLevel {
	critical := 0
	warnings := 0
	for _, finding := range findings {
		switch finding.Severity {
		case SecureCellGovernmentAgentReadinessSeverityCritical:
			critical++
		case SecureCellGovernmentAgentReadinessSeverityWarning:
			warnings++
		}
	}
	switch {
	case critical > 0 || overall < 60:
		return SecureCellGovernmentAgentReadinessBlocked
	case overall >= 90 && warnings == 0:
		return SecureCellGovernmentAgentReadinessAutonomyReady
	case overall >= 75:
		return SecureCellGovernmentAgentReadinessSupervisedReady
	default:
		return SecureCellGovernmentAgentReadinessFoundationReady
	}
}

func secureCellGovernmentAgentNextActions(findings []SecureCellGovernmentAgentReadinessFinding) []SecureCellGovernmentAgentReadinessNextAction {
	actions := make([]SecureCellGovernmentAgentReadinessNextAction, 0)
	for _, finding := range findings {
		if finding.Severity == SecureCellGovernmentAgentReadinessSeverityInfo {
			continue
		}
		priority := 2
		blocks := false
		if finding.Severity == SecureCellGovernmentAgentReadinessSeverityCritical {
			priority = 1
			blocks = true
		}
		actions = append(actions, SecureCellGovernmentAgentReadinessNextAction{
			Priority:       priority,
			Owner:          secureCellGovernmentAgentFindingOwner(finding.Category),
			Action:         finding.Recommendation,
			Rationale:      finding.Title,
			BlocksAutonomy: blocks,
		})
	}
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Priority == actions[j].Priority {
			return actions[i].Action < actions[j].Action
		}
		return actions[i].Priority < actions[j].Priority
	})
	return actions
}

func secureCellGovernmentAgentFindingOwner(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "workflow", "sla":
		return "workflow_owner"
	case "authority":
		return "risk_and_policy_owner"
	case "integration":
		return "platform_integration_owner"
	case "localization":
		return "service_experience_owner"
	case "evidence":
		return "trust_kernel_operator"
	default:
		return "secure_cell_operator"
	}
}

func clampSecureCellGovernmentAgentScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func metadataValue(metadata map[string]string, key string) string {
	for candidate, value := range metadata {
		if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(key)) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func normalizedMetadataList(metadata map[string]string, keys ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, key := range keys {
		raw := metadataValue(metadata, key)
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == '|' || r == '\n' || r == '\t'
		}) {
			normalized := normalizeGovernmentAgentToken(part)
			if normalized == "" {
				continue
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			out = append(out, normalized)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeGovernmentAgentToken(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, " ", "_")
	normalized = strings.ReplaceAll(normalized, "-", "_")
	switch normalized {
	case "arabic":
		return "ar"
	case "english":
		return "en"
	case "uae_pass", "uaepass":
		return "uae_pass"
	default:
		return normalized
	}
}

func metadataTruth(metadata map[string]string, keys ...string) bool {
	for _, key := range keys {
		value := strings.ToLower(strings.TrimSpace(metadataValue(metadata, key)))
		switch value {
		case "1", "true", "yes", "y", "enabled", "required", "collect_once", "official", "present":
			return true
		}
		if strings.Contains(value, "collect_once") || strings.Contains(value, "official") || strings.Contains(value, "required") {
			return true
		}
	}
	return false
}

func metadataListContainsLanguage(values []string, language string) bool {
	target := normalizeGovernmentAgentToken(language)
	for _, value := range values {
		if normalizeGovernmentAgentToken(value) == target {
			return true
		}
	}
	return false
}

func metadataListContainsIdentityProvider(values []string, provider string) bool {
	target := normalizeGovernmentAgentToken(provider)
	for _, value := range values {
		normalized := normalizeGovernmentAgentToken(value)
		if normalized == target || strings.Contains(normalized, target) {
			return true
		}
	}
	return false
}

func secureCellComputeZoneContains(values []string, token string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	for _, value := range values {
		if strings.Contains(strings.ToLower(strings.TrimSpace(value)), token) {
			return true
		}
	}
	return false
}

func secureCellAnyDecisionHasVote(decisions []SecureCellThreadDecision) bool {
	for _, decision := range decisions {
		if len(decision.ApprovalVotes) > 0 {
			return true
		}
	}
	return false
}

func secureCellAnyDecisionHasDelegation(decisions []SecureCellThreadDecision) bool {
	for _, decision := range decisions {
		if len(decision.Delegations) > 0 || len(decision.EscalationLadder) > 0 || strings.TrimSpace(decision.AutoEscalateToDID) != "" {
			return true
		}
	}
	return false
}

func secureCellHasTransitionAction(transitions []SecureCellTransition, tokens ...string) bool {
	for _, transition := range transitions {
		action := strings.ToLower(strings.TrimSpace(transition.Action))
		for _, token := range tokens {
			if strings.Contains(action, strings.ToLower(strings.TrimSpace(token))) {
				return true
			}
		}
	}
	return false
}
