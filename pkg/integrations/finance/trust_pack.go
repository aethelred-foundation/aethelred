package finance

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/confidential"
)

// TreasuryReleaseListFilter narrows operator queries over persisted finance
// workflows.
type TreasuryReleaseListFilter struct {
	Status               TreasuryReleaseWorkflowStatus `json:"status,omitempty"`
	Jurisdiction         string                        `json:"jurisdiction,omitempty"`
	Counterparty         string                        `json:"counterparty,omitempty"`
	ReasonCode           string                        `json:"reason_code,omitempty"`
	RequireConfidential  *bool                         `json:"require_confidential,omitempty"`
	UpdatedAfter         *time.Time                    `json:"updated_after,omitempty"`
	UpdatedBefore        *time.Time                    `json:"updated_before,omitempty"`
	Limit                int                           `json:"limit,omitempty"`
}

// TreasuryReleaseSummary is the operator-facing summary of one treasury
// release workflow.
type TreasuryReleaseSummary struct {
	WorkflowID               string                        `json:"workflow_id"`
	Status                   TreasuryReleaseWorkflowStatus `json:"status"`
	Type                     OperationType                 `json:"type,omitempty"`
	Amount                   float64                       `json:"amount,omitempty"`
	Currency                 string                        `json:"currency,omitempty"`
	Initiator                string                        `json:"initiator,omitempty"`
	Counterparty             string                        `json:"counterparty,omitempty"`
	Jurisdiction             string                        `json:"jurisdiction,omitempty"`
	ReasonCode               string                        `json:"reason_code,omitempty"`
	RequiredApprovals        int                           `json:"required_approvals,omitempty"`
	CurrentApprovals         int                           `json:"current_approvals,omitempty"`
	ConfidentialRequired     bool                          `json:"confidential_required"`
	ConfidentialVerified     bool                          `json:"confidential_verified"`
	SettlementReady          bool                          `json:"settlement_ready"`
	ControlLedgerID          string                        `json:"control_ledger_id,omitempty"`
	PortablePackageHash      string                        `json:"portable_package_hash,omitempty"`
	CreatedAt                time.Time                     `json:"created_at"`
	UpdatedAt                time.Time                     `json:"updated_at"`
}

// FinanceOperatorSurface documents one buyer- or operator-facing runtime
// surface included in the finance trust pack.
type FinanceOperatorSurface struct {
	ID          string   `json:"id"`
	Method      string   `json:"method,omitempty"`
	Path        string   `json:"path,omitempty"`
	Description string   `json:"description,omitempty"`
	Formats     []string `json:"formats,omitempty"`
}

// FinanceWorkflowTemplateSummary captures the buyer-facing workflow template
// encoded in the running finance wedge.
type FinanceWorkflowTemplateSummary struct {
	PolicySetID             string          `json:"policy_set_id,omitempty"`
	PolicySetName           string          `json:"policy_set_name,omitempty"`
	Framework               string          `json:"framework,omitempty"`
	SupportedOperationTypes []OperationType `json:"supported_operation_types,omitempty"`
	SingleThreshold         float64         `json:"single_threshold,omitempty"`
	DualThreshold           float64         `json:"dual_threshold,omitempty"`
	CommitteeThreshold      float64         `json:"committee_threshold,omitempty"`
	RequiredCommitteeSize   int             `json:"required_committee_size,omitempty"`
	Actions                 []string        `json:"actions,omitempty"`
	Tool                    string          `json:"tool,omitempty"`
}

// FinanceSanctionsProfile summarizes the sanctions posture in the running pack.
type FinanceSanctionsProfile struct {
	Provider       string          `json:"provider,omitempty"`
	DefaultLists   []SanctionsList `json:"default_lists,omitempty"`
	BlockOnMatch   bool            `json:"block_on_match"`
	MatchThreshold int             `json:"match_threshold,omitempty"`
}

// FinanceSettlementProfile summarizes the settlement controls in the running
// finance pack.
type FinanceSettlementProfile struct {
	ProviderID            string   `json:"provider_id,omitempty"`
	ProviderStatus        string   `json:"provider_status,omitempty"`
	CorridorID            string   `json:"corridor_id,omitempty"`
	Network               string   `json:"network,omitempty"`
	Method                string   `json:"method,omitempty"`
	FiatCurrency          string   `json:"fiat_currency,omitempty"`
	TokenDenomination     string   `json:"token_denomination,omitempty"`
	ExchangeRate          float64  `json:"exchange_rate,omitempty"`
	MaxFiatAmount         float64  `json:"max_fiat_amount,omitempty"`
	AllowedCounterparties []string `json:"allowed_counterparties,omitempty"`
	AllowedJurisdictions  []string `json:"allowed_jurisdictions,omitempty"`
	AllowedCurrencies     []string `json:"allowed_currencies,omitempty"`
	RequiredReasonCodes   []string `json:"required_reason_codes,omitempty"`
}

// FinanceConfidentialExecutionProfile summarizes workflow-bound confidential
// execution policy in the running finance pack.
type FinanceConfidentialExecutionProfile struct {
	Required                 bool     `json:"required"`
	MinimumValidAttestations int      `json:"minimum_valid_attestations,omitempty"`
	TrustedPlatforms         []string `json:"trusted_platforms,omitempty"`
	AllowedEnclaveIDs        []string `json:"allowed_enclave_ids,omitempty"`
	AllowedMeasurements      []string `json:"allowed_measurements,omitempty"`
	RequireQuoteBinding      bool     `json:"require_quote_binding"`
}

// FinanceControlProfile captures one buyer-facing control included in the
// finance trust pack.
type FinanceControlProfile struct {
	ControlID     string   `json:"control_id"`
	ControlName   string   `json:"control_name"`
	Description   string   `json:"description,omitempty"`
	WorkflowStage string   `json:"workflow_stage,omitempty"`
	EvidenceTypes []string `json:"evidence_types,omitempty"`
}

// FinanceRegulatorProfile captures one supported regulator posture in the
// finance trust pack.
type FinanceRegulatorProfile struct {
	Regulator           Regulator `json:"regulator"`
	ComplianceFramework string    `json:"compliance_framework,omitempty"`
	RetentionYears      int       `json:"retention_years,omitempty"`
	SubmissionDeadline  string    `json:"submission_deadline,omitempty"`
	RequiredSections    []string  `json:"required_sections,omitempty"`
}

// FinanceRuntimeSummary summarizes live workflow posture for operators and
// buyers evaluating the pack.
type FinanceRuntimeSummary struct {
	TotalWorkflows                 int       `json:"total_workflows"`
	PendingWorkflows               int       `json:"pending_workflows"`
	CompletedWorkflows             int       `json:"completed_workflows"`
	RejectedWorkflows              int       `json:"rejected_workflows"`
	ConfidentiallyVerified         int       `json:"confidentially_verified"`
	SettledWorkflows               int       `json:"settled_workflows"`
	LastWorkflowUpdatedAt          time.Time `json:"last_workflow_updated_at,omitempty"`
}

// FinanceTrustPack is the buyer-facing summary of the finance regulated
// autonomy product encoded in the running node.
type FinanceTrustPack struct {
	ID                    string                                 `json:"id"`
	Version               string                                 `json:"version"`
	Name                  string                                 `json:"name"`
	Sector                string                                 `json:"sector"`
	GeneratedAt           time.Time                              `json:"generated_at"`
	Workflow              FinanceWorkflowTemplateSummary         `json:"workflow"`
	Sanctions             FinanceSanctionsProfile                `json:"sanctions"`
	Settlement            FinanceSettlementProfile               `json:"settlement"`
	ConfidentialExecution FinanceConfidentialExecutionProfile    `json:"confidential_execution"`
	Controls              []FinanceControlProfile                `json:"controls,omitempty"`
	Regulators            []FinanceRegulatorProfile              `json:"regulators,omitempty"`
	Runtime               FinanceRuntimeSummary                  `json:"runtime"`
	OperatorSurfaces      []FinanceOperatorSurface               `json:"operator_surfaces,omitempty"`
}

// FinanceTrustPackOptions lets callers enrich trust-pack generation with
// runtime-specific operator surfaces or custom metadata.
type FinanceTrustPackOptions struct {
	ID               string                 `json:"id,omitempty"`
	Version          string                 `json:"version,omitempty"`
	Name             string                 `json:"name,omitempty"`
	OperatorSurfaces []FinanceOperatorSurface `json:"operator_surfaces,omitempty"`
}

// ListReleases returns operator summaries over the persisted workflow set.
func (w *TreasuryReleaseWorkflow) ListReleases(_ context.Context, filter TreasuryReleaseListFilter) ([]TreasuryReleaseSummary, error) {
	if w == nil {
		return nil, nil
	}
	requireConfidential := filter.RequireConfidential
	w.mu.RLock()
	defer w.mu.RUnlock()

	items := make([]TreasuryReleaseSummary, 0, len(w.runs))
	for _, run := range w.runs {
		summary := summarizeTreasuryReleaseRun(run, w.config.ConfidentialPolicy)
		if !matchesTreasuryReleaseFilter(summary, filter, requireConfidential) {
			continue
		}
		items = append(items, summary)
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

// BuildTrustPack returns the buyer-facing finance trust pack summary for the
// current workflow configuration and runtime posture.
func (w *TreasuryReleaseWorkflow) BuildTrustPack(ctx context.Context, options FinanceTrustPackOptions) (*FinanceTrustPack, error) {
	if w == nil {
		return nil, fmt.Errorf("finance/trust_pack: workflow is required")
	}
	policySetID := ""
	policySetName := ""
	if w.config.PolicySet != nil {
		policySetID = strings.TrimSpace(w.config.PolicySet.ID)
		policySetName = strings.TrimSpace(w.config.PolicySet.Name)
	}

	releases, err := w.ListReleases(ctx, TreasuryReleaseListFilter{})
	if err != nil {
		return nil, err
	}
	runtime := summarizeFinanceRuntime(releases)
	reporting := NewReportingService(w.config.AuditTrail)

	pack := &FinanceTrustPack{
		ID:          firstNonEmpty(strings.TrimSpace(options.ID), "finance-regulated-autonomy-trust-pack-v1"),
		Version:     firstNonEmpty(strings.TrimSpace(options.Version), "1.0"),
		Name:        firstNonEmpty(strings.TrimSpace(options.Name), "Finance Regulated Autonomy Trust Pack"),
		Sector:      "finance",
		GeneratedAt: time.Now().UTC(),
		Workflow: FinanceWorkflowTemplateSummary{
			PolicySetID:             policySetID,
			PolicySetName:           policySetName,
			Framework:               w.config.Framework,
			SupportedOperationTypes: supportedTreasuryOperationTypes(),
			SingleThreshold:         w.config.Controller.ApprovalPolicy().SingleThreshold,
			DualThreshold:           w.config.Controller.ApprovalPolicy().DualThreshold,
			CommitteeThreshold:      w.config.Controller.ApprovalPolicy().CommitteeThreshold,
			RequiredCommitteeSize:   w.config.Controller.ApprovalPolicy().RequiredCommitteeSize,
			Actions: []string{
				treasuryReleaseRequestAction,
				treasuryReleaseExecuteAction,
				treasuryReleaseSettlementAction,
			},
			Tool: treasuryReleaseTool,
		},
		Sanctions: FinanceSanctionsProfile{
			Provider:       strings.TrimSpace(w.config.Sanctions.Config().ScreeningProvider),
			DefaultLists:   append([]SanctionsList(nil), w.config.Sanctions.Config().DefaultLists...),
			BlockOnMatch:   w.config.Sanctions.Config().BlockOnMatch,
			MatchThreshold: w.config.Sanctions.Config().MatchThreshold,
		},
		Settlement: settlementProfileFromWorkflow(w.config.SettlementRail),
		ConfidentialExecution: confidentialProfileFromPolicy(w.config.ConfidentialPolicy),
		Controls:              financeTrustPackControls(),
		Regulators:            financeTrustPackRegulators(reporting),
		Runtime:               runtime,
		OperatorSurfaces:      cloneFinanceOperatorSurfaces(options.OperatorSurfaces),
	}
	return pack, nil
}

func summarizeTreasuryReleaseRun(run *treasuryReleaseRun, policy confidential.Policy) TreasuryReleaseSummary {
	if run == nil || run.result == nil {
		return TreasuryReleaseSummary{}
	}
	summary := TreasuryReleaseSummary{
		WorkflowID:           strings.TrimSpace(run.result.WorkflowID),
		Status:               run.result.Status,
		ConfidentialRequired: policy.Required,
		CreatedAt:            run.result.CreatedAt,
		UpdatedAt:            run.result.UpdatedAt,
	}
	if run.request.Operation != nil {
		summary.Type = run.request.Operation.Type
		summary.Amount = run.request.Operation.Amount
		summary.Currency = strings.TrimSpace(run.request.Operation.Currency)
		summary.Initiator = strings.TrimSpace(run.request.Operation.Initiator)
		summary.Counterparty = strings.TrimSpace(run.request.Operation.Counterparty)
	}
	summary.Jurisdiction = strings.TrimSpace(run.request.Jurisdiction)
	summary.ReasonCode = strings.TrimSpace(run.request.ReasonCode)
	if run.result.ApprovalStatus != nil {
		summary.RequiredApprovals = run.result.ApprovalStatus.RequiredApprovals
		summary.CurrentApprovals = run.result.ApprovalStatus.CurrentApprovals
	}
	if run.result.ConfidentialExecution != nil {
		summary.ConfidentialVerified = run.result.ConfidentialExecution.Verified
	}
	if run.result.Settlement != nil {
		summary.SettlementReady = true
	}
	if run.result.ControlLedger != nil {
		summary.ControlLedgerID = strings.TrimSpace(run.result.ControlLedger.Bundle.ID)
	}
	if run.result.PortablePackage != nil {
		summary.PortablePackageHash = strings.TrimSpace(run.result.PortablePackage.PackageHash)
	}
	return summary
}

func matchesTreasuryReleaseFilter(summary TreasuryReleaseSummary, filter TreasuryReleaseListFilter, requireConfidential *bool) bool {
	if filter.Status != "" && summary.Status != filter.Status {
		return false
	}
	if filter.Jurisdiction != "" && !strings.EqualFold(summary.Jurisdiction, filter.Jurisdiction) {
		return false
	}
	if filter.Counterparty != "" && !strings.EqualFold(summary.Counterparty, filter.Counterparty) {
		return false
	}
	if filter.ReasonCode != "" && !strings.EqualFold(summary.ReasonCode, filter.ReasonCode) {
		return false
	}
	if requireConfidential != nil && summary.ConfidentialVerified != *requireConfidential {
		return false
	}
	if filter.UpdatedAfter != nil && !summary.UpdatedAt.IsZero() && summary.UpdatedAt.Before(filter.UpdatedAfter.UTC()) {
		return false
	}
	if filter.UpdatedBefore != nil && !summary.UpdatedAt.IsZero() && summary.UpdatedAt.After(filter.UpdatedBefore.UTC()) {
		return false
	}
	return true
}

func settlementProfileFromWorkflow(rail TreasurySettlementRail) FinanceSettlementProfile {
	profile := FinanceSettlementProfile{}
	policyRail, ok := rail.(*PolicyBoundSettlementRail)
	if !ok || policyRail == nil {
		return profile
	}
	config := policyRail.Config()
	return FinanceSettlementProfile{
		ProviderID:            strings.TrimSpace(config.ProviderID),
		ProviderStatus:        strings.TrimSpace(config.ProviderStatus),
		CorridorID:            strings.TrimSpace(config.CorridorID),
		Network:               strings.TrimSpace(config.Network),
		Method:                strings.TrimSpace(config.Method),
		FiatCurrency:          strings.TrimSpace(config.FiatCurrency),
		TokenDenomination:     strings.TrimSpace(config.TokenDenomination),
		ExchangeRate:          config.ExchangeRate,
		MaxFiatAmount:         config.MaxFiatAmount,
		AllowedCounterparties: append([]string(nil), config.AllowedCounterparties...),
		AllowedJurisdictions:  append([]string(nil), config.AllowedJurisdictions...),
		AllowedCurrencies:     append([]string(nil), config.AllowedCurrencies...),
		RequiredReasonCodes:   append([]string(nil), config.RequiredReasonCodes...),
	}
}

func confidentialProfileFromPolicy(policy confidential.Policy) FinanceConfidentialExecutionProfile {
	return FinanceConfidentialExecutionProfile{
		Required:                 policy.Required,
		MinimumValidAttestations: policy.MinimumValidAttestations,
		TrustedPlatforms:         append([]string(nil), policy.TrustedPlatforms...),
		AllowedEnclaveIDs:        append([]string(nil), policy.AllowedEnclaveIDs...),
		AllowedMeasurements:      append([]string(nil), policy.AllowedMeasurements...),
		RequireQuoteBinding:      policy.RequireQuoteBinding,
	}
}

func financeTrustPackControls() []FinanceControlProfile {
	return []FinanceControlProfile{
		{ControlID: "TREASURY-ID-01", ControlName: "Accountable Agent Passport", Description: "Treasury release carries sponsor-of-record, liability, and jurisdiction-bound identity evidence.", WorkflowStage: "request", EvidenceTypes: []string{"agent_passport", "audit_record"}},
		{ControlID: "TREASURY-POL-01", ControlName: "Policy-Gated Treasury Authorization", Description: "Request, execution, and settlement stages emit signed policy receipts and a verifiable chain hash.", WorkflowStage: "request_execute_settlement", EvidenceTypes: []string{"policy_receipt", "trace_link", "value_settlement"}},
		{ControlID: "TREASURY-APP-01", ControlName: "Authenticated Multi-Party Approval", Description: "Approver passports and approval policy receipts are carried into the final treasury release evidence chain.", WorkflowStage: "approval", EvidenceTypes: []string{"approver_attestation", "policy_receipt", "trace_link"}},
		{ControlID: "TREASURY-AUD-01", ControlName: "Attested Execution and Auditor Package", Description: "Execution is sealed, ledgered, and packaged into a portable auditor artifact.", WorkflowStage: "execution", EvidenceTypes: []string{"seal", "control_ledger", "portable_package", "attestation"}},
		{ControlID: "TREASURY-TEE-01", ControlName: "Bound Confidential Execution Attestation", Description: "Treasury execution carries verifier-checked TEE attestations bound to workflow, stage, and output hash.", WorkflowStage: "execution", EvidenceTypes: []string{"attestation", "seal"}},
		{ControlID: "TREASURY-SET-01", ControlName: "Policy-Bound Treasury Settlement", Description: "Settlement is authorized separately, constrained by the settlement rail, and linked to the sealed execution outcome.", WorkflowStage: "settlement", EvidenceTypes: []string{"value_settlement", "policy_receipt", "seal"}},
	}
}

func financeTrustPackRegulators(reporting *ReportingService) []FinanceRegulatorProfile {
	if reporting == nil {
		return nil
	}
	regulators := reporting.ListRegulators()
	sort.SliceStable(regulators, func(i, j int) bool { return regulators[i] < regulators[j] })
	items := make([]FinanceRegulatorProfile, 0, len(regulators))
	for _, regulator := range regulators {
		template, err := reporting.GetTemplate(regulator)
		if err != nil || template == nil {
			continue
		}
		items = append(items, FinanceRegulatorProfile{
			Regulator:           template.Regulator,
			ComplianceFramework: template.ComplianceFramework,
			RetentionYears:      template.RetentionYears,
			SubmissionDeadline:  template.SubmissionDeadline,
			RequiredSections:    append([]string(nil), template.RequiredSections...),
		})
	}
	return items
}

func summarizeFinanceRuntime(items []TreasuryReleaseSummary) FinanceRuntimeSummary {
	summary := FinanceRuntimeSummary{TotalWorkflows: len(items)}
	for _, item := range items {
		switch item.Status {
		case ReleaseStatusPendingApproval:
			summary.PendingWorkflows++
		case ReleaseStatusCompleted:
			summary.CompletedWorkflows++
		case ReleaseStatusRejected:
			summary.RejectedWorkflows++
		}
		if item.ConfidentialVerified {
			summary.ConfidentiallyVerified++
		}
		if item.SettlementReady {
			summary.SettledWorkflows++
		}
		if item.UpdatedAt.After(summary.LastWorkflowUpdatedAt) {
			summary.LastWorkflowUpdatedAt = item.UpdatedAt
		}
	}
	return summary
}

func supportedTreasuryOperationTypes() []OperationType {
	return []OperationType{
		OpTransfer,
		OpPayment,
		OpFXTrade,
		OpSettlement,
		OpReconciliation,
	}
}

func cloneFinanceOperatorSurfaces(in []FinanceOperatorSurface) []FinanceOperatorSurface {
	if len(in) == 0 {
		return nil
	}
	out := make([]FinanceOperatorSurface, 0, len(in))
	for _, item := range in {
		out = append(out, FinanceOperatorSurface{
			ID:          strings.TrimSpace(item.ID),
			Method:      strings.TrimSpace(item.Method),
			Path:        strings.TrimSpace(item.Path),
			Description: strings.TrimSpace(item.Description),
			Formats:     append([]string(nil), item.Formats...),
		})
	}
	return out
}
