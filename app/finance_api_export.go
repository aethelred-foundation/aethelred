package app

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	financeintegration "github.com/aethelred/aethelred/pkg/integrations/finance"
)

// FinanceTreasuryReleaseCollectionExportHandler exports finance workflow
// operator summaries.
func (app *AethelredApp) FinanceTreasuryReleaseCollectionExportHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeFinanceAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.financeTreasuryReleaseWorkflow == nil {
			writeFinanceAPIError(w, http.StatusServiceUnavailable, "finance treasury release workflow is unavailable")
			return
		}
		filter, err := financeReleaseListFilterFromRequest(r)
		if err != nil {
			writeFinanceAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		items, err := app.financeTreasuryReleaseWorkflow.ListReleases(r.Context(), filter)
		if err != nil {
			writeFinanceAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := writeFinanceReleaseListExport(w, r, items); err != nil {
			writeFinanceAPIError(w, http.StatusBadRequest, err.Error())
		}
	})
}

// FinanceTrustPackExportHandler exports the finance trust pack for buyer and
// operator use.
func (app *AethelredApp) FinanceTrustPackExportHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeFinanceAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.financeTreasuryReleaseWorkflow == nil {
			writeFinanceAPIError(w, http.StatusServiceUnavailable, "finance treasury release workflow is unavailable")
			return
		}
		pack, err := app.financeTreasuryReleaseWorkflow.BuildTrustPack(r.Context(), financeintegration.FinanceTrustPackOptions{
			OperatorSurfaces: financeTrustPackOperatorSurfaces(),
		})
		if err != nil {
			writeFinanceAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := writeFinanceTrustPackExport(w, r, pack); err != nil {
			writeFinanceAPIError(w, http.StatusBadRequest, err.Error())
		}
	})
}

func writeFinanceReleaseListExport(w http.ResponseWriter, r *http.Request, items []financeintegration.TreasuryReleaseSummary) error {
	switch financeExportFormat(r) {
	case "json":
		writeFinanceJSON(w, http.StatusOK, financeTreasuryReleaseListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="finance-treasury-releases.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"workflow_id",
			"status",
			"type",
			"amount",
			"currency",
			"initiator",
			"counterparty",
			"jurisdiction",
			"reason_code",
			"required_approvals",
			"current_approvals",
			"confidential_required",
			"confidential_verified",
			"settlement_ready",
			"control_ledger_id",
			"portable_package_hash",
			"created_at",
			"updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.WorkflowID,
				string(item.Status),
				string(item.Type),
				strconv.FormatFloat(item.Amount, 'f', -1, 64),
				item.Currency,
				item.Initiator,
				item.Counterparty,
				item.Jurisdiction,
				item.ReasonCode,
				strconv.Itoa(item.RequiredApprovals),
				strconv.Itoa(item.CurrentApprovals),
				strconv.FormatBool(item.ConfidentialRequired),
				strconv.FormatBool(item.ConfidentialVerified),
				strconv.FormatBool(item.SettlementReady),
				item.ControlLedgerID,
				item.PortablePackageHash,
				formatFinanceTime(item.CreatedAt),
				formatFinanceTime(item.UpdatedAt),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write finance release csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", financeExportFormat(r))
	}
}

func writeFinanceTrustPackExport(w http.ResponseWriter, r *http.Request, pack *financeintegration.FinanceTrustPack) error {
	switch financeExportFormat(r) {
	case "json":
		writeFinanceJSON(w, http.StatusOK, financeTrustPackResponse{Pack: pack})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="finance-trust-pack.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"row_type",
			"id",
			"name",
			"detail_1",
			"detail_2",
			"detail_3",
			"detail_4",
			"detail_5",
		}}
		if pack != nil {
			rows = append(rows, []string{"pack", pack.ID, pack.Name, pack.Version, pack.Sector, formatFinanceTime(pack.GeneratedAt), pack.Workflow.PolicySetID, pack.Workflow.Framework})
			rows = append(rows, []string{"workflow", "thresholds", pack.Workflow.PolicySetName, formatFloat(pack.Workflow.SingleThreshold), formatFloat(pack.Workflow.DualThreshold), formatFloat(pack.Workflow.CommitteeThreshold), strconv.Itoa(pack.Workflow.RequiredCommitteeSize), strings.Join(operationTypesToStrings(pack.Workflow.SupportedOperationTypes), "|")})
			rows = append(rows, []string{"sanctions", pack.Sanctions.Provider, "", strings.Join(sanctionsListsToStrings(pack.Sanctions.DefaultLists), "|"), strconv.FormatBool(pack.Sanctions.BlockOnMatch), strconv.Itoa(pack.Sanctions.MatchThreshold), "", ""})
			rows = append(rows, []string{"settlement", pack.Settlement.ProviderID, pack.Settlement.CorridorID, pack.Settlement.Network, pack.Settlement.Method, strings.Join(pack.Settlement.AllowedJurisdictions, "|"), strings.Join(pack.Settlement.RequiredReasonCodes, "|"), formatFloat(pack.Settlement.MaxFiatAmount)})
			rows = append(rows, []string{"confidential_execution", boolString(pack.ConfidentialExecution.Required), strconv.Itoa(pack.ConfidentialExecution.MinimumValidAttestations), strings.Join(pack.ConfidentialExecution.TrustedPlatforms, "|"), strings.Join(pack.ConfidentialExecution.AllowedEnclaveIDs, "|"), strings.Join(pack.ConfidentialExecution.AllowedMeasurements, "|"), boolString(pack.ConfidentialExecution.RequireQuoteBinding), ""})
			rows = append(rows, []string{"runtime", "counts", strconv.Itoa(pack.Runtime.TotalWorkflows), strconv.Itoa(pack.Runtime.PendingWorkflows), strconv.Itoa(pack.Runtime.CompletedWorkflows), strconv.Itoa(pack.Runtime.RejectedWorkflows), strconv.Itoa(pack.Runtime.ConfidentiallyVerified), strconv.Itoa(pack.Runtime.SettledWorkflows)})
			for _, control := range pack.Controls {
				rows = append(rows, []string{"control", control.ControlID, control.ControlName, control.WorkflowStage, strings.Join(control.EvidenceTypes, "|"), control.Description, "", ""})
			}
			for _, regulator := range pack.Regulators {
				rows = append(rows, []string{"regulator", string(regulator.Regulator), regulator.ComplianceFramework, strconv.Itoa(regulator.RetentionYears), regulator.SubmissionDeadline, strings.Join(regulator.RequiredSections, "|"), "", ""})
			}
			for _, surface := range pack.OperatorSurfaces {
				rows = append(rows, []string{"operator_surface", surface.ID, surface.Method, surface.Path, strings.Join(surface.Formats, "|"), surface.Description, "", ""})
			}
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write finance trust-pack csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", financeExportFormat(r))
	}
}

func financeExportFormat(r *http.Request) string {
	if r == nil {
		return "json"
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		return "json"
	}
	return format
}

func financeReleaseListFilterFromRequest(r *http.Request) (financeintegration.TreasuryReleaseListFilter, error) {
	if r == nil {
		return financeintegration.TreasuryReleaseListFilter{}, nil
	}
	query := r.URL.Query()
	filter := financeintegration.TreasuryReleaseListFilter{
		Status:       financeintegration.TreasuryReleaseWorkflowStatus(strings.TrimSpace(query.Get("status"))),
		Jurisdiction: strings.TrimSpace(query.Get("jurisdiction")),
		Counterparty: strings.TrimSpace(query.Get("counterparty")),
		ReasonCode:   strings.TrimSpace(query.Get("reason_code")),
		Limit:        parseFinancePositiveInt(query.Get("limit")),
	}
	if raw := strings.TrimSpace(query.Get("confidential_verified")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return financeintegration.TreasuryReleaseListFilter{}, fmt.Errorf("invalid confidential_verified filter: %w", err)
		}
		filter.RequireConfidential = &value
	}
	if raw := strings.TrimSpace(query.Get("updated_after")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return financeintegration.TreasuryReleaseListFilter{}, fmt.Errorf("invalid updated_after filter: %w", err)
		}
		filter.UpdatedAfter = &parsed
	}
	if raw := strings.TrimSpace(query.Get("updated_before")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return financeintegration.TreasuryReleaseListFilter{}, fmt.Errorf("invalid updated_before filter: %w", err)
		}
		filter.UpdatedBefore = &parsed
	}
	return filter, nil
}

func financeTrustPackOperatorSurfaces() []financeintegration.FinanceOperatorSurface {
	return []financeintegration.FinanceOperatorSurface{
		{ID: "settlement_quote", Method: http.MethodPost, Path: financeTreasurySettlementQuoteRoute, Formats: []string{"json"}, Description: "Preview settlement admissibility before execution."},
		{ID: "release_create", Method: http.MethodPost, Path: financeTreasuryReleaseCollectionRoute, Formats: []string{"json"}, Description: "Start a regulated treasury release workflow."},
		{ID: "release_list", Method: http.MethodGet, Path: financeTreasuryReleaseCollectionRoute, Formats: []string{"json"}, Description: "List persisted treasury release workflows with filters."},
		{ID: "release_export", Method: http.MethodGet, Path: financeTreasuryReleaseExportRoute, Formats: []string{"json", "csv"}, Description: "Export treasury release operator summaries."},
		{ID: "release_detail", Method: http.MethodGet, Path: financeTreasuryReleaseItemPrefix + "{id}", Formats: []string{"json"}, Description: "Read the current treasury release workflow state."},
		{ID: "settlement_view", Method: http.MethodGet, Path: financeTreasuryReleaseItemPrefix + "{id}/settlement", Formats: []string{"json"}, Description: "Read settlement readiness and projection data."},
		{ID: "settlement_artifacts", Method: http.MethodGet, Path: financeTreasuryReleaseItemPrefix + "{id}/settlement/artifacts", Formats: []string{"json"}, Description: "Read settlement evidence, confidential execution, and package artifacts."},
		{ID: "release_approve", Method: http.MethodPost, Path: financeTreasuryReleaseItemPrefix + "{id}/approve", Formats: []string{"json"}, Description: "Approve a pending treasury release workflow."},
		{ID: "trust_pack", Method: http.MethodGet, Path: financeTrustPackRoute, Formats: []string{"json"}, Description: "Read the buyer-facing finance trust-pack summary."},
		{ID: "trust_pack_export", Method: http.MethodGet, Path: financeTrustPackExportRoute, Formats: []string{"json", "csv"}, Description: "Export the finance trust pack for buyers, operators, and audits."},
	}
}

func parseFinancePositiveInt(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return 0
	}
	return value
}

func formatFinanceTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func formatFloat(v float64) string {
	if v == 0 {
		return "0"
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func boolString(v bool) string {
	return strconv.FormatBool(v)
}

func operationTypesToStrings(items []financeintegration.OperationType) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(string(item)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func sanctionsListsToStrings(items []financeintegration.SanctionsList) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(string(item)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
