package app

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
)

type secureCellGovernmentAgentExecutionLaunchClosurePortfolioResponse struct {
	Portfolio *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosurePortfolio `json:"portfolio,omitempty"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosurePortfolioGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-portfolio" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		portfolio, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosurePortfolio(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosurePortfolioResponse{Portfolio: portfolio})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-portfolio/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		portfolio, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosurePortfolio(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosurePortfolioExport(w, r, portfolio); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosurePortfolioExport(w http.ResponseWriter, r *http.Request, portfolio *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosurePortfolio) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosurePortfolioResponse{Portfolio: portfolio})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-portfolio.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosurePortfolioCSVRows(portfolio) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-portfolio csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosurePortfolioCSVRows(portfolio *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosurePortfolio) [][]string {
	rows := [][]string{{
		"portfolio_id",
		"jurisdiction",
		"service_code_filter",
		"service_tier_filter",
		"cell_count",
		"blocked_count",
		"awaiting_archive_issue_count",
		"ready_to_close_count",
		"can_close_now_count",
		"can_close_after_archive_count",
		"escalation_required_count",
		"total_item_count",
		"blocked_item_count",
		"pending_item_count",
		"ready_item_count",
		"required_receipt_types",
		"primary_actions",
		"dashboard_cell_id",
		"dashboard_name",
		"dashboard_service_code",
		"dashboard_service_tier",
		"dashboard_status",
		"dashboard_primary_action",
		"dashboard_item_count",
		"dashboard_blocked_item_count",
		"dashboard_pending_item_count",
		"dashboard_ready_item_count",
		"dashboard_digest",
		"portfolio_digest",
		"generated_at",
	}}
	if portfolio == nil {
		return rows
	}
	receiptTypes := strings.Join(portfolio.RequiredReceiptTypes, "|")
	actions := secureCellGovernmentAgentExecutionLaunchClosurePortfolioActionsCSV(portfolio.PrimaryActions)
	if len(portfolio.Dashboards) == 0 {
		rows = append(rows, secureCellGovernmentAgentExecutionLaunchClosurePortfolioCSVRow(
			portfolio,
			receiptTypes,
			actions,
			"", "", "", "", "", "", "", "", "", "", "",
		))
		return rows
	}
	for _, dashboard := range portfolio.Dashboards {
		rows = append(rows, secureCellGovernmentAgentExecutionLaunchClosurePortfolioCSVRow(
			portfolio,
			receiptTypes,
			actions,
			dashboard.CellID,
			dashboard.Name,
			dashboard.ServiceCode,
			dashboard.ServiceTier,
			string(dashboard.Status),
			dashboard.PrimaryAction,
			strconv.Itoa(dashboard.ItemCount),
			strconv.Itoa(dashboard.BlockedItemCount),
			strconv.Itoa(dashboard.PendingItemCount),
			strconv.Itoa(dashboard.ReadyItemCount),
			dashboard.DashboardDigest,
		))
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchClosurePortfolioCSVRow(
	portfolio *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosurePortfolio,
	receiptTypes string,
	actions string,
	dashboardCellID string,
	dashboardName string,
	dashboardServiceCode string,
	dashboardServiceTier string,
	dashboardStatus string,
	dashboardPrimaryAction string,
	dashboardItemCount string,
	dashboardBlockedItemCount string,
	dashboardPendingItemCount string,
	dashboardReadyItemCount string,
	dashboardDigest string,
) []string {
	return []string{
		portfolio.PortfolioID,
		portfolio.Jurisdiction,
		portfolio.ServiceCode,
		portfolio.ServiceTier,
		strconv.Itoa(portfolio.CellCount),
		strconv.Itoa(portfolio.BlockedCount),
		strconv.Itoa(portfolio.AwaitingArchiveIssueCount),
		strconv.Itoa(portfolio.ReadyToCloseCount),
		strconv.Itoa(portfolio.CanCloseNowCount),
		strconv.Itoa(portfolio.CanCloseAfterArchiveCount),
		strconv.Itoa(portfolio.EscalationRequiredCount),
		strconv.Itoa(portfolio.TotalItemCount),
		strconv.Itoa(portfolio.BlockedItemCount),
		strconv.Itoa(portfolio.PendingItemCount),
		strconv.Itoa(portfolio.ReadyItemCount),
		receiptTypes,
		actions,
		dashboardCellID,
		dashboardName,
		dashboardServiceCode,
		dashboardServiceTier,
		dashboardStatus,
		dashboardPrimaryAction,
		dashboardItemCount,
		dashboardBlockedItemCount,
		dashboardPendingItemCount,
		dashboardReadyItemCount,
		dashboardDigest,
		portfolio.PortfolioDigest,
		portfolio.GeneratedAt.UTC().Format(time.RFC3339Nano),
	}
}

func secureCellGovernmentAgentExecutionLaunchClosurePortfolioActionsCSV(actions []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosurePortfolioAction) string {
	if len(actions) == 0 {
		return ""
	}
	parts := make([]string, 0, len(actions))
	for _, action := range actions {
		parts = append(parts, action.Action+":"+strconv.Itoa(action.Count))
	}
	return strings.Join(parts, "|")
}
