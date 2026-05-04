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

type secureCellGovernmentAgentExecutionLaunchCustodyResponse struct {
	Custody *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCustodyRegister `json:"custody,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchCustodyListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCustodyRegister `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchCustodyGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-custodies" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchCustodies(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchCustodyListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-custodies/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchCustodies(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchCustodyExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-custody") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-custody")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		custody, err := app.secureCellService.GetGovernmentAgentExecutionLaunchCustody(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchCustodyResponse{Custody: custody})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchCustodyExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCustodyRegister) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchCustodyListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-custodies.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchCustodyCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-custody csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchCustodyCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCustodyRegister) [][]string {
	rows := [][]string{{
		"custody_id",
		"package_id",
		"cell_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"package_status",
		"can_issue_now",
		"can_issue_after_operator_receipts",
		"can_issue_autonomous",
		"lease_minutes",
		"activation_window_starts_at",
		"activation_window_expires_at",
		"custody_action_count",
		"satisfied_action_count",
		"ready_action_count",
		"pending_action_count",
		"blocked_action_count",
		"required_receipt_types",
		"operator_instructions",
		"package_digest",
		"launch_digest",
		"receipt_manifest_digest",
		"receipt_validation_digest",
		"action_id",
		"action_type",
		"action_status",
		"action_actor_role",
		"action_required_receipt_type",
		"action_evidence_digest",
		"action_due_at",
		"action_digest",
		"custody_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Actions) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchCustodyCSVRow(item, nil))
			continue
		}
		for idx := range item.Actions {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchCustodyCSVRow(item, &item.Actions[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchCustodyCSVRow(
	item securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCustodyRegister,
	action *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCustodyAction,
) []string {
	actionID := ""
	actionType := ""
	actionStatus := ""
	actionActorRole := ""
	actionRequiredReceiptType := ""
	actionEvidenceDigest := ""
	actionDueAt := ""
	actionDigest := ""
	if action != nil {
		actionID = action.ActionID
		actionType = action.ActionType
		actionStatus = string(action.Status)
		actionActorRole = action.ActorRole
		actionRequiredReceiptType = action.RequiredReceiptType
		actionEvidenceDigest = action.EvidenceDigest
		actionDueAt = secureCellGovernmentAgentExecutionLaunchCustodyTime(action.DueAt)
		actionDigest = action.ActionDigest
	}
	return []string{
		item.CustodyID,
		item.PackageID,
		item.CellID,
		item.Name,
		item.Jurisdiction,
		item.ServiceCode,
		item.ServiceTier,
		string(item.Status),
		string(item.PackageStatus),
		strconv.FormatBool(item.CanIssueNow),
		strconv.FormatBool(item.CanIssueAfterOperatorReceipts),
		strconv.FormatBool(item.CanIssueAutonomous),
		strconv.Itoa(item.LeaseMinutes),
		item.ActivationWindowStartsAt.UTC().Format(time.RFC3339Nano),
		item.ActivationWindowExpiresAt.UTC().Format(time.RFC3339Nano),
		strconv.Itoa(item.CustodyActionCount),
		strconv.Itoa(item.SatisfiedActionCount),
		strconv.Itoa(item.ReadyActionCount),
		strconv.Itoa(item.PendingActionCount),
		strconv.Itoa(item.BlockedActionCount),
		strings.Join(item.RequiredReceiptTypes, "|"),
		strings.Join(item.OperatorInstructions, "|"),
		item.PackageDigest,
		item.LaunchDigest,
		item.ReceiptManifestDigest,
		item.ReceiptValidationDigest,
		actionID,
		actionType,
		actionStatus,
		actionActorRole,
		actionRequiredReceiptType,
		actionEvidenceDigest,
		actionDueAt,
		actionDigest,
		item.CustodyDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func secureCellGovernmentAgentExecutionLaunchCustodyTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
