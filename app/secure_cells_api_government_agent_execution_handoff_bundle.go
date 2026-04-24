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

type secureCellGovernmentAgentExecutionHandoffBundleResponse struct {
	Bundle *securecellsintegration.SecureCellGovernmentAgentExecutionHandoffBundle `json:"bundle,omitempty"`
}

type secureCellGovernmentAgentExecutionHandoffBundleListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionHandoffBundle `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionHandoffBundleGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-handoff-bundles" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionHandoffBundles(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionHandoffBundleListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-handoff-bundles/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionHandoffBundles(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionHandoffBundleExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-handoff-bundle") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-handoff-bundle")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		bundle, err := app.secureCellService.GetGovernmentAgentExecutionHandoffBundle(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionHandoffBundleResponse{Bundle: bundle})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionHandoffBundleExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionHandoffBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionHandoffBundleListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-handoff-bundles.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionHandoffBundleCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-handoff-bundle csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionHandoffBundleCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionHandoffBundle) [][]string {
	rows := [][]string{{
		"bundle_id",
		"bundle_version",
		"cell_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"carry_mode",
		"can_handoff",
		"can_autonomous_handoff",
		"requires_operator_review",
		"blocked_action_count",
		"release_gate_action_count",
		"receipt_collection_count",
		"escalation_recommended_count",
		"receipt_obligation_count",
		"required_receipt_types",
		"top_blocker_codes",
		"missing_preconditions",
		"operator_instructions",
		"witness_id",
		"ledger_id",
		"queue_id",
		"witness_digest",
		"ledger_digest",
		"queue_digest",
		"bundle_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		rows = append(rows, []string{
			item.BundleID,
			item.BundleVersion,
			item.CellID,
			item.Name,
			item.Jurisdiction,
			item.ServiceCode,
			item.ServiceTier,
			string(item.Status),
			string(item.CarryMode),
			strconv.FormatBool(item.CanHandoff),
			strconv.FormatBool(item.CanAutonomousHandoff),
			strconv.FormatBool(item.RequiresOperatorReview),
			strconv.Itoa(item.BlockedActionCount),
			strconv.Itoa(item.ReleaseGateActionCount),
			strconv.Itoa(item.ReceiptCollectionCount),
			strconv.Itoa(item.EscalationRecommendedCount),
			strconv.Itoa(item.ReceiptObligationCount),
			strings.Join(item.RequiredReceiptTypes, "|"),
			strings.Join(item.TopBlockerCodes, "|"),
			strings.Join(item.MissingPreconditions, "|"),
			strings.Join(item.OperatorInstructions, "|"),
			item.Witness.WitnessID,
			item.ReceiptLedger.LedgerID,
			item.ActionQueue.QueueID,
			item.WitnessDigest,
			item.LedgerDigest,
			item.QueueDigest,
			item.BundleDigest,
			item.GeneratedAt.UTC().Format(time.RFC3339Nano),
			item.UpdatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}
