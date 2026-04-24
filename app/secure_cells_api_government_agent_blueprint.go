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

type secureCellGovernmentAgentWorkflowBlueprintResponse struct {
	Blueprint *securecellsintegration.SecureCellGovernmentAgentWorkflowBlueprint `json:"blueprint,omitempty"`
}

type secureCellGovernmentAgentWorkflowBlueprintListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentWorkflowBlueprint `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentBlueprintGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-blueprints" {
		filter, err := parseSecureCellGovernmentAgentReadinessFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentWorkflowBlueprints(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentWorkflowBlueprintListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-blueprints/export" {
		filter, err := parseSecureCellGovernmentAgentReadinessFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentWorkflowBlueprints(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentBlueprintExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-blueprint") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-blueprint")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		blueprint, err := app.secureCellService.GetGovernmentAgentWorkflowBlueprint(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentWorkflowBlueprintResponse{Blueprint: blueprint})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentBlueprintExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentWorkflowBlueprint) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentWorkflowBlueprintListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-blueprints.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"blueprint_id",
			"cell_id",
			"name",
			"jurisdiction",
			"readiness_level",
			"coverage_score",
			"service_code",
			"service_tier",
			"step_count",
			"operator_declared_steps",
			"evidence_bound_steps",
			"human_approval_gate_count",
			"sla_protected_step_count",
			"escalation_step_count",
			"automatable_step_count",
			"critical_gap_count",
			"warning_gap_count",
			"workflow_digest",
			"generated_at",
			"updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.BlueprintID,
				item.CellID,
				item.Name,
				item.Jurisdiction,
				string(item.ReadinessLevel),
				strconv.Itoa(item.CoverageScore),
				item.ServiceCode,
				item.ServiceTier,
				strconv.Itoa(item.StepCount),
				strconv.Itoa(item.OperatorDeclaredSteps),
				strconv.Itoa(item.EvidenceBoundSteps),
				strconv.Itoa(item.HumanApprovalGateCount),
				strconv.Itoa(item.SLAProtectedStepCount),
				strconv.Itoa(item.EscalationStepCount),
				strconv.Itoa(item.AutomatableStepCount),
				strconv.Itoa(item.CriticalGapCount),
				strconv.Itoa(item.WarningGapCount),
				item.WorkflowDigest,
				item.GeneratedAt.UTC().Format(time.RFC3339Nano),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-blueprint csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}
