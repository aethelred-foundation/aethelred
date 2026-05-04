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

type secureCellGovernmentAgentRehearsalResponse struct {
	Report *securecellsintegration.SecureCellGovernmentAgentRehearsalReport `json:"report,omitempty"`
}

type secureCellGovernmentAgentRehearsalListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentRehearsalReport `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentRehearsalGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-rehearsals" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentRehearsalReports(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentRehearsalListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-rehearsals/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentRehearsalReports(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentRehearsalExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-rehearsal") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-rehearsal")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		report, err := app.secureCellService.GetGovernmentAgentRehearsalReport(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentRehearsalResponse{Report: report})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentRehearsalExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentRehearsalReport) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentRehearsalListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-rehearsals.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentRehearsalCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-rehearsal csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentRehearsalCSVRows(items []securecellsintegration.SecureCellGovernmentAgentRehearsalReport) [][]string {
	rows := [][]string{{
		"rehearsal_id",
		"cell_id",
		"carry_pack_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"carry_mode",
		"program_stage",
		"ready_for_agent_carry",
		"ready_for_autonomous_carry",
		"rehearsal_score",
		"step_count",
		"pass_step_count",
		"warn_step_count",
		"block_step_count",
		"missing_preconditions",
		"top_blocker_codes",
		"operator_instructions",
		"step_sequence",
		"step_id",
		"step_kind",
		"step_lane",
		"step_name",
		"step_outcome",
		"step_can_execute",
		"step_requires_operator",
		"step_requires_approval",
		"step_checks",
		"step_due_at",
		"rehearsal_digest",
		"carry_pack_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Steps) == 0 {
			rows = append(rows, secureCellGovernmentAgentRehearsalCSVRow(item, nil))
			continue
		}
		for idx := range item.Steps {
			rows = append(rows, secureCellGovernmentAgentRehearsalCSVRow(item, &item.Steps[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentRehearsalCSVRow(item securecellsintegration.SecureCellGovernmentAgentRehearsalReport, step *securecellsintegration.SecureCellGovernmentAgentRehearsalStep) []string {
	stepSequence := ""
	stepID := ""
	stepKind := ""
	stepLane := ""
	stepName := ""
	stepOutcome := ""
	stepCanExecute := ""
	stepRequiresOperator := ""
	stepRequiresApproval := ""
	stepChecks := ""
	stepDueAt := ""
	if step != nil {
		stepSequence = strconv.Itoa(step.Sequence)
		stepID = step.StepID
		stepKind = string(step.Kind)
		stepLane = string(step.Lane)
		stepName = step.Name
		stepOutcome = string(step.Outcome)
		stepCanExecute = strconv.FormatBool(step.CanExecute)
		stepRequiresOperator = strconv.FormatBool(step.RequiresOperator)
		stepRequiresApproval = strconv.FormatBool(step.RequiresApproval)
		stepChecks = secureCellGovernmentAgentRehearsalCheckCodes(step.Checks)
		if step.DueAt != nil {
			stepDueAt = step.DueAt.UTC().Format(time.RFC3339Nano)
		}
	}
	return []string{
		item.RehearsalID,
		item.CellID,
		item.CarryPackID,
		item.Name,
		item.Jurisdiction,
		item.ServiceCode,
		item.ServiceTier,
		string(item.Status),
		string(item.CarryMode),
		string(item.ProgramStage),
		strconv.FormatBool(item.ReadyForAgentCarry),
		strconv.FormatBool(item.ReadyForAutonomousCarry),
		strconv.Itoa(item.RehearsalScore),
		strconv.Itoa(item.StepCount),
		strconv.Itoa(item.PassStepCount),
		strconv.Itoa(item.WarnStepCount),
		strconv.Itoa(item.BlockStepCount),
		strings.Join(item.MissingPreconditions, "|"),
		strings.Join(item.TopBlockerCodes, "|"),
		strings.Join(item.OperatorInstructions, "|"),
		stepSequence,
		stepID,
		stepKind,
		stepLane,
		stepName,
		stepOutcome,
		stepCanExecute,
		stepRequiresOperator,
		stepRequiresApproval,
		stepChecks,
		stepDueAt,
		item.RehearsalDigest,
		item.CarryPackDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func secureCellGovernmentAgentRehearsalCheckCodes(checks []securecellsintegration.SecureCellGovernmentAgentRehearsalCheck) string {
	items := make([]string, 0, len(checks))
	for _, check := range checks {
		if strings.TrimSpace(check.Code) != "" {
			items = append(items, check.Code+":"+string(check.Outcome))
		}
	}
	return strings.Join(items, "|")
}
