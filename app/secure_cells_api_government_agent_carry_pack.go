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

type secureCellGovernmentAgentCarryPackResponse struct {
	CarryPack *securecellsintegration.SecureCellGovernmentAgentCarryPack `json:"carry_pack,omitempty"`
}

type secureCellGovernmentAgentCarryPackListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentCarryPack `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentCarryPackGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-carry-packs" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentCarryPacks(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentCarryPackListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-carry-packs/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentCarryPacks(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentCarryPackExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-carry-pack") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-carry-pack")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		carryPack, err := app.secureCellService.GetGovernmentAgentCarryPack(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentCarryPackResponse{CarryPack: carryPack})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentCarryPackExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentCarryPack) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentCarryPackListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-carry-packs.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentCarryPackCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-carry-pack csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentCarryPackCSVRows(items []securecellsintegration.SecureCellGovernmentAgentCarryPack) [][]string {
	rows := [][]string{{
		"carry_pack_id",
		"cell_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"carry_mode",
		"program_stage",
		"readiness_level",
		"ready_for_agent_carry",
		"ready_for_autonomous_carry",
		"overall_score",
		"blueprint_coverage_score",
		"step_count",
		"blocked_step_count",
		"human_approval_step_count",
		"automatable_step_count",
		"evidence_bound_step_count",
		"sla_protected_step_count",
		"top_blocker_codes",
		"preconditions",
		"required_evidence",
		"step_sequence",
		"step_id",
		"step_kind",
		"step_lane",
		"step_name",
		"step_action",
		"step_blocked",
		"step_blocker_codes",
		"step_requires_human_approval",
		"step_automatable",
		"step_due_at",
		"step_required_evidence",
		"workflow_digest",
		"carry_pack_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Steps) == 0 {
			rows = append(rows, secureCellGovernmentAgentCarryPackCSVRow(item, nil))
			continue
		}
		for idx := range item.Steps {
			rows = append(rows, secureCellGovernmentAgentCarryPackCSVRow(item, &item.Steps[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentCarryPackCSVRow(item securecellsintegration.SecureCellGovernmentAgentCarryPack, step *securecellsintegration.SecureCellGovernmentAgentCarryPackStep) []string {
	stepSequence := ""
	stepID := ""
	stepKind := ""
	stepLane := ""
	stepName := ""
	stepAction := ""
	stepBlocked := ""
	stepBlockers := ""
	stepRequiresHumanApproval := ""
	stepAutomatable := ""
	stepDueAt := ""
	stepRequiredEvidence := ""
	if step != nil {
		stepSequence = strconv.Itoa(step.Sequence)
		stepID = step.StepID
		stepKind = string(step.Kind)
		stepLane = string(step.Lane)
		stepName = step.Name
		stepAction = step.Action
		stepBlocked = strconv.FormatBool(step.Blocked)
		stepBlockers = strings.Join(step.BlockerCodes, "|")
		stepRequiresHumanApproval = strconv.FormatBool(step.RequiresHumanApproval)
		stepAutomatable = strconv.FormatBool(step.Automatable)
		if step.DueAt != nil {
			stepDueAt = step.DueAt.UTC().Format(time.RFC3339Nano)
		}
		stepRequiredEvidence = strings.Join(step.RequiredEvidence, "|")
	}
	return []string{
		item.CarryPackID,
		item.CellID,
		item.Name,
		item.Jurisdiction,
		item.ServiceCode,
		item.ServiceTier,
		string(item.CarryMode),
		string(item.ProgramStage),
		string(item.ReadinessLevel),
		strconv.FormatBool(item.ReadyForAgentCarry),
		strconv.FormatBool(item.ReadyForAutonomousCarry),
		strconv.Itoa(item.OverallScore),
		strconv.Itoa(item.BlueprintCoverageScore),
		strconv.Itoa(item.StepCount),
		strconv.Itoa(item.BlockedStepCount),
		strconv.Itoa(item.HumanApprovalStepCount),
		strconv.Itoa(item.AutomatableStepCount),
		strconv.Itoa(item.EvidenceBoundStepCount),
		strconv.Itoa(item.SLAProtectedStepCount),
		strings.Join(item.TopBlockerCodes, "|"),
		strings.Join(item.Preconditions, "|"),
		strings.Join(item.RequiredEvidence, "|"),
		stepSequence,
		stepID,
		stepKind,
		stepLane,
		stepName,
		stepAction,
		stepBlocked,
		stepBlockers,
		stepRequiresHumanApproval,
		stepAutomatable,
		stepDueAt,
		stepRequiredEvidence,
		item.WorkflowDigest,
		item.CarryPackDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
