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

type secureCellGovernmentAgentReadinessResponse struct {
	Assessment *securecellsintegration.SecureCellGovernmentAgentReadinessAssessment `json:"assessment,omitempty"`
}

type secureCellGovernmentAgentReadinessListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentReadinessAssessment `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentReadinessGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-readiness" {
		filter, err := parseSecureCellGovernmentAgentReadinessFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentReadinessAssessments(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentReadinessListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-readiness/export" {
		filter, err := parseSecureCellGovernmentAgentReadinessFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentReadinessAssessments(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentReadinessExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-readiness") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-readiness")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		assessment, err := app.secureCellService.GetGovernmentAgentReadinessAssessment(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentReadinessResponse{Assessment: assessment})
		return true
	}

	return false
}

func parseSecureCellGovernmentAgentReadinessFilter(r *http.Request) (securecellsintegration.SecureCellGovernmentAgentReadinessFilter, error) {
	query := r.URL.Query()
	filter := securecellsintegration.SecureCellGovernmentAgentReadinessFilter{
		CellID:       strings.TrimSpace(query.Get("cell_id")),
		Jurisdiction: strings.TrimSpace(query.Get("jurisdiction")),
	}
	if raw := strings.TrimSpace(query.Get("readiness_level")); raw != "" {
		level, err := parseSecureCellGovernmentAgentReadinessLevel(raw)
		if err != nil {
			return filter, err
		}
		filter.ReadinessLevel = level
	}
	if raw := strings.TrimSpace(query.Get("min_score")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 || value > 100 {
			return filter, fmt.Errorf("invalid government agent readiness min_score %q", raw)
		}
		filter.MinimumOverallScore = value
	}
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return filter, fmt.Errorf("invalid government agent readiness limit %q", raw)
		}
		filter.Limit = value
	}
	return filter, nil
}

func parseSecureCellGovernmentAgentReadinessLevel(raw string) (securecellsintegration.SecureCellGovernmentAgentReadinessLevel, error) {
	switch level := securecellsintegration.SecureCellGovernmentAgentReadinessLevel(strings.TrimSpace(raw)); level {
	case "",
		securecellsintegration.SecureCellGovernmentAgentReadinessBlocked,
		securecellsintegration.SecureCellGovernmentAgentReadinessFoundationReady,
		securecellsintegration.SecureCellGovernmentAgentReadinessSupervisedReady,
		securecellsintegration.SecureCellGovernmentAgentReadinessAutonomyReady:
		return level, nil
	default:
		return "", fmt.Errorf("invalid government agent readiness level %q", raw)
	}
}

func writeSecureCellGovernmentAgentReadinessExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentReadinessAssessment) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentReadinessListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-readiness.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"assessment_id",
			"cell_id",
			"name",
			"jurisdiction",
			"cell_status",
			"readiness_level",
			"ready_for_supervised_run",
			"ready_for_autonomous_run",
			"service_code",
			"service_tier",
			"overall_score",
			"workflow_legibility_score",
			"evidence_readiness_score",
			"authority_controls_score",
			"integration_readiness_score",
			"sla_automation_score",
			"human_oversight_score",
			"localization_readiness_score",
			"decision_count",
			"timed_decision_count",
			"approval_gate_count",
			"escalation_ladder_count",
			"automation_action_count",
			"evidence_transition_count",
			"policy_receipt_chain_hash",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"critical_findings",
			"warning_findings",
			"workflow_digest",
			"assessed_at",
			"updated_at",
		}}
		for _, item := range items {
			critical, warning := secureCellGovernmentAgentReadinessFindingCounts(item.Findings)
			rows = append(rows, []string{
				item.AssessmentID,
				item.CellID,
				item.Name,
				item.Jurisdiction,
				string(item.CellStatus),
				string(item.ReadinessLevel),
				strconv.FormatBool(item.ReadyForSupervisedRun),
				strconv.FormatBool(item.ReadyForAutonomousRun),
				item.ServiceCode,
				item.ServiceTier,
				strconv.Itoa(item.Scorecard.Overall),
				strconv.Itoa(item.Scorecard.WorkflowLegibility),
				strconv.Itoa(item.Scorecard.EvidenceReadiness),
				strconv.Itoa(item.Scorecard.AuthorityControls),
				strconv.Itoa(item.Scorecard.IntegrationReadiness),
				strconv.Itoa(item.Scorecard.SLAAutomation),
				strconv.Itoa(item.Scorecard.HumanOversight),
				strconv.Itoa(item.Scorecard.LocalizationReadiness),
				strconv.Itoa(item.Signals.DecisionCount),
				strconv.Itoa(item.Signals.TimedDecisionCount),
				strconv.Itoa(item.Signals.ApprovalGateCount),
				strconv.Itoa(item.Signals.EscalationLadderCount),
				strconv.Itoa(item.Signals.AutomationActionCount),
				strconv.Itoa(item.Signals.EvidenceTransitionCount),
				item.Evidence.PolicyReceiptChainHash,
				item.Evidence.ControlLedgerHash,
				item.Evidence.PortablePackageHash,
				strconv.FormatBool(item.Evidence.PortablePackageSigned),
				strconv.FormatBool(item.Evidence.PortablePackageAnchored),
				strconv.Itoa(critical),
				strconv.Itoa(warning),
				item.WorkflowDigest,
				item.AssessedAt.UTC().Format(time.RFC3339Nano),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-readiness csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentReadinessFindingCounts(findings []securecellsintegration.SecureCellGovernmentAgentReadinessFinding) (critical int, warning int) {
	for _, finding := range findings {
		switch finding.Severity {
		case securecellsintegration.SecureCellGovernmentAgentReadinessSeverityCritical:
			critical++
		case securecellsintegration.SecureCellGovernmentAgentReadinessSeverityWarning:
			warning++
		}
	}
	return critical, warning
}
