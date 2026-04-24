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

type secureCellGovernmentAgentProgramResponse struct {
	Summary *securecellsintegration.SecureCellGovernmentAgentProgramSummary `json:"summary,omitempty"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentProgramGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-program" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		summary, err := app.secureCellService.GetGovernmentAgentProgramSummary(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentProgramResponse{Summary: summary})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-program/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		summary, err := app.secureCellService.GetGovernmentAgentProgramSummary(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentProgramExport(w, r, summary); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func parseSecureCellGovernmentAgentProgramFilter(r *http.Request) (securecellsintegration.SecureCellGovernmentAgentProgramFilter, error) {
	readinessFilter, err := parseSecureCellGovernmentAgentReadinessFilter(r)
	if err != nil {
		return securecellsintegration.SecureCellGovernmentAgentProgramFilter{}, err
	}
	query := r.URL.Query()
	return securecellsintegration.SecureCellGovernmentAgentProgramFilter{
		CellID:              readinessFilter.CellID,
		Jurisdiction:        readinessFilter.Jurisdiction,
		ServiceCode:         strings.TrimSpace(query.Get("service_code")),
		ServiceTier:         strings.TrimSpace(query.Get("service_tier")),
		ReadinessLevel:      readinessFilter.ReadinessLevel,
		MinimumOverallScore: readinessFilter.MinimumOverallScore,
		Limit:               readinessFilter.Limit,
	}, nil
}

func writeSecureCellGovernmentAgentProgramExport(w http.ResponseWriter, r *http.Request, summary *securecellsintegration.SecureCellGovernmentAgentProgramSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentProgramResponse{Summary: summary})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-program.csv"`)
		writer := csv.NewWriter(w)
		rows := secureCellGovernmentAgentProgramCSVRows(summary)
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-program csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentProgramCSVRows(summary *securecellsintegration.SecureCellGovernmentAgentProgramSummary) [][]string {
	rows := [][]string{{
		"program_id",
		"jurisdiction",
		"service_code_filter",
		"service_tier_filter",
		"service_count",
		"legible_service_count",
		"evidence_ready_service_count",
		"sla_ready_service_count",
		"identity_ready_service_count",
		"localization_ready_service_count",
		"blocked_count",
		"foundation_ready_count",
		"supervised_ready_count",
		"autonomy_ready_count",
		"average_overall_score",
		"average_blueprint_coverage_score",
		"legibility_rate",
		"supervised_ready_rate",
		"autonomy_ready_rate",
		"critical_finding_count",
		"warning_finding_count",
		"top_blocker_codes",
		"service_cell_id",
		"service_name",
		"service_code",
		"service_tier",
		"service_readiness_level",
		"service_recommended_stage",
		"service_overall_score",
		"service_blueprint_coverage_score",
		"service_legible_for_agent",
		"service_evidence_ready",
		"service_sla_ready",
		"service_identity_ready",
		"service_localization_ready",
		"service_critical_findings",
		"service_warning_findings",
		"service_workflow_digest",
		"program_digest",
		"generated_at",
	}}
	if summary == nil {
		return rows
	}
	topBlockers := secureCellGovernmentAgentProgramBlockerCodes(summary.TopBlockers)
	if len(summary.Services) == 0 {
		rows = append(rows, secureCellGovernmentAgentProgramSummaryCSVPrefix(summary, topBlockers, "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""))
		return rows
	}
	for _, service := range summary.Services {
		rows = append(rows, secureCellGovernmentAgentProgramSummaryCSVPrefix(
			summary,
			topBlockers,
			service.CellID,
			service.Name,
			service.ServiceCode,
			service.ServiceTier,
			string(service.ReadinessLevel),
			string(service.RecommendedStage),
			strconv.Itoa(service.OverallScore),
			strconv.Itoa(service.BlueprintCoverageScore),
			strconv.FormatBool(service.LegibleForAgent),
			strconv.FormatBool(service.EvidenceReady),
			strconv.FormatBool(service.SLAReady),
			strconv.FormatBool(service.IdentityReady),
			strconv.FormatBool(service.LocalizationReady),
			strconv.Itoa(service.CriticalFindingCount),
			strconv.Itoa(service.WarningFindingCount),
			service.WorkflowDigest,
		))
	}
	return rows
}

func secureCellGovernmentAgentProgramSummaryCSVPrefix(
	summary *securecellsintegration.SecureCellGovernmentAgentProgramSummary,
	topBlockers string,
	serviceCellID string,
	serviceName string,
	serviceCode string,
	serviceTier string,
	serviceReadinessLevel string,
	serviceRecommendedStage string,
	serviceOverallScore string,
	serviceBlueprintCoverageScore string,
	serviceLegibleForAgent string,
	serviceEvidenceReady string,
	serviceSLAReady string,
	serviceIdentityReady string,
	serviceLocalizationReady string,
	serviceCriticalFindings string,
	serviceWarningFindings string,
	serviceWorkflowDigest string,
) []string {
	return []string{
		summary.ProgramID,
		summary.Jurisdiction,
		summary.ServiceCode,
		summary.ServiceTier,
		strconv.Itoa(summary.ServiceCount),
		strconv.Itoa(summary.LegibleServiceCount),
		strconv.Itoa(summary.EvidenceReadyServiceCount),
		strconv.Itoa(summary.SLAReadyServiceCount),
		strconv.Itoa(summary.IdentityReadyServiceCount),
		strconv.Itoa(summary.LocalizationReadyServiceCount),
		strconv.Itoa(summary.BlockedCount),
		strconv.Itoa(summary.FoundationReadyCount),
		strconv.Itoa(summary.SupervisedReadyCount),
		strconv.Itoa(summary.AutonomyReadyCount),
		strconv.Itoa(summary.AverageOverallScore),
		strconv.Itoa(summary.AverageBlueprintCoverageScore),
		strconv.Itoa(summary.LegibilityRate),
		strconv.Itoa(summary.SupervisedReadyRate),
		strconv.Itoa(summary.AutonomyReadyRate),
		strconv.Itoa(summary.CriticalFindingCount),
		strconv.Itoa(summary.WarningFindingCount),
		topBlockers,
		serviceCellID,
		serviceName,
		serviceCode,
		serviceTier,
		serviceReadinessLevel,
		serviceRecommendedStage,
		serviceOverallScore,
		serviceBlueprintCoverageScore,
		serviceLegibleForAgent,
		serviceEvidenceReady,
		serviceSLAReady,
		serviceIdentityReady,
		serviceLocalizationReady,
		serviceCriticalFindings,
		serviceWarningFindings,
		serviceWorkflowDigest,
		summary.ProgramDigest,
		summary.GeneratedAt.UTC().Format(time.RFC3339Nano),
	}
}

func secureCellGovernmentAgentProgramBlockerCodes(blockers []securecellsintegration.SecureCellGovernmentAgentProgramBlocker) string {
	codes := make([]string, 0, len(blockers))
	for _, blocker := range blockers {
		if strings.TrimSpace(blocker.Code) != "" {
			codes = append(codes, blocker.Code)
		}
	}
	return strings.Join(codes, "|")
}
