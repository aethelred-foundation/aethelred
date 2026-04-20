package app

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
)

func writeSecureCellFederationIncidentDirectiveExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directives.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_type", "title", "priority", "status", "issuing_party", "assignee_party", "reviewer_party", "assignee_did", "reviewer_did", "due_at", "overdue", "acknowledged_by", "completed_by", "verification_decision", "verified_by", "created_at", "updated_at"}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.ResponseID,
				item.OrganizationID,
				item.IncidentID,
				item.DirectiveID,
				item.DirectiveType,
				item.Title,
				string(item.Priority),
				string(item.Status),
				string(item.IssuingParty),
				string(item.AssigneeParty),
				string(item.ReviewerParty),
				item.AssigneeDID,
				item.ReviewerDID,
				secureCellCSVTime(item.DueAt),
				strconv.FormatBool(item.Overdue),
				item.AcknowledgedBy,
				item.CompletedBy,
				string(item.VerificationDecision),
				item.VerifiedBy,
				item.CreatedAt.UTC().Format(timeCSVFormat),
				item.UpdatedAt.UTC().Format(timeCSVFormat),
			}); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellOverdueFederationIncidentDirectiveExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueFederationIncidentDirective) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-overdue-federation-incident-directives.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "title", "priority", "status", "assignee_party", "reviewer_party", "pending_action", "due_at", "overdue_seconds", "updated_at"}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.ResponseID,
				item.OrganizationID,
				item.IncidentID,
				item.DirectiveID,
				item.Title,
				string(item.Priority),
				string(item.Status),
				string(item.AssigneeParty),
				string(item.ReviewerParty),
				item.PendingAction,
				item.DueAt.UTC().Format(timeCSVFormat),
				strconv.FormatInt(item.OverdueSeconds, 10),
				item.UpdatedAt.UTC().Format(timeCSVFormat),
			}); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentDirectiveActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-actions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "action", "status_before", "status_after", "actor", "reason", "transition_id", "occurred_at"}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.ResponseID,
				item.OrganizationID,
				item.IncidentID,
				item.DirectiveID,
				item.Action,
				string(item.StatusBefore),
				string(item.StatusAfter),
				item.Actor,
				item.Reason,
				item.TransitionID,
				item.OccurredAt.UTC().Format(timeCSVFormat),
			}); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellCSVTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(timeCSVFormat)
}

const timeCSVFormat = "2006-01-02T15:04:05.999999999Z07:00"
