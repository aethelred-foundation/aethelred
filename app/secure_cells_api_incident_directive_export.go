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
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_type", "title", "priority", "status", "issuing_party", "assignee_party", "reviewer_party", "assignee_did", "reviewer_did", "due_at", "overdue", "extension_count", "pending_extension_count", "last_extension_id", "last_extension_status", "last_extension_proposed_due_at", "acknowledged_by", "completed_by", "verification_decision", "verified_by", "created_at", "updated_at"}); err != nil {
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
				strconv.Itoa(item.ExtensionCount),
				strconv.Itoa(item.PendingExtensionCount),
				item.LastExtensionID,
				string(item.LastExtensionStatus),
				secureCellCSVTime(item.LastExtensionProposedDueAt),
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
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "title", "priority", "status", "assignee_party", "reviewer_party", "pending_action", "pending_extension_id", "pending_extension_proposed_due_at", "due_at", "overdue_seconds", "updated_at"}); err != nil {
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
				item.PendingExtensionID,
				secureCellCSVTime(item.PendingExtensionProposedDueAt),
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

func writeSecureCellFederationIncidentDirectiveAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveAutomationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-automation-actions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_title", "directive_priority", "directive_status", "pending_action", "contract_id", "contract_status_before", "contract_status_after", "action", "trigger", "tier_id", "target_did", "due_at", "actor", "automated_actor", "reason", "transition_id", "occurred_at"}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.ResponseID,
				item.OrganizationID,
				item.IncidentID,
				item.DirectiveID,
				item.DirectiveTitle,
				string(item.DirectivePriority),
				string(item.DirectiveStatus),
				item.PendingAction,
				item.ContractID,
				string(item.ContractStatusBefore),
				string(item.ContractStatusAfter),
				item.Action,
				item.Trigger,
				item.TierID,
				item.TargetDID,
				secureCellCSVTime(item.DueAt),
				item.Actor,
				item.AutomatedActor,
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

func writeSecureCellFederationIncidentDirectiveExtensionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extensions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_title", "directive_status", "extension_id", "requesting_party", "reviewing_party", "requested_by", "summary", "status", "dispute_count", "pending_dispute_count", "last_dispute_id", "last_dispute_status", "current_due_at", "proposed_due_at", "decision_summary", "reviewed_by", "reviewed_at", "created_at", "updated_at"}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.ResponseID,
				item.OrganizationID,
				item.IncidentID,
				item.DirectiveID,
				item.DirectiveTitle,
				string(item.DirectiveStatus),
				item.ExtensionID,
				string(item.RequestingParty),
				string(item.ReviewingParty),
				item.RequestedBy,
				item.Summary,
				string(item.Status),
				strconv.Itoa(item.DisputeCount),
				strconv.Itoa(item.PendingDisputeCount),
				item.LastDisputeID,
				string(item.LastDisputeStatus),
				secureCellCSVTime(item.CurrentDueAt),
				secureCellCSVTime(item.ProposedDueAt),
				item.DecisionSummary,
				item.ReviewedBy,
				secureCellCSVTime(item.ReviewedAt),
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

func writeSecureCellOverdueFederationIncidentDirectiveExtensionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtension) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-overdue-federation-incident-directive-extensions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_title", "directive_status", "extension_id", "extension_status", "requesting_party", "reviewing_party", "pending_dispute_id", "pending_action", "automation_action", "overdue_reason", "tier_id", "target_did", "due_at", "review_due_at", "resolution_due_at", "overdue_seconds", "updated_at"}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.ResponseID,
				item.OrganizationID,
				item.IncidentID,
				item.DirectiveID,
				item.DirectiveTitle,
				string(item.DirectiveStatus),
				item.ExtensionID,
				string(item.ExtensionStatus),
				string(item.RequestingParty),
				string(item.ReviewingParty),
				item.PendingDisputeID,
				item.PendingAction,
				item.AutomationAction,
				item.OverdueReason,
				item.TierID,
				item.TargetDID,
				item.DueAt.UTC().Format(timeCSVFormat),
				secureCellCSVTime(item.ReviewDueAt),
				secureCellCSVTime(item.ResolutionDueAt),
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

func writeSecureCellFederationIncidentDirectiveExtensionDisputeExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDisputeSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionDisputeListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-disputes.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_title", "directive_status", "extension_id", "extension_status", "dispute_id", "challenging_party", "responding_party", "challenged_status", "disputed_by", "summary", "status", "resolution", "resolution_summary", "resolved_by", "resolved_at", "created_at", "updated_at"}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.ResponseID,
				item.OrganizationID,
				item.IncidentID,
				item.DirectiveID,
				item.DirectiveTitle,
				string(item.DirectiveStatus),
				item.ExtensionID,
				string(item.ExtensionStatus),
				item.DisputeID,
				string(item.ChallengingParty),
				string(item.RespondingParty),
				string(item.ChallengedStatus),
				item.DisputedBy,
				item.Summary,
				string(item.Status),
				string(item.Resolution),
				item.ResolutionSummary,
				item.ResolvedBy,
				secureCellCSVTime(item.ResolvedAt),
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

func writeSecureCellFederationIncidentDirectiveExtensionAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAutomationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-automation-actions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_title", "directive_status", "extension_id", "extension_status", "pending_dispute_id", "pending_action", "contract_id", "contract_status_before", "contract_status_after", "action", "trigger", "tier_id", "target_did", "due_at", "actor", "automated_actor", "reason", "transition_id", "occurred_at"}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.ResponseID,
				item.OrganizationID,
				item.IncidentID,
				item.DirectiveID,
				item.DirectiveTitle,
				string(item.DirectiveStatus),
				item.ExtensionID,
				string(item.ExtensionStatus),
				item.PendingDisputeID,
				item.PendingAction,
				item.ContractID,
				string(item.ContractStatusBefore),
				string(item.ContractStatusAfter),
				item.Action,
				item.Trigger,
				item.TierID,
				item.TargetDID,
				secureCellCSVTime(item.DueAt),
				item.Actor,
				item.AutomatedActor,
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

func writeSecureCellFederationIncidentDirectiveBundleExport(w http.ResponseWriter, r *http.Request, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveBundleResponse{Result: bundle})
		return nil
	case "csv":
		if bundle == nil {
			return fmt.Errorf("federation incident directive bundle is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-bundle.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"id", "version", "name", "generated_at", "expires_at", "cell_id", "cell_name", "cell_status", "jurisdiction", "framework",
			"organization_id", "sponsor_of_record", "organization_name", "organization_status", "response_id", "response_status", "response_source_type",
			"incident_id", "incident_status", "incident_severity", "incident_category", "directive_id", "directive_type", "directive_title", "directive_priority",
			"directive_status", "issuing_party", "assignee_party", "reviewer_party", "directive_due_at", "directive_extension_count", "directive_pending_extension_count", "directive_last_extension_id", "directive_last_extension_status", "directive_last_extension_proposed_due_at", "response_bundle_hash", "contract_ids", "control_ids",
			"operator_surface_ids", "operator_surface_paths", "control_ledger_id", "control_ledger_hash", "portable_package_hash", "portable_package_signed",
			"portable_package_anchored", "content_hash", "signature_algorithm", "signature_signer", "signature_key_id", "signature_signed_at", "metadata",
		}); err != nil {
			return err
		}
		signatureAlgorithm := ""
		signatureSigner := ""
		signatureKeyID := ""
		signatureSignedAt := ""
		if bundle.Signature != nil {
			signatureAlgorithm = bundle.Signature.Algorithm
			signatureSigner = bundle.Signature.Signer
			signatureKeyID = bundle.Signature.KeyID
			signatureSignedAt = bundle.Signature.SignedAt.UTC().Format(timeCSVFormat)
		}
		if err := cw.Write([]string{
			bundle.ID,
			bundle.Version,
			bundle.Name,
			bundle.GeneratedAt.UTC().Format(timeCSVFormat),
			secureCellCSVTime(bundle.ExpiresAt),
			bundle.CellID,
			bundle.CellName,
			string(bundle.CellStatus),
			bundle.Jurisdiction,
			bundle.Framework,
			bundle.Organization.OrganizationID,
			bundle.Organization.SponsorOfRecord,
			bundle.Organization.OrganizationName,
			string(bundle.Organization.Status),
			bundle.ResponseSummary.ResponseID,
			string(bundle.ResponseSummary.Status),
			string(bundle.ResponseSummary.SourceType),
			bundle.ResponseSummary.IncidentID,
			string(bundle.ResponseSummary.IncidentStatus),
			string(bundle.ResponseSummary.IncidentSeverity),
			string(bundle.ResponseSummary.IncidentCategory),
			bundle.DirectiveSummary.DirectiveID,
			bundle.DirectiveSummary.DirectiveType,
			bundle.DirectiveSummary.Title,
			string(bundle.DirectiveSummary.Priority),
			string(bundle.DirectiveSummary.Status),
			string(bundle.DirectiveSummary.IssuingParty),
			string(bundle.DirectiveSummary.AssigneeParty),
			string(bundle.DirectiveSummary.ReviewerParty),
			secureCellCSVTime(bundle.DirectiveSummary.DueAt),
			strconv.Itoa(bundle.DirectiveSummary.ExtensionCount),
			strconv.Itoa(bundle.DirectiveSummary.PendingExtensionCount),
			bundle.DirectiveSummary.LastExtensionID,
			string(bundle.DirectiveSummary.LastExtensionStatus),
			secureCellCSVTime(bundle.DirectiveSummary.LastExtensionProposedDueAt),
			bundle.ResponseBundleHash,
			joinSecureCellFederationContractIDs(bundle.Contracts),
			joinSecureCellFederationControlIDs(bundle.Controls),
			joinSecureCellFederationOperatorSurfaceIDs(bundle.OperatorSurfaces),
			joinSecureCellFederationOperatorSurfacePaths(bundle.OperatorSurfaces),
			bundle.ControlLedgerID,
			bundle.ControlLedgerHash,
			bundle.PortablePackageHash,
			strconv.FormatBool(bundle.PortablePackageSigned),
			strconv.FormatBool(bundle.PortablePackageAnchored),
			bundle.ContentHash,
			signatureAlgorithm,
			signatureSigner,
			signatureKeyID,
			signatureSignedAt,
			formatSecureCellStringMap(bundle.Metadata),
		}); err != nil {
			return err
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
