package app

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
)

func writeSecureCellOverdueDecisionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueDecision) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueDecisionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-overdue-decisions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"name",
			"jurisdiction",
			"cell_status",
			"session_id",
			"thread_id",
			"decision_id",
			"decision_title",
			"decision_status",
			"governance_template",
			"sla_template",
			"sector_policy_pack",
			"automation_action",
			"overdue_reason",
			"tier_id",
			"target_did",
			"due_at",
			"overdue_seconds",
			"escalation_due_at",
			"resolution_due_at",
			"updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.Name,
				item.Jurisdiction,
				string(item.CellStatus),
				item.SessionID,
				item.ThreadID,
				item.DecisionID,
				item.DecisionTitle,
				string(item.DecisionStatus),
				item.GovernanceTemplate,
				item.SLATemplate,
				item.SectorPolicyPack,
				item.AutomationAction,
				item.OverdueReason,
				item.TierID,
				item.TargetDID,
				item.DueAt.UTC().Format(time.RFC3339Nano),
				strconv.FormatInt(item.OverdueSeconds, 10),
				formatSecureCellOptionalTime(item.EscalationDueAt),
				formatSecureCellOptionalTime(item.ResolutionDueAt),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write overdue-decision csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellDecisionAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellDecisionAutomationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellDecisionAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-decision-automation-actions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"name",
			"jurisdiction",
			"cell_status",
			"session_id",
			"thread_id",
			"decision_id",
			"decision_title",
			"governance_template",
			"sla_template",
			"sector_policy_pack",
			"decision_status_before",
			"decision_status_after",
			"action",
			"tier_id",
			"target_did",
			"trigger",
			"due_at",
			"actor",
			"automated_actor",
			"reason",
			"transition_id",
			"occurred_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.Name,
				item.Jurisdiction,
				string(item.CellStatus),
				item.SessionID,
				item.ThreadID,
				item.DecisionID,
				item.DecisionTitle,
				item.GovernanceTemplate,
				item.SLATemplate,
				item.SectorPolicyPack,
				string(item.DecisionStatusBefore),
				string(item.DecisionStatusAfter),
				item.Action,
				item.TierID,
				item.TargetDID,
				item.Trigger,
				formatSecureCellOptionalTime(item.DueAt),
				item.Actor,
				item.AutomatedActor,
				item.Reason,
				item.TransitionID,
				item.OccurredAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write decision-automation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellOverdueFederationCounterproposalExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueFederationCounterproposal) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationCounterproposalListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-overdue-counterproposals.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"invitation_id",
			"counterproposal_id",
			"status",
			"governance_template",
			"automation_action",
			"overdue_reason",
			"tier_id",
			"target_did",
			"due_at",
			"overdue_seconds",
			"resolution_due_at",
			"auto_suspend_on_overdue",
			"updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.InvitationID,
				item.CounterproposalID,
				string(item.Status),
				item.GovernanceTemplate,
				item.AutomationAction,
				item.OverdueReason,
				item.TierID,
				item.TargetDID,
				item.DueAt.UTC().Format(time.RFC3339Nano),
				strconv.FormatInt(item.OverdueSeconds, 10),
				formatSecureCellOptionalTime(item.ResolutionDueAt),
				strconv.FormatBool(item.AutoSuspendOnOverdue),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write overdue-federation-counterproposal csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationAutomationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-automation-actions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"invitation_id",
			"counterproposal_id",
			"counterproposal_status_before",
			"counterproposal_status_after",
			"contract_id",
			"contract_status_before",
			"contract_status_after",
			"action",
			"tier_id",
			"target_did",
			"trigger",
			"due_at",
			"actor",
			"automated_actor",
			"reason",
			"transition_id",
			"occurred_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.InvitationID,
				item.CounterproposalID,
				string(item.CounterproposalStatusBefore),
				string(item.CounterproposalStatusAfter),
				item.ContractID,
				string(item.ContractStatusBefore),
				string(item.ContractStatusAfter),
				item.Action,
				item.TierID,
				item.TargetDID,
				item.Trigger,
				formatSecureCellOptionalTime(item.DueAt),
				item.Actor,
				item.AutomatedActor,
				item.Reason,
				item.TransitionID,
				item.OccurredAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-automation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationAssuranceFindingExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationAssuranceFinding) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationAssuranceFindingListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-assurance-findings.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"finding_id",
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"invitation_id",
			"contract_id",
			"contract_revision",
			"contract_status",
			"participant_did",
			"expected_did",
			"credential_id",
			"severity",
			"category",
			"summary",
			"reason",
			"suggested_action",
			"auto_containment_eligible",
			"session_ids",
			"artifact_ids",
			"artifact_type",
			"detected_at",
			"metadata",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.ID,
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.InvitationID,
				item.ContractID,
				strconv.Itoa(item.ContractRevision),
				string(item.ContractStatus),
				item.ParticipantDID,
				item.ExpectedDID,
				item.CredentialID,
				string(item.Severity),
				string(item.Category),
				item.Summary,
				item.Reason,
				item.SuggestedAction,
				strconv.FormatBool(item.AutoContainmentEligible),
				strings.Join(item.SessionIDs, "|"),
				strings.Join(item.ArtifactIDs, "|"),
				item.ArtifactType,
				item.DetectedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-assurance-finding csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationAssuranceActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationAssuranceActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationAssuranceActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-assurance-actions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"contract_id",
			"invitation_id",
			"finding_id",
			"category",
			"severity",
			"action",
			"trigger",
			"actor",
			"automated_actor",
			"reason",
			"transition_id",
			"occurred_at",
			"metadata",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.ContractID,
				item.InvitationID,
				item.FindingID,
				string(item.Category),
				string(item.Severity),
				item.Action,
				item.Trigger,
				item.Actor,
				item.AutomatedActor,
				item.Reason,
				item.TransitionID,
				item.OccurredAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-assurance-action csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationAssuranceReportExport(w http.ResponseWriter, r *http.Request, report *securecellsintegration.SecureCellFederationAssuranceReport) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationAssuranceReportResponse{Result: report})
		return nil
	case "csv":
		if report == nil {
			return fmt.Errorf("federation assurance report is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-assurance-report.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id",
			"version",
			"name",
			"generated_at",
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"framework",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"organization_status",
			"runtime_active_participants",
			"runtime_active_contracts",
			"finding_count",
			"critical_finding_count",
			"warning_finding_count",
			"info_finding_count",
			"auto_containment_eligible_count",
			"require_confidential_compute",
			"confidential_execution_verified",
			"confidential_execution_present",
			"confidential_execution_valid",
			"confidential_execution_binding_hash",
			"contract_ids",
			"finding_ids",
			"finding_categories",
			"automation_action_ids",
			"operator_surface_ids",
			"operator_surface_paths",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
		}}
		rows = append(rows, []string{
			report.ID,
			report.Version,
			report.Name,
			report.GeneratedAt.UTC().Format(time.RFC3339Nano),
			report.CellID,
			report.CellName,
			string(report.CellStatus),
			report.Jurisdiction,
			report.Framework,
			report.Organization.OrganizationID,
			report.Organization.SponsorOfRecord,
			report.Organization.OrganizationName,
			string(report.Organization.Status),
			strconv.Itoa(report.Runtime.ActiveParticipantCount),
			strconv.Itoa(report.Runtime.ActiveContracts),
			strconv.Itoa(report.FindingCount),
			strconv.Itoa(report.CriticalFindingCount),
			strconv.Itoa(report.WarningFindingCount),
			strconv.Itoa(report.InfoFindingCount),
			strconv.Itoa(report.AutoContainmentEligibleCount),
			strconv.FormatBool(report.RequireConfidentialCompute),
			strconv.FormatBool(report.ConfidentialExecutionVerified),
			strconv.Itoa(report.ConfidentialExecutionPresent),
			strconv.Itoa(report.ConfidentialExecutionValid),
			report.ConfidentialExecutionBindingHash,
			joinSecureCellFederationContractIDs(report.Contracts),
			joinSecureCellFederationAssuranceFindingIDs(report.Findings),
			joinSecureCellFederationAssuranceFindingCategories(report.Findings),
			joinSecureCellFederationAssuranceActionIDs(report.AutomationActions),
			joinSecureCellFederationOperatorSurfaceIDs(report.OperatorSurfaces),
			joinSecureCellFederationOperatorSurfacePaths(report.OperatorSurfaces),
			report.ControlLedgerID,
			report.ControlLedgerHash,
			report.PortablePackageHash,
			strconv.FormatBool(report.PortablePackageSigned),
			strconv.FormatBool(report.PortablePackageAnchored),
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-assurance-report csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellDecisionSLATemplateExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellDecisionSLATemplateSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellDecisionSLATemplateListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-decision-sla-templates.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id",
			"name",
			"description",
			"sector",
			"sector_policy_pack",
			"default_for_pack",
			"governance_template",
			"approval_threshold",
			"required_approver_roles",
			"allowed_vote_choices",
			"rejector_roles",
			"abstainer_roles",
			"reopen_roles",
			"resolution_after",
			"escalation_tiers",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.ID,
				item.Name,
				item.Description,
				item.Sector,
				item.SectorPolicyPack,
				strconv.FormatBool(item.DefaultForPack),
				item.GovernanceTemplate,
				strconv.Itoa(item.ApprovalThreshold),
				strings.Join(item.RequiredApproverRoles, "|"),
				joinSecureCellDecisionVoteChoiceStrings(item.AllowedVoteChoices),
				strings.Join(item.RejectorRoles, "|"),
				strings.Join(item.AbstainerRoles, "|"),
				strings.Join(item.ReopenRoles, "|"),
				item.ResolutionAfter,
				formatSecureCellDecisionSLATiers(item.EscalationTiers),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write decision-sla-template csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationOrganizationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationOrganizationSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationOrganizationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-organizations.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"status",
			"participant_dids",
			"participant_count",
			"active_participant_count",
			"invitation_count",
			"pending_invitation_count",
			"accepted_invitation_count",
			"revoked_invitation_count",
			"counterproposal_count",
			"pending_counterproposal_count",
			"approved_counterproposal_count",
			"rejected_counterproposal_count",
			"superseded_counterproposal_count",
			"contract_count",
			"active_contract_count",
			"suspended_contract_count",
			"revoked_contract_count",
			"control_ledger_id",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"created_at",
			"updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				string(item.CellStatus),
				item.Jurisdiction,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				string(item.Status),
				strings.Join(item.ParticipantDIDs, "|"),
				strconv.Itoa(item.ParticipantCount),
				strconv.Itoa(item.ActiveParticipantCount),
				strconv.Itoa(item.InvitationCount),
				strconv.Itoa(item.PendingInvitationCount),
				strconv.Itoa(item.AcceptedInvitationCount),
				strconv.Itoa(item.RevokedInvitationCount),
				strconv.Itoa(item.CounterproposalCount),
				strconv.Itoa(item.PendingCounterproposalCount),
				strconv.Itoa(item.ApprovedCounterproposalCount),
				strconv.Itoa(item.RejectedCounterproposalCount),
				strconv.Itoa(item.SupersededCounterproposalCount),
				strconv.Itoa(item.ContractCount),
				strconv.Itoa(item.ActiveContractCount),
				strconv.Itoa(item.SuspendedContractCount),
				strconv.Itoa(item.RevokedContractCount),
				item.ControlLedgerID,
				item.PortablePackageHash,
				strconv.FormatBool(item.PortablePackageSigned),
				strconv.FormatBool(item.PortablePackageAnchored),
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-organization csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationInvitationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationInvitationSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationInvitationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-invitations.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"invitation_id",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"status",
			"expected_did",
			"role",
			"session_scope_count",
			"data_class_count",
			"compute_zone_count",
			"resource",
			"created_by",
			"accepted_by",
			"revoked_by",
			"reason",
			"control_ledger_id",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"created_at",
			"accepted_at",
			"revoked_at",
			"updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				string(item.CellStatus),
				item.Jurisdiction,
				item.InvitationID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				string(item.Status),
				item.ExpectedDID,
				item.Role,
				strconv.Itoa(item.SessionScopeCount),
				strconv.Itoa(item.DataClassCount),
				strconv.Itoa(item.ComputeZoneCount),
				item.Resource,
				item.CreatedBy,
				item.AcceptedBy,
				item.RevokedBy,
				item.Reason,
				item.ControlLedgerID,
				item.PortablePackageHash,
				strconv.FormatBool(item.PortablePackageSigned),
				strconv.FormatBool(item.PortablePackageAnchored),
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellOptionalTime(item.AcceptedAt),
				formatSecureCellOptionalTime(item.RevokedAt),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-invitation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationCounterproposalExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationCounterproposalSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterproposalListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-counterproposals.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"counterproposal_id",
			"invitation_id",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"status",
			"governance_template",
			"approval_threshold",
			"eligible_approver_count",
			"approval_vote_count",
			"approve_vote_count",
			"reject_vote_count",
			"threshold_satisfied",
			"escalation_tier_count",
			"escalated_tier_count",
			"resolution_due_at",
			"auto_suspend_on_overdue",
			"offered_session_scope_ids",
			"offered_data_classes",
			"offered_compute_zones",
			"offered_actions",
			"negotiated_session_scope_ids",
			"negotiated_data_classes",
			"negotiated_compute_zones",
			"negotiated_actions",
			"negotiation_diff_count",
			"negotiation_diffs",
			"resource",
			"submitted_by",
			"approved_by",
			"rejected_by",
			"superseded_by",
			"reason",
			"control_ledger_id",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"created_at",
			"approved_at",
			"rejected_at",
			"superseded_at",
			"updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				string(item.CellStatus),
				item.Jurisdiction,
				item.CounterproposalID,
				item.InvitationID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				string(item.Status),
				item.GovernanceTemplate,
				strconv.Itoa(item.ApprovalThreshold),
				strconv.Itoa(item.EligibleApproverCount),
				strconv.Itoa(item.ApprovalVoteCount),
				strconv.Itoa(item.ApproveVoteCount),
				strconv.Itoa(item.RejectVoteCount),
				strconv.FormatBool(item.ThresholdSatisfied),
				strconv.Itoa(item.EscalationTierCount),
				strconv.Itoa(item.EscalatedTierCount),
				formatSecureCellOptionalTime(item.ResolutionDueAt),
				strconv.FormatBool(item.AutoSuspendOnOverdue),
				strings.Join(item.OfferedSessionScopeIDs, "|"),
				strings.Join(item.OfferedDataClasses, "|"),
				strings.Join(item.OfferedComputeZones, "|"),
				strings.Join(item.OfferedActions, "|"),
				strings.Join(item.NegotiatedSessionScopeIDs, "|"),
				strings.Join(item.NegotiatedDataClasses, "|"),
				strings.Join(item.NegotiatedComputeZones, "|"),
				strings.Join(item.NegotiatedActions, "|"),
				strconv.Itoa(item.NegotiationDiffCount),
				secureCellFederationPolicyDiffSummaryCSV(item.NegotiationDiffs),
				item.Resource,
				item.SubmittedBy,
				item.ApprovedBy,
				item.RejectedBy,
				item.SupersededBy,
				item.Reason,
				item.ControlLedgerID,
				item.PortablePackageHash,
				strconv.FormatBool(item.PortablePackageSigned),
				strconv.FormatBool(item.PortablePackageAnchored),
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellOptionalTime(item.ApprovedAt),
				formatSecureCellOptionalTime(item.RejectedAt),
				formatSecureCellOptionalTime(item.SupersededAt),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-counterproposal csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationContractExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationContractSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationContractListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-contracts.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"contract_id",
			"organization_id",
			"invitation_id",
			"sponsor_of_record",
			"organization_name",
			"status",
			"participant_dids",
			"participant_count",
			"session_scope_ids",
			"session_scope_count",
			"offered_session_scope_ids",
			"data_classes",
			"data_class_count",
			"offered_data_classes",
			"compute_zones",
			"compute_zone_count",
			"offered_compute_zones",
			"allowed_actions",
			"offered_actions",
			"negotiation_diff_count",
			"negotiation_diffs",
			"resource",
			"negotiation_id",
			"credential_id",
			"policy_receipt_id",
			"policy_receipt_hash",
			"revision",
			"supersedes_contract_id",
			"replaced_by_contract_id",
			"control_ledger_id",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"created_at",
			"activated_at",
			"suspended_at",
			"resumed_at",
			"revoked_at",
			"updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				string(item.CellStatus),
				item.Jurisdiction,
				item.ContractID,
				item.OrganizationID,
				item.InvitationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				string(item.Status),
				strings.Join(item.ParticipantDIDs, "|"),
				strconv.Itoa(item.ParticipantCount),
				strings.Join(item.SessionScopeIDs, "|"),
				strconv.Itoa(item.SessionScopeCount),
				strings.Join(item.OfferedSessionScopeIDs, "|"),
				strings.Join(item.DataClasses, "|"),
				strconv.Itoa(item.DataClassCount),
				strings.Join(item.OfferedDataClasses, "|"),
				strings.Join(item.ComputeZones, "|"),
				strconv.Itoa(item.ComputeZoneCount),
				strings.Join(item.OfferedComputeZones, "|"),
				strings.Join(item.AllowedActions, "|"),
				strings.Join(item.OfferedActions, "|"),
				strconv.Itoa(item.NegotiationDiffCount),
				secureCellFederationPolicyDiffSummaryCSV(item.NegotiationDiffs),
				item.Resource,
				item.NegotiationID,
				item.CredentialID,
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				strconv.Itoa(item.Revision),
				item.SupersedesContractID,
				item.ReplacedByContractID,
				item.ControlLedgerID,
				item.PortablePackageHash,
				strconv.FormatBool(item.PortablePackageSigned),
				strconv.FormatBool(item.PortablePackageAnchored),
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellOptionalTime(item.ActivatedAt),
				formatSecureCellOptionalTime(item.SuspendedAt),
				formatSecureCellOptionalTime(item.ResumedAt),
				formatSecureCellOptionalTime(item.RevokedAt),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-contract csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationCounterpartyAssuranceExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationCounterpartyAssuranceSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyAssuranceListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-counterparty-assurance.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"snapshot_id",
			"bundle_id",
			"bundle_name",
			"bundle_version",
			"status",
			"verified",
			"signer",
			"key_id",
			"generated_at",
			"expires_at",
			"received_at",
			"contract_ids",
			"finding_count",
			"critical_finding_count",
			"warning_finding_count",
			"info_finding_count",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"verification_message",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.SnapshotID,
				item.BundleID,
				item.BundleName,
				item.BundleVersion,
				string(item.Status),
				strconv.FormatBool(item.Verified),
				item.Signer,
				item.KeyID,
				item.GeneratedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellOptionalTime(item.ExpiresAt),
				item.ReceivedAt.UTC().Format(time.RFC3339Nano),
				strings.Join(item.ContractIDs, "|"),
				strconv.Itoa(item.FindingCount),
				strconv.Itoa(item.CriticalFindingCount),
				strconv.Itoa(item.WarningFindingCount),
				strconv.Itoa(item.InfoFindingCount),
				item.ControlLedgerID,
				item.ControlLedgerHash,
				item.PortablePackageHash,
				strconv.FormatBool(item.PortablePackageSigned),
				strconv.FormatBool(item.PortablePackageAnchored),
				item.VerificationMessage,
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-counterparty-assurance csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incidents.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"incident_id",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"status",
			"severity",
			"category",
			"summary",
			"description",
			"contract_ids",
			"session_ids",
			"thread_ids",
			"shared_output_ids",
			"session_exchange_ids",
			"contract_count",
			"session_count",
			"thread_count",
			"shared_output_count",
			"session_exchange_count",
			"auto_containment_requested",
			"reported_by",
			"reported_at",
			"expires_at",
			"resolved_by",
			"resolved_at",
			"resolution_reason",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.IncidentID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				string(item.Status),
				string(item.Severity),
				string(item.Category),
				item.Summary,
				item.Description,
				strings.Join(item.ContractIDs, "|"),
				strings.Join(item.SessionIDs, "|"),
				strings.Join(item.ThreadIDs, "|"),
				strings.Join(item.SharedOutputIDs, "|"),
				strings.Join(item.SessionExchangeIDs, "|"),
				strconv.Itoa(item.ContractCount),
				strconv.Itoa(item.SessionCount),
				strconv.Itoa(item.ThreadCount),
				strconv.Itoa(item.SharedOutputCount),
				strconv.Itoa(item.SessionExchangeCount),
				strconv.FormatBool(item.AutoContainmentRequested),
				item.ReportedBy,
				item.ReportedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellOptionalTime(item.ExpiresAt),
				item.ResolvedBy,
				formatSecureCellOptionalTime(item.ResolvedAt),
				item.ResolutionReason,
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-actions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"incident_id",
			"incident_status",
			"severity",
			"category",
			"contract_id",
			"session_id",
			"thread_id",
			"shared_output_ids",
			"session_exchange_ids",
			"action",
			"trigger",
			"actor",
			"automated_actor",
			"reason",
			"transition_id",
			"occurred_at",
			"metadata",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				string(item.IncidentStatus),
				string(item.Severity),
				string(item.Category),
				item.ContractID,
				item.SessionID,
				item.ThreadID,
				strings.Join(item.SharedOutputIDs, "|"),
				strings.Join(item.SessionExchangeIDs, "|"),
				item.Action,
				item.Trigger,
				item.Actor,
				item.AutomatedActor,
				item.Reason,
				item.TransitionID,
				item.OccurredAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-action csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentResponseExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentResponseSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentResponseListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-responses.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "organization_name",
			"source_type", "source_snapshot_id", "source_bulletin_id", "incident_id", "incident_status", "incident_severity", "incident_category",
			"incident_summary", "incident_description", "status", "required_acknowledgement", "expected_remediation_from", "playbook_template",
			"contract_ids", "session_ids", "thread_ids", "shared_output_ids", "session_exchange_ids", "contract_count", "session_count", "thread_count",
			"shared_output_count", "session_exchange_count", "ack_due_at", "ack_status", "remediation_due_at", "remediation_status",
			"verification_required_from", "verification_due_at", "verification_status", "verification_count", "closure_attestation_count",
			"dispute_count", "last_verification_decision", "escalation_tier_count", "escalated_tier_count", "next_escalation_tier_id",
			"next_escalation_target_did", "remediation_count", "acknowledged_by", "acknowledged_at", "remediated_by", "remediated_at",
			"verified_by", "verified_at", "closed_by", "closed_at", "last_disputed_by", "last_disputed_at", "reopened_by", "reopened_at", "closure_ready",
			"created_at", "updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				string(item.SourceType),
				item.SourceSnapshotID,
				item.SourceBulletinID,
				item.IncidentID,
				string(item.IncidentStatus),
				string(item.IncidentSeverity),
				string(item.IncidentCategory),
				item.IncidentSummary,
				item.IncidentDescription,
				string(item.Status),
				string(item.RequiredAcknowledgement),
				string(item.ExpectedRemediationFrom),
				item.PlaybookTemplate,
				strings.Join(item.ContractIDs, "|"),
				strings.Join(item.SessionIDs, "|"),
				strings.Join(item.ThreadIDs, "|"),
				strings.Join(item.SharedOutputIDs, "|"),
				strings.Join(item.SessionExchangeIDs, "|"),
				strconv.Itoa(item.ContractCount),
				strconv.Itoa(item.SessionCount),
				strconv.Itoa(item.ThreadCount),
				strconv.Itoa(item.SharedOutputCount),
				strconv.Itoa(item.SessionExchangeCount),
				formatSecureCellOptionalTime(item.AckDueAt),
				string(item.AckStatus),
				formatSecureCellOptionalTime(item.RemediationDueAt),
				string(item.RemediationStatus),
				string(item.VerificationRequiredFrom),
				formatSecureCellOptionalTime(item.VerificationDueAt),
				string(item.VerificationStatus),
				strconv.Itoa(item.VerificationCount),
				strconv.Itoa(item.ClosureAttestationCount),
				strconv.Itoa(item.DisputeCount),
				string(item.LastVerificationDecision),
				strconv.Itoa(item.EscalationTierCount),
				strconv.Itoa(item.EscalatedTierCount),
				item.NextEscalationTierID,
				item.NextEscalationTargetDID,
				strconv.Itoa(item.RemediationCount),
				item.AcknowledgedBy,
				formatSecureCellOptionalTime(item.AcknowledgedAt),
				item.RemediatedBy,
				formatSecureCellOptionalTime(item.RemediatedAt),
				item.VerifiedBy,
				formatSecureCellOptionalTime(item.VerifiedAt),
				item.ClosedBy,
				formatSecureCellOptionalTime(item.ClosedAt),
				item.LastDisputedBy,
				formatSecureCellOptionalTime(item.LastDisputedAt),
				item.ReopenedBy,
				formatSecureCellOptionalTime(item.ReopenedAt),
				strconv.FormatBool(item.ClosureReady),
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-response csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellOverdueFederationIncidentResponseExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueFederationIncidentResponse) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentResponseListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-overdue-federation-incident-responses.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "incident_id", "incident_severity", "incident_category", "incident_summary", "response_status", "source_type", "playbook_template", "overdue_step_type", "overdue_step_status", "automation_action", "overdue_reason", "tier_id", "target_did", "due_at", "overdue_seconds", "acknowledged_at", "remediated_at", "verified_at", "closed_at", "updated_at"}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				string(item.IncidentSeverity),
				string(item.IncidentCategory),
				item.IncidentSummary,
				string(item.ResponseStatus),
				string(item.SourceType),
				item.PlaybookTemplate,
				string(item.OverdueStepType),
				string(item.OverdueStepStatus),
				item.AutomationAction,
				item.OverdueReason,
				item.TierID,
				item.TargetDID,
				item.DueAt.UTC().Format(time.RFC3339Nano),
				strconv.FormatInt(item.OverdueSeconds, 10),
				formatSecureCellOptionalTime(item.AcknowledgedAt),
				formatSecureCellOptionalTime(item.RemediatedAt),
				formatSecureCellOptionalTime(item.VerifiedAt),
				formatSecureCellOptionalTime(item.ClosedAt),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write overdue federation-incident-response csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentResponseActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentResponseActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentResponseActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-response-actions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record", "incident_id", "response_id", "contract_ids", "source_type", "response_status_before", "response_status_after", "action", "trigger", "tier_id", "target_did", "actor", "automated_actor", "reason", "transition_id", "occurred_at", "metadata"}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				item.ResponseID,
				strings.Join(item.ContractIDs, "|"),
				string(item.SourceType),
				string(item.ResponseStatusBefore),
				string(item.ResponseStatusAfter),
				item.Action,
				item.Trigger,
				item.TierID,
				item.TargetDID,
				item.Actor,
				item.AutomatedActor,
				item.Reason,
				item.TransitionID,
				item.OccurredAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-response-action csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentRemediationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentRemediationSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentRemediationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-remediations.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "incident_id", "attestation_id", "attesting_party", "submitted_by", "summary", "description", "evidence_ids", "policy_receipt_id", "policy_receipt_hash", "seal_id", "trace_link_id", "created_at", "metadata"}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				item.AttestationID,
				string(item.AttestingParty),
				item.SubmittedBy,
				item.Summary,
				item.Description,
				strings.Join(item.EvidenceIDs, "|"),
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				item.SealID,
				item.TraceLinkID,
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-remediation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentVerificationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentVerificationSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentVerificationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-verifications.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "incident_id", "verification_id", "reviewing_party", "decision", "verified_attestation_id", "submitted_by", "summary", "description", "evidence_ids", "policy_receipt_id", "policy_receipt_hash", "seal_id", "trace_link_id", "created_at", "metadata"}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				item.VerificationID,
				string(item.ReviewingParty),
				string(item.Decision),
				item.VerifiedAttestationID,
				item.SubmittedBy,
				item.Summary,
				item.Description,
				strings.Join(item.EvidenceIDs, "|"),
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				item.SealID,
				item.TraceLinkID,
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-verification csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentClosureExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentClosureAttestationSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentClosureListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-closures.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "incident_id", "attestation_id", "attesting_party", "submitted_by", "summary", "description", "evidence_ids", "policy_receipt_id", "policy_receipt_hash", "seal_id", "trace_link_id", "created_at", "metadata"}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				item.AttestationID,
				string(item.AttestingParty),
				item.SubmittedBy,
				item.Summary,
				item.Description,
				strings.Join(item.EvidenceIDs, "|"),
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				item.SealID,
				item.TraceLinkID,
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-closure csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentDisputeExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDisputeSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDisputeListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-disputes.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "incident_id", "dispute_id", "disputing_party", "submitted_by", "related_verification_id", "related_closure_id", "summary", "description", "evidence_ids", "reopened", "reopened_response_status", "policy_receipt_id", "policy_receipt_hash", "seal_id", "trace_link_id", "created_at", "metadata"}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				item.DisputeID,
				string(item.DisputingParty),
				item.SubmittedBy,
				item.RelatedVerificationID,
				item.RelatedClosureID,
				item.Summary,
				item.Description,
				strings.Join(item.EvidenceIDs, "|"),
				strconv.FormatBool(item.Reopened),
				string(item.ReopenedResponseStatus),
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				item.SealID,
				item.TraceLinkID,
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-dispute csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentReportSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-reports.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "incident_id",
			"report_id", "reporting_party", "regulator", "framework", "report_type", "status", "summary", "description",
			"required_sections", "evidence_ids", "due_at", "overdue", "submission_reference", "submitted_by", "submitted_at",
			"acknowledgement_reference", "acknowledged_by", "acknowledged_at", "created_by", "created_at", "updated_at", "metadata",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				item.ReportID,
				string(item.ReportingParty),
				item.Regulator,
				item.Framework,
				item.ReportType,
				string(item.Status),
				item.Summary,
				item.Description,
				strings.Join(item.RequiredSections, "|"),
				strings.Join(item.EvidenceIDs, "|"),
				formatSecureCellOptionalTime(item.DueAt),
				strconv.FormatBool(item.Overdue),
				item.SubmissionReference,
				item.SubmittedBy,
				formatSecureCellOptionalTime(item.SubmittedAt),
				item.AcknowledgementReference,
				item.AcknowledgedBy,
				formatSecureCellOptionalTime(item.AcknowledgedAt),
				item.CreatedBy,
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportAmendmentExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentReportAmendmentSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-amendments.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "incident_id",
			"report_id", "report_regulator", "report_framework", "report_type", "report_status", "amendment_id", "sequence", "supersedes_amendment_id",
			"status", "summary", "description", "changed_sections", "evidence_ids", "submission_reference", "submitted_by", "submitted_at",
			"acknowledgement_reference", "acknowledged_by", "acknowledged_at", "created_by", "created_at", "updated_at", "metadata",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				item.ReportID,
				item.ReportRegulator,
				item.ReportFramework,
				item.ReportType,
				string(item.ReportStatus),
				item.AmendmentID,
				strconv.Itoa(item.Sequence),
				item.SupersedesAmendmentID,
				string(item.Status),
				item.Summary,
				item.Description,
				strings.Join(item.ChangedSections, "|"),
				strings.Join(item.EvidenceIDs, "|"),
				item.SubmissionReference,
				item.SubmittedBy,
				formatSecureCellOptionalTime(item.SubmittedAt),
				item.AcknowledgementReference,
				item.AcknowledgedBy,
				formatSecureCellOptionalTime(item.AcknowledgedAt),
				item.CreatedBy,
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-amendment csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellOverdueFederationIncidentReportExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueFederationIncidentReport) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentReportListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-overdue-federation-incident-reports.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "incident_id",
			"report_id", "reporting_party", "regulator", "framework", "report_type", "status", "summary", "due_at", "overdue_seconds", "updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				item.ReportID,
				string(item.ReportingParty),
				item.Regulator,
				item.Framework,
				item.ReportType,
				string(item.Status),
				item.Summary,
				item.DueAt.UTC().Format(time.RFC3339Nano),
				strconv.FormatInt(item.OverdueSeconds, 10),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write overdue federation-incident-report csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportBundleExport(w http.ResponseWriter, r *http.Request, bundle *securecellsintegration.SecureCellFederationIncidentReportBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportBundleResponse{Result: bundle})
		return nil
	case "csv":
		if bundle == nil {
			return fmt.Errorf("federation incident report bundle is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-bundle.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id", "version", "name", "generated_at", "expires_at", "cell_id", "cell_name", "cell_status", "jurisdiction", "framework",
			"organization_id", "sponsor_of_record", "organization_name", "organization_status", "response_id", "response_status", "response_source_type",
			"incident_id", "incident_status", "incident_severity", "incident_category", "report_id", "report_status", "reporting_party", "regulator",
			"report_framework", "report_type", "report_summary", "report_due_at", "response_bundle_hash", "contract_ids", "control_ids",
			"operator_surface_ids", "operator_surface_paths", "control_ledger_id", "control_ledger_hash", "portable_package_hash",
			"portable_package_signed", "portable_package_anchored", "content_hash", "signature_algorithm", "signature_signer",
			"signature_key_id", "signature_signed_at", "metadata",
		}}
		signatureAlgorithm := ""
		signatureSigner := ""
		signatureKeyID := ""
		signatureSignedAt := ""
		if bundle.Signature != nil {
			signatureAlgorithm = bundle.Signature.Algorithm
			signatureSigner = bundle.Signature.Signer
			signatureKeyID = bundle.Signature.KeyID
			signatureSignedAt = bundle.Signature.SignedAt.UTC().Format(time.RFC3339Nano)
		}
		rows = append(rows, []string{
			bundle.ID,
			bundle.Version,
			bundle.Name,
			bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			formatSecureCellOptionalTime(bundle.ExpiresAt),
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
			bundle.ReportSummary.ReportID,
			string(bundle.ReportSummary.Status),
			string(bundle.ReportSummary.ReportingParty),
			bundle.ReportSummary.Regulator,
			bundle.ReportSummary.Framework,
			bundle.ReportSummary.ReportType,
			bundle.ReportSummary.Summary,
			formatSecureCellOptionalTime(bundle.ReportSummary.DueAt),
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
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-bundle csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentResponseBundleExport(w http.ResponseWriter, r *http.Request, bundle *securecellsintegration.SecureCellFederationIncidentResponseBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentResponseBundleResponse{Result: bundle})
		return nil
	case "csv":
		if bundle == nil {
			return fmt.Errorf("federation incident response bundle is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-response-bundle.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id", "version", "name", "generated_at", "expires_at", "cell_id", "cell_name", "cell_status", "jurisdiction", "framework",
			"organization_id", "sponsor_of_record", "organization_name", "organization_status", "response_id", "response_status",
			"source_type", "incident_id", "incident_status", "incident_severity", "incident_category", "incident_summary",
			"contract_ids", "closure_attestation_count", "dispute_count", "remediation_count", "verification_count", "control_ids",
			"operator_surface_ids", "operator_surface_paths", "control_ledger_id", "control_ledger_hash", "portable_package_hash",
			"portable_package_signed", "portable_package_anchored", "content_hash", "signature_algorithm", "signature_signer",
			"signature_key_id", "signature_signed_at", "metadata",
		}}
		signatureAlgorithm := ""
		signatureSigner := ""
		signatureKeyID := ""
		signatureSignedAt := ""
		if bundle.Signature != nil {
			signatureAlgorithm = bundle.Signature.Algorithm
			signatureSigner = bundle.Signature.Signer
			signatureKeyID = bundle.Signature.KeyID
			signatureSignedAt = bundle.Signature.SignedAt.UTC().Format(time.RFC3339Nano)
		}
		rows = append(rows, []string{
			bundle.ID,
			bundle.Version,
			bundle.Name,
			bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			formatSecureCellOptionalTime(bundle.ExpiresAt),
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
			bundle.ResponseSummary.IncidentSummary,
			joinSecureCellFederationContractIDs(bundle.Contracts),
			strconv.Itoa(bundle.ResponseSummary.ClosureAttestationCount),
			strconv.Itoa(bundle.ResponseSummary.DisputeCount),
			strconv.Itoa(bundle.ResponseSummary.RemediationCount),
			strconv.Itoa(bundle.ResponseSummary.VerificationCount),
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
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-response-bundle csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentCasePackExport(w http.ResponseWriter, r *http.Request, pack *securecellsintegration.SecureCellFederationIncidentCasePack) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentCasePackResponse{Result: pack})
		return nil
	case "csv":
		if pack == nil {
			return fmt.Errorf("federation incident case pack is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-case-pack.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id", "version", "name", "generated_at", "expires_at", "cell_id", "cell_name", "cell_status", "jurisdiction", "framework",
			"organization_id", "sponsor_of_record", "organization_name", "response_id", "response_status", "incident_id", "source_type",
			"directive_bundle_ids", "directive_bundle_count", "directive_extension_summary_count", "directive_extension_appeal_bundle_count", "directive_extension_appeal_reconciliation_bundle_ids", "directive_extension_appeal_reconciliation_bundle_count", "directive_extension_appeal_reconciliation_challenge_count", "directive_extension_appeal_reconciliation_challenge_action_count", "directive_extension_appeal_reconciliation_challenge_appeal_count", "directive_extension_appeal_reconciliation_challenge_appeal_recusal_count", "directive_extension_appeal_reconciliation_challenge_appeal_action_count", "directive_extension_appeal_reconciliation_challenge_appeal_automation_action_count", "directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_action_count", "directive_extension_appeal_reconciliation_challenge_automation_action_count", "directive_extension_appeal_automation_action_count", "directive_extension_appeal_reconciliation_automation_action_count",
			"report_bundle_ids", "report_bundle_count", "amendment_bundle_ids", "amendment_bundle_count",
			"report_reconciliation_bundle_ids", "report_reconciliation_bundle_count",
			"amendment_reconciliation_bundle_ids", "amendment_reconciliation_bundle_count",
			"response_action_count", "directive_automation_action_count", "remediation_count", "verification_count", "closure_count", "dispute_count",
			"report_reconciliation_automation_action_count", "amendment_reconciliation_attestation_count", "amendment_reconciliation_automation_action_count",
			"control_ids", "operator_surface_ids", "operator_surface_paths", "control_ledger_id", "control_ledger_hash", "portable_package_hash",
			"portable_package_signed", "portable_package_anchored", "content_hash", "signature_algorithm", "signature_signer",
			"signature_key_id", "signature_signed_at", "metadata",
		}}
		signatureAlgorithm := ""
		signatureSigner := ""
		signatureKeyID := ""
		signatureSignedAt := ""
		if pack.Signature != nil {
			signatureAlgorithm = pack.Signature.Algorithm
			signatureSigner = pack.Signature.Signer
			signatureKeyID = pack.Signature.KeyID
			signatureSignedAt = pack.Signature.SignedAt.UTC().Format(time.RFC3339Nano)
		}
		rows = append(rows, []string{
			pack.ID,
			pack.Version,
			pack.Name,
			pack.GeneratedAt.UTC().Format(time.RFC3339Nano),
			formatSecureCellOptionalTime(pack.ExpiresAt),
			pack.CellID,
			pack.CellName,
			string(pack.CellStatus),
			pack.Jurisdiction,
			pack.Framework,
			pack.Organization.OrganizationID,
			pack.Organization.SponsorOfRecord,
			pack.Organization.OrganizationName,
			pack.ResponseSummary.ResponseID,
			string(pack.ResponseSummary.Status),
			pack.ResponseSummary.IncidentID,
			string(pack.ResponseSummary.SourceType),
			joinSecureCellFederationIncidentDirectiveBundleIDs(pack.DirectiveBundles),
			strconv.Itoa(len(pack.DirectiveBundles)),
			strconv.Itoa(len(pack.DirectiveExtensionSummaries)),
			strconv.Itoa(len(pack.DirectiveExtensionAppealBundles)),
			joinSecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleIDs(pack.DirectiveExtensionAppealReconciliationBundles),
			strconv.Itoa(len(pack.DirectiveExtensionAppealReconciliationBundles)),
			strconv.Itoa(len(pack.DirectiveExtensionAppealReconciliationChallenges)),
			strconv.Itoa(len(pack.DirectiveExtensionAppealReconciliationChallengeActions)),
			strconv.Itoa(len(pack.DirectiveExtensionAppealReconciliationChallengeAppeals)),
			strconv.Itoa(len(pack.DirectiveExtensionAppealReconciliationChallengeAppealRecusals)),
			strconv.Itoa(len(pack.DirectiveExtensionAppealReconciliationChallengeAppealActions)),
			strconv.Itoa(len(pack.DirectiveExtensionAppealReconciliationChallengeAppealAutomationActions)),
			strconv.Itoa(len(pack.DirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActions)),
			strconv.Itoa(len(pack.DirectiveExtensionAppealReconciliationChallengeAutomationActions)),
			strconv.Itoa(len(pack.DirectiveExtensionAppealAutomationActions)),
			strconv.Itoa(len(pack.DirectiveExtensionAppealReconciliationAutomationActions)),
			joinSecureCellFederationIncidentReportBundleIDs(pack.ReportBundles),
			strconv.Itoa(len(pack.ReportBundles)),
			joinSecureCellFederationIncidentReportAmendmentBundleIDs(pack.AmendmentBundles),
			strconv.Itoa(len(pack.AmendmentBundles)),
			joinSecureCellFederationIncidentReportReconciliationBundleIDs(pack.ReportReconciliationBundles),
			strconv.Itoa(len(pack.ReportReconciliationBundles)),
			joinSecureCellFederationIncidentReportAmendmentReconciliationBundleIDs(pack.AmendmentReconciliationBundles),
			strconv.Itoa(len(pack.AmendmentReconciliationBundles)),
			strconv.Itoa(len(pack.ResponseActions)),
			strconv.Itoa(len(pack.DirectiveAutomationActions)),
			strconv.Itoa(len(pack.Remediations)),
			strconv.Itoa(len(pack.Verifications)),
			strconv.Itoa(len(pack.Closures)),
			strconv.Itoa(len(pack.Disputes)),
			strconv.Itoa(len(pack.ReportReconciliationAutomationActions)),
			strconv.Itoa(len(pack.AmendmentReconciliationAttestations)),
			strconv.Itoa(len(pack.AmendmentReconciliationAutomationActions)),
			joinSecureCellFederationControlIDs(pack.Controls),
			joinSecureCellFederationOperatorSurfaceIDs(pack.OperatorSurfaces),
			joinSecureCellFederationOperatorSurfacePaths(pack.OperatorSurfaces),
			pack.ControlLedgerID,
			pack.ControlLedgerHash,
			pack.PortablePackageHash,
			strconv.FormatBool(pack.PortablePackageSigned),
			strconv.FormatBool(pack.PortablePackageAnchored),
			pack.ContentHash,
			signatureAlgorithm,
			signatureSigner,
			signatureKeyID,
			signatureSignedAt,
			formatSecureCellStringMap(pack.Metadata),
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-case-pack csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func joinSecureCellFederationIncidentDirectiveBundleIDs(items []*securecellsintegration.SecureCellFederationIncidentDirectiveBundle) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		ids = append(ids, strings.TrimSpace(item.ID))
	}
	return strings.Join(ids, "|")
}

func joinSecureCellFederationIncidentReportBundleIDs(items []*securecellsintegration.SecureCellFederationIncidentReportBundle) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		ids = append(ids, strings.TrimSpace(item.ID))
	}
	return strings.Join(ids, "|")
}

func joinSecureCellFederationIncidentReportAmendmentBundleIDs(items []*securecellsintegration.SecureCellFederationIncidentReportAmendmentBundle) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		ids = append(ids, strings.TrimSpace(item.ID))
	}
	return strings.Join(ids, "|")
}

func joinSecureCellFederationIncidentReportReconciliationBundleIDs(items []*securecellsintegration.SecureCellFederationIncidentReportReconciliationBundle) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		ids = append(ids, strings.TrimSpace(item.ID))
	}
	return strings.Join(ids, "|")
}

func joinSecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleIDs(items []*securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		if id := strings.TrimSpace(item.ID); id != "" {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, "|")
}

func joinSecureCellFederationIncidentReportAmendmentReconciliationBundleIDs(items []*securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationBundle) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		ids = append(ids, strings.TrimSpace(item.ID))
	}
	return strings.Join(ids, "|")
}

func writeSecureCellFederationCounterpartyIncidentExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationCounterpartyIncidentSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-counterparty-incidents.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"snapshot_id",
			"bulletin_id",
			"bulletin_version",
			"bulletin_name",
			"status",
			"verified",
			"signer",
			"key_id",
			"contract_ids",
			"incident_count",
			"open_incident_count",
			"critical_incident_count",
			"high_incident_count",
			"generated_at",
			"expires_at",
			"received_at",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"verification_message",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.SnapshotID,
				item.BulletinID,
				item.BulletinVersion,
				item.BulletinName,
				string(item.Status),
				strconv.FormatBool(item.Verified),
				item.Signer,
				item.KeyID,
				strings.Join(item.ContractIDs, "|"),
				strconv.Itoa(item.IncidentCount),
				strconv.Itoa(item.OpenIncidentCount),
				strconv.Itoa(item.CriticalIncidentCount),
				strconv.Itoa(item.HighIncidentCount),
				item.GeneratedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellOptionalTime(item.ExpiresAt),
				item.ReceivedAt.UTC().Format(time.RFC3339Nano),
				item.ControlLedgerID,
				item.ControlLedgerHash,
				item.PortablePackageHash,
				strconv.FormatBool(item.PortablePackageSigned),
				strconv.FormatBool(item.PortablePackageAnchored),
				item.VerificationMessage,
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-counterparty-incident csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationCounterpartyIncidentReportExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationCounterpartyIncidentReportSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentReportListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-counterparty-incident-reports.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"snapshot_id",
			"bundle_id",
			"bundle_version",
			"bundle_name",
			"status",
			"verified",
			"signer",
			"key_id",
			"contract_ids",
			"incident_id",
			"response_id",
			"report_id",
			"reporting_party",
			"regulator",
			"framework",
			"report_type",
			"report_status",
			"due_at",
			"submission_reference",
			"acknowledgement_reference",
			"generated_at",
			"expires_at",
			"received_at",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"verification_message",
			"matched_local_report_id",
			"matched_local_response_id",
			"reconciliation_status",
			"reconciliation_divergence_count",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.SnapshotID,
				item.BundleID,
				item.BundleVersion,
				item.BundleName,
				string(item.Status),
				strconv.FormatBool(item.Verified),
				item.Signer,
				item.KeyID,
				strings.Join(item.ContractIDs, "|"),
				item.IncidentID,
				item.ResponseID,
				item.ReportID,
				string(item.ReportingParty),
				item.Regulator,
				item.Framework,
				item.ReportType,
				string(item.ReportStatus),
				formatSecureCellOptionalTime(item.DueAt),
				item.SubmissionReference,
				item.AcknowledgementReference,
				item.GeneratedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellOptionalTime(item.ExpiresAt),
				item.ReceivedAt.UTC().Format(time.RFC3339Nano),
				item.ControlLedgerID,
				item.ControlLedgerHash,
				item.PortablePackageHash,
				strconv.FormatBool(item.PortablePackageSigned),
				strconv.FormatBool(item.PortablePackageAnchored),
				item.VerificationMessage,
				item.MatchedLocalReportID,
				item.MatchedLocalResponseID,
				string(item.ReconciliationStatus),
				strconv.Itoa(item.ReconciliationDivergenceCount),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-counterparty-incident-report csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationCounterpartyIncidentReportAmendmentExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentReportAmendmentListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-counterparty-incident-report-amendments.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"snapshot_id",
			"bundle_id",
			"bundle_version",
			"bundle_name",
			"status",
			"verified",
			"signer",
			"key_id",
			"contract_ids",
			"incident_id",
			"response_id",
			"report_id",
			"amendment_id",
			"sequence",
			"reporting_party",
			"regulator",
			"framework",
			"report_type",
			"amendment_status",
			"changed_sections",
			"submission_reference",
			"acknowledgement_reference",
			"generated_at",
			"expires_at",
			"received_at",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"verification_message",
			"matched_local_amendment_id",
			"matched_local_report_id",
			"matched_local_response_id",
			"reconciliation_status",
			"reconciliation_divergence_count",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.SnapshotID,
				item.BundleID,
				item.BundleVersion,
				item.BundleName,
				string(item.Status),
				strconv.FormatBool(item.Verified),
				item.Signer,
				item.KeyID,
				strings.Join(item.ContractIDs, "|"),
				item.IncidentID,
				item.ResponseID,
				item.ReportID,
				item.AmendmentID,
				strconv.Itoa(item.Sequence),
				string(item.ReportingParty),
				item.Regulator,
				item.Framework,
				item.ReportType,
				string(item.AmendmentStatus),
				strings.Join(item.ChangedSections, "|"),
				item.SubmissionReference,
				item.AcknowledgementReference,
				item.GeneratedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellOptionalTime(item.ExpiresAt),
				item.ReceivedAt.UTC().Format(time.RFC3339Nano),
				item.ControlLedgerID,
				item.ControlLedgerHash,
				item.PortablePackageHash,
				strconv.FormatBool(item.PortablePackageSigned),
				strconv.FormatBool(item.PortablePackageAnchored),
				item.VerificationMessage,
				item.MatchedLocalAmendmentID,
				item.MatchedLocalReportID,
				item.MatchedLocalResponseID,
				string(item.ReconciliationStatus),
				strconv.Itoa(item.ReconciliationDivergenceCount),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-counterparty-incident-report-amendment csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportAmendmentBundleExport(w http.ResponseWriter, r *http.Request, bundle *securecellsintegration.SecureCellFederationIncidentReportAmendmentBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentBundleResponse{Result: bundle})
		return nil
	case "csv":
		if bundle == nil {
			return fmt.Errorf("federation incident report amendment bundle is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-amendment-bundle.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id", "version", "name", "generated_at", "expires_at", "cell_id", "cell_name", "cell_status", "jurisdiction", "framework",
			"organization_id", "sponsor_of_record", "organization_name", "response_id", "incident_id", "report_id", "report_status",
			"amendment_id", "amendment_sequence", "amendment_status", "report_bundle_hash", "contract_ids", "control_ids",
			"operator_surface_ids", "operator_surface_paths", "control_ledger_id", "control_ledger_hash", "portable_package_hash",
			"portable_package_signed", "portable_package_anchored", "content_hash", "signature_algorithm", "signature_signer",
			"signature_key_id", "signature_signed_at", "metadata",
		}}
		signatureAlgorithm := ""
		signatureSigner := ""
		signatureKeyID := ""
		signatureSignedAt := ""
		if bundle.Signature != nil {
			signatureAlgorithm = bundle.Signature.Algorithm
			signatureSigner = bundle.Signature.Signer
			signatureKeyID = bundle.Signature.KeyID
			signatureSignedAt = bundle.Signature.SignedAt.UTC().Format(time.RFC3339Nano)
		}
		rows = append(rows, []string{
			bundle.ID,
			bundle.Version,
			bundle.Name,
			bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			formatSecureCellOptionalTime(bundle.ExpiresAt),
			bundle.CellID,
			bundle.CellName,
			string(bundle.CellStatus),
			bundle.Jurisdiction,
			bundle.Framework,
			bundle.Organization.OrganizationID,
			bundle.Organization.SponsorOfRecord,
			bundle.Organization.OrganizationName,
			bundle.ResponseSummary.ResponseID,
			bundle.ResponseSummary.IncidentID,
			bundle.ReportSummary.ReportID,
			string(bundle.ReportSummary.Status),
			bundle.AmendmentSummary.AmendmentID,
			strconv.Itoa(bundle.AmendmentSummary.Sequence),
			string(bundle.AmendmentSummary.Status),
			bundle.ReportBundleHash,
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
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-amendment-bundle csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportReconciliationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentReportReconciliationSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportReconciliationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-reconciliations.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"comparison_key",
			"incident_id",
			"regulator",
			"framework",
			"report_type",
			"reporting_party",
			"status",
			"local_report_id",
			"local_response_id",
			"local_report_status",
			"local_due_at",
			"local_updated_at",
			"local_submission_reference",
			"local_acknowledgement_reference",
			"counterparty_snapshot_id",
			"counterparty_bundle_id",
			"counterparty_report_id",
			"counterparty_response_id",
			"counterparty_bundle_status",
			"counterparty_report_status",
			"counterparty_due_at",
			"counterparty_generated_at",
			"counterparty_received_at",
			"counterparty_submission_reference",
			"counterparty_acknowledgement_reference",
			"review_status",
			"last_reviewed_by",
			"last_reviewed_at",
			"review_action_count",
			"divergences",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.Regulator,
				item.Framework,
				item.ReportType,
				string(item.ReportingParty),
				string(item.Status),
				item.LocalReportID,
				item.LocalResponseID,
				string(item.LocalReportStatus),
				formatSecureCellOptionalTime(item.LocalDueAt),
				formatSecureCellOptionalTime(item.LocalUpdatedAt),
				item.LocalSubmissionReference,
				item.LocalAcknowledgementReference,
				item.CounterpartySnapshotID,
				item.CounterpartyBundleID,
				item.CounterpartyReportID,
				item.CounterpartyResponseID,
				string(item.CounterpartyBundleStatus),
				string(item.CounterpartyReportStatus),
				formatSecureCellOptionalTime(item.CounterpartyDueAt),
				formatSecureCellOptionalTime(item.CounterpartyGeneratedAt),
				formatSecureCellOptionalTime(item.CounterpartyReceivedAt),
				item.CounterpartySubmissionReference,
				item.CounterpartyAcknowledgementReference,
				string(item.ReviewStatus),
				item.LastReviewedBy,
				formatSecureCellOptionalTime(item.LastReviewedAt),
				strconv.Itoa(item.ReviewActionCount),
				strings.Join(item.Divergences, "|"),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-reconciliation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportAmendmentReconciliationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentReconciliationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-amendment-reconciliations.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"comparison_key",
			"incident_id",
			"regulator",
			"framework",
			"report_type",
			"reporting_party",
			"status",
			"local_report_id",
			"local_response_id",
			"local_amendment_id",
			"local_amendment_status",
			"local_sequence",
			"local_changed_sections",
			"local_updated_at",
			"local_submission_reference",
			"local_acknowledgement_reference",
			"counterparty_snapshot_id",
			"counterparty_bundle_id",
			"counterparty_report_id",
			"counterparty_response_id",
			"counterparty_amendment_id",
			"counterparty_bundle_status",
			"counterparty_amendment_status",
			"counterparty_sequence",
			"counterparty_changed_sections",
			"counterparty_generated_at",
			"counterparty_received_at",
			"counterparty_submission_reference",
			"counterparty_acknowledgement_reference",
			"review_status",
			"last_reviewed_by",
			"last_reviewed_at",
			"review_action_count",
			"counterparty_attestation_status",
			"last_counterparty_attested_by",
			"last_counterparty_attested_at",
			"counterparty_attestation_count",
			"divergences",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.Regulator,
				item.Framework,
				item.ReportType,
				string(item.ReportingParty),
				string(item.Status),
				item.LocalReportID,
				item.LocalResponseID,
				item.LocalAmendmentID,
				string(item.LocalAmendmentStatus),
				strconv.Itoa(item.LocalSequence),
				strings.Join(item.LocalChangedSections, "|"),
				formatSecureCellOptionalTime(item.LocalUpdatedAt),
				item.LocalSubmissionReference,
				item.LocalAcknowledgementReference,
				item.CounterpartySnapshotID,
				item.CounterpartyBundleID,
				item.CounterpartyReportID,
				item.CounterpartyResponseID,
				item.CounterpartyAmendmentID,
				string(item.CounterpartyBundleStatus),
				string(item.CounterpartyAmendmentStatus),
				strconv.Itoa(item.CounterpartySequence),
				strings.Join(item.CounterpartyChangedSections, "|"),
				formatSecureCellOptionalTime(item.CounterpartyGeneratedAt),
				formatSecureCellOptionalTime(item.CounterpartyReceivedAt),
				item.CounterpartySubmissionReference,
				item.CounterpartyAcknowledgementReference,
				string(item.ReviewStatus),
				item.LastReviewedBy,
				formatSecureCellOptionalTime(item.LastReviewedAt),
				strconv.Itoa(item.ReviewActionCount),
				string(item.CounterpartyAttestationStatus),
				item.LastCounterpartyAttestedBy,
				formatSecureCellOptionalTime(item.LastCounterpartyAttestedAt),
				strconv.Itoa(item.CounterpartyAttestationCount),
				strings.Join(item.Divergences, "|"),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-amendment-reconciliation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-amendment-reconciliation-attestations.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"comparison_key",
			"incident_id",
			"local_report_id",
			"local_response_id",
			"local_amendment_id",
			"counterparty_snapshot_id",
			"counterparty_bundle_id",
			"counterparty_report_id",
			"counterparty_response_id",
			"counterparty_amendment_id",
			"reconciliation_status",
			"review_status",
			"attestation",
			"attestation_status",
			"transition_id",
			"policy_receipt_id",
			"policy_receipt_hash",
			"seal_id",
			"trace_link_id",
			"actor_did",
			"counterparty_reference",
			"reason",
			"occurred_at",
			"metadata",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.LocalReportID,
				item.LocalResponseID,
				item.LocalAmendmentID,
				item.CounterpartySnapshotID,
				item.CounterpartyBundleID,
				item.CounterpartyReportID,
				item.CounterpartyResponseID,
				item.CounterpartyAmendmentID,
				string(item.ReconciliationStatus),
				string(item.ReviewStatus),
				string(item.Attestation),
				string(item.AttestationStatus),
				item.TransitionID,
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				item.SealID,
				item.TraceLinkID,
				item.ActorDID,
				item.CounterpartyReference,
				item.Reason,
				item.OccurredAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-amendment-reconciliation-attestation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportAmendmentReconciliationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentReconciliationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-amendment-reconciliation-actions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"comparison_key",
			"incident_id",
			"local_report_id",
			"local_response_id",
			"local_amendment_id",
			"counterparty_snapshot_id",
			"counterparty_bundle_id",
			"counterparty_report_id",
			"counterparty_response_id",
			"counterparty_amendment_id",
			"reconciliation_status",
			"review_status",
			"action",
			"transition_id",
			"policy_receipt_id",
			"policy_receipt_hash",
			"seal_id",
			"trace_link_id",
			"actor_did",
			"reason",
			"divergences",
			"occurred_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.LocalReportID,
				item.LocalResponseID,
				item.LocalAmendmentID,
				item.CounterpartySnapshotID,
				item.CounterpartyBundleID,
				item.CounterpartyReportID,
				item.CounterpartyResponseID,
				item.CounterpartyAmendmentID,
				string(item.ReconciliationStatus),
				string(item.ReviewStatus),
				string(item.Action),
				item.TransitionID,
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				item.SealID,
				item.TraceLinkID,
				item.ActorDID,
				item.Reason,
				strings.Join(item.Divergences, "|"),
				item.OccurredAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-amendment-reconciliation-action csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellOverdueFederationIncidentReportAmendmentReconciliationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueFederationIncidentReportAmendmentReconciliation) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentReportAmendmentReconciliationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-overdue-federation-incident-report-amendment-reconciliations.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"comparison_key",
			"incident_id",
			"regulator",
			"framework",
			"report_type",
			"reporting_party",
			"status",
			"review_status",
			"attestation_status",
			"automation_action",
			"overdue_reason",
			"due_at",
			"overdue_seconds",
			"review_due_at",
			"counterparty_acknowledge_due_at",
			"resolution_due_at",
			"local_amendment_id",
			"counterparty_amendment_id",
			"last_reviewed_by",
			"last_reviewed_at",
			"last_counterparty_attested_by",
			"last_counterparty_attested_at",
			"divergences",
			"updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.Regulator,
				item.Framework,
				item.ReportType,
				string(item.ReportingParty),
				string(item.Status),
				string(item.ReviewStatus),
				string(item.AttestationStatus),
				item.AutomationAction,
				item.OverdueReason,
				item.DueAt.UTC().Format(time.RFC3339Nano),
				strconv.FormatInt(item.OverdueSeconds, 10),
				formatSecureCellOptionalTime(item.ReviewDueAt),
				formatSecureCellOptionalTime(item.CounterpartyAcknowledgeDueAt),
				formatSecureCellOptionalTime(item.ResolutionDueAt),
				item.LocalAmendmentID,
				item.CounterpartyAmendmentID,
				item.LastReviewedBy,
				formatSecureCellOptionalTime(item.LastReviewedAt),
				item.LastCounterpartyAttestedBy,
				formatSecureCellOptionalTime(item.LastCounterpartyAttestedAt),
				strings.Join(item.Divergences, "|"),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write overdue federation-incident-report-amendment-reconciliation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportAmendmentReconciliationAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentReconciliationAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-amendment-reconciliation-automation-actions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"comparison_key",
			"incident_id",
			"regulator",
			"reconciliation_status",
			"review_status_before",
			"review_status_after",
			"attestation_status_before",
			"attestation_status_after",
			"contract_id",
			"contract_status_before",
			"contract_status_after",
			"action",
			"trigger",
			"due_at",
			"actor",
			"automated_actor",
			"reason",
			"transition_id",
			"occurred_at",
			"metadata",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.ComparisonKey,
				item.IncidentID,
				item.Regulator,
				string(item.ReconciliationStatus),
				string(item.ReviewStatusBefore),
				string(item.ReviewStatusAfter),
				string(item.AttestationStatusBefore),
				string(item.AttestationStatusAfter),
				item.ContractID,
				string(item.ContractStatusBefore),
				string(item.ContractStatusAfter),
				item.Action,
				item.Trigger,
				formatSecureCellOptionalTime(item.DueAt),
				item.Actor,
				item.AutomatedActor,
				item.Reason,
				item.TransitionID,
				item.OccurredAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-amendment-reconciliation-automation-action csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportReconciliationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentReportReconciliationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportReconciliationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-reconciliation-actions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"comparison_key",
			"incident_id",
			"local_report_id",
			"local_response_id",
			"counterparty_snapshot_id",
			"counterparty_bundle_id",
			"counterparty_report_id",
			"counterparty_response_id",
			"reconciliation_status",
			"review_status",
			"action",
			"transition_id",
			"policy_receipt_id",
			"policy_receipt_hash",
			"seal_id",
			"trace_link_id",
			"actor_did",
			"reason",
			"divergences",
			"occurred_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.LocalReportID,
				item.LocalResponseID,
				item.CounterpartySnapshotID,
				item.CounterpartyBundleID,
				item.CounterpartyReportID,
				item.CounterpartyResponseID,
				string(item.ReconciliationStatus),
				string(item.ReviewStatus),
				string(item.Action),
				item.TransitionID,
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				item.SealID,
				item.TraceLinkID,
				item.ActorDID,
				item.Reason,
				strings.Join(item.Divergences, "|"),
				item.OccurredAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-reconciliation-action csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellOverdueFederationIncidentReportReconciliationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueFederationIncidentReportReconciliation) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentReportReconciliationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-overdue-federation-incident-report-reconciliations.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"comparison_key",
			"incident_id",
			"regulator",
			"framework",
			"report_type",
			"reporting_party",
			"status",
			"review_status",
			"automation_action",
			"overdue_reason",
			"due_at",
			"overdue_seconds",
			"review_due_at",
			"resolution_due_at",
			"local_report_id",
			"counterparty_report_id",
			"last_reviewed_by",
			"last_reviewed_at",
			"divergences",
			"updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.Regulator,
				item.Framework,
				item.ReportType,
				string(item.ReportingParty),
				string(item.Status),
				string(item.ReviewStatus),
				item.AutomationAction,
				item.OverdueReason,
				item.DueAt.UTC().Format(time.RFC3339Nano),
				strconv.FormatInt(item.OverdueSeconds, 10),
				formatSecureCellOptionalTime(item.ReviewDueAt),
				formatSecureCellOptionalTime(item.ResolutionDueAt),
				item.LocalReportID,
				item.CounterpartyReportID,
				item.LastReviewedBy,
				formatSecureCellOptionalTime(item.LastReviewedAt),
				strings.Join(item.Divergences, "|"),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write overdue federation-incident-report-reconciliation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportReconciliationAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentReportReconciliationAutomationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportReconciliationAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-reconciliation-automation-actions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"cell_name",
			"jurisdiction",
			"cell_status",
			"organization_id",
			"sponsor_of_record",
			"comparison_key",
			"incident_id",
			"regulator",
			"reconciliation_status",
			"review_status_before",
			"review_status_after",
			"contract_id",
			"contract_status_before",
			"contract_status_after",
			"action",
			"trigger",
			"due_at",
			"actor",
			"automated_actor",
			"reason",
			"transition_id",
			"occurred_at",
			"metadata",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.ComparisonKey,
				item.IncidentID,
				item.Regulator,
				string(item.ReconciliationStatus),
				string(item.ReviewStatusBefore),
				string(item.ReviewStatusAfter),
				item.ContractID,
				string(item.ContractStatusBefore),
				string(item.ContractStatusAfter),
				item.Action,
				item.Trigger,
				formatSecureCellOptionalTime(item.DueAt),
				item.Actor,
				item.AutomatedActor,
				item.Reason,
				item.TransitionID,
				item.OccurredAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellStringMap(item.Metadata),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-reconciliation-automation-action csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportReconciliationBundleExport(w http.ResponseWriter, r *http.Request, bundle *securecellsintegration.SecureCellFederationIncidentReportReconciliationBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportReconciliationBundleResponse{Result: bundle})
		return nil
	case "csv":
		if bundle == nil {
			return fmt.Errorf("federation incident report reconciliation bundle is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-reconciliation-bundle.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id",
			"version",
			"name",
			"generated_at",
			"expires_at",
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"framework",
			"organization_id",
			"organization_name",
			"comparison_key",
			"incident_id",
			"reconciliation_status",
			"review_status",
			"action_count",
			"local_report_id",
			"counterparty_report_id",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"content_hash",
			"signature_key_id",
			"signature_signer",
			"signature_signed_at",
		}}
		signatureKeyID := ""
		signatureSigner := ""
		signatureSignedAt := ""
		if bundle.Signature != nil {
			signatureKeyID = bundle.Signature.KeyID
			signatureSigner = bundle.Signature.Signer
			signatureSignedAt = bundle.Signature.SignedAt.UTC().Format(time.RFC3339Nano)
		}
		rows = append(rows, []string{
			bundle.ID,
			bundle.Version,
			bundle.Name,
			bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			formatSecureCellOptionalTime(bundle.ExpiresAt),
			bundle.CellID,
			bundle.CellName,
			string(bundle.CellStatus),
			bundle.Jurisdiction,
			bundle.Framework,
			bundle.Organization.OrganizationID,
			bundle.Organization.OrganizationName,
			bundle.Reconciliation.ComparisonKey,
			bundle.Reconciliation.IncidentID,
			string(bundle.Reconciliation.Status),
			string(bundle.Reconciliation.ReviewStatus),
			strconv.Itoa(len(bundle.Actions)),
			bundle.Reconciliation.LocalReportID,
			bundle.Reconciliation.CounterpartyReportID,
			bundle.ControlLedgerID,
			bundle.ControlLedgerHash,
			bundle.PortablePackageHash,
			strconv.FormatBool(bundle.PortablePackageSigned),
			strconv.FormatBool(bundle.PortablePackageAnchored),
			bundle.ContentHash,
			signatureKeyID,
			signatureSigner,
			signatureSignedAt,
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-reconciliation-bundle csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentReportAmendmentReconciliationBundleExport(w http.ResponseWriter, r *http.Request, bundle *securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentReconciliationBundleResponse{Result: bundle})
		return nil
	case "csv":
		if bundle == nil {
			return fmt.Errorf("federation incident report amendment reconciliation bundle is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-report-amendment-reconciliation-bundle.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id",
			"version",
			"name",
			"generated_at",
			"expires_at",
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"framework",
			"organization_id",
			"organization_name",
			"comparison_key",
			"incident_id",
			"reconciliation_status",
			"review_status",
			"action_count",
			"local_amendment_id",
			"counterparty_amendment_id",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"content_hash",
			"signature_key_id",
			"signature_signer",
			"signature_signed_at",
		}}
		signatureKeyID := ""
		signatureSigner := ""
		signatureSignedAt := ""
		if bundle.Signature != nil {
			signatureKeyID = bundle.Signature.KeyID
			signatureSigner = bundle.Signature.Signer
			signatureSignedAt = bundle.Signature.SignedAt.UTC().Format(time.RFC3339Nano)
		}
		rows = append(rows, []string{
			bundle.ID,
			bundle.Version,
			bundle.Name,
			bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			formatSecureCellOptionalTime(bundle.ExpiresAt),
			bundle.CellID,
			bundle.CellName,
			string(bundle.CellStatus),
			bundle.Jurisdiction,
			bundle.Framework,
			bundle.Organization.OrganizationID,
			bundle.Organization.OrganizationName,
			bundle.Reconciliation.ComparisonKey,
			bundle.Reconciliation.IncidentID,
			string(bundle.Reconciliation.Status),
			string(bundle.Reconciliation.ReviewStatus),
			strconv.Itoa(len(bundle.Actions)),
			bundle.Reconciliation.LocalAmendmentID,
			bundle.Reconciliation.CounterpartyAmendmentID,
			bundle.ControlLedgerID,
			bundle.ControlLedgerHash,
			bundle.PortablePackageHash,
			strconv.FormatBool(bundle.PortablePackageSigned),
			strconv.FormatBool(bundle.PortablePackageAnchored),
			bundle.ContentHash,
			signatureKeyID,
			signatureSigner,
			signatureSignedAt,
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-report-amendment-reconciliation-bundle csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationIncidentBulletinExport(w http.ResponseWriter, r *http.Request, bulletin *securecellsintegration.SecureCellFederationIncidentBulletin) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentBulletinResponse{Result: bulletin})
		return nil
	case "csv":
		if bulletin == nil {
			return fmt.Errorf("federation incident bulletin is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-bulletin.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id",
			"version",
			"name",
			"generated_at",
			"expires_at",
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"framework",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"organization_status",
			"runtime_contract_count",
			"runtime_active_contracts",
			"incident_count",
			"open_incident_count",
			"critical_incident_count",
			"high_incident_count",
			"contract_ids",
			"incident_ids",
			"operator_surface_ids",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"content_hash",
			"signature_algorithm",
			"signature_signer",
			"signature_key_id",
			"signature_signed_at",
			"metadata",
		}}
		signatureAlgorithm := ""
		signatureSigner := ""
		signatureKeyID := ""
		signatureSignedAt := ""
		if bulletin.Signature != nil {
			signatureAlgorithm = bulletin.Signature.Algorithm
			signatureSigner = bulletin.Signature.Signer
			signatureKeyID = bulletin.Signature.KeyID
			signatureSignedAt = bulletin.Signature.SignedAt.UTC().Format(time.RFC3339Nano)
		}
		incidentIDs := make([]string, 0, len(bulletin.Incidents))
		openIncidentCount := 0
		criticalIncidentCount := 0
		highIncidentCount := 0
		for _, incident := range bulletin.Incidents {
			if trimmed := strings.TrimSpace(incident.IncidentID); trimmed != "" {
				incidentIDs = append(incidentIDs, trimmed)
			}
			if incident.Status == securecellsintegration.SecureCellFederationIncidentStatusOpen {
				openIncidentCount++
			}
			if incident.Severity == securecellsintegration.SecureCellFederationIncidentSeverityCritical {
				criticalIncidentCount++
			}
			if incident.Severity == securecellsintegration.SecureCellFederationIncidentSeverityHigh {
				highIncidentCount++
			}
		}
		rows = append(rows, []string{
			bulletin.ID,
			bulletin.Version,
			bulletin.Name,
			bulletin.GeneratedAt.UTC().Format(time.RFC3339Nano),
			formatSecureCellOptionalTime(bulletin.ExpiresAt),
			bulletin.CellID,
			bulletin.CellName,
			string(bulletin.CellStatus),
			bulletin.Jurisdiction,
			bulletin.Framework,
			bulletin.Organization.OrganizationID,
			bulletin.Organization.SponsorOfRecord,
			bulletin.Organization.OrganizationName,
			string(bulletin.Organization.Status),
			strconv.Itoa(bulletin.Runtime.ContractCount),
			strconv.Itoa(bulletin.Runtime.ActiveContracts),
			strconv.Itoa(len(bulletin.Incidents)),
			strconv.Itoa(openIncidentCount),
			strconv.Itoa(criticalIncidentCount),
			strconv.Itoa(highIncidentCount),
			joinSecureCellFederationContractIDs(bulletin.Contracts),
			strings.Join(incidentIDs, "|"),
			joinSecureCellFederationOperatorSurfaceIDs(bulletin.OperatorSurfaces),
			bulletin.ControlLedgerID,
			bulletin.ControlLedgerHash,
			bulletin.PortablePackageHash,
			strconv.FormatBool(bulletin.PortablePackageSigned),
			strconv.FormatBool(bulletin.PortablePackageAnchored),
			bulletin.ContentHash,
			signatureAlgorithm,
			signatureSigner,
			signatureKeyID,
			signatureSignedAt,
			formatSecureCellStringMap(bulletin.Metadata),
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-incident-bulletin csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationAssuranceBundleExport(w http.ResponseWriter, r *http.Request, bundle *securecellsintegration.SecureCellFederationAssuranceBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationAssuranceBundleResponse{Result: bundle})
		return nil
	case "csv":
		if bundle == nil {
			return fmt.Errorf("federation assurance bundle is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-assurance-bundle.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id",
			"version",
			"name",
			"generated_at",
			"expires_at",
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"framework",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"runtime_active_participants",
			"runtime_active_contracts",
			"contract_ids",
			"assurance_finding_count",
			"assurance_critical_finding_count",
			"assurance_warning_finding_count",
			"assurance_info_finding_count",
			"require_confidential_compute",
			"confidential_execution_verified",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"content_hash",
			"signature_algorithm",
			"signature_signer",
			"signature_key_id",
			"signature_signed_at",
			"operator_surface_ids",
			"metadata",
		}}
		signatureAlgorithm := ""
		signatureSigner := ""
		signatureKeyID := ""
		signatureSignedAt := ""
		if bundle.Signature != nil {
			signatureAlgorithm = bundle.Signature.Algorithm
			signatureSigner = bundle.Signature.Signer
			signatureKeyID = bundle.Signature.KeyID
			signatureSignedAt = bundle.Signature.SignedAt.UTC().Format(time.RFC3339Nano)
		}
		operatorSurfaceIDs := make([]string, 0, len(bundle.OperatorSurfaces))
		for _, item := range bundle.OperatorSurfaces {
			if trimmed := strings.TrimSpace(item.ID); trimmed != "" {
				operatorSurfaceIDs = append(operatorSurfaceIDs, trimmed)
			}
		}
		rows = append(rows, []string{
			bundle.ID,
			bundle.Version,
			bundle.Name,
			bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			formatSecureCellOptionalTime(bundle.ExpiresAt),
			bundle.CellID,
			bundle.CellName,
			string(bundle.CellStatus),
			bundle.Jurisdiction,
			bundle.Framework,
			bundle.Organization.OrganizationID,
			bundle.Organization.SponsorOfRecord,
			bundle.Organization.OrganizationName,
			strconv.Itoa(bundle.Runtime.ActiveParticipantCount),
			strconv.Itoa(bundle.Runtime.ActiveContracts),
			joinSecureCellFederationContractIDs(bundle.Contracts),
			strconv.Itoa(bundle.Assurance.FindingCount),
			strconv.Itoa(bundle.Assurance.CriticalFindingCount),
			strconv.Itoa(bundle.Assurance.WarningFindingCount),
			strconv.Itoa(bundle.Assurance.InfoFindingCount),
			strconv.FormatBool(bundle.Assurance.RequireConfidentialCompute),
			strconv.FormatBool(bundle.Assurance.ConfidentialExecutionVerified),
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
			strings.Join(operatorSurfaceIDs, "|"),
			formatSecureCellStringMap(bundle.Metadata),
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation-assurance-bundle csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationTrustPackExport(w http.ResponseWriter, r *http.Request, pack *securecellsintegration.SecureCellFederationOrganizationTrustPack) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationTrustPackResponse{Result: pack})
		return nil
	case "csv":
		if pack == nil {
			return fmt.Errorf("federation trust pack is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-trust-pack.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id",
			"version",
			"name",
			"sector",
			"generated_at",
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"framework",
			"policy_set_id",
			"policy_set_name",
			"required_tool",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"organization_status",
			"organization_participant_dids",
			"organization_participant_count",
			"organization_active_participant_count",
			"runtime_participant_count",
			"runtime_active_participant_count",
			"runtime_quarantined_participants",
			"runtime_revoked_participants",
			"runtime_invitation_count",
			"runtime_pending_invitations",
			"runtime_accepted_invitations",
			"runtime_revoked_invitations",
			"runtime_counterproposal_count",
			"runtime_pending_counterproposals",
			"runtime_approved_counterproposals",
			"runtime_rejected_counterproposals",
			"runtime_superseded_counterproposals",
			"runtime_contract_count",
			"runtime_active_contracts",
			"runtime_suspended_contracts",
			"runtime_revoked_contracts",
			"runtime_last_updated_at",
			"invitation_ids",
			"counterproposal_ids",
			"contract_ids",
			"assurance_report_id",
			"assurance_generated_at",
			"assurance_finding_count",
			"assurance_critical_finding_count",
			"assurance_warning_finding_count",
			"assurance_info_finding_count",
			"assurance_auto_containment_eligible_count",
			"counterparty_assurance_snapshot_ids",
			"counterparty_assurance_bundle_ids",
			"counterparty_assurance_statuses",
			"control_ids",
			"operator_surface_ids",
			"operator_surface_paths",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
		}}
		rows = append(rows, []string{
			pack.ID,
			pack.Version,
			pack.Name,
			pack.Sector,
			pack.GeneratedAt.UTC().Format(time.RFC3339Nano),
			pack.CellID,
			pack.CellName,
			string(pack.CellStatus),
			pack.Jurisdiction,
			pack.Framework,
			pack.PolicySetID,
			pack.PolicySetName,
			pack.RequiredTool,
			pack.Organization.OrganizationID,
			pack.Organization.SponsorOfRecord,
			pack.Organization.OrganizationName,
			string(pack.Organization.Status),
			strings.Join(pack.Organization.ParticipantDIDs, "|"),
			strconv.Itoa(pack.Organization.ParticipantCount),
			strconv.Itoa(pack.Organization.ActiveParticipantCount),
			strconv.Itoa(pack.Runtime.ParticipantCount),
			strconv.Itoa(pack.Runtime.ActiveParticipantCount),
			strconv.Itoa(pack.Runtime.QuarantinedParticipants),
			strconv.Itoa(pack.Runtime.RevokedParticipants),
			strconv.Itoa(pack.Runtime.InvitationCount),
			strconv.Itoa(pack.Runtime.PendingInvitations),
			strconv.Itoa(pack.Runtime.AcceptedInvitations),
			strconv.Itoa(pack.Runtime.RevokedInvitations),
			strconv.Itoa(pack.Runtime.CounterproposalCount),
			strconv.Itoa(pack.Runtime.PendingCounterproposals),
			strconv.Itoa(pack.Runtime.ApprovedCounterproposals),
			strconv.Itoa(pack.Runtime.RejectedCounterproposals),
			strconv.Itoa(pack.Runtime.SupersededCounterproposals),
			strconv.Itoa(pack.Runtime.ContractCount),
			strconv.Itoa(pack.Runtime.ActiveContracts),
			strconv.Itoa(pack.Runtime.SuspendedContracts),
			strconv.Itoa(pack.Runtime.RevokedContracts),
			pack.Runtime.LastUpdatedAt.UTC().Format(time.RFC3339Nano),
			joinSecureCellFederationInvitationIDs(pack.Invitations),
			joinSecureCellFederationCounterproposalIDs(pack.Counterproposals),
			joinSecureCellFederationContractIDs(pack.Contracts),
			safeSecureCellFederationAssuranceReportID(pack.Assurance),
			safeSecureCellFederationAssuranceGeneratedAt(pack.Assurance),
			strconv.Itoa(safeSecureCellFederationAssuranceFindingCount(pack.Assurance)),
			strconv.Itoa(safeSecureCellFederationAssuranceCriticalFindingCount(pack.Assurance)),
			strconv.Itoa(safeSecureCellFederationAssuranceWarningFindingCount(pack.Assurance)),
			strconv.Itoa(safeSecureCellFederationAssuranceInfoFindingCount(pack.Assurance)),
			strconv.Itoa(safeSecureCellFederationAssuranceAutoContainmentEligibleCount(pack.Assurance)),
			joinSecureCellFederationCounterpartyAssuranceSnapshotIDs(pack.CounterpartyAssurance),
			joinSecureCellFederationCounterpartyAssuranceBundleIDs(pack.CounterpartyAssurance),
			joinSecureCellFederationCounterpartyAssuranceStatuses(pack.CounterpartyAssurance),
			joinSecureCellFederationControlIDs(pack.Controls),
			joinSecureCellFederationOperatorSurfaceIDs(pack.OperatorSurfaces),
			joinSecureCellFederationOperatorSurfacePaths(pack.OperatorSurfaces),
			pack.ControlLedgerID,
			pack.ControlLedgerHash,
			pack.PortablePackageHash,
			strconv.FormatBool(pack.PortablePackageSigned),
			strconv.FormatBool(pack.PortablePackageAnchored),
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation trust-pack csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationInvitationBundleExport(w http.ResponseWriter, r *http.Request, bundle *securecellsintegration.SecureCellFederationInvitationBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationInvitationBundleResponse{Result: bundle})
		return nil
	case "csv":
		if bundle == nil {
			return fmt.Errorf("federation invitation bundle is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-invitation-bundle.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id",
			"version",
			"name",
			"generated_at",
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"framework",
			"organization_id",
			"sponsor_of_record",
			"organization_name",
			"organization_status",
			"invitation_id",
			"invitation_status",
			"expected_did",
			"role",
			"resource",
			"session_scope_count",
			"offered_session_scope_count",
			"data_class_count",
			"offered_data_class_count",
			"compute_zone_count",
			"offered_compute_zone_count",
			"allowed_action_count",
			"offered_action_count",
			"negotiation_diff_count",
			"created_by",
			"accepted_by",
			"revoked_by",
			"reason",
			"contract_id",
			"counterproposal_ids",
			"control_ids",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
		}}
		rows = append(rows, []string{
			bundle.ID,
			bundle.Version,
			bundle.Name,
			bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			bundle.CellID,
			bundle.CellName,
			string(bundle.CellStatus),
			bundle.Jurisdiction,
			bundle.Framework,
			bundle.Organization.OrganizationID,
			bundle.Organization.SponsorOfRecord,
			bundle.Organization.OrganizationName,
			string(bundle.Organization.Status),
			bundle.Invitation.InvitationID,
			string(bundle.Invitation.Status),
			bundle.Invitation.ExpectedDID,
			bundle.Invitation.Role,
			bundle.Invitation.Resource,
			strconv.Itoa(bundle.Invitation.SessionScopeCount),
			strconv.Itoa(bundle.Invitation.OfferedSessionScopeCount),
			strconv.Itoa(bundle.Invitation.DataClassCount),
			strconv.Itoa(bundle.Invitation.OfferedDataClassCount),
			strconv.Itoa(bundle.Invitation.ComputeZoneCount),
			strconv.Itoa(bundle.Invitation.OfferedComputeZoneCount),
			strconv.Itoa(bundle.Invitation.AllowedActionCount),
			strconv.Itoa(bundle.Invitation.OfferedActionCount),
			strconv.Itoa(bundle.Invitation.NegotiationDiffCount),
			bundle.Invitation.CreatedBy,
			bundle.Invitation.AcceptedBy,
			bundle.Invitation.RevokedBy,
			bundle.Invitation.Reason,
			secureCellOptionalFederationContractID(bundle.Contract),
			joinSecureCellFederationCounterproposalIDs(bundle.Counterproposals),
			joinSecureCellFederationControlIDs(bundle.Controls),
			bundle.ControlLedgerID,
			bundle.ControlLedgerHash,
			bundle.PortablePackageHash,
			strconv.FormatBool(bundle.PortablePackageSigned),
			strconv.FormatBool(bundle.PortablePackageAnchored),
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation invitation-bundle csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellFederationContractBundleExport(w http.ResponseWriter, r *http.Request, bundle *securecellsintegration.SecureCellFederationContractBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationContractBundleResponse{Result: bundle})
		return nil
	case "csv":
		if bundle == nil {
			return fmt.Errorf("federation contract bundle is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-contract-bundle.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"id",
			"version",
			"name",
			"generated_at",
			"cell_id",
			"cell_name",
			"cell_status",
			"jurisdiction",
			"framework",
			"organization_id",
			"organization_name",
			"organization_status",
			"invitation_id",
			"contract_id",
			"contract_status",
			"participant_dids",
			"session_scope_ids",
			"offered_session_scope_ids",
			"data_classes",
			"offered_data_classes",
			"compute_zones",
			"offered_compute_zones",
			"allowed_actions",
			"offered_actions",
			"negotiation_diff_count",
			"negotiation_diffs",
			"resource",
			"negotiation_id",
			"credential_id",
			"policy_receipt_id",
			"policy_receipt_hash",
			"revision",
			"supersedes_contract_id",
			"replaced_by_contract_id",
			"control_ids",
			"operator_surface_ids",
			"operator_surface_paths",
			"control_ledger_id",
			"control_ledger_hash",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
		}}
		rows = append(rows, []string{
			bundle.ID,
			bundle.Version,
			bundle.Name,
			bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			bundle.CellID,
			bundle.CellName,
			string(bundle.CellStatus),
			bundle.Jurisdiction,
			bundle.Framework,
			bundle.Organization.OrganizationID,
			bundle.Organization.OrganizationName,
			string(bundle.Organization.Status),
			secureCellOptionalFederationInvitationID(bundle.Invitation),
			bundle.Contract.ContractID,
			string(bundle.Contract.Status),
			strings.Join(bundle.Contract.ParticipantDIDs, "|"),
			strings.Join(bundle.Contract.SessionScopeIDs, "|"),
			strings.Join(bundle.Contract.OfferedSessionScopeIDs, "|"),
			strings.Join(bundle.Contract.DataClasses, "|"),
			strings.Join(bundle.Contract.OfferedDataClasses, "|"),
			strings.Join(bundle.Contract.ComputeZones, "|"),
			strings.Join(bundle.Contract.OfferedComputeZones, "|"),
			strings.Join(bundle.Contract.AllowedActions, "|"),
			strings.Join(bundle.Contract.OfferedActions, "|"),
			strconv.Itoa(bundle.Contract.NegotiationDiffCount),
			secureCellFederationPolicyDiffSummaryCSV(bundle.Contract.NegotiationDiffs),
			bundle.Contract.Resource,
			bundle.Contract.NegotiationID,
			bundle.Contract.CredentialID,
			bundle.Contract.PolicyReceiptID,
			bundle.Contract.PolicyReceiptHash,
			strconv.Itoa(bundle.Contract.Revision),
			bundle.Contract.SupersedesContractID,
			bundle.Contract.ReplacedByContractID,
			joinSecureCellFederationControlIDs(bundle.Controls),
			joinSecureCellFederationOperatorSurfaceIDs(bundle.OperatorSurfaces),
			joinSecureCellFederationOperatorSurfacePaths(bundle.OperatorSurfaces),
			bundle.ControlLedgerID,
			bundle.ControlLedgerHash,
			bundle.PortablePackageHash,
			strconv.FormatBool(bundle.PortablePackageSigned),
			strconv.FormatBool(bundle.PortablePackageAnchored),
		})
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write federation contract-bundle csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellExportFormat(r *http.Request) string {
	if r == nil {
		return "json"
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		return "json"
	}
	return format
}

func formatSecureCellOptionalTime(in *time.Time) string {
	if in == nil || in.IsZero() {
		return ""
	}
	return in.UTC().Format(time.RFC3339Nano)
}

func formatSecureCellStringMap(in map[string]string) string {
	if len(in) == 0 {
		return ""
	}
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]string, 0, len(keys))
	for _, key := range keys {
		items = append(items, key+"="+in[key])
	}
	return strings.Join(items, "|")
}

func joinSecureCellDecisionVoteChoiceStrings(choices []securecellsintegration.SecureCellThreadDecisionVoteChoice) string {
	out := make([]string, 0, len(choices))
	for _, choice := range choices {
		if trimmed := strings.TrimSpace(string(choice)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func formatSecureCellDecisionSLATiers(tiers []securecellsintegration.SecureCellDecisionSLATemplateSummaryTier) string {
	if len(tiers) == 0 {
		return ""
	}
	formatted := make([]string, 0, len(tiers))
	for _, tier := range tiers {
		target := tier.TargetRole
		if strings.TrimSpace(target) == "" {
			target = tier.TargetDID
		}
		formatted = append(formatted, strings.TrimSpace(strings.Join([]string{
			tier.TierID,
			string(tier.Mode),
			target,
			tier.After,
		}, ":")))
	}
	return strings.Join(formatted, ";")
}

func joinSecureCellFederationControlIDs(controls []securecellsintegration.SecureCellFederationTrustPackControl) string {
	out := make([]string, 0, len(controls))
	for _, control := range controls {
		if trimmed := strings.TrimSpace(control.ControlID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func joinSecureCellFederationInvitationIDs(items []securecellsintegration.SecureCellFederationInvitationSummary) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item.InvitationID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func joinSecureCellFederationCounterproposalIDs(items []securecellsintegration.SecureCellFederationCounterproposalSummary) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item.CounterproposalID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func joinSecureCellFederationContractIDs(items []securecellsintegration.SecureCellFederationContractSummary) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item.ContractID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func joinSecureCellFederationAssuranceFindingIDs(items []securecellsintegration.SecureCellFederationAssuranceFinding) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item.ID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func joinSecureCellFederationAssuranceFindingCategories(items []securecellsintegration.SecureCellFederationAssuranceFinding) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(string(item.Category)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func joinSecureCellFederationAssuranceActionIDs(items []securecellsintegration.SecureCellFederationAssuranceActionRecord) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item.TransitionID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func joinSecureCellFederationCounterpartyAssuranceSnapshotIDs(items []securecellsintegration.SecureCellFederationCounterpartyAssuranceSummary) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item.SnapshotID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func joinSecureCellFederationCounterpartyAssuranceBundleIDs(items []securecellsintegration.SecureCellFederationCounterpartyAssuranceSummary) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item.BundleID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func joinSecureCellFederationCounterpartyAssuranceStatuses(items []securecellsintegration.SecureCellFederationCounterpartyAssuranceSummary) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(string(item.Status)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func joinSecureCellFederationOperatorSurfaceIDs(items []securecellsintegration.SecureCellFederationOperatorSurface) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item.ID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func joinSecureCellFederationOperatorSurfacePaths(items []securecellsintegration.SecureCellFederationOperatorSurface) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item.Path); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, "|")
}

func safeSecureCellFederationAssuranceReportID(report *securecellsintegration.SecureCellFederationAssuranceReport) string {
	if report == nil {
		return ""
	}
	return strings.TrimSpace(report.ID)
}

func safeSecureCellFederationAssuranceGeneratedAt(report *securecellsintegration.SecureCellFederationAssuranceReport) string {
	if report == nil || report.GeneratedAt.IsZero() {
		return ""
	}
	return report.GeneratedAt.UTC().Format(time.RFC3339Nano)
}

func safeSecureCellFederationAssuranceFindingCount(report *securecellsintegration.SecureCellFederationAssuranceReport) int {
	if report == nil {
		return 0
	}
	return report.FindingCount
}

func safeSecureCellFederationAssuranceCriticalFindingCount(report *securecellsintegration.SecureCellFederationAssuranceReport) int {
	if report == nil {
		return 0
	}
	return report.CriticalFindingCount
}

func safeSecureCellFederationAssuranceWarningFindingCount(report *securecellsintegration.SecureCellFederationAssuranceReport) int {
	if report == nil {
		return 0
	}
	return report.WarningFindingCount
}

func safeSecureCellFederationAssuranceInfoFindingCount(report *securecellsintegration.SecureCellFederationAssuranceReport) int {
	if report == nil {
		return 0
	}
	return report.InfoFindingCount
}

func safeSecureCellFederationAssuranceAutoContainmentEligibleCount(report *securecellsintegration.SecureCellFederationAssuranceReport) int {
	if report == nil {
		return 0
	}
	return report.AutoContainmentEligibleCount
}

func secureCellOptionalFederationContractID(contract *securecellsintegration.SecureCellFederationContractSummary) string {
	if contract == nil {
		return ""
	}
	return strings.TrimSpace(contract.ContractID)
}

func secureCellFederationPolicyDiffSummaryCSV(diffs []securecellsintegration.SecureCellFederationPolicyDiff) string {
	if len(diffs) == 0 {
		return ""
	}
	items := make([]string, 0, len(diffs))
	for _, diff := range diffs {
		field := strings.TrimSpace(diff.Field)
		if field == "" {
			continue
		}
		effect := strings.TrimSpace(diff.Effect)
		negotiated := strings.Join(diff.NegotiatedValues, "|")
		items = append(items, strings.Trim(strings.Join([]string{field, effect, negotiated}, ":"), ":"))
	}
	return strings.Join(items, ";")
}

func secureCellOptionalFederationInvitationID(invitation *securecellsintegration.SecureCellFederationInvitationSummary) string {
	if invitation == nil {
		return ""
	}
	return strings.TrimSpace(invitation.InvitationID)
}
