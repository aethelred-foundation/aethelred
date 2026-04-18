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
			"contract_count",
			"active_contract_count",
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
				strconv.Itoa(item.ContractCount),
				strconv.Itoa(item.ActiveContractCount),
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
			"data_classes",
			"data_class_count",
			"compute_zones",
			"compute_zone_count",
			"allowed_actions",
			"resource",
			"negotiation_id",
			"credential_id",
			"policy_receipt_id",
			"policy_receipt_hash",
			"control_ledger_id",
			"portable_package_hash",
			"portable_package_signed",
			"portable_package_anchored",
			"created_at",
			"activated_at",
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
				strings.Join(item.DataClasses, "|"),
				strconv.Itoa(item.DataClassCount),
				strings.Join(item.ComputeZones, "|"),
				strconv.Itoa(item.ComputeZoneCount),
				strings.Join(item.AllowedActions, "|"),
				item.Resource,
				item.NegotiationID,
				item.CredentialID,
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				item.ControlLedgerID,
				item.PortablePackageHash,
				strconv.FormatBool(item.PortablePackageSigned),
				strconv.FormatBool(item.PortablePackageAnchored),
				item.CreatedAt.UTC().Format(time.RFC3339Nano),
				formatSecureCellOptionalTime(item.ActivatedAt),
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
			"runtime_contract_count",
			"runtime_active_contracts",
			"runtime_revoked_contracts",
			"runtime_last_updated_at",
			"invitation_ids",
			"contract_ids",
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
			strconv.Itoa(pack.Runtime.ContractCount),
			strconv.Itoa(pack.Runtime.ActiveContracts),
			strconv.Itoa(pack.Runtime.RevokedContracts),
			pack.Runtime.LastUpdatedAt.UTC().Format(time.RFC3339Nano),
			joinSecureCellFederationInvitationIDs(pack.Invitations),
			joinSecureCellFederationContractIDs(pack.Contracts),
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
			"data_class_count",
			"compute_zone_count",
			"created_by",
			"accepted_by",
			"revoked_by",
			"reason",
			"contract_id",
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
			strconv.Itoa(bundle.Invitation.DataClassCount),
			strconv.Itoa(bundle.Invitation.ComputeZoneCount),
			bundle.Invitation.CreatedBy,
			bundle.Invitation.AcceptedBy,
			bundle.Invitation.RevokedBy,
			bundle.Invitation.Reason,
			secureCellOptionalFederationContractID(bundle.Contract),
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
			"data_classes",
			"compute_zones",
			"allowed_actions",
			"resource",
			"negotiation_id",
			"credential_id",
			"policy_receipt_id",
			"policy_receipt_hash",
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
			strings.Join(bundle.Contract.DataClasses, "|"),
			strings.Join(bundle.Contract.ComputeZones, "|"),
			strings.Join(bundle.Contract.AllowedActions, "|"),
			bundle.Contract.Resource,
			bundle.Contract.NegotiationID,
			bundle.Contract.CredentialID,
			bundle.Contract.PolicyReceiptID,
			bundle.Contract.PolicyReceiptHash,
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

func joinSecureCellFederationContractIDs(items []securecellsintegration.SecureCellFederationContractSummary) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item.ContractID); trimmed != "" {
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

func secureCellOptionalFederationContractID(contract *securecellsintegration.SecureCellFederationContractSummary) string {
	if contract == nil {
		return ""
	}
	return strings.TrimSpace(contract.ContractID)
}

func secureCellOptionalFederationInvitationID(invitation *securecellsintegration.SecureCellFederationInvitationSummary) string {
	if invitation == nil {
		return ""
	}
	return strings.TrimSpace(invitation.InvitationID)
}
