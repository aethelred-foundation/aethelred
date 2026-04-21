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
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_title", "directive_status", "extension_id", "requesting_party", "reviewing_party", "requested_by", "summary", "status", "review_approval_threshold", "eligible_reviewer_count", "review_delegation_count", "review_committee_member_count", "review_recorded_vote_count", "review_outstanding_votes", "review_missing_quorum_count", "approve_vote_count", "reject_vote_count", "review_threshold_satisfied", "dispute_resolution_threshold", "eligible_resolver_count", "dispute_count", "pending_dispute_count", "last_dispute_id", "last_dispute_status", "current_due_at", "proposed_due_at", "decision_summary", "reviewed_by", "reviewed_at", "created_at", "updated_at"}); err != nil {
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
				strconv.Itoa(item.ReviewApprovalThreshold),
				strconv.Itoa(item.EligibleReviewerCount),
				strconv.Itoa(item.ReviewDelegationCount),
				strconv.Itoa(item.ReviewCommitteeMemberCount),
				strconv.Itoa(item.ReviewRecordedVoteCount),
				strconv.Itoa(item.ReviewOutstandingVotes),
				strconv.Itoa(item.ReviewMissingQuorumCount),
				strconv.Itoa(item.ApproveVoteCount),
				strconv.Itoa(item.RejectVoteCount),
				strconv.FormatBool(item.ReviewThresholdSatisfied),
				strconv.Itoa(item.DisputeResolutionThreshold),
				strconv.Itoa(item.EligibleResolverCount),
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
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_title", "directive_status", "extension_id", "extension_status", "requesting_party", "reviewing_party", "pending_dispute_id", "pending_action", "automation_action", "overdue_reason", "committee_threshold", "committee_member_count", "committee_delegation_count", "committee_recorded_vote_count", "committee_outstanding_votes", "committee_missing_quorum_count", "committee_quorum_satisfied", "tier_id", "target_did", "due_at", "review_due_at", "resolution_due_at", "overdue_seconds", "updated_at"}); err != nil {
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
				strconv.Itoa(item.CommitteeThreshold),
				strconv.Itoa(item.CommitteeMemberCount),
				strconv.Itoa(item.CommitteeDelegationCount),
				strconv.Itoa(item.CommitteeRecordedVoteCount),
				strconv.Itoa(item.CommitteeOutstandingVotes),
				strconv.Itoa(item.CommitteeMissingQuorumCount),
				strconv.FormatBool(item.CommitteeQuorumSatisfied),
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
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_title", "directive_status", "extension_id", "extension_status", "dispute_id", "challenging_party", "responding_party", "challenged_status", "disputed_by", "summary", "status", "resolution_threshold", "eligible_resolver_count", "resolution_delegation_count", "resolution_committee_member_count", "resolution_recorded_vote_count", "resolution_outstanding_votes", "resolution_missing_quorum_count", "uphold_vote_count", "reverse_vote_count", "resolution_threshold_satisfied", "resolution", "resolution_summary", "resolved_by", "resolved_at", "created_at", "updated_at"}); err != nil {
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
				strconv.Itoa(item.ResolutionThreshold),
				strconv.Itoa(item.EligibleResolverCount),
				strconv.Itoa(item.ResolutionDelegationCount),
				strconv.Itoa(item.ResolutionCommitteeMemberCount),
				strconv.Itoa(item.ResolutionRecordedVoteCount),
				strconv.Itoa(item.ResolutionOutstandingVotes),
				strconv.Itoa(item.ResolutionMissingQuorumCount),
				strconv.Itoa(item.UpholdVoteCount),
				strconv.Itoa(item.ReverseVoteCount),
				strconv.FormatBool(item.ResolutionThresholdSatisfied),
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeals.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "incident_id",
			"directive_id", "directive_title", "directive_status", "extension_id", "extension_status", "dispute_id", "dispute_status",
			"appeal_id", "parent_appeal_id", "appeal_generation", "status", "appealing_party", "board_party", "enforcement_acknowledgement_party", "appealed_by", "summary",
			"board_review_threshold", "eligible_board_reviewer_count", "board_delegation_count", "board_committee_member_count",
			"board_recusal_count", "board_recorded_vote_count", "board_outstanding_votes", "board_missing_quorum_count", "ratify_vote_count", "overturn_vote_count",
			"board_threshold_satisfied", "ruling", "ruled_by", "ruled_at", "enforcement_acknowledged_by", "enforcement_acknowledged_at",
			"created_at", "updated_at",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				item.DirectiveID,
				item.DirectiveTitle,
				string(item.DirectiveStatus),
				item.ExtensionID,
				string(item.ExtensionStatus),
				item.DisputeID,
				string(item.DisputeStatus),
				item.AppealID,
				item.ParentAppealID,
				strconv.Itoa(item.AppealGeneration),
				string(item.Status),
				string(item.AppealingParty),
				string(item.BoardParty),
				string(item.EnforcementAcknowledgementParty),
				item.AppealedBy,
				item.Summary,
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(item.EligibleBoardReviewerCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardCommitteeMemberCount),
				strconv.Itoa(item.BoardRecusalCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				strconv.Itoa(item.BoardOutstandingVotes),
				strconv.Itoa(item.BoardMissingQuorumCount),
				strconv.Itoa(item.RatifyVoteCount),
				strconv.Itoa(item.OverturnVoteCount),
				strconv.FormatBool(item.BoardThresholdSatisfied),
				string(item.Ruling),
				item.RuledBy,
				secureCellCSVTime(item.RuledAt),
				item.EnforcementAcknowledgedBy,
				secureCellCSVTime(item.EnforcementAcknowledgedAt),
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealRecusalExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRecusalSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealRecusalListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-recusals.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "incident_id",
			"directive_id", "directive_title", "directive_status", "extension_id", "extension_status", "dispute_id", "dispute_status",
			"appeal_id", "parent_appeal_id", "appeal_generation", "appeal_status", "board_party", "recusal_id", "actor_did", "summary",
			"description", "created_at",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				item.DirectiveID,
				item.DirectiveTitle,
				string(item.DirectiveStatus),
				item.ExtensionID,
				string(item.ExtensionStatus),
				item.DisputeID,
				string(item.DisputeStatus),
				item.AppealID,
				item.ParentAppealID,
				strconv.Itoa(item.AppealGeneration),
				string(item.AppealStatus),
				string(item.BoardParty),
				item.RecusalID,
				item.ActorDID,
				item.Summary,
				item.Description,
				item.CreatedAt.UTC().Format(timeCSVFormat),
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

func writeSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-counterparty-incident-directive-extension-appeals.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record", "organization_name", "snapshot_id",
			"bundle_id", "bundle_version", "bundle_name", "status", "verified", "signer", "key_id", "contract_ids", "incident_id",
			"response_id", "directive_id", "extension_id", "dispute_id", "appeal_id", "parent_appeal_id", "appeal_generation",
			"appeal_status", "appealing_party", "board_party", "enforcement_acknowledgement_party", "ruling", "board_review_threshold",
			"board_recusal_count", "board_delegation_count", "board_recorded_vote_count", "generated_at", "expires_at", "received_at",
			"control_ledger_id", "control_ledger_hash", "portable_package_hash", "portable_package_signed", "portable_package_anchored",
			"verification_message", "matched_local_appeal_id", "matched_local_dispute_id", "reconciliation_status", "reconciliation_divergence_count",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
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
				item.DirectiveID,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.ParentAppealID,
				strconv.Itoa(item.AppealGeneration),
				string(item.AppealStatus),
				string(item.AppealingParty),
				string(item.BoardParty),
				string(item.EnforcementAcknowledgementParty),
				string(item.Ruling),
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(item.BoardRecusalCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				item.GeneratedAt.UTC().Format(timeCSVFormat),
				secureCellCSVTime(item.ExpiresAt),
				item.ReceivedAt.UTC().Format(timeCSVFormat),
				item.ControlLedgerID,
				item.ControlLedgerHash,
				item.PortablePackageHash,
				strconv.FormatBool(item.PortablePackageSigned),
				strconv.FormatBool(item.PortablePackageAnchored),
				item.VerificationMessage,
				item.MatchedLocalAppealID,
				item.MatchedLocalDisputeID,
				string(item.ReconciliationStatus),
				strconv.Itoa(item.ReconciliationDivergenceCount),
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliations.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record", "organization_name",
			"comparison_key", "incident_id", "response_id", "directive_id", "directive_title", "extension_id", "dispute_id", "appeal_id",
			"parent_appeal_id", "appeal_generation", "appealing_party", "board_party", "status", "local_appeal_id", "local_appeal_status",
			"local_ruling", "local_recusal_count", "local_updated_at", "counterparty_snapshot_id", "counterparty_bundle_id",
			"counterparty_appeal_id", "counterparty_appeal_status", "counterparty_ruling", "counterparty_bundle_status",
			"counterparty_recusal_count", "counterparty_generated_at", "counterparty_received_at",
			"review_status", "last_reviewed_by", "last_reviewed_at", "review_action_count", "divergences",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.ResponseID,
				item.DirectiveID,
				item.DirectiveTitle,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.ParentAppealID,
				strconv.Itoa(item.AppealGeneration),
				string(item.AppealingParty),
				string(item.BoardParty),
				string(item.Status),
				item.LocalAppealID,
				string(item.LocalAppealStatus),
				string(item.LocalRuling),
				strconv.Itoa(item.LocalRecusalCount),
				secureCellCSVTime(item.LocalUpdatedAt),
				item.CounterpartySnapshotID,
				item.CounterpartyBundleID,
				item.CounterpartyAppealID,
				string(item.CounterpartyAppealStatus),
				string(item.CounterpartyRuling),
				string(item.CounterpartyBundleStatus),
				strconv.Itoa(item.CounterpartyRecusalCount),
				secureCellCSVTime(item.CounterpartyGeneratedAt),
				secureCellCSVTime(item.CounterpartyReceivedAt),
				string(item.ReviewStatus),
				item.LastReviewedBy,
				secureCellCSVTime(item.LastReviewedAt),
				strconv.Itoa(item.ReviewActionCount),
				strings.Join(item.Divergences, "|"),
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-actions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record", "organization_name",
			"comparison_key", "incident_id", "response_id", "directive_id", "extension_id", "dispute_id", "appeal_id",
			"local_appeal_id", "counterparty_snapshot_id", "counterparty_bundle_id", "counterparty_appeal_id",
			"reconciliation_status", "review_status", "action", "actor_did", "reason", "divergences",
			"policy_receipt_id", "policy_receipt_hash", "seal_id", "trace_link_id", "transition_id", "occurred_at",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.ResponseID,
				item.DirectiveID,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.LocalAppealID,
				item.CounterpartySnapshotID,
				item.CounterpartyBundleID,
				item.CounterpartyAppealID,
				string(item.ReconciliationStatus),
				string(item.ReviewStatus),
				string(item.Action),
				item.ActorDID,
				item.Reason,
				strings.Join(item.Divergences, "|"),
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				item.SealID,
				item.TraceLinkID,
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-challenges.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record", "organization_name",
			"comparison_key", "incident_id", "response_id", "directive_id", "directive_title", "extension_id", "dispute_id", "appeal_id",
			"challenge_id", "reconciliation_status", "review_status", "attestation_status", "challenge_status", "challenging_party", "board_party",
			"challenge_summary", "board_review_threshold", "eligible_board_reviewer_count", "board_committee_member_count", "board_delegation_count",
			"board_recorded_vote_count", "board_outstanding_votes", "board_missing_quorum_count", "board_quorum_satisfied",
			"ratify_vote_count", "overturn_vote_count", "ruling", "ruling_summary", "created_by", "created_at", "ruled_by", "ruled_at", "updated_at", "action_count",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.ResponseID,
				item.DirectiveID,
				item.DirectiveTitle,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.ChallengeID,
				string(item.ReconciliationStatus),
				string(item.ReviewStatus),
				string(item.AttestationStatus),
				string(item.ChallengeStatus),
				string(item.ChallengingParty),
				string(item.BoardParty),
				item.ChallengeSummary,
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(len(item.EligibleBoardReviewerDIDs)),
				strconv.Itoa(item.BoardCommitteeMemberCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				strconv.Itoa(item.BoardOutstandingVotes),
				strconv.Itoa(item.BoardMissingQuorumCount),
				strconv.FormatBool(item.BoardQuorumSatisfied),
				strconv.Itoa(item.RatifyVoteCount),
				strconv.Itoa(item.OverturnVoteCount),
				string(item.Ruling),
				item.RulingSummary,
				item.CreatedBy,
				item.CreatedAt.UTC().Format(timeCSVFormat),
				item.RuledBy,
				secureCellCSVTime(item.RuledAt),
				item.UpdatedAt.UTC().Format(timeCSVFormat),
				strconv.Itoa(item.ActionCount),
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-challenge-actions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record", "organization_name",
			"comparison_key", "incident_id", "response_id", "directive_id", "extension_id", "dispute_id", "appeal_id",
			"challenge_id", "reconciliation_status", "review_status", "attestation_status", "challenge_status", "action", "challenging_party", "board_party",
			"board_review_threshold", "board_committee_member_count", "board_delegation_count", "board_recorded_vote_count", "board_outstanding_votes", "board_missing_quorum_count",
			"board_quorum_satisfied", "ratify_vote_count", "overturn_vote_count", "ruling", "delegated_to_did", "actor_did", "reason",
			"policy_receipt_id", "policy_receipt_hash", "seal_id", "trace_link_id", "transition_id", "occurred_at",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.ResponseID,
				item.DirectiveID,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.ChallengeID,
				string(item.ReconciliationStatus),
				string(item.ReviewStatus),
				string(item.AttestationStatus),
				string(item.ChallengeStatus),
				string(item.Action),
				string(item.ChallengingParty),
				string(item.BoardParty),
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(item.BoardCommitteeMemberCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				strconv.Itoa(item.BoardOutstandingVotes),
				strconv.Itoa(item.BoardMissingQuorumCount),
				strconv.FormatBool(item.BoardQuorumSatisfied),
				strconv.Itoa(item.RatifyVoteCount),
				strconv.Itoa(item.OverturnVoteCount),
				string(item.Ruling),
				item.DelegatedToDID,
				item.ActorDID,
				item.Reason,
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				item.SealID,
				item.TraceLinkID,
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-challenge-appeals.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record", "organization_name",
			"comparison_key", "incident_id", "response_id", "directive_id", "directive_title", "extension_id", "dispute_id", "appeal_id",
			"challenge_id", "challenge_appeal_id", "parent_challenge_appeal_id", "challenge_appeal_generation", "reconciliation_status", "review_status", "attestation_status", "challenge_status", "challenge_ruling", "challenge_appeal_status",
			"appealing_party", "board_party", "enforcement_acknowledgement_party", "summary", "board_review_threshold", "eligible_board_reviewer_count", "board_committee_member_count", "board_delegation_count",
			"board_recusal_count", "board_recorded_vote_count", "board_outstanding_votes", "board_missing_quorum_count", "board_threshold_satisfied", "ratify_vote_count", "overturn_vote_count", "ruling",
			"ruling_summary", "enforcement_acknowledged_by", "enforcement_acknowledged_at", "created_by", "created_at", "ruled_by", "ruled_at", "updated_at", "action_count",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.ResponseID,
				item.DirectiveID,
				item.DirectiveTitle,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.ChallengeID,
				item.ChallengeAppealID,
				item.ParentChallengeAppealID,
				strconv.Itoa(item.ChallengeAppealGeneration),
				string(item.ReconciliationStatus),
				string(item.ReviewStatus),
				string(item.AttestationStatus),
				string(item.ChallengeStatus),
				string(item.ChallengeRuling),
				string(item.ChallengeAppealStatus),
				string(item.AppealingParty),
				string(item.BoardParty),
				string(item.EnforcementAcknowledgementParty),
				item.Summary,
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(len(item.EligibleBoardReviewerDIDs)),
				strconv.Itoa(item.BoardCommitteeMemberCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardRecusalCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				strconv.Itoa(item.BoardOutstandingVotes),
				strconv.Itoa(item.BoardMissingQuorumCount),
				strconv.FormatBool(item.BoardThresholdSatisfied),
				strconv.Itoa(item.RatifyVoteCount),
				strconv.Itoa(item.OverturnVoteCount),
				string(item.Ruling),
				item.RulingSummary,
				item.EnforcementAcknowledgedBy,
				secureCellCSVTime(item.EnforcementAcknowledgedAt),
				item.CreatedBy,
				item.CreatedAt.UTC().Format(timeCSVFormat),
				item.RuledBy,
				secureCellCSVTime(item.RuledAt),
				item.UpdatedAt.UTC().Format(timeCSVFormat),
				strconv.Itoa(item.ActionCount),
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-actions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record", "organization_name",
			"comparison_key", "incident_id", "response_id", "directive_id", "extension_id", "dispute_id", "appeal_id",
			"challenge_id", "challenge_appeal_id", "parent_challenge_appeal_id", "challenge_appeal_generation", "reconciliation_status", "review_status", "attestation_status", "challenge_status", "challenge_ruling", "challenge_appeal_status",
			"action", "appealing_party", "board_party", "enforcement_acknowledgement_party", "board_review_threshold", "board_committee_member_count", "board_delegation_count",
			"board_recusal_count", "board_recorded_vote_count", "board_outstanding_votes", "board_missing_quorum_count", "board_threshold_satisfied", "ratify_vote_count", "overturn_vote_count", "ruling",
			"actor_did", "delegated_to_did", "recusal_id", "reason", "policy_receipt_id", "policy_receipt_hash", "seal_id", "trace_link_id", "transition_id", "occurred_at",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.ResponseID,
				item.DirectiveID,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.ChallengeID,
				item.ChallengeAppealID,
				item.ParentChallengeAppealID,
				strconv.Itoa(item.ChallengeAppealGeneration),
				string(item.ReconciliationStatus),
				string(item.ReviewStatus),
				string(item.AttestationStatus),
				string(item.ChallengeStatus),
				string(item.ChallengeRuling),
				string(item.ChallengeAppealStatus),
				string(item.Action),
				string(item.AppealingParty),
				string(item.BoardParty),
				string(item.EnforcementAcknowledgementParty),
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(item.BoardCommitteeMemberCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardRecusalCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				strconv.Itoa(item.BoardOutstandingVotes),
				strconv.Itoa(item.BoardMissingQuorumCount),
				strconv.FormatBool(item.BoardThresholdSatisfied),
				strconv.Itoa(item.RatifyVoteCount),
				strconv.Itoa(item.OverturnVoteCount),
				string(item.Ruling),
				item.ActorDID,
				item.DelegatedToDID,
				item.RecusalID,
				item.Reason,
				item.PolicyReceiptID,
				item.PolicyReceiptHash,
				item.SealID,
				item.TraceLinkID,
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-recusals.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record", "organization_name",
			"comparison_key", "incident_id", "response_id", "directive_id", "directive_title", "extension_id", "dispute_id", "appeal_id",
			"challenge_id", "challenge_appeal_id", "parent_challenge_appeal_id", "challenge_appeal_generation", "challenge_appeal_status",
			"board_party", "recusal_id", "actor_did", "summary", "description", "created_at",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.ResponseID,
				item.DirectiveID,
				item.DirectiveTitle,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.ChallengeID,
				item.ChallengeAppealID,
				item.ParentChallengeAppealID,
				strconv.Itoa(item.ChallengeAppealGeneration),
				string(item.ChallengeAppealStatus),
				string(item.BoardParty),
				item.RecusalID,
				item.ActorDID,
				item.Summary,
				item.Description,
				item.CreatedAt.UTC().Format(timeCSVFormat),
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

func writeSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-challenge-appeals-overdue.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"cell_id", "organization_id", "response_id", "directive_id", "directive_title", "extension_id", "dispute_id", "appeal_id", "comparison_key", "challenge_id", "challenge_appeal_id", "challenge_status", "challenge_ruling", "challenge_appeal_status", "appealing_party", "board_party", "enforcement_acknowledgement_party", "pending_action", "automation_action", "overdue_reason", "board_review_threshold", "board_committee_member_count", "board_delegation_count", "board_recorded_vote_count", "board_outstanding_votes", "board_missing_quorum_count", "board_threshold_satisfied", "ratify_vote_count", "overturn_vote_count", "ruling", "tier_id", "target_did", "due_at", "overdue_seconds", "created_at", "ruled_at", "updated_at"}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.OrganizationID,
				item.ResponseID,
				item.DirectiveID,
				item.DirectiveTitle,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.ComparisonKey,
				item.ChallengeID,
				item.ChallengeAppealID,
				string(item.ChallengeStatus),
				string(item.ChallengeRuling),
				string(item.ChallengeAppealStatus),
				string(item.AppealingParty),
				string(item.BoardParty),
				string(item.EnforcementAcknowledgementParty),
				item.PendingAction,
				item.AutomationAction,
				item.OverdueReason,
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(item.BoardCommitteeMemberCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				strconv.Itoa(item.BoardOutstandingVotes),
				strconv.Itoa(item.BoardMissingQuorumCount),
				strconv.FormatBool(item.BoardThresholdSatisfied),
				strconv.Itoa(item.RatifyVoteCount),
				strconv.Itoa(item.OverturnVoteCount),
				string(item.Ruling),
				item.TierID,
				item.TargetDID,
				item.DueAt.UTC().Format(timeCSVFormat),
				strconv.FormatInt(item.OverdueSeconds, 10),
				item.CreatedAt.UTC().Format(timeCSVFormat),
				secureCellCSVTime(item.RuledAt),
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-automation-actions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"cell_id", "organization_id", "response_id", "directive_id", "directive_title", "extension_id", "dispute_id", "appeal_id", "comparison_key", "challenge_id", "challenge_appeal_id", "challenge_status", "challenge_ruling", "challenge_appeal_status", "appealing_party", "board_party", "enforcement_acknowledgement_party", "pending_action", "board_review_threshold", "board_committee_member_count", "board_delegation_count", "board_recorded_vote_count", "board_outstanding_votes", "board_missing_quorum_count", "board_threshold_satisfied", "ratify_vote_count", "overturn_vote_count", "ruling", "contract_id", "contract_status_before", "contract_status_after", "action", "trigger", "tier_id", "target_did", "due_at", "actor", "automated_actor", "reason", "transition_id", "occurred_at"}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.OrganizationID,
				item.ResponseID,
				item.DirectiveID,
				item.DirectiveTitle,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.ComparisonKey,
				item.ChallengeID,
				item.ChallengeAppealID,
				string(item.ChallengeStatus),
				string(item.ChallengeRuling),
				string(item.ChallengeAppealStatus),
				string(item.AppealingParty),
				string(item.BoardParty),
				string(item.EnforcementAcknowledgementParty),
				item.PendingAction,
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(item.BoardCommitteeMemberCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				strconv.Itoa(item.BoardOutstandingVotes),
				strconv.Itoa(item.BoardMissingQuorumCount),
				strconv.FormatBool(item.BoardThresholdSatisfied),
				strconv.Itoa(item.RatifyVoteCount),
				strconv.Itoa(item.OverturnVoteCount),
				string(item.Ruling),
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

func writeSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenge) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-challenges-overdue.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record", "organization_name",
			"comparison_key", "incident_id", "response_id", "directive_id", "directive_title", "extension_id", "dispute_id", "appeal_id", "challenge_id",
			"reconciliation_status", "review_status", "attestation_status", "challenge_status", "challenging_party", "board_party",
			"pending_action", "automation_action", "overdue_reason", "board_review_threshold", "board_committee_member_count", "board_delegation_count",
			"board_recorded_vote_count", "board_outstanding_votes", "board_missing_quorum_count", "board_quorum_satisfied",
			"ratify_vote_count", "overturn_vote_count", "ruling", "tier_id", "target_did", "due_at", "overdue_seconds",
			"board_review_due_at", "created_by", "created_at", "updated_at",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.ResponseID,
				item.DirectiveID,
				item.DirectiveTitle,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.ChallengeID,
				string(item.ReconciliationStatus),
				string(item.ReviewStatus),
				string(item.AttestationStatus),
				string(item.ChallengeStatus),
				string(item.ChallengingParty),
				string(item.BoardParty),
				item.PendingAction,
				item.AutomationAction,
				item.OverdueReason,
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(item.BoardCommitteeMemberCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				strconv.Itoa(item.BoardOutstandingVotes),
				strconv.Itoa(item.BoardMissingQuorumCount),
				strconv.FormatBool(item.BoardQuorumSatisfied),
				strconv.Itoa(item.RatifyVoteCount),
				strconv.Itoa(item.OverturnVoteCount),
				string(item.Ruling),
				item.TierID,
				item.TargetDID,
				item.DueAt.UTC().Format(timeCSVFormat),
				strconv.FormatInt(item.OverdueSeconds, 10),
				secureCellCSVTime(item.BoardReviewDueAt),
				item.CreatedBy,
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-challenge-automation-actions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record",
			"comparison_key", "incident_id", "response_id", "directive_id", "directive_title", "extension_id", "dispute_id", "appeal_id", "challenge_id",
			"reconciliation_status", "review_status", "attestation_status", "challenge_status", "challenging_party", "board_party", "pending_action",
			"board_review_threshold", "board_committee_member_count", "board_delegation_count", "board_recorded_vote_count", "board_outstanding_votes",
			"board_missing_quorum_count", "board_quorum_satisfied", "ratify_vote_count", "overturn_vote_count", "ruling",
			"contract_id", "contract_status_before", "contract_status_after", "action", "trigger", "tier_id", "target_did", "due_at",
			"actor", "automated_actor", "reason", "transition_id", "occurred_at", "metadata",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.ComparisonKey,
				item.IncidentID,
				item.ResponseID,
				item.DirectiveID,
				item.DirectiveTitle,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.ChallengeID,
				string(item.ReconciliationStatus),
				string(item.ReviewStatus),
				string(item.AttestationStatus),
				string(item.ChallengeStatus),
				string(item.ChallengingParty),
				string(item.BoardParty),
				item.PendingAction,
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(item.BoardCommitteeMemberCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				strconv.Itoa(item.BoardOutstandingVotes),
				strconv.Itoa(item.BoardMissingQuorumCount),
				strconv.FormatBool(item.BoardQuorumSatisfied),
				strconv.Itoa(item.RatifyVoteCount),
				strconv.Itoa(item.OverturnVoteCount),
				string(item.Ruling),
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
				formatSecureCellStringMap(item.Metadata),
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-attestations.csv"`)
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
			"response_id",
			"directive_id",
			"extension_id",
			"dispute_id",
			"appeal_id",
			"local_appeal_id",
			"counterparty_snapshot_id",
			"counterparty_bundle_id",
			"counterparty_appeal_id",
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
				item.ResponseID,
				item.DirectiveID,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				item.LocalAppealID,
				item.CounterpartySnapshotID,
				item.CounterpartyBundleID,
				item.CounterpartyAppealID,
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
				return fmt.Errorf("write federation-incident-directive-extension-appeal-reconciliation-attestation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliation) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliations-overdue.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record", "organization_name",
			"comparison_key", "incident_id", "response_id", "directive_id", "directive_title", "extension_id", "dispute_id", "appeal_id",
			"reconciliation_status", "review_status", "attestation_status", "automation_action", "overdue_reason", "due_at", "overdue_seconds",
			"review_due_at", "counterparty_acknowledge_due_at", "resolution_due_at", "local_appeal_id", "counterparty_appeal_id",
			"last_reviewed_by", "last_reviewed_at", "last_counterparty_attested_by", "last_counterparty_attested_at", "divergences", "updated_at",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.OrganizationName,
				item.ComparisonKey,
				item.IncidentID,
				item.ResponseID,
				item.DirectiveID,
				item.DirectiveTitle,
				item.ExtensionID,
				item.DisputeID,
				item.AppealID,
				string(item.Status),
				string(item.ReviewStatus),
				string(item.AttestationStatus),
				item.AutomationAction,
				item.OverdueReason,
				item.DueAt.UTC().Format(timeCSVFormat),
				strconv.FormatInt(item.OverdueSeconds, 10),
				secureCellCSVTime(item.ReviewDueAt),
				secureCellCSVTime(item.CounterpartyAcknowledgeDueAt),
				secureCellCSVTime(item.ResolutionDueAt),
				item.LocalAppealID,
				item.CounterpartyAppealID,
				item.LastReviewedBy,
				secureCellCSVTime(item.LastReviewedAt),
				item.LastCounterpartyAttestedBy,
				secureCellCSVTime(item.LastCounterpartyAttestedAt),
				strings.Join(item.Divergences, "|"),
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-automation-actions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "organization_id", "sponsor_of_record",
			"comparison_key", "incident_id", "response_id", "directive_id", "dispute_id", "appeal_id",
			"reconciliation_status", "review_status_before", "review_status_after", "attestation_status_before", "attestation_status_after",
			"contract_id", "contract_status_before", "contract_status_after", "action", "trigger", "due_at",
			"actor", "automated_actor", "reason", "transition_id", "occurred_at", "metadata",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.OrganizationID,
				item.SponsorOfRecord,
				item.ComparisonKey,
				item.IncidentID,
				item.ResponseID,
				item.DirectiveID,
				item.DisputeID,
				item.AppealID,
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
				secureCellCSVTime(item.DueAt),
				item.Actor,
				item.AutomatedActor,
				item.Reason,
				item.TransitionID,
				item.OccurredAt.UTC().Format(timeCSVFormat),
				formatSecureCellStringMap(item.Metadata),
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

func writeSecureCellOverdueFederationIncidentDirectiveExtensionAppealExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppeal) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionAppealListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeals-overdue.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "cell_name", "jurisdiction", "cell_status", "response_id", "organization_id", "sponsor_of_record", "incident_id",
			"directive_id", "directive_title", "directive_status", "extension_id", "extension_status", "dispute_id", "dispute_status",
			"appeal_id", "appeal_status", "appealing_party", "board_party", "enforcement_acknowledgement_party",
			"pending_action", "automation_action", "overdue_reason",
			"board_review_threshold", "board_committee_member_count", "board_delegation_count", "board_recorded_vote_count",
			"board_outstanding_votes", "board_missing_quorum_count", "board_quorum_satisfied", "ratify_vote_count", "overturn_vote_count",
			"ruling", "tier_id", "target_did", "due_at", "overdue_seconds", "board_review_due_at", "enforcement_acknowledgement_due_at", "ruled_at", "updated_at",
		}); err != nil {
			return err
		}
		for _, item := range items {
			if err := cw.Write([]string{
				item.CellID,
				item.CellName,
				item.Jurisdiction,
				string(item.CellStatus),
				item.ResponseID,
				item.OrganizationID,
				item.SponsorOfRecord,
				item.IncidentID,
				item.DirectiveID,
				item.DirectiveTitle,
				string(item.DirectiveStatus),
				item.ExtensionID,
				string(item.ExtensionStatus),
				item.DisputeID,
				string(item.DisputeStatus),
				item.AppealID,
				string(item.AppealStatus),
				string(item.AppealingParty),
				string(item.BoardParty),
				string(item.EnforcementAcknowledgementParty),
				item.PendingAction,
				item.AutomationAction,
				item.OverdueReason,
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(item.BoardCommitteeMemberCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				strconv.Itoa(item.BoardOutstandingVotes),
				strconv.Itoa(item.BoardMissingQuorumCount),
				strconv.FormatBool(item.BoardQuorumSatisfied),
				strconv.Itoa(item.RatifyVoteCount),
				strconv.Itoa(item.OverturnVoteCount),
				string(item.Ruling),
				item.TierID,
				item.TargetDID,
				item.DueAt.UTC().Format(timeCSVFormat),
				strconv.FormatInt(item.OverdueSeconds, 10),
				secureCellCSVTime(item.BoardReviewDueAt),
				secureCellCSVTime(item.EnforcementAcknowledgementDueAt),
				secureCellCSVTime(item.RuledAt),
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
		if err := cw.Write([]string{"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_title", "directive_status", "extension_id", "extension_status", "pending_dispute_id", "pending_action", "committee_threshold", "committee_member_count", "committee_delegation_count", "committee_recorded_vote_count", "committee_outstanding_votes", "committee_missing_quorum_count", "committee_quorum_satisfied", "contract_id", "contract_status_before", "contract_status_after", "action", "trigger", "tier_id", "target_did", "due_at", "actor", "automated_actor", "reason", "transition_id", "occurred_at"}); err != nil {
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
				strconv.Itoa(item.CommitteeThreshold),
				strconv.Itoa(item.CommitteeMemberCount),
				strconv.Itoa(item.CommitteeDelegationCount),
				strconv.Itoa(item.CommitteeRecordedVoteCount),
				strconv.Itoa(item.CommitteeOutstandingVotes),
				strconv.Itoa(item.CommitteeMissingQuorumCount),
				strconv.FormatBool(item.CommitteeQuorumSatisfied),
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-automation-actions.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"cell_id", "response_id", "organization_id", "incident_id", "directive_id", "directive_title", "directive_status",
			"extension_id", "extension_status", "dispute_id", "dispute_status", "appeal_id", "appeal_status", "appealing_party",
			"board_party", "enforcement_acknowledgement_party", "pending_action", "board_review_threshold", "board_committee_member_count",
			"board_delegation_count", "board_recorded_vote_count", "board_outstanding_votes", "board_missing_quorum_count",
			"board_quorum_satisfied", "ratify_vote_count", "overturn_vote_count", "ruling", "contract_id", "contract_status_before",
			"contract_status_after", "action", "trigger", "tier_id", "target_did", "due_at", "actor", "automated_actor", "reason",
			"transition_id", "occurred_at",
		}); err != nil {
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
				string(item.DisputeStatus),
				item.AppealID,
				string(item.AppealStatus),
				string(item.AppealingParty),
				string(item.BoardParty),
				string(item.EnforcementAcknowledgementParty),
				item.PendingAction,
				strconv.Itoa(item.BoardReviewThreshold),
				strconv.Itoa(item.BoardCommitteeMemberCount),
				strconv.Itoa(item.BoardDelegationCount),
				strconv.Itoa(item.BoardRecordedVoteCount),
				strconv.Itoa(item.BoardOutstandingVotes),
				strconv.Itoa(item.BoardMissingQuorumCount),
				strconv.FormatBool(item.BoardQuorumSatisfied),
				strconv.Itoa(item.RatifyVoteCount),
				strconv.Itoa(item.OverturnVoteCount),
				string(item.Ruling),
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealBundleExport(w http.ResponseWriter, r *http.Request, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealBundleResponse{Result: bundle})
		return nil
	case "csv":
		if bundle == nil {
			return fmt.Errorf("federation incident directive extension appeal bundle is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-bundle.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"id", "version", "name", "generated_at", "expires_at", "cell_id", "cell_name", "cell_status", "jurisdiction", "framework",
			"organization_id", "sponsor_of_record", "organization_name", "organization_status", "response_id", "response_status", "response_source_type",
			"incident_id", "incident_status", "incident_severity", "incident_category", "directive_id", "directive_type", "directive_title",
			"directive_priority", "directive_status", "extension_id", "extension_status", "dispute_id", "dispute_status", "appeal_id", "appeal_status",
			"parent_appeal_id", "appeal_generation", "appealing_party", "board_party", "enforcement_acknowledgement_party", "board_review_threshold", "ratify_vote_count", "overturn_vote_count",
			"appeal_recusal_count",
			"board_threshold_satisfied", "ruling", "enforcement_acknowledged_by", "appeal_automation_action_count", "directive_bundle_hash", "control_ids",
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
			bundle.ExtensionSummary.ExtensionID,
			string(bundle.ExtensionSummary.Status),
			bundle.DisputeSummary.DisputeID,
			string(bundle.DisputeSummary.Status),
			bundle.AppealSummary.AppealID,
			string(bundle.AppealSummary.Status),
			bundle.AppealSummary.ParentAppealID,
			strconv.Itoa(bundle.AppealSummary.AppealGeneration),
			string(bundle.AppealSummary.AppealingParty),
			string(bundle.AppealSummary.BoardParty),
			string(bundle.AppealSummary.EnforcementAcknowledgementParty),
			strconv.Itoa(bundle.AppealSummary.BoardReviewThreshold),
			strconv.Itoa(bundle.AppealSummary.RatifyVoteCount),
			strconv.Itoa(bundle.AppealSummary.OverturnVoteCount),
			strconv.Itoa(bundle.AppealSummary.BoardRecusalCount),
			strconv.FormatBool(bundle.AppealSummary.BoardThresholdSatisfied),
			string(bundle.AppealSummary.Ruling),
			bundle.AppealSummary.EnforcementAcknowledgedBy,
			strconv.Itoa(len(bundle.AutomationActions)),
			bundle.DirectiveBundleHash,
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

func writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleExport(w http.ResponseWriter, r *http.Request, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleResponse{Result: bundle})
		return nil
	case "csv":
		if bundle == nil {
			return fmt.Errorf("federation incident directive extension appeal reconciliation bundle is required")
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-federation-incident-directive-extension-appeal-reconciliation-bundle.csv"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{
			"id", "version", "name", "generated_at", "expires_at", "cell_id", "cell_name", "cell_status", "jurisdiction", "framework",
			"organization_id", "sponsor_of_record", "organization_name", "organization_status",
			"comparison_key", "incident_id", "response_id", "directive_id", "extension_id", "dispute_id", "appeal_id",
			"reconciliation_status", "review_status", "last_reviewed_by", "last_reviewed_at", "review_action_count",
			"local_appeal_id", "counterparty_appeal_id", "counterparty_snapshot_id", "action_count", "attestation_count", "challenge_count", "challenge_action_count", "challenge_appeal_count", "challenge_appeal_action_count", "challenge_appeal_automation_action_count", "automation_action_count", "contract_ids", "control_ids",
			"operator_surface_ids", "operator_surface_paths", "control_ledger_id", "control_ledger_hash", "portable_package_hash",
			"portable_package_signed", "portable_package_anchored", "content_hash", "signature_algorithm", "signature_signer",
			"signature_key_id", "signature_signed_at", "metadata",
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
			bundle.Reconciliation.ComparisonKey,
			bundle.Reconciliation.IncidentID,
			bundle.Reconciliation.ResponseID,
			bundle.Reconciliation.DirectiveID,
			bundle.Reconciliation.ExtensionID,
			bundle.Reconciliation.DisputeID,
			bundle.Reconciliation.AppealID,
			string(bundle.Reconciliation.Status),
			string(bundle.Reconciliation.ReviewStatus),
			bundle.Reconciliation.LastReviewedBy,
			secureCellCSVTime(bundle.Reconciliation.LastReviewedAt),
			strconv.Itoa(bundle.Reconciliation.ReviewActionCount),
			bundle.Reconciliation.LocalAppealID,
			bundle.Reconciliation.CounterpartyAppealID,
			bundle.Reconciliation.CounterpartySnapshotID,
			strconv.Itoa(len(bundle.Actions)),
			strconv.Itoa(len(bundle.Attestations)),
			strconv.Itoa(len(bundle.Challenges)),
			strconv.Itoa(len(bundle.ChallengeActions)),
			strconv.Itoa(len(bundle.ChallengeAppeals)),
			strconv.Itoa(len(bundle.ChallengeAppealActions)),
			strconv.Itoa(len(bundle.ChallengeAppealAutomationActions)),
			strconv.Itoa(len(bundle.AutomationActions)),
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
			"directive_status", "issuing_party", "assignee_party", "reviewer_party", "directive_due_at", "directive_extension_count", "directive_pending_extension_count", "directive_last_extension_id", "directive_last_extension_status", "directive_last_extension_proposed_due_at", "extension_summary_count", "extension_dispute_count", "extension_appeal_count", "extension_appeal_automation_action_count", "extension_automation_action_count", "response_bundle_hash", "contract_ids", "control_ids",
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
			strconv.Itoa(len(bundle.ExtensionSummaries)),
			strconv.Itoa(len(bundle.ExtensionDisputes)),
			strconv.Itoa(len(bundle.ExtensionAppeals)),
			strconv.Itoa(len(bundle.ExtensionAppealAutomationActions)),
			strconv.Itoa(len(bundle.ExtensionAutomationActions)),
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
