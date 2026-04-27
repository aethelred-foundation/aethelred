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

type secureCellGovernmentAgentExecutionLaunchReceiptManifestResponse struct {
	Manifest *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptManifest `json:"manifest,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchReceiptManifestListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptManifest `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchReceiptManifestGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-receipt-manifests" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchReceiptManifests(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchReceiptManifestListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-receipt-manifests/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchReceiptManifests(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchReceiptManifestExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-receipt-manifest") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-receipt-manifest")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		manifest, err := app.secureCellService.GetGovernmentAgentExecutionLaunchReceiptManifest(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchReceiptManifestResponse{Manifest: manifest})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchReceiptManifestExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptManifest) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchReceiptManifestListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-receipt-manifests.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchReceiptManifestCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-receipt-manifest csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptManifestCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptManifest) [][]string {
	rows := [][]string{{
		"manifest_id",
		"register_id",
		"authorization_id",
		"verification_id",
		"bundle_id",
		"cell_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"clearance_status",
		"can_accept_receipts",
		"can_launch_after_receipts",
		"receipt_requirement_count",
		"pending_acknowledgement_receipt_count",
		"pending_collection_receipt_count",
		"blocked_receipt_count",
		"remediation_receipt_count",
		"evidence_preservation_receipt_count",
		"required_receipt_types",
		"witness_id",
		"ledger_id",
		"queue_id",
		"register_digest",
		"launch_digest",
		"verification_digest",
		"bundle_digest",
		"requirement_id",
		"requirement_sequence",
		"clearance_item_id",
		"gate_code",
		"receipt_type",
		"requirement_status",
		"validation_rule",
		"expected_attachment",
		"evidence_binding_id",
		"clearance_item_digest",
		"requirement_digest",
		"manifest_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Requirements) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchReceiptManifestCSVRow(item, nil))
			continue
		}
		for idx := range item.Requirements {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchReceiptManifestCSVRow(item, &item.Requirements[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchReceiptManifestCSVRow(
	manifest securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptManifest,
	requirement *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptRequirement,
) []string {
	requirementID := ""
	requirementSequence := ""
	clearanceItemID := ""
	gateCode := ""
	receiptType := ""
	requirementStatus := ""
	validationRule := ""
	expectedAttachment := ""
	evidenceBindingID := ""
	clearanceItemDigest := ""
	requirementDigest := ""
	if requirement != nil {
		requirementID = requirement.RequirementID
		requirementSequence = strconv.Itoa(requirement.Sequence)
		clearanceItemID = requirement.ClearanceItemID
		gateCode = requirement.GateCode
		receiptType = requirement.ReceiptType
		requirementStatus = string(requirement.Status)
		validationRule = requirement.ValidationRule
		expectedAttachment = requirement.ExpectedAttachment
		evidenceBindingID = requirement.EvidenceBindingID
		clearanceItemDigest = requirement.ClearanceItemDigest
		requirementDigest = requirement.RequirementDigest
	}
	return []string{
		manifest.ManifestID,
		manifest.RegisterID,
		manifest.AuthorizationID,
		manifest.VerificationID,
		manifest.BundleID,
		manifest.CellID,
		manifest.Name,
		manifest.Jurisdiction,
		manifest.ServiceCode,
		manifest.ServiceTier,
		string(manifest.Status),
		string(manifest.ClearanceStatus),
		strconv.FormatBool(manifest.CanAcceptReceipts),
		strconv.FormatBool(manifest.CanLaunchAfterReceipts),
		strconv.Itoa(manifest.ReceiptRequirementCount),
		strconv.Itoa(manifest.PendingAcknowledgementReceiptCount),
		strconv.Itoa(manifest.PendingCollectionReceiptCount),
		strconv.Itoa(manifest.BlockedReceiptCount),
		strconv.Itoa(manifest.RemediationReceiptCount),
		strconv.Itoa(manifest.EvidencePreservationReceiptCount),
		strings.Join(manifest.RequiredReceiptTypes, "|"),
		manifest.WitnessID,
		manifest.LedgerID,
		manifest.QueueID,
		manifest.RegisterDigest,
		manifest.LaunchDigest,
		manifest.VerificationDigest,
		manifest.BundleDigest,
		requirementID,
		requirementSequence,
		clearanceItemID,
		gateCode,
		receiptType,
		requirementStatus,
		validationRule,
		expectedAttachment,
		evidenceBindingID,
		clearanceItemDigest,
		requirementDigest,
		manifest.ManifestDigest,
		manifest.GeneratedAt.UTC().Format(time.RFC3339Nano),
		manifest.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
