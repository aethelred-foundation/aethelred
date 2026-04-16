package export

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
)

// ExportControlLedgerCSV exports a control ledger to a single auditor-ready CSV
// where each row is typed by `row_type` and can be imported by spreadsheet or
// GRC tooling without losing the identity/policy/seal chain.
func ExportControlLedgerCSV(ledger any) ([]byte, error) {
	snap, err := normalizeControlLedger(ledger)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	header := []string{
		"row_type",
		"ledger_id",
		"framework",
		"entity_id",
		"entity_name",
		"status",
		"artifact_hash",
		"agent_did",
		"approver_attestation_id",
		"policy_receipt_id",
		"seal_id",
		"trace_link_id",
		"evidence_count",
		"controls_total",
		"passports_total",
		"approver_attestations_total",
		"value_settlements_total",
		"policy_receipts_total",
		"seals_total",
		"trace_links_total",
		"trust_compliance_packages_total",
		"chain_intact",
		"description",
		"issued_at",
		"created_at",
		"metadata",
		"exported_at",
	}
	if err := w.Write(header); err != nil {
		return nil, fmt.Errorf("evidence/export/csv: write header: %w", err)
	}

	writeRow := func(row []string) error {
		row, err = normalizeCSVRow(row, len(header))
		if err != nil {
			return err
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("evidence/export/csv: write row: %w", err)
		}
		return nil
	}

	if err := writeRow([]string{
		"summary",
		snap.LedgerID,
		snap.Framework,
		"summary",
		"control ledger",
		"summary",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		strconv.Itoa(snap.Summary.TotalControls),
		strconv.Itoa(snap.Summary.TotalPassports),
		strconv.Itoa(snap.Summary.TotalApproverAttestations),
		strconv.Itoa(snap.Summary.TotalValueSettlements),
		strconv.Itoa(snap.Summary.TotalPolicyReceipts),
		strconv.Itoa(snap.Summary.TotalSeals),
		strconv.Itoa(snap.Summary.TotalTraceLinks),
		strconv.Itoa(snap.Summary.TotalTrustCompliancePackages),
		boolString(snap.Summary.ChainIntact),
		"auditor-ready control ledger summary",
		"",
		snap.CreatedAt,
		encodeMetadata(snap.Metadata),
		snap.ExportedAt,
	}); err != nil {
		return nil, err
	}

	for _, control := range snap.Controls {
		if err := writeRow([]string{
			"control",
			snap.LedgerID,
			snap.Framework,
			control.ControlID,
			control.ControlName,
			control.Status,
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			strconv.Itoa(control.EvidenceCount),
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			control.Description,
			"",
			snap.CreatedAt,
			encodeMetadata(control.Metadata),
			snap.ExportedAt,
		}); err != nil {
			return nil, err
		}
	}

	for _, passport := range snap.Passports {
		if err := writeRow([]string{
			"passport",
			snap.LedgerID,
			snap.Framework,
			passport.DID,
			passport.HumanOwner,
			passport.LiabilityModel,
			passport.PublicKeyHash,
			passport.DID,
			"",
			"",
			"",
			"",
			strconv.Itoa(len(passport.SponsorChain)),
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"enterprise agent passport",
			passport.IssuedAt,
			snap.CreatedAt,
			encodeMetadata(passport.Metadata),
			snap.ExportedAt,
		}); err != nil {
			return nil, err
		}
	}

	for _, attestation := range snap.ApproverAttestations {
		description := "authenticated approver attestation"
		if attestation.Comment != "" {
			description = attestation.Comment
		}
		if err := writeRow([]string{
			"approver_attestation",
			snap.LedgerID,
			snap.Framework,
			attestation.ID,
			attestation.Approver,
			attestation.Decision,
			attestation.PolicyReceiptHash,
			attestation.ApproverDID,
			attestation.ID,
			attestation.PolicyReceiptID,
			attestation.SealID,
			attestation.TraceLinkID,
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			description,
			attestation.AuthorizedAt,
			snap.CreatedAt,
			encodeMetadata(attestation.Metadata),
			snap.ExportedAt,
		}); err != nil {
			return nil, err
		}
	}

	for _, settlement := range snap.ValueSettlements {
		description := settlement.ReasonCode
		if description == "" {
			description = "policy-bound value settlement"
		}
		if err := writeRow([]string{
			"value_settlement",
			snap.LedgerID,
			snap.Framework,
			settlement.ID,
			settlement.Counterparty,
			settlement.Status,
			settlement.TxHash,
			settlement.Beneficiary,
			"",
			settlement.PolicyReceiptID,
			settlement.SealID,
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			description,
			settlement.SettledAt,
			snap.CreatedAt,
			encodeMetadata(settlement.Metadata),
			snap.ExportedAt,
		}); err != nil {
			return nil, err
		}
	}

	for _, receipt := range snap.PolicyReceipts {
		if err := writeRow([]string{
			"policy_receipt",
			snap.LedgerID,
			snap.Framework,
			receipt.ID,
			receipt.Action,
			receipt.Decision,
			receipt.ContentHash,
			receipt.Actor,
			"",
			receipt.ID,
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			receipt.Resource,
			receipt.EvaluatedAt,
			snap.CreatedAt,
			encodeMetadata(receipt.Metadata),
			snap.ExportedAt,
		}); err != nil {
			return nil, err
		}
	}

	for _, seal := range snap.Seals {
		if err := writeRow([]string{
			"seal",
			snap.LedgerID,
			snap.Framework,
			seal.SealID,
			"execution seal",
			"sealed",
			seal.OutputHash,
			"",
			"",
			"",
			seal.SealID,
			"",
			strconv.Itoa(seal.ValidatorCount),
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			seal.Timestamp,
			snap.CreatedAt,
			encodeMetadata(seal.Metadata),
			snap.ExportedAt,
		}); err != nil {
			return nil, err
		}
	}

	for _, link := range snap.TraceLinks {
		if err := writeRow([]string{
			"trace_link",
			snap.LedgerID,
			snap.Framework,
			link.ID,
			"trace link",
			"linked",
			link.OutputHash,
			link.AgentDID,
			"",
			link.PolicyReceiptID,
			link.SealID,
			link.ID,
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			link.Description,
			link.LinkedAt,
			snap.CreatedAt,
			"",
			snap.ExportedAt,
		}); err != nil {
			return nil, err
		}
	}

	for _, pkg := range snap.TrustCompliancePackages {
		artifactHash := pkg.PackageHash
		if artifactHash == "" {
			artifactHash = pkg.DocumentHash
		}
		description := "anchored trust compliance package"
		if pkg.AuditAnchorAction != "" {
			description = pkg.AuditAnchorAction
		}
		entityName := pkg.Format
		if pkg.Signer != "" {
			entityName = pkg.Signer
		}
		if err := writeRow([]string{
			"trust_compliance_package",
			snap.LedgerID,
			snap.Framework,
			pkg.ID,
			entityName,
			boolString(pkg.Signed),
			artifactHash,
			"",
			"",
			"",
			"",
			"",
			strconv.Itoa(pkg.CustodyEntries),
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			boolString(pkg.AuditAnchorRecordHash != ""),
			description,
			pkg.GeneratedAt,
			snap.CreatedAt,
			encodeMetadata(pkg.Metadata),
			snap.ExportedAt,
		}); err != nil {
			return nil, err
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("evidence/export/csv: flush: %w", err)
	}

	return buf.Bytes(), nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func normalizeCSVRow(row []string, expected int) ([]string, error) {
	if len(row) > expected {
		return nil, fmt.Errorf("evidence/export/csv: row has %d columns, expected %d", len(row), expected)
	}
	if len(row) == expected {
		return row, nil
	}
	normalized := make([]string, expected)
	copy(normalized, row)
	return normalized, nil
}
