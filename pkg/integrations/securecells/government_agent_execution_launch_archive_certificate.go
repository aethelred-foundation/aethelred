package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus describes
// whether the launch record can be institutionally closed.
type SecureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchArchiveCertificateBlocked              SecureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus = "archive_blocked"
	SecureCellGovernmentAgentExecutionLaunchArchiveCertificateAwaitingPreservation SecureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus = "awaiting_preservation"
	SecureCellGovernmentAgentExecutionLaunchArchiveCertificateIssued               SecureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus = "archive_issued"
)

// SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus records
// the final archive posture for one settlement item.
type SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemBlocked              SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemAwaitingPreservation SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus = "awaiting_preservation"
	SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemArchived             SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus = "archived"
)

// SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItem is one archive
// clause bound to a settlement item.
type SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItem struct {
	ItemID               string                                                               `json:"item_id"`
	Sequence             int                                                                  `json:"sequence"`
	CellID               string                                                               `json:"cell_id"`
	SettlementRegisterID string                                                               `json:"settlement_register_id"`
	CloseoutRegisterID   string                                                               `json:"closeout_register_id"`
	SettlementItemID     string                                                               `json:"settlement_item_id"`
	ReceiptType          string                                                               `json:"receipt_type"`
	GateKind             string                                                               `json:"gate_kind"`
	Status               SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus `json:"status"`
	ArchiveDisposition   string                                                               `json:"archive_disposition"`
	RequiredAction       string                                                               `json:"required_action"`
	DueAt                *time.Time                                                           `json:"due_at,omitempty"`
	EvidenceBindingID    string                                                               `json:"evidence_binding_id"`
	EvidenceDigest       string                                                               `json:"evidence_digest,omitempty"`
	SettlementDigest     string                                                               `json:"settlement_digest"`
	ArchiveItemDigest    string                                                               `json:"archive_item_digest"`
	GeneratedAt          time.Time                                                            `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchArchiveCertificate is the final
// digest-bound institutional archive record for a launch execution.
type SecureCellGovernmentAgentExecutionLaunchArchiveCertificate struct {
	CertificateID             string                                                           `json:"certificate_id"`
	SettlementRegisterID      string                                                           `json:"settlement_register_id"`
	CloseoutRegisterID        string                                                           `json:"closeout_register_id"`
	LedgerID                  string                                                           `json:"ledger_id"`
	MonitorID                 string                                                           `json:"monitor_id"`
	OrderID                   string                                                           `json:"order_id"`
	ActivationID              string                                                           `json:"activation_id"`
	CustodyID                 string                                                           `json:"custody_id"`
	PackageID                 string                                                           `json:"package_id"`
	CellID                    string                                                           `json:"cell_id"`
	Name                      string                                                           `json:"name"`
	Jurisdiction              string                                                           `json:"jurisdiction,omitempty"`
	ServiceCode               string                                                           `json:"service_code,omitempty"`
	ServiceTier               string                                                           `json:"service_tier,omitempty"`
	Status                    SecureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus `json:"status"`
	SettlementStatus          SecureCellGovernmentAgentExecutionLaunchSettlementStatus         `json:"settlement_status"`
	CanIssueNow               bool                                                             `json:"can_issue_now"`
	CanIssueAfterPreservation bool                                                             `json:"can_issue_after_preservation"`
	CanEscalateBlocked        bool                                                             `json:"can_escalate_blocked"`
	ArchiveItemCount          int                                                              `json:"archive_item_count"`
	BlockedArchiveItemCount   int                                                              `json:"blocked_archive_item_count"`
	PendingArchiveItemCount   int                                                              `json:"pending_archive_item_count"`
	ArchivedItemCount         int                                                              `json:"archived_item_count"`
	RequiredReceiptTypes      []string                                                         `json:"required_receipt_types,omitempty"`
	OperatorInstructions      []string                                                         `json:"operator_instructions,omitempty"`
	SettlementRegisterDigest  string                                                           `json:"settlement_register_digest"`
	CloseoutDigest            string                                                           `json:"closeout_digest"`
	LedgerDigest              string                                                           `json:"ledger_digest"`
	MonitorDigest             string                                                           `json:"monitor_digest"`
	OrderDigest               string                                                           `json:"order_digest"`
	ActivationDigest          string                                                           `json:"activation_digest"`
	CustodyDigest             string                                                           `json:"custody_digest"`
	PackageDigest             string                                                           `json:"package_digest"`
	LaunchDigest              string                                                           `json:"launch_digest"`
	ReceiptManifestDigest     string                                                           `json:"receipt_manifest_digest"`
	ReceiptValidationDigest   string                                                           `json:"receipt_validation_digest"`
	Items                     []SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItem `json:"items"`
	Settlement                SecureCellGovernmentAgentExecutionLaunchSettlementRegister       `json:"settlement"`
	CertificateDigest         string                                                           `json:"certificate_digest"`
	GeneratedAt               time.Time                                                        `json:"generated_at"`
	UpdatedAt                 time.Time                                                        `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchArchiveCertificate returns the final archive
// certificate for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchArchiveCertificate(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchArchiveCertificate, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchArchiveCertificates(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-archive-certificate: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchArchiveCertificates returns archive
// certificates for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchArchiveCertificates(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchArchiveCertificate, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-archive-certificate: service is required")
	}
	settlements, err := s.ListGovernmentAgentExecutionLaunchSettlements(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	certs := make([]SecureCellGovernmentAgentExecutionLaunchArchiveCertificate, 0, len(settlements))
	for _, settlement := range settlements {
		certs = append(certs, secureCellGovernmentAgentExecutionLaunchArchiveCertificate(settlement, now))
	}
	sort.SliceStable(certs, func(i, j int) bool {
		if certs[i].Status == certs[j].Status {
			if certs[i].BlockedArchiveItemCount == certs[j].BlockedArchiveItemCount {
				if certs[i].PendingArchiveItemCount == certs[j].PendingArchiveItemCount {
					return certs[i].CellID < certs[j].CellID
				}
				return certs[i].PendingArchiveItemCount > certs[j].PendingArchiveItemCount
			}
			return certs[i].BlockedArchiveItemCount > certs[j].BlockedArchiveItemCount
		}
		return secureCellGovernmentAgentExecutionLaunchArchiveCertificateStatusRank(certs[i].Status) < secureCellGovernmentAgentExecutionLaunchArchiveCertificateStatusRank(certs[j].Status)
	})
	return certs, nil
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificate(
	settlement SecureCellGovernmentAgentExecutionLaunchSettlementRegister,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchArchiveCertificate {
	items := secureCellGovernmentAgentExecutionLaunchArchiveCertificateItems(settlement, generatedAt)
	cert := SecureCellGovernmentAgentExecutionLaunchArchiveCertificate{
		SettlementRegisterID:     settlement.RegisterID,
		CloseoutRegisterID:       settlement.CloseoutRegisterID,
		LedgerID:                 settlement.LedgerID,
		MonitorID:                settlement.MonitorID,
		OrderID:                  settlement.OrderID,
		ActivationID:             settlement.ActivationID,
		CustodyID:                settlement.CustodyID,
		PackageID:                settlement.PackageID,
		CellID:                   settlement.CellID,
		Name:                     settlement.Name,
		Jurisdiction:             settlement.Jurisdiction,
		ServiceCode:              settlement.ServiceCode,
		ServiceTier:              settlement.ServiceTier,
		SettlementStatus:         settlement.Status,
		SettlementRegisterDigest: settlement.SettlementRegisterDigest,
		CloseoutDigest:           settlement.CloseoutDigest,
		LedgerDigest:             settlement.LedgerDigest,
		MonitorDigest:            settlement.MonitorDigest,
		OrderDigest:              settlement.OrderDigest,
		ActivationDigest:         settlement.ActivationDigest,
		CustodyDigest:            settlement.CustodyDigest,
		PackageDigest:            settlement.PackageDigest,
		LaunchDigest:             settlement.LaunchDigest,
		ReceiptManifestDigest:    settlement.ReceiptManifestDigest,
		ReceiptValidationDigest:  settlement.ReceiptValidationDigest,
		Items:                    items,
		Settlement:               settlement,
		GeneratedAt:              generatedAt.UTC(),
		UpdatedAt:                settlement.UpdatedAt.UTC(),
	}
	receiptTypes := make([]string, 0, len(items))
	for _, item := range cert.Items {
		cert.ArchiveItemCount++
		receiptTypes = append(receiptTypes, item.ReceiptType)
		switch item.Status {
		case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemBlocked:
			cert.BlockedArchiveItemCount++
		case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemAwaitingPreservation:
			cert.PendingArchiveItemCount++
		default:
			cert.ArchivedItemCount++
		}
	}
	cert.RequiredReceiptTypes = uniqueSortedStrings(receiptTypes)
	cert.Status = secureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus(cert)
	cert.CanIssueNow = cert.Status == SecureCellGovernmentAgentExecutionLaunchArchiveCertificateIssued
	cert.CanIssueAfterPreservation = cert.Status == SecureCellGovernmentAgentExecutionLaunchArchiveCertificateAwaitingPreservation
	cert.CanEscalateBlocked = cert.Status == SecureCellGovernmentAgentExecutionLaunchArchiveCertificateBlocked
	cert.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchArchiveCertificateInstructions(cert)
	cert.CertificateDigest = secureCellGovernmentAgentExecutionLaunchArchiveCertificateDigest(cert)
	cert.CertificateID = "government-agent-execution-launch-archive-certificate:" + cert.CellID + ":" + cert.CertificateDigest[:12]
	return cert
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateItems(
	settlement SecureCellGovernmentAgentExecutionLaunchSettlementRegister,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItem {
	items := make([]SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItem, 0, len(settlement.Items))
	for _, settlementItem := range settlement.Items {
		item := SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItem{
			Sequence:             settlementItem.Sequence,
			CellID:               settlement.CellID,
			SettlementRegisterID: settlement.RegisterID,
			CloseoutRegisterID:   settlement.CloseoutRegisterID,
			SettlementItemID:     settlementItem.ItemID,
			ReceiptType:          settlementItem.ReceiptType,
			GateKind:             settlementItem.GateKind,
			Status:               secureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus(settlementItem.Status),
			ArchiveDisposition:   secureCellGovernmentAgentExecutionLaunchArchiveCertificateDisposition(settlementItem.Status),
			RequiredAction:       secureCellGovernmentAgentExecutionLaunchArchiveCertificateRequiredAction(settlementItem),
			DueAt:                cloneTimePtr(settlementItem.DueAt),
			EvidenceBindingID:    settlementItem.EvidenceBindingID,
			EvidenceDigest:       settlementItem.EvidenceDigest,
			SettlementDigest:     settlementItem.SettlementDigest,
			GeneratedAt:          generatedAt.UTC(),
		}
		item.ArchiveItemDigest = secureCellGovernmentAgentExecutionLaunchArchiveCertificateItemDigest(item)
		item.ItemID = "government-agent-execution-launch-archive-item:" + item.CellID + ":" + item.ArchiveItemDigest[:12]
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status == items[j].Status {
			if items[i].Sequence == items[j].Sequence {
				return items[i].ReceiptType < items[j].ReceiptType
			}
			return items[i].Sequence < items[j].Sequence
		}
		return secureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatusRank(items[i].Status) < secureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatusRank(items[j].Status)
	})
	return items
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus(status SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus) SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchSettlementItemBlocked:
		return SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemBlocked
	case SecureCellGovernmentAgentExecutionLaunchSettlementItemReady:
		return SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemArchived
	default:
		return SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemAwaitingPreservation
	}
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateDisposition(status SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchSettlementItemBlocked:
		return "archive_escalation_required"
	case SecureCellGovernmentAgentExecutionLaunchSettlementItemReady:
		return "archived"
	default:
		return "pending_archive_preservation"
	}
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateRequiredAction(item SecureCellGovernmentAgentExecutionLaunchSettlementItem) string {
	switch item.Status {
	case SecureCellGovernmentAgentExecutionLaunchSettlementItemBlocked:
		return "Resolve blocked archive clause before issuing the certificate."
	case SecureCellGovernmentAgentExecutionLaunchSettlementItemReady:
		return "Record archived evidence as part of the institutional certificate."
	default:
		return "Preserve evidence and release it to archive before certificate issue."
	}
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus(cert SecureCellGovernmentAgentExecutionLaunchArchiveCertificate) SecureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus {
	if cert.SettlementStatus == SecureCellGovernmentAgentExecutionLaunchSettlementBlocked || cert.BlockedArchiveItemCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchArchiveCertificateBlocked
	}
	if cert.PendingArchiveItemCount > 0 || cert.SettlementStatus == SecureCellGovernmentAgentExecutionLaunchSettlementAwaitingPreservation {
		return SecureCellGovernmentAgentExecutionLaunchArchiveCertificateAwaitingPreservation
	}
	return SecureCellGovernmentAgentExecutionLaunchArchiveCertificateIssued
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateInstructions(cert SecureCellGovernmentAgentExecutionLaunchArchiveCertificate) []string {
	instructions := append([]string(nil), cert.Settlement.OperatorInstructions...)
	switch cert.Status {
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateBlocked:
		instructions = append(instructions, "Escalate blocked archive clauses before certificate issue.")
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateAwaitingPreservation:
		instructions = append(instructions, "Preserve pending evidence before issuing the archive certificate.")
	default:
		instructions = append(instructions, "Issue the archive certificate and close the launch record.")
	}
	if cert.ArchiveItemCount > 0 {
		instructions = append(instructions, fmt.Sprintf("Review %d archive certificate items before institutional closure.", cert.ArchiveItemCount))
	}
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateStatusRank(status SecureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateAwaitingPreservation:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateIssued:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatusRank(status SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemAwaitingPreservation:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemArchived:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateItemDigest(item SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItem) string {
	core := struct {
		Sequence             int                                                                  `json:"sequence"`
		CellID               string                                                               `json:"cell_id"`
		SettlementRegisterID string                                                               `json:"settlement_register_id"`
		CloseoutRegisterID   string                                                               `json:"closeout_register_id"`
		SettlementItemID     string                                                               `json:"settlement_item_id"`
		ReceiptType          string                                                               `json:"receipt_type"`
		GateKind             string                                                               `json:"gate_kind"`
		Status               SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus `json:"status"`
		ArchiveDisposition   string                                                               `json:"archive_disposition"`
		SettlementDigest     string                                                               `json:"settlement_digest"`
	}{
		Sequence:             item.Sequence,
		CellID:               item.CellID,
		SettlementRegisterID: item.SettlementRegisterID,
		CloseoutRegisterID:   item.CloseoutRegisterID,
		SettlementItemID:     item.SettlementItemID,
		ReceiptType:          item.ReceiptType,
		GateKind:             item.GateKind,
		Status:               item.Status,
		ArchiveDisposition:   item.ArchiveDisposition,
		SettlementDigest:     item.SettlementDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateDigest(cert SecureCellGovernmentAgentExecutionLaunchArchiveCertificate) string {
	itemDigests := make([]string, 0, len(cert.Items))
	for _, item := range cert.Items {
		itemDigests = append(itemDigests, item.ArchiveItemDigest)
	}
	core := struct {
		SettlementRegisterID      string                                                           `json:"settlement_register_id"`
		CloseoutRegisterID        string                                                           `json:"closeout_register_id"`
		LedgerID                  string                                                           `json:"ledger_id"`
		MonitorID                 string                                                           `json:"monitor_id"`
		OrderID                   string                                                           `json:"order_id"`
		ActivationID              string                                                           `json:"activation_id"`
		CellID                    string                                                           `json:"cell_id"`
		Status                    SecureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus `json:"status"`
		SettlementStatus          SecureCellGovernmentAgentExecutionLaunchSettlementStatus         `json:"settlement_status"`
		CanIssueNow               bool                                                             `json:"can_issue_now"`
		CanIssueAfterPreservation bool                                                             `json:"can_issue_after_preservation"`
		CanEscalateBlocked        bool                                                             `json:"can_escalate_blocked"`
		RequiredReceiptTypes      []string                                                         `json:"required_receipt_types,omitempty"`
		ItemDigests               []string                                                         `json:"item_digests,omitempty"`
		SettlementRegisterDigest  string                                                           `json:"settlement_register_digest"`
		CloseoutDigest            string                                                           `json:"closeout_digest"`
		LedgerDigest              string                                                           `json:"ledger_digest"`
		MonitorDigest             string                                                           `json:"monitor_digest"`
		OrderDigest               string                                                           `json:"order_digest"`
		ActivationDigest          string                                                           `json:"activation_digest"`
		CustodyDigest             string                                                           `json:"custody_digest"`
		PackageDigest             string                                                           `json:"package_digest"`
		LaunchDigest              string                                                           `json:"launch_digest"`
		ReceiptManifestDigest     string                                                           `json:"receipt_manifest_digest"`
		ReceiptValidationDigest   string                                                           `json:"receipt_validation_digest"`
	}{
		SettlementRegisterID:      cert.SettlementRegisterID,
		CloseoutRegisterID:        cert.CloseoutRegisterID,
		LedgerID:                  cert.LedgerID,
		MonitorID:                 cert.MonitorID,
		OrderID:                   cert.OrderID,
		ActivationID:              cert.ActivationID,
		CellID:                    cert.CellID,
		Status:                    cert.Status,
		SettlementStatus:          cert.SettlementStatus,
		CanIssueNow:               cert.CanIssueNow,
		CanIssueAfterPreservation: cert.CanIssueAfterPreservation,
		CanEscalateBlocked:        cert.CanEscalateBlocked,
		RequiredReceiptTypes:      cert.RequiredReceiptTypes,
		ItemDigests:               itemDigests,
		SettlementRegisterDigest:  cert.SettlementRegisterDigest,
		CloseoutDigest:            cert.CloseoutDigest,
		LedgerDigest:              cert.LedgerDigest,
		MonitorDigest:             cert.MonitorDigest,
		OrderDigest:               cert.OrderDigest,
		ActivationDigest:          cert.ActivationDigest,
		CustodyDigest:             cert.CustodyDigest,
		PackageDigest:             cert.PackageDigest,
		LaunchDigest:              cert.LaunchDigest,
		ReceiptManifestDigest:     cert.ReceiptManifestDigest,
		ReceiptValidationDigest:   cert.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
