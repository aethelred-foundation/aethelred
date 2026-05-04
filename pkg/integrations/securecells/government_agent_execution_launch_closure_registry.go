package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureRegistryStatus describes
// whether the launch record can be finally closed.
type SecureCellGovernmentAgentExecutionLaunchClosureRegistryStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureRegistryBlocked              SecureCellGovernmentAgentExecutionLaunchClosureRegistryStatus = "closure_blocked"
	SecureCellGovernmentAgentExecutionLaunchClosureRegistryAwaitingArchiveIssue SecureCellGovernmentAgentExecutionLaunchClosureRegistryStatus = "awaiting_archive_issue"
	SecureCellGovernmentAgentExecutionLaunchClosureRegistryClosed               SecureCellGovernmentAgentExecutionLaunchClosureRegistryStatus = "closure_closed"
)

// SecureCellGovernmentAgentExecutionLaunchClosureItemStatus records the final
// closure posture for one archive certificate item.
type SecureCellGovernmentAgentExecutionLaunchClosureItemStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureItemBlocked              SecureCellGovernmentAgentExecutionLaunchClosureItemStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchClosureItemAwaitingArchiveIssue SecureCellGovernmentAgentExecutionLaunchClosureItemStatus = "awaiting_archive_issue"
	SecureCellGovernmentAgentExecutionLaunchClosureItemClosed               SecureCellGovernmentAgentExecutionLaunchClosureItemStatus = "closed"
)

// SecureCellGovernmentAgentExecutionLaunchClosureItem is one final closure
// clause derived from an archive certificate item.
type SecureCellGovernmentAgentExecutionLaunchClosureItem struct {
	ItemID               string                                                    `json:"item_id"`
	Sequence             int                                                       `json:"sequence"`
	CellID               string                                                    `json:"cell_id"`
	CertificateID        string                                                    `json:"certificate_id"`
	SettlementRegisterID string                                                    `json:"settlement_register_id"`
	ArchiveItemID        string                                                    `json:"archive_item_id"`
	ReceiptType          string                                                    `json:"receipt_type"`
	GateKind             string                                                    `json:"gate_kind"`
	Status               SecureCellGovernmentAgentExecutionLaunchClosureItemStatus `json:"status"`
	ClosureAction        string                                                    `json:"closure_action"`
	RequiredAction       string                                                    `json:"required_action"`
	DueAt                *time.Time                                                `json:"due_at,omitempty"`
	EvidenceBindingID    string                                                    `json:"evidence_binding_id"`
	EvidenceDigest       string                                                    `json:"evidence_digest,omitempty"`
	ArchiveItemDigest    string                                                    `json:"archive_item_digest"`
	ClosureItemDigest    string                                                    `json:"closure_item_digest"`
	GeneratedAt          time.Time                                                 `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureRegistry is the operator
// surface for final launch record closure.
type SecureCellGovernmentAgentExecutionLaunchClosureRegistry struct {
	RegistryID                string                                                           `json:"registry_id"`
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
	Status                    SecureCellGovernmentAgentExecutionLaunchClosureRegistryStatus    `json:"status"`
	CertificateStatus         SecureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus `json:"certificate_status"`
	CanCloseRecordNow         bool                                                             `json:"can_close_record_now"`
	CanCloseAfterArchiveIssue bool                                                             `json:"can_close_after_archive_issue"`
	CanEscalateBlocked        bool                                                             `json:"can_escalate_blocked"`
	ClosureItemCount          int                                                              `json:"closure_item_count"`
	BlockedClosureItemCount   int                                                              `json:"blocked_closure_item_count"`
	PendingClosureItemCount   int                                                              `json:"pending_closure_item_count"`
	ClosedClosureItemCount    int                                                              `json:"closed_closure_item_count"`
	RequiredReceiptTypes      []string                                                         `json:"required_receipt_types,omitempty"`
	OperatorInstructions      []string                                                         `json:"operator_instructions,omitempty"`
	CertificateDigest         string                                                           `json:"certificate_digest"`
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
	Items                     []SecureCellGovernmentAgentExecutionLaunchClosureItem            `json:"items"`
	Certificate               SecureCellGovernmentAgentExecutionLaunchArchiveCertificate       `json:"certificate"`
	RegistryDigest            string                                                           `json:"registry_digest"`
	GeneratedAt               time.Time                                                        `json:"generated_at"`
	UpdatedAt                 time.Time                                                        `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureRegistry returns the final closure
// registry for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureRegistry(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchClosureRegistry, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchClosureRegistries(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-registry: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchClosureRegistries returns final closure
// registries for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchClosureRegistries(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchClosureRegistry, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-registry: service is required")
	}
	certificates, err := s.ListGovernmentAgentExecutionLaunchArchiveCertificates(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	registries := make([]SecureCellGovernmentAgentExecutionLaunchClosureRegistry, 0, len(certificates))
	for _, certificate := range certificates {
		registries = append(registries, secureCellGovernmentAgentExecutionLaunchClosureRegistry(certificate, now))
	}
	sort.SliceStable(registries, func(i, j int) bool {
		if registries[i].Status == registries[j].Status {
			if registries[i].BlockedClosureItemCount == registries[j].BlockedClosureItemCount {
				if registries[i].PendingClosureItemCount == registries[j].PendingClosureItemCount {
					return registries[i].CellID < registries[j].CellID
				}
				return registries[i].PendingClosureItemCount > registries[j].PendingClosureItemCount
			}
			return registries[i].BlockedClosureItemCount > registries[j].BlockedClosureItemCount
		}
		return secureCellGovernmentAgentExecutionLaunchClosureRegistryStatusRank(registries[i].Status) < secureCellGovernmentAgentExecutionLaunchClosureRegistryStatusRank(registries[j].Status)
	})
	return registries, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureRegistry(
	certificate SecureCellGovernmentAgentExecutionLaunchArchiveCertificate,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureRegistry {
	items := secureCellGovernmentAgentExecutionLaunchClosureItems(certificate, generatedAt)
	registry := SecureCellGovernmentAgentExecutionLaunchClosureRegistry{
		CertificateID:            certificate.CertificateID,
		SettlementRegisterID:     certificate.SettlementRegisterID,
		CloseoutRegisterID:       certificate.CloseoutRegisterID,
		LedgerID:                 certificate.LedgerID,
		MonitorID:                certificate.MonitorID,
		OrderID:                  certificate.OrderID,
		ActivationID:             certificate.ActivationID,
		CustodyID:                certificate.CustodyID,
		PackageID:                certificate.PackageID,
		CellID:                   certificate.CellID,
		Name:                     certificate.Name,
		Jurisdiction:             certificate.Jurisdiction,
		ServiceCode:              certificate.ServiceCode,
		ServiceTier:              certificate.ServiceTier,
		CertificateStatus:        certificate.Status,
		CertificateDigest:        certificate.CertificateDigest,
		SettlementRegisterDigest: certificate.SettlementRegisterDigest,
		CloseoutDigest:           certificate.CloseoutDigest,
		LedgerDigest:             certificate.LedgerDigest,
		MonitorDigest:            certificate.MonitorDigest,
		OrderDigest:              certificate.OrderDigest,
		ActivationDigest:         certificate.ActivationDigest,
		CustodyDigest:            certificate.CustodyDigest,
		PackageDigest:            certificate.PackageDigest,
		LaunchDigest:             certificate.LaunchDigest,
		ReceiptManifestDigest:    certificate.ReceiptManifestDigest,
		ReceiptValidationDigest:  certificate.ReceiptValidationDigest,
		Items:                    items,
		Certificate:              certificate,
		GeneratedAt:              generatedAt.UTC(),
		UpdatedAt:                certificate.UpdatedAt.UTC(),
	}
	receiptTypes := make([]string, 0, len(items))
	for _, item := range registry.Items {
		registry.ClosureItemCount++
		receiptTypes = append(receiptTypes, item.ReceiptType)
		switch item.Status {
		case SecureCellGovernmentAgentExecutionLaunchClosureItemBlocked:
			registry.BlockedClosureItemCount++
		case SecureCellGovernmentAgentExecutionLaunchClosureItemAwaitingArchiveIssue:
			registry.PendingClosureItemCount++
		default:
			registry.ClosedClosureItemCount++
		}
	}
	registry.RequiredReceiptTypes = uniqueSortedStrings(receiptTypes)
	registry.Status = secureCellGovernmentAgentExecutionLaunchClosureRegistryStatus(registry)
	registry.CanCloseRecordNow = registry.Status == SecureCellGovernmentAgentExecutionLaunchClosureRegistryClosed
	registry.CanCloseAfterArchiveIssue = registry.Status == SecureCellGovernmentAgentExecutionLaunchClosureRegistryAwaitingArchiveIssue
	registry.CanEscalateBlocked = registry.Status == SecureCellGovernmentAgentExecutionLaunchClosureRegistryBlocked
	registry.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchClosureRegistryInstructions(registry)
	registry.RegistryDigest = secureCellGovernmentAgentExecutionLaunchClosureRegistryDigest(registry)
	registry.RegistryID = "government-agent-execution-launch-closure-registry:" + registry.CellID + ":" + registry.RegistryDigest[:12]
	return registry
}

func secureCellGovernmentAgentExecutionLaunchClosureItems(
	certificate SecureCellGovernmentAgentExecutionLaunchArchiveCertificate,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchClosureItem {
	items := make([]SecureCellGovernmentAgentExecutionLaunchClosureItem, 0, len(certificate.Items))
	for _, certificateItem := range certificate.Items {
		item := SecureCellGovernmentAgentExecutionLaunchClosureItem{
			Sequence:             certificateItem.Sequence,
			CellID:               certificate.CellID,
			CertificateID:        certificate.CertificateID,
			SettlementRegisterID: certificate.SettlementRegisterID,
			ArchiveItemID:        certificateItem.ItemID,
			ReceiptType:          certificateItem.ReceiptType,
			GateKind:             certificateItem.GateKind,
			Status:               secureCellGovernmentAgentExecutionLaunchClosureItemStatus(certificateItem.Status),
			ClosureAction:        secureCellGovernmentAgentExecutionLaunchClosureAction(certificateItem.Status),
			RequiredAction:       secureCellGovernmentAgentExecutionLaunchClosureRequiredAction(certificateItem),
			DueAt:                cloneTimePtr(certificateItem.DueAt),
			EvidenceBindingID:    certificateItem.EvidenceBindingID,
			EvidenceDigest:       certificateItem.EvidenceDigest,
			ArchiveItemDigest:    certificateItem.ArchiveItemDigest,
			GeneratedAt:          generatedAt.UTC(),
		}
		item.ClosureItemDigest = secureCellGovernmentAgentExecutionLaunchClosureItemDigest(item)
		item.ItemID = "government-agent-execution-launch-closure-item:" + item.CellID + ":" + item.ClosureItemDigest[:12]
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status == items[j].Status {
			if items[i].Sequence == items[j].Sequence {
				return items[i].ReceiptType < items[j].ReceiptType
			}
			return items[i].Sequence < items[j].Sequence
		}
		return secureCellGovernmentAgentExecutionLaunchClosureItemStatusRank(items[i].Status) < secureCellGovernmentAgentExecutionLaunchClosureItemStatusRank(items[j].Status)
	})
	return items
}

func secureCellGovernmentAgentExecutionLaunchClosureItemStatus(status SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus) SecureCellGovernmentAgentExecutionLaunchClosureItemStatus {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemBlocked:
		return SecureCellGovernmentAgentExecutionLaunchClosureItemBlocked
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemArchived:
		return SecureCellGovernmentAgentExecutionLaunchClosureItemClosed
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureItemAwaitingArchiveIssue
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAction(status SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemStatus) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemBlocked:
		return "escalate_closure_blocker"
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemArchived:
		return "close_record"
	default:
		return "issue_archive_certificate"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureRequiredAction(item SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItem) string {
	switch item.Status {
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemBlocked:
		return "Resolve blocked archive certificate item before record closure."
	case SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItemArchived:
		return "Mark the launch record closed from the archived certificate evidence."
	default:
		return "Issue the archive certificate before record closure."
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureRegistryStatus(registry SecureCellGovernmentAgentExecutionLaunchClosureRegistry) SecureCellGovernmentAgentExecutionLaunchClosureRegistryStatus {
	if registry.CertificateStatus == SecureCellGovernmentAgentExecutionLaunchArchiveCertificateBlocked || registry.BlockedClosureItemCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureRegistryBlocked
	}
	if registry.PendingClosureItemCount > 0 || registry.CertificateStatus == SecureCellGovernmentAgentExecutionLaunchArchiveCertificateAwaitingPreservation {
		return SecureCellGovernmentAgentExecutionLaunchClosureRegistryAwaitingArchiveIssue
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureRegistryClosed
}

func secureCellGovernmentAgentExecutionLaunchClosureRegistryInstructions(registry SecureCellGovernmentAgentExecutionLaunchClosureRegistry) []string {
	instructions := append([]string(nil), registry.Certificate.OperatorInstructions...)
	switch registry.Status {
	case SecureCellGovernmentAgentExecutionLaunchClosureRegistryBlocked:
		instructions = append(instructions, "Escalate blocked closure items before marking the launch record closed.")
	case SecureCellGovernmentAgentExecutionLaunchClosureRegistryAwaitingArchiveIssue:
		instructions = append(instructions, "Issue the archive certificate before marking the launch record closed.")
	default:
		instructions = append(instructions, "Mark the launch record institutionally closed.")
	}
	if registry.ClosureItemCount > 0 {
		instructions = append(instructions, fmt.Sprintf("Review %d closure items before closing the launch record.", registry.ClosureItemCount))
	}
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchClosureRegistryStatusRank(status SecureCellGovernmentAgentExecutionLaunchClosureRegistryStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureRegistryBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureRegistryAwaitingArchiveIssue:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureRegistryClosed:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureItemStatusRank(status SecureCellGovernmentAgentExecutionLaunchClosureItemStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureItemBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureItemAwaitingArchiveIssue:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureItemClosed:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureItemDigest(item SecureCellGovernmentAgentExecutionLaunchClosureItem) string {
	core := struct {
		Sequence             int                                                       `json:"sequence"`
		CellID               string                                                    `json:"cell_id"`
		CertificateID        string                                                    `json:"certificate_id"`
		SettlementRegisterID string                                                    `json:"settlement_register_id"`
		ArchiveItemID        string                                                    `json:"archive_item_id"`
		ReceiptType          string                                                    `json:"receipt_type"`
		GateKind             string                                                    `json:"gate_kind"`
		Status               SecureCellGovernmentAgentExecutionLaunchClosureItemStatus `json:"status"`
		ClosureAction        string                                                    `json:"closure_action"`
		ArchiveItemDigest    string                                                    `json:"archive_item_digest"`
	}{
		Sequence:             item.Sequence,
		CellID:               item.CellID,
		CertificateID:        item.CertificateID,
		SettlementRegisterID: item.SettlementRegisterID,
		ArchiveItemID:        item.ArchiveItemID,
		ReceiptType:          item.ReceiptType,
		GateKind:             item.GateKind,
		Status:               item.Status,
		ClosureAction:        item.ClosureAction,
		ArchiveItemDigest:    item.ArchiveItemDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchClosureRegistryDigest(registry SecureCellGovernmentAgentExecutionLaunchClosureRegistry) string {
	itemDigests := make([]string, 0, len(registry.Items))
	for _, item := range registry.Items {
		itemDigests = append(itemDigests, item.ClosureItemDigest)
	}
	core := struct {
		CertificateID             string                                                           `json:"certificate_id"`
		SettlementRegisterID      string                                                           `json:"settlement_register_id"`
		CloseoutRegisterID        string                                                           `json:"closeout_register_id"`
		LedgerID                  string                                                           `json:"ledger_id"`
		MonitorID                 string                                                           `json:"monitor_id"`
		OrderID                   string                                                           `json:"order_id"`
		ActivationID              string                                                           `json:"activation_id"`
		CellID                    string                                                           `json:"cell_id"`
		Status                    SecureCellGovernmentAgentExecutionLaunchClosureRegistryStatus    `json:"status"`
		CertificateStatus         SecureCellGovernmentAgentExecutionLaunchArchiveCertificateStatus `json:"certificate_status"`
		CanCloseRecordNow         bool                                                             `json:"can_close_record_now"`
		CanCloseAfterArchiveIssue bool                                                             `json:"can_close_after_archive_issue"`
		CanEscalateBlocked        bool                                                             `json:"can_escalate_blocked"`
		RequiredReceiptTypes      []string                                                         `json:"required_receipt_types,omitempty"`
		ItemDigests               []string                                                         `json:"item_digests,omitempty"`
		CertificateDigest         string                                                           `json:"certificate_digest"`
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
		CertificateID:             registry.CertificateID,
		SettlementRegisterID:      registry.SettlementRegisterID,
		CloseoutRegisterID:        registry.CloseoutRegisterID,
		LedgerID:                  registry.LedgerID,
		MonitorID:                 registry.MonitorID,
		OrderID:                   registry.OrderID,
		ActivationID:              registry.ActivationID,
		CellID:                    registry.CellID,
		Status:                    registry.Status,
		CertificateStatus:         registry.CertificateStatus,
		CanCloseRecordNow:         registry.CanCloseRecordNow,
		CanCloseAfterArchiveIssue: registry.CanCloseAfterArchiveIssue,
		CanEscalateBlocked:        registry.CanEscalateBlocked,
		RequiredReceiptTypes:      registry.RequiredReceiptTypes,
		ItemDigests:               itemDigests,
		CertificateDigest:         registry.CertificateDigest,
		SettlementRegisterDigest:  registry.SettlementRegisterDigest,
		CloseoutDigest:            registry.CloseoutDigest,
		LedgerDigest:              registry.LedgerDigest,
		MonitorDigest:             registry.MonitorDigest,
		OrderDigest:               registry.OrderDigest,
		ActivationDigest:          registry.ActivationDigest,
		CustodyDigest:             registry.CustodyDigest,
		PackageDigest:             registry.PackageDigest,
		LaunchDigest:              registry.LaunchDigest,
		ReceiptManifestDigest:     registry.ReceiptManifestDigest,
		ReceiptValidationDigest:   registry.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
