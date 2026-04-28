package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureBoardStatus describes the
// operator posture for final record closure across one launch workflow.
type SecureCellGovernmentAgentExecutionLaunchClosureBoardStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureBoardBlocked              SecureCellGovernmentAgentExecutionLaunchClosureBoardStatus = "board_blocked"
	SecureCellGovernmentAgentExecutionLaunchClosureBoardAwaitingArchiveIssue SecureCellGovernmentAgentExecutionLaunchClosureBoardStatus = "awaiting_archive_issue"
	SecureCellGovernmentAgentExecutionLaunchClosureBoardReadyToClose         SecureCellGovernmentAgentExecutionLaunchClosureBoardStatus = "ready_to_close"
)

// SecureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus records the
// board-facing posture for one closure item.
type SecureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureBoardItemBlocked              SecureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchClosureBoardItemAwaitingArchiveIssue SecureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus = "awaiting_archive_issue"
	SecureCellGovernmentAgentExecutionLaunchClosureBoardItemReadyToClose         SecureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus = "ready_to_close"
)

// SecureCellGovernmentAgentExecutionLaunchClosureBoardItem is one closure task
// shown on the operator board.
type SecureCellGovernmentAgentExecutionLaunchClosureBoardItem struct {
	ItemID            string                                                         `json:"item_id"`
	Sequence          int                                                            `json:"sequence"`
	CellID            string                                                         `json:"cell_id"`
	RegistryID        string                                                         `json:"registry_id"`
	CertificateID     string                                                         `json:"certificate_id"`
	ClosureItemID     string                                                         `json:"closure_item_id"`
	ReceiptType       string                                                         `json:"receipt_type"`
	GateKind          string                                                         `json:"gate_kind"`
	Status            SecureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus `json:"status"`
	BoardAction       string                                                         `json:"board_action"`
	RequiredAction    string                                                         `json:"required_action"`
	DueAt             *time.Time                                                     `json:"due_at,omitempty"`
	EvidenceBindingID string                                                         `json:"evidence_binding_id"`
	EvidenceDigest    string                                                         `json:"evidence_digest,omitempty"`
	ClosureItemDigest string                                                         `json:"closure_item_digest"`
	BoardItemDigest   string                                                         `json:"board_item_digest"`
	GeneratedAt       time.Time                                                      `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureBoard is the operator surface
// for closure queueing and final release decisions.
type SecureCellGovernmentAgentExecutionLaunchClosureBoard struct {
	BoardID                   string                                                        `json:"board_id"`
	RegistryID                string                                                        `json:"registry_id"`
	CertificateID             string                                                        `json:"certificate_id"`
	SettlementRegisterID      string                                                        `json:"settlement_register_id"`
	CloseoutRegisterID        string                                                        `json:"closeout_register_id"`
	LedgerID                  string                                                        `json:"ledger_id"`
	MonitorID                 string                                                        `json:"monitor_id"`
	OrderID                   string                                                        `json:"order_id"`
	ActivationID              string                                                        `json:"activation_id"`
	CustodyID                 string                                                        `json:"custody_id"`
	PackageID                 string                                                        `json:"package_id"`
	CellID                    string                                                        `json:"cell_id"`
	Name                      string                                                        `json:"name"`
	Jurisdiction              string                                                        `json:"jurisdiction,omitempty"`
	ServiceCode               string                                                        `json:"service_code,omitempty"`
	ServiceTier               string                                                        `json:"service_tier,omitempty"`
	Status                    SecureCellGovernmentAgentExecutionLaunchClosureBoardStatus    `json:"status"`
	RegistryStatus            SecureCellGovernmentAgentExecutionLaunchClosureRegistryStatus `json:"registry_status"`
	CanCloseNow               bool                                                          `json:"can_close_now"`
	CanCloseAfterArchiveIssue bool                                                          `json:"can_close_after_archive_issue"`
	CanEscalateBlocked        bool                                                          `json:"can_escalate_blocked"`
	ItemCount                 int                                                           `json:"item_count"`
	BlockedItemCount          int                                                           `json:"blocked_item_count"`
	PendingItemCount          int                                                           `json:"pending_item_count"`
	ReadyItemCount            int                                                           `json:"ready_item_count"`
	RequiredReceiptTypes      []string                                                      `json:"required_receipt_types,omitempty"`
	OperatorInstructions      []string                                                      `json:"operator_instructions,omitempty"`
	RegistryDigest            string                                                        `json:"registry_digest"`
	CertificateDigest         string                                                        `json:"certificate_digest"`
	SettlementRegisterDigest  string                                                        `json:"settlement_register_digest"`
	CloseoutDigest            string                                                        `json:"closeout_digest"`
	LedgerDigest              string                                                        `json:"ledger_digest"`
	MonitorDigest             string                                                        `json:"monitor_digest"`
	OrderDigest               string                                                        `json:"order_digest"`
	ActivationDigest          string                                                        `json:"activation_digest"`
	CustodyDigest             string                                                        `json:"custody_digest"`
	PackageDigest             string                                                        `json:"package_digest"`
	LaunchDigest              string                                                        `json:"launch_digest"`
	ReceiptManifestDigest     string                                                        `json:"receipt_manifest_digest"`
	ReceiptValidationDigest   string                                                        `json:"receipt_validation_digest"`
	Items                     []SecureCellGovernmentAgentExecutionLaunchClosureBoardItem    `json:"items"`
	Registry                  SecureCellGovernmentAgentExecutionLaunchClosureRegistry       `json:"registry"`
	BoardDigest               string                                                        `json:"board_digest"`
	GeneratedAt               time.Time                                                     `json:"generated_at"`
	UpdatedAt                 time.Time                                                     `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureBoard returns the operator closure
// board for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureBoard(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchClosureBoard, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchClosureBoards(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-board: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchClosureBoards returns operator closure
// boards for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchClosureBoards(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchClosureBoard, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-board: service is required")
	}
	registries, err := s.ListGovernmentAgentExecutionLaunchClosureRegistries(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	boards := make([]SecureCellGovernmentAgentExecutionLaunchClosureBoard, 0, len(registries))
	for _, registry := range registries {
		boards = append(boards, secureCellGovernmentAgentExecutionLaunchClosureBoard(registry, now))
	}
	sort.SliceStable(boards, func(i, j int) bool {
		if boards[i].Status == boards[j].Status {
			if boards[i].BlockedItemCount == boards[j].BlockedItemCount {
				if boards[i].PendingItemCount == boards[j].PendingItemCount {
					return boards[i].CellID < boards[j].CellID
				}
				return boards[i].PendingItemCount > boards[j].PendingItemCount
			}
			return boards[i].BlockedItemCount > boards[j].BlockedItemCount
		}
		return secureCellGovernmentAgentExecutionLaunchClosureBoardStatusRank(boards[i].Status) < secureCellGovernmentAgentExecutionLaunchClosureBoardStatusRank(boards[j].Status)
	})
	return boards, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureBoard(
	registry SecureCellGovernmentAgentExecutionLaunchClosureRegistry,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureBoard {
	items := secureCellGovernmentAgentExecutionLaunchClosureBoardItems(registry, generatedAt)
	board := SecureCellGovernmentAgentExecutionLaunchClosureBoard{
		RegistryID:               registry.RegistryID,
		CertificateID:            registry.CertificateID,
		SettlementRegisterID:     registry.SettlementRegisterID,
		CloseoutRegisterID:       registry.CloseoutRegisterID,
		LedgerID:                 registry.LedgerID,
		MonitorID:                registry.MonitorID,
		OrderID:                  registry.OrderID,
		ActivationID:             registry.ActivationID,
		CustodyID:                registry.CustodyID,
		PackageID:                registry.PackageID,
		CellID:                   registry.CellID,
		Name:                     registry.Name,
		Jurisdiction:             registry.Jurisdiction,
		ServiceCode:              registry.ServiceCode,
		ServiceTier:              registry.ServiceTier,
		RegistryStatus:           registry.Status,
		RegistryDigest:           registry.RegistryDigest,
		CertificateDigest:        registry.CertificateDigest,
		SettlementRegisterDigest: registry.SettlementRegisterDigest,
		CloseoutDigest:           registry.CloseoutDigest,
		LedgerDigest:             registry.LedgerDigest,
		MonitorDigest:            registry.MonitorDigest,
		OrderDigest:              registry.OrderDigest,
		ActivationDigest:         registry.ActivationDigest,
		CustodyDigest:            registry.CustodyDigest,
		PackageDigest:            registry.PackageDigest,
		LaunchDigest:             registry.LaunchDigest,
		ReceiptManifestDigest:    registry.ReceiptManifestDigest,
		ReceiptValidationDigest:  registry.ReceiptValidationDigest,
		Items:                    items,
		Registry:                 registry,
		GeneratedAt:              generatedAt.UTC(),
		UpdatedAt:                registry.UpdatedAt.UTC(),
	}
	receiptTypes := make([]string, 0, len(items))
	for _, item := range board.Items {
		board.ItemCount++
		receiptTypes = append(receiptTypes, item.ReceiptType)
		switch item.Status {
		case SecureCellGovernmentAgentExecutionLaunchClosureBoardItemBlocked:
			board.BlockedItemCount++
		case SecureCellGovernmentAgentExecutionLaunchClosureBoardItemAwaitingArchiveIssue:
			board.PendingItemCount++
		default:
			board.ReadyItemCount++
		}
	}
	board.RequiredReceiptTypes = uniqueSortedStrings(receiptTypes)
	board.Status = secureCellGovernmentAgentExecutionLaunchClosureBoardStatus(board)
	board.CanCloseNow = board.Status == SecureCellGovernmentAgentExecutionLaunchClosureBoardReadyToClose
	board.CanCloseAfterArchiveIssue = board.Status == SecureCellGovernmentAgentExecutionLaunchClosureBoardAwaitingArchiveIssue
	board.CanEscalateBlocked = board.Status == SecureCellGovernmentAgentExecutionLaunchClosureBoardBlocked
	board.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchClosureBoardInstructions(board)
	board.BoardDigest = secureCellGovernmentAgentExecutionLaunchClosureBoardDigest(board)
	board.BoardID = "government-agent-execution-launch-closure-board:" + board.CellID + ":" + board.BoardDigest[:12]
	return board
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardItems(
	registry SecureCellGovernmentAgentExecutionLaunchClosureRegistry,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchClosureBoardItem {
	items := make([]SecureCellGovernmentAgentExecutionLaunchClosureBoardItem, 0, len(registry.Items))
	for _, closureItem := range registry.Items {
		item := SecureCellGovernmentAgentExecutionLaunchClosureBoardItem{
			Sequence:          closureItem.Sequence,
			CellID:            registry.CellID,
			RegistryID:        registry.RegistryID,
			CertificateID:     registry.CertificateID,
			ClosureItemID:     closureItem.ItemID,
			ReceiptType:       closureItem.ReceiptType,
			GateKind:          closureItem.GateKind,
			Status:            secureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus(closureItem.Status),
			BoardAction:       secureCellGovernmentAgentExecutionLaunchClosureBoardAction(closureItem.Status),
			RequiredAction:    secureCellGovernmentAgentExecutionLaunchClosureBoardRequiredAction(closureItem),
			DueAt:             cloneTimePtr(closureItem.DueAt),
			EvidenceBindingID: closureItem.EvidenceBindingID,
			EvidenceDigest:    closureItem.EvidenceDigest,
			ClosureItemDigest: closureItem.ClosureItemDigest,
			GeneratedAt:       generatedAt.UTC(),
		}
		item.BoardItemDigest = secureCellGovernmentAgentExecutionLaunchClosureBoardItemDigest(item)
		item.ItemID = "government-agent-execution-launch-closure-board-item:" + item.CellID + ":" + item.BoardItemDigest[:12]
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status == items[j].Status {
			if items[i].Sequence == items[j].Sequence {
				return items[i].ReceiptType < items[j].ReceiptType
			}
			return items[i].Sequence < items[j].Sequence
		}
		return secureCellGovernmentAgentExecutionLaunchClosureBoardItemStatusRank(items[i].Status) < secureCellGovernmentAgentExecutionLaunchClosureBoardItemStatusRank(items[j].Status)
	})
	return items
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus(status SecureCellGovernmentAgentExecutionLaunchClosureItemStatus) SecureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureItemBlocked:
		return SecureCellGovernmentAgentExecutionLaunchClosureBoardItemBlocked
	case SecureCellGovernmentAgentExecutionLaunchClosureItemClosed:
		return SecureCellGovernmentAgentExecutionLaunchClosureBoardItemReadyToClose
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureBoardItemAwaitingArchiveIssue
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardAction(status SecureCellGovernmentAgentExecutionLaunchClosureItemStatus) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureItemBlocked:
		return "escalate_board_blocker"
	case SecureCellGovernmentAgentExecutionLaunchClosureItemClosed:
		return "close_from_board"
	default:
		return "issue_archive_from_board"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardRequiredAction(item SecureCellGovernmentAgentExecutionLaunchClosureItem) string {
	switch item.Status {
	case SecureCellGovernmentAgentExecutionLaunchClosureItemBlocked:
		return "Resolve blocked closure item before board closure."
	case SecureCellGovernmentAgentExecutionLaunchClosureItemClosed:
		return "Mark this launch record ready for final board closure."
	default:
		return "Issue the archive certificate before board closure."
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardStatus(board SecureCellGovernmentAgentExecutionLaunchClosureBoard) SecureCellGovernmentAgentExecutionLaunchClosureBoardStatus {
	if board.RegistryStatus == SecureCellGovernmentAgentExecutionLaunchClosureRegistryBlocked || board.BlockedItemCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureBoardBlocked
	}
	if board.PendingItemCount > 0 || board.RegistryStatus == SecureCellGovernmentAgentExecutionLaunchClosureRegistryAwaitingArchiveIssue {
		return SecureCellGovernmentAgentExecutionLaunchClosureBoardAwaitingArchiveIssue
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureBoardReadyToClose
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardInstructions(board SecureCellGovernmentAgentExecutionLaunchClosureBoard) []string {
	instructions := append([]string(nil), board.Registry.OperatorInstructions...)
	switch board.Status {
	case SecureCellGovernmentAgentExecutionLaunchClosureBoardBlocked:
		instructions = append(instructions, "Escalate blocked board items before final launch closure.")
	case SecureCellGovernmentAgentExecutionLaunchClosureBoardAwaitingArchiveIssue:
		instructions = append(instructions, "Issue the archive certificate before final launch closure.")
	default:
		instructions = append(instructions, "Close the launch record from the operator board.")
	}
	if board.ItemCount > 0 {
		instructions = append(instructions, fmt.Sprintf("Review %d operator board items before closing the record.", board.ItemCount))
	}
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardStatusRank(status SecureCellGovernmentAgentExecutionLaunchClosureBoardStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureBoardBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureBoardAwaitingArchiveIssue:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureBoardReadyToClose:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardItemStatusRank(status SecureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureBoardItemBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureBoardItemAwaitingArchiveIssue:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureBoardItemReadyToClose:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardItemDigest(item SecureCellGovernmentAgentExecutionLaunchClosureBoardItem) string {
	core := struct {
		Sequence          int                                                            `json:"sequence"`
		CellID            string                                                         `json:"cell_id"`
		RegistryID        string                                                         `json:"registry_id"`
		CertificateID     string                                                         `json:"certificate_id"`
		ClosureItemID     string                                                         `json:"closure_item_id"`
		ReceiptType       string                                                         `json:"receipt_type"`
		GateKind          string                                                         `json:"gate_kind"`
		Status            SecureCellGovernmentAgentExecutionLaunchClosureBoardItemStatus `json:"status"`
		BoardAction       string                                                         `json:"board_action"`
		ClosureItemDigest string                                                         `json:"closure_item_digest"`
	}{
		Sequence:          item.Sequence,
		CellID:            item.CellID,
		RegistryID:        item.RegistryID,
		CertificateID:     item.CertificateID,
		ClosureItemID:     item.ClosureItemID,
		ReceiptType:       item.ReceiptType,
		GateKind:          item.GateKind,
		Status:            item.Status,
		BoardAction:       item.BoardAction,
		ClosureItemDigest: item.ClosureItemDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardDigest(board SecureCellGovernmentAgentExecutionLaunchClosureBoard) string {
	itemDigests := make([]string, 0, len(board.Items))
	for _, item := range board.Items {
		itemDigests = append(itemDigests, item.BoardItemDigest)
	}
	core := struct {
		RegistryID                string                                                        `json:"registry_id"`
		CertificateID             string                                                        `json:"certificate_id"`
		SettlementRegisterID      string                                                        `json:"settlement_register_id"`
		CloseoutRegisterID        string                                                        `json:"closeout_register_id"`
		LedgerID                  string                                                        `json:"ledger_id"`
		MonitorID                 string                                                        `json:"monitor_id"`
		OrderID                   string                                                        `json:"order_id"`
		ActivationID              string                                                        `json:"activation_id"`
		CellID                    string                                                        `json:"cell_id"`
		Status                    SecureCellGovernmentAgentExecutionLaunchClosureBoardStatus    `json:"status"`
		RegistryStatus            SecureCellGovernmentAgentExecutionLaunchClosureRegistryStatus `json:"registry_status"`
		CanCloseNow               bool                                                          `json:"can_close_now"`
		CanCloseAfterArchiveIssue bool                                                          `json:"can_close_after_archive_issue"`
		CanEscalateBlocked        bool                                                          `json:"can_escalate_blocked"`
		RequiredReceiptTypes      []string                                                      `json:"required_receipt_types,omitempty"`
		ItemDigests               []string                                                      `json:"item_digests,omitempty"`
		RegistryDigest            string                                                        `json:"registry_digest"`
		CertificateDigest         string                                                        `json:"certificate_digest"`
		SettlementRegisterDigest  string                                                        `json:"settlement_register_digest"`
		CloseoutDigest            string                                                        `json:"closeout_digest"`
		LedgerDigest              string                                                        `json:"ledger_digest"`
		MonitorDigest             string                                                        `json:"monitor_digest"`
		OrderDigest               string                                                        `json:"order_digest"`
		ActivationDigest          string                                                        `json:"activation_digest"`
		CustodyDigest             string                                                        `json:"custody_digest"`
		PackageDigest             string                                                        `json:"package_digest"`
		LaunchDigest              string                                                        `json:"launch_digest"`
		ReceiptManifestDigest     string                                                        `json:"receipt_manifest_digest"`
		ReceiptValidationDigest   string                                                        `json:"receipt_validation_digest"`
	}{
		RegistryID:                board.RegistryID,
		CertificateID:             board.CertificateID,
		SettlementRegisterID:      board.SettlementRegisterID,
		CloseoutRegisterID:        board.CloseoutRegisterID,
		LedgerID:                  board.LedgerID,
		MonitorID:                 board.MonitorID,
		OrderID:                   board.OrderID,
		ActivationID:              board.ActivationID,
		CellID:                    board.CellID,
		Status:                    board.Status,
		RegistryStatus:            board.RegistryStatus,
		CanCloseNow:               board.CanCloseNow,
		CanCloseAfterArchiveIssue: board.CanCloseAfterArchiveIssue,
		CanEscalateBlocked:        board.CanEscalateBlocked,
		RequiredReceiptTypes:      board.RequiredReceiptTypes,
		ItemDigests:               itemDigests,
		RegistryDigest:            board.RegistryDigest,
		CertificateDigest:         board.CertificateDigest,
		SettlementRegisterDigest:  board.SettlementRegisterDigest,
		CloseoutDigest:            board.CloseoutDigest,
		LedgerDigest:              board.LedgerDigest,
		MonitorDigest:             board.MonitorDigest,
		OrderDigest:               board.OrderDigest,
		ActivationDigest:          board.ActivationDigest,
		CustodyDigest:             board.CustodyDigest,
		PackageDigest:             board.PackageDigest,
		LaunchDigest:              board.LaunchDigest,
		ReceiptManifestDigest:     board.ReceiptManifestDigest,
		ReceiptValidationDigest:   board.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
