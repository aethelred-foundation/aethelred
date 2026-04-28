package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus describes
// the top-level operator posture for one launch record.
type SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterBlocked              SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus = "command_blocked"
	SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterAwaitingArchiveIssue SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus = "awaiting_archive_issue"
	SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterReadyToClose         SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus = "ready_to_close"
)

// SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter is the compact
// operator-facing closure command view for one secure cell.
type SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter struct {
	CenterID                  string                                                             `json:"center_id"`
	BoardID                   string                                                             `json:"board_id"`
	RegistryID                string                                                             `json:"registry_id"`
	CertificateID             string                                                             `json:"certificate_id"`
	SettlementRegisterID      string                                                             `json:"settlement_register_id"`
	CloseoutRegisterID        string                                                             `json:"closeout_register_id"`
	LedgerID                  string                                                             `json:"ledger_id"`
	MonitorID                 string                                                             `json:"monitor_id"`
	OrderID                   string                                                             `json:"order_id"`
	ActivationID              string                                                             `json:"activation_id"`
	CustodyID                 string                                                             `json:"custody_id"`
	PackageID                 string                                                             `json:"package_id"`
	CellID                    string                                                             `json:"cell_id"`
	Name                      string                                                             `json:"name"`
	Jurisdiction              string                                                             `json:"jurisdiction,omitempty"`
	ServiceCode               string                                                             `json:"service_code,omitempty"`
	ServiceTier               string                                                             `json:"service_tier,omitempty"`
	Status                    SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus `json:"status"`
	BoardStatus               SecureCellGovernmentAgentExecutionLaunchClosureBoardStatus         `json:"board_status"`
	CanCloseNow               bool                                                               `json:"can_close_now"`
	CanCloseAfterArchiveIssue bool                                                               `json:"can_close_after_archive_issue"`
	CanEscalateBlocked        bool                                                               `json:"can_escalate_blocked"`
	ItemCount                 int                                                                `json:"item_count"`
	BlockedItemCount          int                                                                `json:"blocked_item_count"`
	PendingItemCount          int                                                                `json:"pending_item_count"`
	ReadyItemCount            int                                                                `json:"ready_item_count"`
	RequiredReceiptTypes      []string                                                           `json:"required_receipt_types,omitempty"`
	PrimaryAction             string                                                             `json:"primary_action"`
	OperatorInstructions      []string                                                           `json:"operator_instructions,omitempty"`
	BoardDigest               string                                                             `json:"board_digest"`
	RegistryDigest            string                                                             `json:"registry_digest"`
	CertificateDigest         string                                                             `json:"certificate_digest"`
	SettlementRegisterDigest  string                                                             `json:"settlement_register_digest"`
	CloseoutDigest            string                                                             `json:"closeout_digest"`
	LedgerDigest              string                                                             `json:"ledger_digest"`
	MonitorDigest             string                                                             `json:"monitor_digest"`
	OrderDigest               string                                                             `json:"order_digest"`
	ActivationDigest          string                                                             `json:"activation_digest"`
	CustodyDigest             string                                                             `json:"custody_digest"`
	PackageDigest             string                                                             `json:"package_digest"`
	LaunchDigest              string                                                             `json:"launch_digest"`
	ReceiptManifestDigest     string                                                             `json:"receipt_manifest_digest"`
	ReceiptValidationDigest   string                                                             `json:"receipt_validation_digest"`
	Board                     SecureCellGovernmentAgentExecutionLaunchClosureBoard               `json:"board"`
	CenterDigest              string                                                             `json:"center_digest"`
	GeneratedAt               time.Time                                                          `json:"generated_at"`
	UpdatedAt                 time.Time                                                          `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureCommandCenter returns the command
// center view for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureCommandCenter(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchClosureCommandCenters(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-command-center: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchClosureCommandCenters returns command
// center views for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchClosureCommandCenters(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-command-center: service is required")
	}
	boards, err := s.ListGovernmentAgentExecutionLaunchClosureBoards(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	centers := make([]SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter, 0, len(boards))
	for _, board := range boards {
		centers = append(centers, secureCellGovernmentAgentExecutionLaunchClosureCommandCenter(board, now))
	}
	sort.SliceStable(centers, func(i, j int) bool {
		if centers[i].Status == centers[j].Status {
			if centers[i].BlockedItemCount == centers[j].BlockedItemCount {
				if centers[i].PendingItemCount == centers[j].PendingItemCount {
					return centers[i].CellID < centers[j].CellID
				}
				return centers[i].PendingItemCount > centers[j].PendingItemCount
			}
			return centers[i].BlockedItemCount > centers[j].BlockedItemCount
		}
		return secureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatusRank(centers[i].Status) < secureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatusRank(centers[j].Status)
	})
	return centers, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureCommandCenter(
	board SecureCellGovernmentAgentExecutionLaunchClosureBoard,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter {
	center := SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter{
		BoardID:                   board.BoardID,
		RegistryID:                board.RegistryID,
		CertificateID:             board.CertificateID,
		SettlementRegisterID:      board.SettlementRegisterID,
		CloseoutRegisterID:        board.CloseoutRegisterID,
		LedgerID:                  board.LedgerID,
		MonitorID:                 board.MonitorID,
		OrderID:                   board.OrderID,
		ActivationID:              board.ActivationID,
		CustodyID:                 board.CustodyID,
		PackageID:                 board.PackageID,
		CellID:                    board.CellID,
		Name:                      board.Name,
		Jurisdiction:              board.Jurisdiction,
		ServiceCode:               board.ServiceCode,
		ServiceTier:               board.ServiceTier,
		BoardStatus:               board.Status,
		CanCloseNow:               board.CanCloseNow,
		CanCloseAfterArchiveIssue: board.CanCloseAfterArchiveIssue,
		CanEscalateBlocked:        board.CanEscalateBlocked,
		ItemCount:                 board.ItemCount,
		BlockedItemCount:          board.BlockedItemCount,
		PendingItemCount:          board.PendingItemCount,
		ReadyItemCount:            board.ReadyItemCount,
		RequiredReceiptTypes:      append([]string(nil), board.RequiredReceiptTypes...),
		BoardDigest:               board.BoardDigest,
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
		Board:                     board,
		GeneratedAt:               generatedAt.UTC(),
		UpdatedAt:                 board.UpdatedAt.UTC(),
	}
	center.Status = secureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus(center)
	center.PrimaryAction = secureCellGovernmentAgentExecutionLaunchClosureCommandCenterAction(center)
	center.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchClosureCommandCenterInstructions(center)
	center.CenterDigest = secureCellGovernmentAgentExecutionLaunchClosureCommandCenterDigest(center)
	center.CenterID = "government-agent-execution-launch-closure-command-center:" + center.CellID + ":" + center.CenterDigest[:12]
	return center
}

func secureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus(center SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter) SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus {
	switch center.BoardStatus {
	case SecureCellGovernmentAgentExecutionLaunchClosureBoardBlocked:
		return SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterBlocked
	case SecureCellGovernmentAgentExecutionLaunchClosureBoardAwaitingArchiveIssue:
		return SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterAwaitingArchiveIssue
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterReadyToClose
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureCommandCenterAction(center SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter) string {
	switch center.Status {
	case SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterBlocked:
		return "escalate_blocked_closure"
	case SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterAwaitingArchiveIssue:
		return "issue_archive_certificate"
	default:
		return "close_launch_record"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureCommandCenterInstructions(center SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter) []string {
	instructions := append([]string(nil), center.Board.OperatorInstructions...)
	switch center.Status {
	case SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterBlocked:
		instructions = append(instructions, "Escalate blocked launch closure before final record release.")
	case SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterAwaitingArchiveIssue:
		instructions = append(instructions, "Issue the archive certificate before final record release.")
	default:
		instructions = append(instructions, "Close the launch record from the command center.")
	}
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatusRank(status SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterAwaitingArchiveIssue:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterReadyToClose:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureCommandCenterDigest(center SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter) string {
	core := struct {
		BoardID                   string                                                             `json:"board_id"`
		RegistryID                string                                                             `json:"registry_id"`
		CertificateID             string                                                             `json:"certificate_id"`
		SettlementRegisterID      string                                                             `json:"settlement_register_id"`
		CloseoutRegisterID        string                                                             `json:"closeout_register_id"`
		LedgerID                  string                                                             `json:"ledger_id"`
		MonitorID                 string                                                             `json:"monitor_id"`
		OrderID                   string                                                             `json:"order_id"`
		ActivationID              string                                                             `json:"activation_id"`
		CellID                    string                                                             `json:"cell_id"`
		Status                    SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus `json:"status"`
		BoardStatus               SecureCellGovernmentAgentExecutionLaunchClosureBoardStatus         `json:"board_status"`
		CanCloseNow               bool                                                               `json:"can_close_now"`
		CanCloseAfterArchiveIssue bool                                                               `json:"can_close_after_archive_issue"`
		CanEscalateBlocked        bool                                                               `json:"can_escalate_blocked"`
		ItemCount                 int                                                                `json:"item_count"`
		BlockedItemCount          int                                                                `json:"blocked_item_count"`
		PendingItemCount          int                                                                `json:"pending_item_count"`
		ReadyItemCount            int                                                                `json:"ready_item_count"`
		RequiredReceiptTypes      []string                                                           `json:"required_receipt_types,omitempty"`
		PrimaryAction             string                                                             `json:"primary_action"`
		BoardDigest               string                                                             `json:"board_digest"`
		RegistryDigest            string                                                             `json:"registry_digest"`
		CertificateDigest         string                                                             `json:"certificate_digest"`
		SettlementRegisterDigest  string                                                             `json:"settlement_register_digest"`
		CloseoutDigest            string                                                             `json:"closeout_digest"`
		LedgerDigest              string                                                             `json:"ledger_digest"`
		MonitorDigest             string                                                             `json:"monitor_digest"`
		OrderDigest               string                                                             `json:"order_digest"`
		ActivationDigest          string                                                             `json:"activation_digest"`
		CustodyDigest             string                                                             `json:"custody_digest"`
		PackageDigest             string                                                             `json:"package_digest"`
		LaunchDigest              string                                                             `json:"launch_digest"`
		ReceiptManifestDigest     string                                                             `json:"receipt_manifest_digest"`
		ReceiptValidationDigest   string                                                             `json:"receipt_validation_digest"`
	}{
		BoardID:                   center.BoardID,
		RegistryID:                center.RegistryID,
		CertificateID:             center.CertificateID,
		SettlementRegisterID:      center.SettlementRegisterID,
		CloseoutRegisterID:        center.CloseoutRegisterID,
		LedgerID:                  center.LedgerID,
		MonitorID:                 center.MonitorID,
		OrderID:                   center.OrderID,
		ActivationID:              center.ActivationID,
		CellID:                    center.CellID,
		Status:                    center.Status,
		BoardStatus:               center.BoardStatus,
		CanCloseNow:               center.CanCloseNow,
		CanCloseAfterArchiveIssue: center.CanCloseAfterArchiveIssue,
		CanEscalateBlocked:        center.CanEscalateBlocked,
		ItemCount:                 center.ItemCount,
		BlockedItemCount:          center.BlockedItemCount,
		PendingItemCount:          center.PendingItemCount,
		ReadyItemCount:            center.ReadyItemCount,
		RequiredReceiptTypes:      center.RequiredReceiptTypes,
		PrimaryAction:             center.PrimaryAction,
		BoardDigest:               center.BoardDigest,
		RegistryDigest:            center.RegistryDigest,
		CertificateDigest:         center.CertificateDigest,
		SettlementRegisterDigest:  center.SettlementRegisterDigest,
		CloseoutDigest:            center.CloseoutDigest,
		LedgerDigest:              center.LedgerDigest,
		MonitorDigest:             center.MonitorDigest,
		OrderDigest:               center.OrderDigest,
		ActivationDigest:          center.ActivationDigest,
		CustodyDigest:             center.CustodyDigest,
		PackageDigest:             center.PackageDigest,
		LaunchDigest:              center.LaunchDigest,
		ReceiptManifestDigest:     center.ReceiptManifestDigest,
		ReceiptValidationDigest:   center.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
