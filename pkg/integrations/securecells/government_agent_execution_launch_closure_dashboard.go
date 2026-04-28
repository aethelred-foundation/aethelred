package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus describes the
// portfolio-facing posture for one launch record.
type SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureDashboardBlocked              SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus = "dashboard_blocked"
	SecureCellGovernmentAgentExecutionLaunchClosureDashboardAwaitingArchiveIssue SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus = "awaiting_archive_issue"
	SecureCellGovernmentAgentExecutionLaunchClosureDashboardReadyToClose         SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus = "ready_to_close"
)

// SecureCellGovernmentAgentExecutionLaunchClosureDashboard is the portfolio
// dashboard row for one secure cell.
type SecureCellGovernmentAgentExecutionLaunchClosureDashboard struct {
	DashboardID               string                                                             `json:"dashboard_id"`
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
	Status                    SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus     `json:"status"`
	CenterStatus              SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus `json:"center_status"`
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
	CenterDigest              string                                                             `json:"center_digest"`
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
	CommandCenter             SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter       `json:"command_center"`
	DashboardDigest           string                                                             `json:"dashboard_digest"`
	GeneratedAt               time.Time                                                          `json:"generated_at"`
	UpdatedAt                 time.Time                                                          `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureDashboard returns the portfolio
// dashboard view for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureDashboard(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchClosureDashboard, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchClosureDashboards(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-dashboard: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchClosureDashboards returns dashboard rows
// for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchClosureDashboards(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchClosureDashboard, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-dashboard: service is required")
	}
	centers, err := s.ListGovernmentAgentExecutionLaunchClosureCommandCenters(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	dashboards := make([]SecureCellGovernmentAgentExecutionLaunchClosureDashboard, 0, len(centers))
	for _, center := range centers {
		dashboards = append(dashboards, secureCellGovernmentAgentExecutionLaunchClosureDashboard(center, now))
	}
	sort.SliceStable(dashboards, func(i, j int) bool {
		if dashboards[i].Status == dashboards[j].Status {
			if dashboards[i].BlockedItemCount == dashboards[j].BlockedItemCount {
				if dashboards[i].PendingItemCount == dashboards[j].PendingItemCount {
					return dashboards[i].CellID < dashboards[j].CellID
				}
				return dashboards[i].PendingItemCount > dashboards[j].PendingItemCount
			}
			return dashboards[i].BlockedItemCount > dashboards[j].BlockedItemCount
		}
		return secureCellGovernmentAgentExecutionLaunchClosureDashboardStatusRank(dashboards[i].Status) < secureCellGovernmentAgentExecutionLaunchClosureDashboardStatusRank(dashboards[j].Status)
	})
	return dashboards, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureDashboard(
	center SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureDashboard {
	dashboard := SecureCellGovernmentAgentExecutionLaunchClosureDashboard{
		CenterID:                  center.CenterID,
		BoardID:                   center.BoardID,
		RegistryID:                center.RegistryID,
		CertificateID:             center.CertificateID,
		SettlementRegisterID:      center.SettlementRegisterID,
		CloseoutRegisterID:        center.CloseoutRegisterID,
		LedgerID:                  center.LedgerID,
		MonitorID:                 center.MonitorID,
		OrderID:                   center.OrderID,
		ActivationID:              center.ActivationID,
		CustodyID:                 center.CustodyID,
		PackageID:                 center.PackageID,
		CellID:                    center.CellID,
		Name:                      center.Name,
		Jurisdiction:              center.Jurisdiction,
		ServiceCode:               center.ServiceCode,
		ServiceTier:               center.ServiceTier,
		CenterStatus:              center.Status,
		CanCloseNow:               center.CanCloseNow,
		CanCloseAfterArchiveIssue: center.CanCloseAfterArchiveIssue,
		CanEscalateBlocked:        center.CanEscalateBlocked,
		ItemCount:                 center.ItemCount,
		BlockedItemCount:          center.BlockedItemCount,
		PendingItemCount:          center.PendingItemCount,
		ReadyItemCount:            center.ReadyItemCount,
		RequiredReceiptTypes:      append([]string(nil), center.RequiredReceiptTypes...),
		PrimaryAction:             center.PrimaryAction,
		OperatorInstructions:      append([]string(nil), center.OperatorInstructions...),
		CenterDigest:              center.CenterDigest,
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
		CommandCenter:             center,
		GeneratedAt:               generatedAt.UTC(),
		UpdatedAt:                 center.UpdatedAt.UTC(),
	}
	dashboard.Status = secureCellGovernmentAgentExecutionLaunchClosureDashboardStatus(dashboard)
	dashboard.DashboardDigest = secureCellGovernmentAgentExecutionLaunchClosureDashboardDigest(dashboard)
	dashboard.DashboardID = "government-agent-execution-launch-closure-dashboard:" + dashboard.CellID + ":" + dashboard.DashboardDigest[:12]
	return dashboard
}

func secureCellGovernmentAgentExecutionLaunchClosureDashboardStatus(dashboard SecureCellGovernmentAgentExecutionLaunchClosureDashboard) SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus {
	switch dashboard.CenterStatus {
	case SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterBlocked:
		return SecureCellGovernmentAgentExecutionLaunchClosureDashboardBlocked
	case SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterAwaitingArchiveIssue:
		return SecureCellGovernmentAgentExecutionLaunchClosureDashboardAwaitingArchiveIssue
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureDashboardReadyToClose
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureDashboardStatusRank(status SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureDashboardBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureDashboardAwaitingArchiveIssue:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureDashboardReadyToClose:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureDashboardDigest(dashboard SecureCellGovernmentAgentExecutionLaunchClosureDashboard) string {
	core := struct {
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
		CellID                    string                                                             `json:"cell_id"`
		Status                    SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus     `json:"status"`
		CenterStatus              SecureCellGovernmentAgentExecutionLaunchClosureCommandCenterStatus `json:"center_status"`
		CanCloseNow               bool                                                               `json:"can_close_now"`
		CanCloseAfterArchiveIssue bool                                                               `json:"can_close_after_archive_issue"`
		CanEscalateBlocked        bool                                                               `json:"can_escalate_blocked"`
		ItemCount                 int                                                                `json:"item_count"`
		BlockedItemCount          int                                                                `json:"blocked_item_count"`
		PendingItemCount          int                                                                `json:"pending_item_count"`
		ReadyItemCount            int                                                                `json:"ready_item_count"`
		RequiredReceiptTypes      []string                                                           `json:"required_receipt_types,omitempty"`
		PrimaryAction             string                                                             `json:"primary_action"`
		CenterDigest              string                                                             `json:"center_digest"`
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
		CenterID:                  dashboard.CenterID,
		BoardID:                   dashboard.BoardID,
		RegistryID:                dashboard.RegistryID,
		CertificateID:             dashboard.CertificateID,
		SettlementRegisterID:      dashboard.SettlementRegisterID,
		CloseoutRegisterID:        dashboard.CloseoutRegisterID,
		LedgerID:                  dashboard.LedgerID,
		MonitorID:                 dashboard.MonitorID,
		OrderID:                   dashboard.OrderID,
		ActivationID:              dashboard.ActivationID,
		CellID:                    dashboard.CellID,
		Status:                    dashboard.Status,
		CenterStatus:              dashboard.CenterStatus,
		CanCloseNow:               dashboard.CanCloseNow,
		CanCloseAfterArchiveIssue: dashboard.CanCloseAfterArchiveIssue,
		CanEscalateBlocked:        dashboard.CanEscalateBlocked,
		ItemCount:                 dashboard.ItemCount,
		BlockedItemCount:          dashboard.BlockedItemCount,
		PendingItemCount:          dashboard.PendingItemCount,
		ReadyItemCount:            dashboard.ReadyItemCount,
		RequiredReceiptTypes:      dashboard.RequiredReceiptTypes,
		PrimaryAction:             dashboard.PrimaryAction,
		CenterDigest:              dashboard.CenterDigest,
		BoardDigest:               dashboard.BoardDigest,
		RegistryDigest:            dashboard.RegistryDigest,
		CertificateDigest:         dashboard.CertificateDigest,
		SettlementRegisterDigest:  dashboard.SettlementRegisterDigest,
		CloseoutDigest:            dashboard.CloseoutDigest,
		LedgerDigest:              dashboard.LedgerDigest,
		MonitorDigest:             dashboard.MonitorDigest,
		OrderDigest:               dashboard.OrderDigest,
		ActivationDigest:          dashboard.ActivationDigest,
		CustodyDigest:             dashboard.CustodyDigest,
		PackageDigest:             dashboard.PackageDigest,
		LaunchDigest:              dashboard.LaunchDigest,
		ReceiptManifestDigest:     dashboard.ReceiptManifestDigest,
		ReceiptValidationDigest:   dashboard.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
