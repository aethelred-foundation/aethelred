package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosurePortfolioAction captures an
// operator action recurring across closure dashboards.
type SecureCellGovernmentAgentExecutionLaunchClosurePortfolioAction struct {
	Action  string   `json:"action"`
	Count   int      `json:"count"`
	CellIDs []string `json:"cell_ids,omitempty"`
}

// SecureCellGovernmentAgentExecutionLaunchClosurePortfolio is the estate-wide
// operator summary for launch closure posture across filtered secure cells.
type SecureCellGovernmentAgentExecutionLaunchClosurePortfolio struct {
	PortfolioID               string                                                           `json:"portfolio_id"`
	Jurisdiction              string                                                           `json:"jurisdiction,omitempty"`
	ServiceCode               string                                                           `json:"service_code,omitempty"`
	ServiceTier               string                                                           `json:"service_tier,omitempty"`
	CellCount                 int                                                              `json:"cell_count"`
	BlockedCount              int                                                              `json:"blocked_count"`
	AwaitingArchiveIssueCount int                                                              `json:"awaiting_archive_issue_count"`
	ReadyToCloseCount         int                                                              `json:"ready_to_close_count"`
	CanCloseNowCount          int                                                              `json:"can_close_now_count"`
	CanCloseAfterArchiveCount int                                                              `json:"can_close_after_archive_count"`
	EscalationRequiredCount   int                                                              `json:"escalation_required_count"`
	TotalItemCount            int                                                              `json:"total_item_count"`
	BlockedItemCount          int                                                              `json:"blocked_item_count"`
	PendingItemCount          int                                                              `json:"pending_item_count"`
	ReadyItemCount            int                                                              `json:"ready_item_count"`
	RequiredReceiptTypes      []string                                                         `json:"required_receipt_types,omitempty"`
	PrimaryActions            []SecureCellGovernmentAgentExecutionLaunchClosurePortfolioAction `json:"primary_actions,omitempty"`
	Dashboards                []SecureCellGovernmentAgentExecutionLaunchClosureDashboard       `json:"dashboards"`
	PortfolioDigest           string                                                           `json:"portfolio_digest"`
	GeneratedAt               time.Time                                                        `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosurePortfolio returns the aggregate
// closure posture for matching government-service workflows.
func (s *Service) GetGovernmentAgentExecutionLaunchClosurePortfolio(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) (*SecureCellGovernmentAgentExecutionLaunchClosurePortfolio, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-portfolio: service is required")
	}
	dashboards, err := s.ListGovernmentAgentExecutionLaunchClosureDashboards(ctx, filter)
	if err != nil {
		return nil, err
	}
	portfolio := secureCellGovernmentAgentExecutionLaunchClosurePortfolio(filter, dashboards, time.Now().UTC())
	return &portfolio, nil
}

func secureCellGovernmentAgentExecutionLaunchClosurePortfolio(
	filter SecureCellGovernmentAgentProgramFilter,
	dashboards []SecureCellGovernmentAgentExecutionLaunchClosureDashboard,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosurePortfolio {
	portfolio := SecureCellGovernmentAgentExecutionLaunchClosurePortfolio{
		Jurisdiction: strings.TrimSpace(filter.Jurisdiction),
		ServiceCode:  strings.TrimSpace(filter.ServiceCode),
		ServiceTier:  strings.TrimSpace(filter.ServiceTier),
		Dashboards:   append([]SecureCellGovernmentAgentExecutionLaunchClosureDashboard(nil), dashboards...),
		GeneratedAt:  generatedAt.UTC(),
	}

	actionIndex := map[string]int{}
	for _, dashboard := range dashboards {
		portfolio.CellCount++
		portfolio.TotalItemCount += dashboard.ItemCount
		portfolio.BlockedItemCount += dashboard.BlockedItemCount
		portfolio.PendingItemCount += dashboard.PendingItemCount
		portfolio.ReadyItemCount += dashboard.ReadyItemCount

		switch dashboard.Status {
		case SecureCellGovernmentAgentExecutionLaunchClosureDashboardBlocked:
			portfolio.BlockedCount++
		case SecureCellGovernmentAgentExecutionLaunchClosureDashboardAwaitingArchiveIssue:
			portfolio.AwaitingArchiveIssueCount++
		case SecureCellGovernmentAgentExecutionLaunchClosureDashboardReadyToClose:
			portfolio.ReadyToCloseCount++
		}
		if dashboard.CanCloseNow {
			portfolio.CanCloseNowCount++
		}
		if dashboard.CanCloseAfterArchiveIssue {
			portfolio.CanCloseAfterArchiveCount++
		}
		if dashboard.CanEscalateBlocked {
			portfolio.EscalationRequiredCount++
		}
		portfolio.RequiredReceiptTypes = append(portfolio.RequiredReceiptTypes, dashboard.RequiredReceiptTypes...)

		action := strings.TrimSpace(dashboard.PrimaryAction)
		if action == "" {
			continue
		}
		idx, ok := actionIndex[action]
		if !ok {
			actionIndex[action] = len(portfolio.PrimaryActions)
			portfolio.PrimaryActions = append(portfolio.PrimaryActions, SecureCellGovernmentAgentExecutionLaunchClosurePortfolioAction{
				Action: action,
			})
			idx = len(portfolio.PrimaryActions) - 1
		}
		portfolio.PrimaryActions[idx].Count++
		portfolio.PrimaryActions[idx].CellIDs = append(portfolio.PrimaryActions[idx].CellIDs, dashboard.CellID)
	}

	portfolio.RequiredReceiptTypes = uniqueTrimmedStrings(portfolio.RequiredReceiptTypes)
	for i := range portfolio.PrimaryActions {
		portfolio.PrimaryActions[i].CellIDs = uniqueTrimmedStrings(portfolio.PrimaryActions[i].CellIDs)
	}
	sort.SliceStable(portfolio.PrimaryActions, func(i, j int) bool {
		if portfolio.PrimaryActions[i].Count == portfolio.PrimaryActions[j].Count {
			return portfolio.PrimaryActions[i].Action < portfolio.PrimaryActions[j].Action
		}
		return portfolio.PrimaryActions[i].Count > portfolio.PrimaryActions[j].Count
	})

	portfolio.PortfolioDigest = secureCellGovernmentAgentExecutionLaunchClosurePortfolioDigest(portfolio)
	portfolio.PortfolioID = "government-agent-execution-launch-closure-portfolio:" + firstNonEmpty(portfolio.Jurisdiction, "all") + ":" + portfolio.PortfolioDigest[:12]
	return portfolio
}

func secureCellGovernmentAgentExecutionLaunchClosurePortfolioDigest(portfolio SecureCellGovernmentAgentExecutionLaunchClosurePortfolio) string {
	type dashboardDigestRow struct {
		DashboardID      string `json:"dashboard_id"`
		CenterID         string `json:"center_id"`
		CellID           string `json:"cell_id"`
		Status           string `json:"status"`
		PrimaryAction    string `json:"primary_action"`
		DashboardDigest  string `json:"dashboard_digest"`
		CenterDigest     string `json:"center_digest"`
		BoardDigest      string `json:"board_digest"`
		ItemCount        int    `json:"item_count"`
		BlockedItemCount int    `json:"blocked_item_count"`
		PendingItemCount int    `json:"pending_item_count"`
		ReadyItemCount   int    `json:"ready_item_count"`
	}
	rows := make([]dashboardDigestRow, 0, len(portfolio.Dashboards))
	for _, dashboard := range portfolio.Dashboards {
		rows = append(rows, dashboardDigestRow{
			DashboardID:      dashboard.DashboardID,
			CenterID:         dashboard.CenterID,
			CellID:           dashboard.CellID,
			Status:           string(dashboard.Status),
			PrimaryAction:    dashboard.PrimaryAction,
			DashboardDigest:  dashboard.DashboardDigest,
			CenterDigest:     dashboard.CenterDigest,
			BoardDigest:      dashboard.BoardDigest,
			ItemCount:        dashboard.ItemCount,
			BlockedItemCount: dashboard.BlockedItemCount,
			PendingItemCount: dashboard.PendingItemCount,
			ReadyItemCount:   dashboard.ReadyItemCount,
		})
	}

	core := struct {
		Jurisdiction string                                                           `json:"jurisdiction,omitempty"`
		ServiceCode  string                                                           `json:"service_code,omitempty"`
		ServiceTier  string                                                           `json:"service_tier,omitempty"`
		Dashboards   []dashboardDigestRow                                             `json:"dashboards"`
		Actions      []SecureCellGovernmentAgentExecutionLaunchClosurePortfolioAction `json:"actions,omitempty"`
	}{
		Jurisdiction: portfolio.Jurisdiction,
		ServiceCode:  portfolio.ServiceCode,
		ServiceTier:  portfolio.ServiceTier,
		Dashboards:   rows,
		Actions:      portfolio.PrimaryActions,
	}
	return EvidenceHash(core)
}
