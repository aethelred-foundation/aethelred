package securecells

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketStep is one
// operator instruction group for the current focus lane.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketStep struct {
	Sequence         int      `json:"sequence"`
	Lane             string   `json:"lane"`
	PendingAction    string   `json:"pending_action"`
	AutomationAction string   `json:"automation_action"`
	Instruction      string   `json:"instruction"`
	CellIDs          []string `json:"cell_ids,omitempty"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket is the
// compact operator work artifact derived from the command board.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket struct {
	PacketID     string                                                                `json:"packet_id"`
	BoardID      string                                                                `json:"board_id"`
	SummaryID    string                                                                `json:"summary_id"`
	Jurisdiction string                                                                `json:"jurisdiction,omitempty"`
	ServiceCode  string                                                                `json:"service_code,omitempty"`
	ServiceTier  string                                                                `json:"service_tier,omitempty"`
	EvaluatedAt  time.Time                                                             `json:"evaluated_at"`
	FocusLane    SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane    `json:"focus_lane"`
	FocusAction  string                                                                `json:"focus_action"`
	CellCount    int                                                                   `json:"cell_count"`
	ItemCount    int                                                                   `json:"item_count"`
	Steps        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketStep `json:"steps"`
	Items        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem  `json:"items"`
	BoardDigest  string                                                                `json:"board_digest"`
	PacketDigest string                                                                `json:"packet_digest"`
	GeneratedAt  time.Time                                                             `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationPacket returns the
// operator execution packet for matching government-service workflows.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationPacket(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-packet: service is required")
	}
	board, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationBoard(ctx, filter)
	if err != nil {
		return nil, err
	}
	packet := secureCellGovernmentAgentExecutionLaunchClosureAutomationPacket(*board, time.Now().UTC())
	return &packet, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationPacket(
	board SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoard,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket {
	items := make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem, 0, len(board.Items))
	cellIDs := make([]string, 0, len(board.Items))
	for _, item := range board.Items {
		if item.Lane != board.RecommendedLane {
			continue
		}
		items = append(items, item)
		cellIDs = append(cellIDs, item.CellID)
	}
	if len(items) == 0 {
		items = append(items, board.Items...)
		for _, item := range items {
			cellIDs = append(cellIDs, item.CellID)
		}
	}
	packet := SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket{
		BoardID:      board.BoardID,
		SummaryID:    board.SummaryID,
		Jurisdiction: board.Jurisdiction,
		ServiceCode:  board.ServiceCode,
		ServiceTier:  board.ServiceTier,
		EvaluatedAt:  board.EvaluatedAt.UTC(),
		FocusLane:    board.RecommendedLane,
		FocusAction:  board.RecommendedAction,
		Items:        items,
		BoardDigest:  board.BoardDigest,
		GeneratedAt:  generatedAt.UTC(),
	}
	packet.CellCount = len(uniqueTrimmedStrings(cellIDs))
	packet.ItemCount = len(packet.Items)
	packet.Steps = secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketSteps(packet)
	packet.PacketDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketDigest(packet)
	packet.PacketID = "government-agent-execution-launch-closure-automation-packet:" + firstNonEmpty(packet.Jurisdiction, "all") + ":" + packet.PacketDigest[:12]
	return packet
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketSteps(
	packet SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket,
) []SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketStep {
	type key struct {
		lane             string
		pendingAction    string
		automationAction string
	}
	stepMap := map[key]*SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketStep{}
	order := make([]key, 0)
	for _, item := range packet.Items {
		k := key{
			lane:             string(item.Lane),
			pendingAction:    item.PendingAction,
			automationAction: item.AutomationAction,
		}
		step, ok := stepMap[k]
		if !ok {
			step = &SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketStep{
				Lane:             string(item.Lane),
				PendingAction:    item.PendingAction,
				AutomationAction: item.AutomationAction,
				Instruction:      secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketInstruction(item),
			}
			stepMap[k] = step
			order = append(order, k)
		}
		step.CellIDs = append(step.CellIDs, item.CellID)
	}
	steps := make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketStep, 0, len(order))
	for idx, k := range order {
		step := stepMap[k]
		step.Sequence = idx + 1
		step.CellIDs = uniqueTrimmedStrings(step.CellIDs)
		steps = append(steps, *step)
	}
	sort.SliceStable(steps, func(i, j int) bool {
		if steps[i].Lane == steps[j].Lane {
			if steps[i].PendingAction == steps[j].PendingAction {
				return steps[i].AutomationAction < steps[j].AutomationAction
			}
			return steps[i].PendingAction < steps[j].PendingAction
		}
		return secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneRank(SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane(steps[i].Lane)) < secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneRank(SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane(steps[j].Lane))
	})
	for idx := range steps {
		steps[idx].Sequence = idx + 1
	}
	return steps
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketInstruction(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem,
) string {
	switch item.Lane {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked:
		return "Escalate and clear blocked closure records before any archive or closeout work proceeds."
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue:
		return "Drain breached closure timers immediately, starting with the highest-priority records."
	default:
		return "Work the next due closure actions before they cross SLA."
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketDigest(
	packet SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket,
) string {
	core := struct {
		BoardID     string                                                                `json:"board_id"`
		SummaryID   string                                                                `json:"summary_id"`
		FocusLane   SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane    `json:"focus_lane"`
		FocusAction string                                                                `json:"focus_action"`
		Steps       []SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketStep `json:"steps"`
		Items       []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem  `json:"items"`
		BoardDigest string                                                                `json:"board_digest"`
	}{
		BoardID:     packet.BoardID,
		SummaryID:   packet.SummaryID,
		FocusLane:   packet.FocusLane,
		FocusAction: packet.FocusAction,
		Steps:       packet.Steps,
		Items:       packet.Items,
		BoardDigest: packet.BoardDigest,
	}
	return EvidenceHash(core)
}
