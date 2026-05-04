package securecells

import (
	"context"
	"fmt"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep is one
// ordered execution checkpoint for the current closure focus lane.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep struct {
	Sequence      int      `json:"sequence"`
	Title         string   `json:"title"`
	Instruction   string   `json:"instruction"`
	PendingAction string   `json:"pending_action"`
	CellIDs       []string `json:"cell_ids,omitempty"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook is the
// operator-ready execution narrative derived from one automation packet.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook struct {
	RunbookID     string                                                                 `json:"runbook_id"`
	PacketID      string                                                                 `json:"packet_id"`
	BoardID       string                                                                 `json:"board_id"`
	SummaryID     string                                                                 `json:"summary_id"`
	Jurisdiction  string                                                                 `json:"jurisdiction,omitempty"`
	ServiceCode   string                                                                 `json:"service_code,omitempty"`
	ServiceTier   string                                                                 `json:"service_tier,omitempty"`
	EvaluatedAt   time.Time                                                              `json:"evaluated_at"`
	FocusLane     SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane     `json:"focus_lane"`
	FocusAction   string                                                                 `json:"focus_action"`
	Headline      string                                                                 `json:"headline"`
	CellCount     int                                                                    `json:"cell_count"`
	ItemCount     int                                                                    `json:"item_count"`
	Steps         []SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep `json:"steps"`
	Items         []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem   `json:"items"`
	PacketDigest  string                                                                 `json:"packet_digest"`
	RunbookDigest string                                                                 `json:"runbook_digest"`
	GeneratedAt   time.Time                                                              `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationRunbook returns the
// operator runbook for matching government-service workflows.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationRunbook(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-runbook: service is required")
	}
	packet, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationPacket(ctx, filter)
	if err != nil {
		return nil, err
	}
	runbook := secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook(*packet, time.Now().UTC())
	return &runbook, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook(
	packet SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook {
	runbook := SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook{
		PacketID:     packet.PacketID,
		BoardID:      packet.BoardID,
		SummaryID:    packet.SummaryID,
		Jurisdiction: packet.Jurisdiction,
		ServiceCode:  packet.ServiceCode,
		ServiceTier:  packet.ServiceTier,
		EvaluatedAt:  packet.EvaluatedAt.UTC(),
		FocusLane:    packet.FocusLane,
		FocusAction:  packet.FocusAction,
		Headline:     secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookHeadline(packet),
		CellCount:    packet.CellCount,
		ItemCount:    packet.ItemCount,
		Items:        append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem(nil), packet.Items...),
		PacketDigest: packet.PacketDigest,
		GeneratedAt:  generatedAt.UTC(),
	}
	runbook.Steps = secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookSteps(packet)
	runbook.RunbookDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookDigest(runbook)
	runbook.RunbookID = "government-agent-execution-launch-closure-automation-runbook:" + firstNonEmpty(runbook.Jurisdiction, "all") + ":" + runbook.RunbookDigest[:12]
	return runbook
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookHeadline(
	packet SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket,
) string {
	switch packet.FocusLane {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked:
		return "Clear blocked closure paths before archive or closeout execution."
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue:
		return "Drain breached closure timers immediately across the current estate slice."
	default:
		return "Work the next due closure actions before they breach SLA."
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookSteps(
	packet SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket,
) []SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep {
	steps := make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep, 0, len(packet.Steps)+1)
	steps = append(steps, SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep{
		Sequence:    1,
		Title:       "Align on focus lane",
		Instruction: secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookHeadline(packet),
		CellIDs:     uniqueTrimmedStrings(secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketCellIDs(packet.Items)),
	})
	for _, step := range packet.Steps {
		steps = append(steps, SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep{
			Sequence:      len(steps) + 1,
			Title:         secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStepTitle(step),
			Instruction:   step.Instruction,
			PendingAction: step.PendingAction,
			CellIDs:       append([]string(nil), step.CellIDs...),
		})
	}
	return steps
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStepTitle(
	step SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketStep,
) string {
	switch step.PendingAction {
	case "escalate_blocked_closure":
		return "Escalate blocked closure records"
	case "issue_archive_certificate":
		return "Issue archive certificates"
	case "close_launch_record":
		return "Close launch records"
	default:
		return "Execute closure action"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketCellIDs(
	items []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem,
) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.CellID)
	}
	return out
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookDigest(
	runbook SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook,
) string {
	core := struct {
		PacketID     string                                                                 `json:"packet_id"`
		BoardID      string                                                                 `json:"board_id"`
		FocusLane    SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane     `json:"focus_lane"`
		FocusAction  string                                                                 `json:"focus_action"`
		Headline     string                                                                 `json:"headline"`
		Steps        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep `json:"steps"`
		Items        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem   `json:"items"`
		PacketDigest string                                                                 `json:"packet_digest"`
	}{
		PacketID:     runbook.PacketID,
		BoardID:      runbook.BoardID,
		FocusLane:    runbook.FocusLane,
		FocusAction:  runbook.FocusAction,
		Headline:     runbook.Headline,
		Steps:        runbook.Steps,
		Items:        runbook.Items,
		PacketDigest: runbook.PacketDigest,
	}
	return EvidenceHash(core)
}
