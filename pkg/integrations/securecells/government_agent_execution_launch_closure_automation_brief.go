package securecells

import (
	"context"
	"fmt"
	"time"
)

type SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityCritical SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity = "critical"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityHigh     SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity = "high"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityMedium   SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity = "medium"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief is a compact
// operator and leadership handoff derived from one runbook.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief struct {
	BriefID             string                                                                 `json:"brief_id"`
	RunbookID           string                                                                 `json:"runbook_id"`
	PacketID            string                                                                 `json:"packet_id"`
	BoardID             string                                                                 `json:"board_id"`
	SummaryID           string                                                                 `json:"summary_id"`
	Jurisdiction        string                                                                 `json:"jurisdiction,omitempty"`
	ServiceCode         string                                                                 `json:"service_code,omitempty"`
	ServiceTier         string                                                                 `json:"service_tier,omitempty"`
	EvaluatedAt         time.Time                                                              `json:"evaluated_at"`
	FocusLane           SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane     `json:"focus_lane"`
	FocusAction         string                                                                 `json:"focus_action"`
	Severity            SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity `json:"severity"`
	Headline            string                                                                 `json:"headline"`
	Directive           string                                                                 `json:"directive"`
	TopCheckpoint       string                                                                 `json:"top_checkpoint,omitempty"`
	UniquePendingAction []string                                                               `json:"unique_pending_actions,omitempty"`
	CellCount           int                                                                    `json:"cell_count"`
	ItemCount           int                                                                    `json:"item_count"`
	Steps               []SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep `json:"steps"`
	Items               []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem   `json:"items"`
	RunbookDigest       string                                                                 `json:"runbook_digest"`
	BriefDigest         string                                                                 `json:"brief_digest"`
	GeneratedAt         time.Time                                                              `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationBrief returns the compact
// closure briefing for matching government-service workflows.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationBrief(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-brief: service is required")
	}
	runbook, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationRunbook(ctx, filter)
	if err != nil {
		return nil, err
	}
	brief := secureCellGovernmentAgentExecutionLaunchClosureAutomationBrief(*runbook, time.Now().UTC())
	return &brief, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBrief(
	runbook SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief {
	brief := SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief{
		RunbookID:           runbook.RunbookID,
		PacketID:            runbook.PacketID,
		BoardID:             runbook.BoardID,
		SummaryID:           runbook.SummaryID,
		Jurisdiction:        runbook.Jurisdiction,
		ServiceCode:         runbook.ServiceCode,
		ServiceTier:         runbook.ServiceTier,
		EvaluatedAt:         runbook.EvaluatedAt.UTC(),
		FocusLane:           runbook.FocusLane,
		FocusAction:         runbook.FocusAction,
		Severity:            secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity(runbook),
		Headline:            runbook.Headline,
		Directive:           secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefDirective(runbook),
		TopCheckpoint:       secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefTopCheckpoint(runbook),
		UniquePendingAction: secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefPendingActions(runbook),
		CellCount:           runbook.CellCount,
		ItemCount:           runbook.ItemCount,
		Steps:               append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep(nil), runbook.Steps...),
		Items:               append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem(nil), runbook.Items...),
		RunbookDigest:       runbook.RunbookDigest,
		GeneratedAt:         generatedAt.UTC(),
	}
	brief.BriefDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefDigest(brief)
	brief.BriefID = "government-agent-execution-launch-closure-automation-brief:" + firstNonEmpty(brief.Jurisdiction, "all") + ":" + brief.BriefDigest[:12]
	return brief
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity(
	runbook SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity {
	switch runbook.FocusLane {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityCritical
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityHigh
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverityMedium
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefDirective(
	runbook SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook,
) string {
	switch runbook.FocusLane {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked:
		return "Escalate blocked closure paths first, then resume archive issuance and record closeout."
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue:
		return "Work breached closure timers immediately and clear the highest-priority archive or closeout backlog."
	default:
		return "Work the next due closure actions before they convert into SLA breaches."
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefTopCheckpoint(
	runbook SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook,
) string {
	for _, step := range runbook.Steps {
		if step.PendingAction != "" {
			return step.Title
		}
	}
	return ""
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefPendingActions(
	runbook SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook,
) []string {
	actions := make([]string, 0, len(runbook.Steps))
	for _, step := range runbook.Steps {
		if step.PendingAction == "" {
			continue
		}
		actions = append(actions, step.PendingAction)
	}
	return uniqueTrimmedStrings(actions)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefDigest(
	brief SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief,
) string {
	core := struct {
		RunbookID           string                                                                 `json:"runbook_id"`
		PacketID            string                                                                 `json:"packet_id"`
		FocusLane           SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane     `json:"focus_lane"`
		FocusAction         string                                                                 `json:"focus_action"`
		Severity            SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity `json:"severity"`
		Headline            string                                                                 `json:"headline"`
		Directive           string                                                                 `json:"directive"`
		TopCheckpoint       string                                                                 `json:"top_checkpoint"`
		UniquePendingAction []string                                                               `json:"unique_pending_actions"`
		Steps               []SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep `json:"steps"`
		Items               []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem   `json:"items"`
		RunbookDigest       string                                                                 `json:"runbook_digest"`
	}{
		RunbookID:           brief.RunbookID,
		PacketID:            brief.PacketID,
		FocusLane:           brief.FocusLane,
		FocusAction:         brief.FocusAction,
		Severity:            brief.Severity,
		Headline:            brief.Headline,
		Directive:           brief.Directive,
		TopCheckpoint:       brief.TopCheckpoint,
		UniquePendingAction: brief.UniquePendingAction,
		Steps:               brief.Steps,
		Items:               brief.Items,
		RunbookDigest:       brief.RunbookDigest,
	}
	return EvidenceHash(core)
}
