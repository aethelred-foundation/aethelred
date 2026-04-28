package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchCustodyStatus describes whether a
// portable package can be issued, must wait for receipts, or is blocked.
type SecureCellGovernmentAgentExecutionLaunchCustodyStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchCustodyBlocked         SecureCellGovernmentAgentExecutionLaunchCustodyStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchCustodyAwaitingReceipt SecureCellGovernmentAgentExecutionLaunchCustodyStatus = "awaiting_operator_receipts"
	SecureCellGovernmentAgentExecutionLaunchCustodyEscrowed        SecureCellGovernmentAgentExecutionLaunchCustodyStatus = "escrowed_for_launch"
)

// SecureCellGovernmentAgentExecutionLaunchCustodyActionStatus records the
// custody posture for one package issue action.
type SecureCellGovernmentAgentExecutionLaunchCustodyActionStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchCustodyActionBlocked   SecureCellGovernmentAgentExecutionLaunchCustodyActionStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchCustodyActionPending   SecureCellGovernmentAgentExecutionLaunchCustodyActionStatus = "pending"
	SecureCellGovernmentAgentExecutionLaunchCustodyActionReady     SecureCellGovernmentAgentExecutionLaunchCustodyActionStatus = "ready"
	SecureCellGovernmentAgentExecutionLaunchCustodyActionSatisfied SecureCellGovernmentAgentExecutionLaunchCustodyActionStatus = "satisfied"
)

// SecureCellGovernmentAgentExecutionLaunchCustodyAction is one custody action
// needed before a launch package can be handed to an executor.
type SecureCellGovernmentAgentExecutionLaunchCustodyAction struct {
	ActionID            string                                                      `json:"action_id"`
	Sequence            int                                                         `json:"sequence"`
	CellID              string                                                      `json:"cell_id"`
	PackageID           string                                                      `json:"package_id"`
	ActionType          string                                                      `json:"action_type"`
	Status              SecureCellGovernmentAgentExecutionLaunchCustodyActionStatus `json:"status"`
	ActorRole           string                                                      `json:"actor_role,omitempty"`
	Detail              string                                                      `json:"detail"`
	RequiredReceiptType string                                                      `json:"required_receipt_type,omitempty"`
	EvidenceDigest      string                                                      `json:"evidence_digest,omitempty"`
	DueAt               *time.Time                                                  `json:"due_at,omitempty"`
	ActionDigest        string                                                      `json:"action_digest"`
	GeneratedAt         time.Time                                                   `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchCustodyRegister is the issue-control
// register for a portable launch package.
type SecureCellGovernmentAgentExecutionLaunchCustodyRegister struct {
	CustodyID                     string                                                  `json:"custody_id"`
	PackageID                     string                                                  `json:"package_id"`
	PackageVersion                string                                                  `json:"package_version"`
	CellID                        string                                                  `json:"cell_id"`
	Name                          string                                                  `json:"name"`
	Jurisdiction                  string                                                  `json:"jurisdiction,omitempty"`
	ServiceCode                   string                                                  `json:"service_code,omitempty"`
	ServiceTier                   string                                                  `json:"service_tier,omitempty"`
	Status                        SecureCellGovernmentAgentExecutionLaunchCustodyStatus   `json:"status"`
	PackageStatus                 SecureCellGovernmentAgentExecutionLaunchPackageStatus   `json:"package_status"`
	CanIssueNow                   bool                                                    `json:"can_issue_now"`
	CanIssueAfterOperatorReceipts bool                                                    `json:"can_issue_after_operator_receipts"`
	CanIssueAutonomous            bool                                                    `json:"can_issue_autonomous"`
	LeaseMinutes                  int                                                     `json:"lease_minutes"`
	ActivationWindowStartsAt      time.Time                                               `json:"activation_window_starts_at"`
	ActivationWindowExpiresAt     time.Time                                               `json:"activation_window_expires_at"`
	CustodyActionCount            int                                                     `json:"custody_action_count"`
	SatisfiedActionCount          int                                                     `json:"satisfied_action_count"`
	ReadyActionCount              int                                                     `json:"ready_action_count"`
	PendingActionCount            int                                                     `json:"pending_action_count"`
	BlockedActionCount            int                                                     `json:"blocked_action_count"`
	RequiredReceiptTypes          []string                                                `json:"required_receipt_types,omitempty"`
	OperatorInstructions          []string                                                `json:"operator_instructions,omitempty"`
	PackageDigest                 string                                                  `json:"package_digest"`
	LaunchDigest                  string                                                  `json:"launch_digest"`
	ReceiptManifestDigest         string                                                  `json:"receipt_manifest_digest"`
	ReceiptValidationDigest       string                                                  `json:"receipt_validation_digest"`
	Actions                       []SecureCellGovernmentAgentExecutionLaunchCustodyAction `json:"actions"`
	Package                       SecureCellGovernmentAgentExecutionLaunchPackage         `json:"package"`
	CustodyDigest                 string                                                  `json:"custody_digest"`
	GeneratedAt                   time.Time                                               `json:"generated_at"`
	UpdatedAt                     time.Time                                               `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchCustody returns the package custody register
// for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchCustody(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchCustodyRegister, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchCustodies(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-custody: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchCustodies returns launch package issue
// registers for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchCustodies(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchCustodyRegister, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-custody: service is required")
	}
	packages, err := s.ListGovernmentAgentExecutionLaunchPackages(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	registers := make([]SecureCellGovernmentAgentExecutionLaunchCustodyRegister, 0, len(packages))
	for _, pkg := range packages {
		registers = append(registers, secureCellGovernmentAgentExecutionLaunchCustodyRegister(pkg, now))
	}
	sort.SliceStable(registers, func(i, j int) bool {
		if registers[i].Status == registers[j].Status {
			if registers[i].BlockedActionCount == registers[j].BlockedActionCount {
				if registers[i].PendingActionCount == registers[j].PendingActionCount {
					return registers[i].CellID < registers[j].CellID
				}
				return registers[i].PendingActionCount > registers[j].PendingActionCount
			}
			return registers[i].BlockedActionCount > registers[j].BlockedActionCount
		}
		return secureCellGovernmentAgentExecutionLaunchCustodyStatusRank(registers[i].Status) < secureCellGovernmentAgentExecutionLaunchCustodyStatusRank(registers[j].Status)
	})
	return registers, nil
}

func secureCellGovernmentAgentExecutionLaunchCustodyRegister(
	pkg SecureCellGovernmentAgentExecutionLaunchPackage,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchCustodyRegister {
	leaseMinutes := secureCellGovernmentAgentExecutionLaunchCustodyLeaseMinutes(pkg.ServiceTier)
	startsAt := generatedAt.UTC()
	expiresAt := startsAt.Add(time.Duration(leaseMinutes) * time.Minute)
	register := SecureCellGovernmentAgentExecutionLaunchCustodyRegister{
		PackageID:                 pkg.PackageID,
		PackageVersion:            pkg.PackageVersion,
		CellID:                    pkg.CellID,
		Name:                      pkg.Name,
		Jurisdiction:              pkg.Jurisdiction,
		ServiceCode:               pkg.ServiceCode,
		ServiceTier:               pkg.ServiceTier,
		PackageStatus:             pkg.Status,
		LeaseMinutes:              leaseMinutes,
		ActivationWindowStartsAt:  startsAt,
		ActivationWindowExpiresAt: expiresAt,
		RequiredReceiptTypes:      append([]string(nil), pkg.RequiredReceiptTypes...),
		PackageDigest:             pkg.PackageDigest,
		LaunchDigest:              pkg.LaunchDigest,
		ReceiptManifestDigest:     pkg.ReceiptManifestDigest,
		ReceiptValidationDigest:   pkg.ReceiptValidationDigest,
		Package:                   pkg,
		GeneratedAt:               startsAt,
		UpdatedAt:                 pkg.UpdatedAt.UTC(),
	}
	register.Status = secureCellGovernmentAgentExecutionLaunchCustodyStatus(pkg)
	register.CanIssueNow = register.Status == SecureCellGovernmentAgentExecutionLaunchCustodyEscrowed && pkg.CanLaunchNow
	register.CanIssueAfterOperatorReceipts = register.Status == SecureCellGovernmentAgentExecutionLaunchCustodyAwaitingReceipt && pkg.CanLaunchAfterOperatorReview
	register.CanIssueAutonomous = register.CanIssueNow && pkg.CanAutonomousLaunch
	register.Actions = secureCellGovernmentAgentExecutionLaunchCustodyActions(register, pkg)
	for _, action := range register.Actions {
		register.CustodyActionCount++
		switch action.Status {
		case SecureCellGovernmentAgentExecutionLaunchCustodyActionBlocked:
			register.BlockedActionCount++
		case SecureCellGovernmentAgentExecutionLaunchCustodyActionPending:
			register.PendingActionCount++
		case SecureCellGovernmentAgentExecutionLaunchCustodyActionReady:
			register.ReadyActionCount++
		default:
			register.SatisfiedActionCount++
		}
	}
	register.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchCustodyInstructions(register)
	register.CustodyDigest = secureCellGovernmentAgentExecutionLaunchCustodyDigest(register)
	register.CustodyID = "government-agent-execution-launch-custody:" + register.CellID + ":" + register.CustodyDigest[:12]
	return register
}

func secureCellGovernmentAgentExecutionLaunchCustodyActions(
	register SecureCellGovernmentAgentExecutionLaunchCustodyRegister,
	pkg SecureCellGovernmentAgentExecutionLaunchPackage,
) []SecureCellGovernmentAgentExecutionLaunchCustodyAction {
	actions := []SecureCellGovernmentAgentExecutionLaunchCustodyAction{
		secureCellGovernmentAgentExecutionLaunchCustodyAction(register, 1, "preserve_package_digest", SecureCellGovernmentAgentExecutionLaunchCustodyActionSatisfied, "launch_operator", "Preserve the package digest, manifest digest, and validation digest with the execution record.", "", pkg.PackageDigest, nil),
	}
	switch register.Status {
	case SecureCellGovernmentAgentExecutionLaunchCustodyBlocked:
		dueAt := register.ActivationWindowStartsAt.Add(time.Duration(register.LeaseMinutes/4) * time.Minute)
		actions = append(actions, secureCellGovernmentAgentExecutionLaunchCustodyAction(register, len(actions)+1, "resolve_blocked_receipts", SecureCellGovernmentAgentExecutionLaunchCustodyActionBlocked, "service_owner", "Resolve blocked receipts or validation failures before package issue.", "remediation_receipt", pkg.ReceiptValidationDigest, &dueAt))
	case SecureCellGovernmentAgentExecutionLaunchCustodyAwaitingReceipt:
		dueAt := register.ActivationWindowStartsAt.Add(time.Duration(register.LeaseMinutes/2) * time.Minute)
		actions = append(actions, secureCellGovernmentAgentExecutionLaunchCustodyAction(register, len(actions)+1, "collect_operator_acknowledgement", SecureCellGovernmentAgentExecutionLaunchCustodyActionPending, "launch_operator", "Collect operator acknowledgement receipts before issuing the package.", "operator_acknowledgement_receipt", pkg.ReceiptManifestDigest, &dueAt))
	default:
		actions = append(actions, secureCellGovernmentAgentExecutionLaunchCustodyAction(register, len(actions)+1, "issue_launch_package", SecureCellGovernmentAgentExecutionLaunchCustodyActionReady, "launch_operator", "Issue the package inside the activation window and preserve return receipts.", "", pkg.LaunchDigest, nil))
	}
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Status == actions[j].Status {
			return actions[i].Sequence < actions[j].Sequence
		}
		return secureCellGovernmentAgentExecutionLaunchCustodyActionStatusRank(actions[i].Status) < secureCellGovernmentAgentExecutionLaunchCustodyActionStatusRank(actions[j].Status)
	})
	return actions
}

func secureCellGovernmentAgentExecutionLaunchCustodyAction(
	register SecureCellGovernmentAgentExecutionLaunchCustodyRegister,
	sequence int,
	actionType string,
	status SecureCellGovernmentAgentExecutionLaunchCustodyActionStatus,
	actorRole string,
	detail string,
	requiredReceiptType string,
	evidenceDigest string,
	dueAt *time.Time,
) SecureCellGovernmentAgentExecutionLaunchCustodyAction {
	action := SecureCellGovernmentAgentExecutionLaunchCustodyAction{
		Sequence:            sequence,
		CellID:              register.CellID,
		PackageID:           register.PackageID,
		ActionType:          strings.TrimSpace(actionType),
		Status:              status,
		ActorRole:           strings.TrimSpace(actorRole),
		Detail:              strings.TrimSpace(detail),
		RequiredReceiptType: strings.TrimSpace(requiredReceiptType),
		EvidenceDigest:      strings.TrimSpace(evidenceDigest),
		DueAt:               cloneTimePtr(dueAt),
		GeneratedAt:         register.GeneratedAt.UTC(),
	}
	action.ActionDigest = secureCellGovernmentAgentExecutionLaunchCustodyActionDigest(action)
	action.ActionID = "government-agent-execution-launch-custody-action:" + action.CellID + ":" + action.ActionDigest[:12]
	return action
}

func secureCellGovernmentAgentExecutionLaunchCustodyStatus(pkg SecureCellGovernmentAgentExecutionLaunchPackage) SecureCellGovernmentAgentExecutionLaunchCustodyStatus {
	switch pkg.Status {
	case SecureCellGovernmentAgentExecutionLaunchPackageBlocked:
		return SecureCellGovernmentAgentExecutionLaunchCustodyBlocked
	case SecureCellGovernmentAgentExecutionLaunchPackageReviewRequired:
		return SecureCellGovernmentAgentExecutionLaunchCustodyAwaitingReceipt
	default:
		return SecureCellGovernmentAgentExecutionLaunchCustodyEscrowed
	}
}

func secureCellGovernmentAgentExecutionLaunchCustodyInstructions(register SecureCellGovernmentAgentExecutionLaunchCustodyRegister) []string {
	instructions := append([]string(nil), register.Package.OperatorInstructions...)
	switch register.Status {
	case SecureCellGovernmentAgentExecutionLaunchCustodyBlocked:
		instructions = append(instructions, "Keep the package sealed until blocked custody actions are cleared.")
	case SecureCellGovernmentAgentExecutionLaunchCustodyAwaitingReceipt:
		instructions = append(instructions, "Do not issue the package until operator acknowledgement receipts are attached.")
	default:
		instructions = append(instructions, "Issue only inside the activation window and preserve the custody digest.")
	}
	if register.ActivationWindowExpiresAt.After(register.ActivationWindowStartsAt) {
		instructions = append(instructions, fmt.Sprintf("Revalidate the launch package after %d minutes if it is not issued.", register.LeaseMinutes))
	}
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchCustodyLeaseMinutes(serviceTier string) int {
	switch strings.ToLower(strings.TrimSpace(serviceTier)) {
	case "tier_1", "tier1", "critical":
		return 120
	case "tier_2", "tier2", "high":
		return 240
	case "tier_3", "tier3", "standard":
		return 480
	default:
		return 240
	}
}

func secureCellGovernmentAgentExecutionLaunchCustodyStatusRank(status SecureCellGovernmentAgentExecutionLaunchCustodyStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchCustodyBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchCustodyAwaitingReceipt:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchCustodyEscrowed:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchCustodyActionStatusRank(status SecureCellGovernmentAgentExecutionLaunchCustodyActionStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchCustodyActionBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchCustodyActionPending:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchCustodyActionReady:
		return 2
	case SecureCellGovernmentAgentExecutionLaunchCustodyActionSatisfied:
		return 3
	default:
		return 4
	}
}

func secureCellGovernmentAgentExecutionLaunchCustodyActionDigest(action SecureCellGovernmentAgentExecutionLaunchCustodyAction) string {
	core := struct {
		Sequence            int                                                         `json:"sequence"`
		CellID              string                                                      `json:"cell_id"`
		PackageID           string                                                      `json:"package_id"`
		ActionType          string                                                      `json:"action_type"`
		Status              SecureCellGovernmentAgentExecutionLaunchCustodyActionStatus `json:"status"`
		ActorRole           string                                                      `json:"actor_role,omitempty"`
		RequiredReceiptType string                                                      `json:"required_receipt_type,omitempty"`
		EvidenceDigest      string                                                      `json:"evidence_digest,omitempty"`
	}{
		Sequence:            action.Sequence,
		CellID:              action.CellID,
		PackageID:           action.PackageID,
		ActionType:          action.ActionType,
		Status:              action.Status,
		ActorRole:           action.ActorRole,
		RequiredReceiptType: action.RequiredReceiptType,
		EvidenceDigest:      action.EvidenceDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchCustodyDigest(register SecureCellGovernmentAgentExecutionLaunchCustodyRegister) string {
	actionDigests := make([]string, 0, len(register.Actions))
	for _, action := range register.Actions {
		actionDigests = append(actionDigests, action.ActionDigest)
	}
	core := struct {
		PackageID                     string                                                `json:"package_id"`
		CellID                        string                                                `json:"cell_id"`
		Status                        SecureCellGovernmentAgentExecutionLaunchCustodyStatus `json:"status"`
		PackageStatus                 SecureCellGovernmentAgentExecutionLaunchPackageStatus `json:"package_status"`
		CanIssueNow                   bool                                                  `json:"can_issue_now"`
		CanIssueAfterOperatorReceipts bool                                                  `json:"can_issue_after_operator_receipts"`
		CanIssueAutonomous            bool                                                  `json:"can_issue_autonomous"`
		LeaseMinutes                  int                                                   `json:"lease_minutes"`
		RequiredReceiptTypes          []string                                              `json:"required_receipt_types,omitempty"`
		ActionDigests                 []string                                              `json:"action_digests,omitempty"`
		PackageDigest                 string                                                `json:"package_digest"`
		LaunchDigest                  string                                                `json:"launch_digest"`
		ReceiptManifestDigest         string                                                `json:"receipt_manifest_digest"`
		ReceiptValidationDigest       string                                                `json:"receipt_validation_digest"`
	}{
		PackageID:                     register.PackageID,
		CellID:                        register.CellID,
		Status:                        register.Status,
		PackageStatus:                 register.PackageStatus,
		CanIssueNow:                   register.CanIssueNow,
		CanIssueAfterOperatorReceipts: register.CanIssueAfterOperatorReceipts,
		CanIssueAutonomous:            register.CanIssueAutonomous,
		LeaseMinutes:                  register.LeaseMinutes,
		RequiredReceiptTypes:          register.RequiredReceiptTypes,
		ActionDigests:                 actionDigests,
		PackageDigest:                 register.PackageDigest,
		LaunchDigest:                  register.LaunchDigest,
		ReceiptManifestDigest:         register.ReceiptManifestDigest,
		ReceiptValidationDigest:       register.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
