package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchOrderStatus describes whether an
// activation certificate can be consumed by a runtime executor.
type SecureCellGovernmentAgentExecutionLaunchOrderStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchOrderDenied                  SecureCellGovernmentAgentExecutionLaunchOrderStatus = "start_denied"
	SecureCellGovernmentAgentExecutionLaunchOrderWaitingOperatorReceipts SecureCellGovernmentAgentExecutionLaunchOrderStatus = "waiting_for_operator_receipts"
	SecureCellGovernmentAgentExecutionLaunchOrderReadySupervised         SecureCellGovernmentAgentExecutionLaunchOrderStatus = "ready_for_supervised_start"
	SecureCellGovernmentAgentExecutionLaunchOrderReadyAutonomous         SecureCellGovernmentAgentExecutionLaunchOrderStatus = "ready_for_autonomous_start"
)

// SecureCellGovernmentAgentExecutionLaunchOrderStopPriority is the severity of
// one runtime stop condition.
type SecureCellGovernmentAgentExecutionLaunchOrderStopPriority string

const (
	SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityCritical SecureCellGovernmentAgentExecutionLaunchOrderStopPriority = "critical"
	SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityHigh     SecureCellGovernmentAgentExecutionLaunchOrderStopPriority = "high"
	SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityStandard SecureCellGovernmentAgentExecutionLaunchOrderStopPriority = "standard"
)

// SecureCellGovernmentAgentExecutionLaunchOrderStopCondition is one condition
// that must stop or pause execution.
type SecureCellGovernmentAgentExecutionLaunchOrderStopCondition struct {
	ConditionID     string                                                    `json:"condition_id"`
	Sequence        int                                                       `json:"sequence"`
	CellID          string                                                    `json:"cell_id"`
	OrderID         string                                                    `json:"order_id,omitempty"`
	Code            string                                                    `json:"code"`
	Priority        SecureCellGovernmentAgentExecutionLaunchOrderStopPriority `json:"priority"`
	Detail          string                                                    `json:"detail"`
	RequiredAction  string                                                    `json:"required_action"`
	EvidenceDigest  string                                                    `json:"evidence_digest,omitempty"`
	ConditionDigest string                                                    `json:"condition_digest"`
	GeneratedAt     time.Time                                                 `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchOrder is the digest-bound runtime
// order generated from a launch activation certificate.
type SecureCellGovernmentAgentExecutionLaunchOrder struct {
	OrderID                       string                                                        `json:"order_id"`
	ActivationID                  string                                                        `json:"activation_id"`
	CustodyID                     string                                                        `json:"custody_id"`
	PackageID                     string                                                        `json:"package_id"`
	CellID                        string                                                        `json:"cell_id"`
	Name                          string                                                        `json:"name"`
	Jurisdiction                  string                                                        `json:"jurisdiction,omitempty"`
	ServiceCode                   string                                                        `json:"service_code,omitempty"`
	ServiceTier                   string                                                        `json:"service_tier,omitempty"`
	Status                        SecureCellGovernmentAgentExecutionLaunchOrderStatus           `json:"status"`
	ActivationStatus              SecureCellGovernmentAgentExecutionLaunchActivationStatus      `json:"activation_status"`
	CanStartNow                   bool                                                          `json:"can_start_now"`
	CanStartAfterOperatorReceipts bool                                                          `json:"can_start_after_operator_receipts"`
	CanStartAutonomous            bool                                                          `json:"can_start_autonomous"`
	LeaseMinutes                  int                                                           `json:"lease_minutes"`
	RuntimeMinutes                int                                                           `json:"runtime_minutes"`
	StartWindowOpensAt            time.Time                                                     `json:"start_window_opens_at"`
	StartWindowExpiresAt          time.Time                                                     `json:"start_window_expires_at"`
	StopConditionCount            int                                                           `json:"stop_condition_count"`
	CriticalStopConditionCount    int                                                           `json:"critical_stop_condition_count"`
	HighStopConditionCount        int                                                           `json:"high_stop_condition_count"`
	StandardStopConditionCount    int                                                           `json:"standard_stop_condition_count"`
	ReturnReceiptCount            int                                                           `json:"return_receipt_count"`
	RequiredReturnReceipts        []string                                                      `json:"required_return_receipts,omitempty"`
	RequiredLaunchReceipts        []string                                                      `json:"required_launch_receipts,omitempty"`
	OperatorInstructions          []string                                                      `json:"operator_instructions,omitempty"`
	PackageDigest                 string                                                        `json:"package_digest"`
	CustodyDigest                 string                                                        `json:"custody_digest"`
	ActivationDigest              string                                                        `json:"activation_digest"`
	LaunchDigest                  string                                                        `json:"launch_digest"`
	ReceiptManifestDigest         string                                                        `json:"receipt_manifest_digest"`
	ReceiptValidationDigest       string                                                        `json:"receipt_validation_digest"`
	StopConditions                []SecureCellGovernmentAgentExecutionLaunchOrderStopCondition  `json:"stop_conditions"`
	Activation                    SecureCellGovernmentAgentExecutionLaunchActivationCertificate `json:"activation"`
	OrderDigest                   string                                                        `json:"order_digest"`
	GeneratedAt                   time.Time                                                     `json:"generated_at"`
	UpdatedAt                     time.Time                                                     `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchOrder returns the runtime launch order for
// one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchOrder(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchOrder, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchOrders(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-order: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchOrders returns launch orders for matching
// government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchOrders(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchOrder, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-order: service is required")
	}
	activations, err := s.ListGovernmentAgentExecutionLaunchActivations(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	orders := make([]SecureCellGovernmentAgentExecutionLaunchOrder, 0, len(activations))
	for _, activation := range activations {
		orders = append(orders, secureCellGovernmentAgentExecutionLaunchOrder(activation, now))
	}
	sort.SliceStable(orders, func(i, j int) bool {
		if orders[i].Status == orders[j].Status {
			if orders[i].CriticalStopConditionCount == orders[j].CriticalStopConditionCount {
				if orders[i].HighStopConditionCount == orders[j].HighStopConditionCount {
					return orders[i].CellID < orders[j].CellID
				}
				return orders[i].HighStopConditionCount > orders[j].HighStopConditionCount
			}
			return orders[i].CriticalStopConditionCount > orders[j].CriticalStopConditionCount
		}
		return secureCellGovernmentAgentExecutionLaunchOrderStatusRank(orders[i].Status) < secureCellGovernmentAgentExecutionLaunchOrderStatusRank(orders[j].Status)
	})
	return orders, nil
}

func secureCellGovernmentAgentExecutionLaunchOrder(
	activation SecureCellGovernmentAgentExecutionLaunchActivationCertificate,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchOrder {
	runtimeMinutes := secureCellGovernmentAgentExecutionLaunchOrderRuntimeMinutes(activation.LeaseMinutes)
	order := SecureCellGovernmentAgentExecutionLaunchOrder{
		ActivationID:            activation.ActivationID,
		CustodyID:               activation.CustodyID,
		PackageID:               activation.PackageID,
		CellID:                  activation.CellID,
		Name:                    activation.Name,
		Jurisdiction:            activation.Jurisdiction,
		ServiceCode:             activation.ServiceCode,
		ServiceTier:             activation.ServiceTier,
		ActivationStatus:        activation.Status,
		LeaseMinutes:            activation.LeaseMinutes,
		RuntimeMinutes:          runtimeMinutes,
		StartWindowOpensAt:      activation.ActivationWindowStartsAt.UTC(),
		StartWindowExpiresAt:    activation.ActivationWindowExpiresAt.UTC(),
		RequiredLaunchReceipts:  append([]string(nil), activation.RequiredReceiptTypes...),
		PackageDigest:           activation.PackageDigest,
		CustodyDigest:           activation.CustodyDigest,
		ActivationDigest:        activation.ActivationDigest,
		LaunchDigest:            activation.LaunchDigest,
		ReceiptManifestDigest:   activation.ReceiptManifestDigest,
		ReceiptValidationDigest: activation.ReceiptValidationDigest,
		Activation:              activation,
		GeneratedAt:             generatedAt.UTC(),
		UpdatedAt:               activation.UpdatedAt.UTC(),
	}
	order.Status = secureCellGovernmentAgentExecutionLaunchOrderStatus(activation)
	order.CanStartNow = order.Status == SecureCellGovernmentAgentExecutionLaunchOrderReadySupervised || order.Status == SecureCellGovernmentAgentExecutionLaunchOrderReadyAutonomous
	order.CanStartAfterOperatorReceipts = order.Status == SecureCellGovernmentAgentExecutionLaunchOrderWaitingOperatorReceipts && activation.CanExecuteAfterOperatorReceipts
	order.CanStartAutonomous = order.Status == SecureCellGovernmentAgentExecutionLaunchOrderReadyAutonomous
	order.RequiredReturnReceipts = secureCellGovernmentAgentExecutionLaunchOrderReturnReceipts(order)
	order.StopConditions = secureCellGovernmentAgentExecutionLaunchOrderStopConditions(order, activation, generatedAt)
	for _, condition := range order.StopConditions {
		order.StopConditionCount++
		switch condition.Priority {
		case SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityCritical:
			order.CriticalStopConditionCount++
		case SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityHigh:
			order.HighStopConditionCount++
		default:
			order.StandardStopConditionCount++
		}
	}
	order.ReturnReceiptCount = len(order.RequiredReturnReceipts)
	order.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchOrderInstructions(order)
	order.OrderDigest = secureCellGovernmentAgentExecutionLaunchOrderDigest(order)
	order.OrderID = "government-agent-execution-launch-order:" + order.CellID + ":" + order.OrderDigest[:12]
	for idx := range order.StopConditions {
		order.StopConditions[idx].OrderID = order.OrderID
	}
	return order
}

func secureCellGovernmentAgentExecutionLaunchOrderStopConditions(
	order SecureCellGovernmentAgentExecutionLaunchOrder,
	activation SecureCellGovernmentAgentExecutionLaunchActivationCertificate,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchOrderStopCondition {
	conditions := make([]SecureCellGovernmentAgentExecutionLaunchOrderStopCondition, 0, 5)
	sequence := 1
	if activation.FailCount > 0 || activation.Status == SecureCellGovernmentAgentExecutionLaunchActivationDenied {
		conditions = append(conditions, secureCellGovernmentAgentExecutionLaunchOrderStopCondition(order, sequence, "ACTIVATION_CHECK_FAILED", SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityCritical, "Activation contains failed checks.", "Stop launch and correct failed activation checks.", activation.ActivationDigest, generatedAt))
		sequence++
	}
	if activation.WarnCount > 0 || activation.Status == SecureCellGovernmentAgentExecutionLaunchActivationOperatorReceiptsRequired {
		conditions = append(conditions, secureCellGovernmentAgentExecutionLaunchOrderStopCondition(order, sequence, "OPERATOR_RECEIPTS_MISSING", SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityHigh, "Operator receipts are required before execution can start.", "Collect operator receipts and regenerate activation.", activation.ReceiptManifestDigest, generatedAt))
		sequence++
	}
	if !generatedAt.UTC().Before(order.StartWindowExpiresAt.UTC()) || generatedAt.UTC().Before(order.StartWindowOpensAt.UTC()) {
		conditions = append(conditions, secureCellGovernmentAgentExecutionLaunchOrderStopCondition(order, sequence, "START_WINDOW_CLOSED", SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityCritical, "The activation start window is not open.", "Regenerate custody and activation before execution.", activation.CustodyDigest, generatedAt))
		sequence++
	}
	conditions = append(conditions,
		secureCellGovernmentAgentExecutionLaunchOrderStopCondition(order, sequence, "RETURN_RECEIPTS_REQUIRED", SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityStandard, "Execution must return all required receipts.", "Pause completion until return receipts are preserved.", activation.LaunchDigest, generatedAt),
	)
	sequence++
	conditions = append(conditions,
		secureCellGovernmentAgentExecutionLaunchOrderStopCondition(order, sequence, "SCOPE_DRIFT_STOP", SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityStandard, "Executor must stop if requested action, data, or tool scope differs from the launch package.", "Escalate to operator and regenerate the launch package for changed scope.", activation.PackageDigest, generatedAt),
	)
	sort.SliceStable(conditions, func(i, j int) bool {
		if conditions[i].Priority == conditions[j].Priority {
			return conditions[i].Sequence < conditions[j].Sequence
		}
		return secureCellGovernmentAgentExecutionLaunchOrderStopPriorityRank(conditions[i].Priority) < secureCellGovernmentAgentExecutionLaunchOrderStopPriorityRank(conditions[j].Priority)
	})
	return conditions
}

func secureCellGovernmentAgentExecutionLaunchOrderStopCondition(
	order SecureCellGovernmentAgentExecutionLaunchOrder,
	sequence int,
	code string,
	priority SecureCellGovernmentAgentExecutionLaunchOrderStopPriority,
	detail string,
	requiredAction string,
	evidenceDigest string,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchOrderStopCondition {
	condition := SecureCellGovernmentAgentExecutionLaunchOrderStopCondition{
		Sequence:       sequence,
		CellID:         order.CellID,
		Code:           strings.TrimSpace(code),
		Priority:       priority,
		Detail:         strings.TrimSpace(detail),
		RequiredAction: strings.TrimSpace(requiredAction),
		EvidenceDigest: strings.TrimSpace(evidenceDigest),
		GeneratedAt:    generatedAt.UTC(),
	}
	condition.ConditionDigest = secureCellGovernmentAgentExecutionLaunchOrderStopConditionDigest(condition)
	condition.ConditionID = "government-agent-execution-launch-order-stop:" + condition.CellID + ":" + condition.ConditionDigest[:12]
	return condition
}

func secureCellGovernmentAgentExecutionLaunchOrderStatus(activation SecureCellGovernmentAgentExecutionLaunchActivationCertificate) SecureCellGovernmentAgentExecutionLaunchOrderStatus {
	if activation.Status == SecureCellGovernmentAgentExecutionLaunchActivationDenied || activation.FailCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchOrderDenied
	}
	if activation.Status == SecureCellGovernmentAgentExecutionLaunchActivationOperatorReceiptsRequired || activation.WarnCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchOrderWaitingOperatorReceipts
	}
	if activation.CanExecuteAutonomous {
		return SecureCellGovernmentAgentExecutionLaunchOrderReadyAutonomous
	}
	if activation.CanExecuteNow {
		return SecureCellGovernmentAgentExecutionLaunchOrderReadySupervised
	}
	return SecureCellGovernmentAgentExecutionLaunchOrderDenied
}

func secureCellGovernmentAgentExecutionLaunchOrderRuntimeMinutes(leaseMinutes int) int {
	if leaseMinutes <= 0 {
		return 60
	}
	runtimeMinutes := leaseMinutes / 2
	if runtimeMinutes < 30 {
		return 30
	}
	if runtimeMinutes > 240 {
		return 240
	}
	return runtimeMinutes
}

func secureCellGovernmentAgentExecutionLaunchOrderReturnReceipts(order SecureCellGovernmentAgentExecutionLaunchOrder) []string {
	receipts := []string{
		"execution_start_receipt",
		"package_consumption_receipt",
		"execution_completion_receipt",
		"exception_receipt",
	}
	if order.Status == SecureCellGovernmentAgentExecutionLaunchOrderReadyAutonomous {
		receipts = append(receipts, "autonomous_supervision_receipt")
	}
	if order.Status == SecureCellGovernmentAgentExecutionLaunchOrderWaitingOperatorReceipts {
		receipts = append(receipts, "operator_acknowledgement_receipt")
	}
	return uniqueSortedStrings(receipts)
}

func secureCellGovernmentAgentExecutionLaunchOrderInstructions(order SecureCellGovernmentAgentExecutionLaunchOrder) []string {
	instructions := append([]string(nil), order.Activation.OperatorInstructions...)
	switch order.Status {
	case SecureCellGovernmentAgentExecutionLaunchOrderDenied:
		instructions = append(instructions, "Do not start execution until launch order blockers are cleared.")
	case SecureCellGovernmentAgentExecutionLaunchOrderWaitingOperatorReceipts:
		instructions = append(instructions, "Collect operator receipts before issuing the start order.")
	case SecureCellGovernmentAgentExecutionLaunchOrderReadyAutonomous:
		instructions = append(instructions, "Start autonomous execution only with the order digest and supervision receipt enabled.")
	default:
		instructions = append(instructions, "Start supervised execution only with the order digest preserved.")
	}
	instructions = append(instructions, fmt.Sprintf("Stop execution after %d minutes or when any stop condition is triggered.", order.RuntimeMinutes))
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchOrderStatusRank(status SecureCellGovernmentAgentExecutionLaunchOrderStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchOrderDenied:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchOrderWaitingOperatorReceipts:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchOrderReadySupervised:
		return 2
	case SecureCellGovernmentAgentExecutionLaunchOrderReadyAutonomous:
		return 3
	default:
		return 4
	}
}

func secureCellGovernmentAgentExecutionLaunchOrderStopPriorityRank(priority SecureCellGovernmentAgentExecutionLaunchOrderStopPriority) int {
	switch priority {
	case SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityCritical:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityHigh:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityStandard:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchOrderStopConditionDigest(condition SecureCellGovernmentAgentExecutionLaunchOrderStopCondition) string {
	core := struct {
		Sequence       int                                                       `json:"sequence"`
		CellID         string                                                    `json:"cell_id"`
		Code           string                                                    `json:"code"`
		Priority       SecureCellGovernmentAgentExecutionLaunchOrderStopPriority `json:"priority"`
		Detail         string                                                    `json:"detail"`
		RequiredAction string                                                    `json:"required_action"`
		EvidenceDigest string                                                    `json:"evidence_digest,omitempty"`
	}{
		Sequence:       condition.Sequence,
		CellID:         condition.CellID,
		Code:           condition.Code,
		Priority:       condition.Priority,
		Detail:         condition.Detail,
		RequiredAction: condition.RequiredAction,
		EvidenceDigest: condition.EvidenceDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchOrderDigest(order SecureCellGovernmentAgentExecutionLaunchOrder) string {
	conditionDigests := make([]string, 0, len(order.StopConditions))
	for _, condition := range order.StopConditions {
		conditionDigests = append(conditionDigests, condition.ConditionDigest)
	}
	core := struct {
		ActivationID                  string                                                   `json:"activation_id"`
		CustodyID                     string                                                   `json:"custody_id"`
		PackageID                     string                                                   `json:"package_id"`
		CellID                        string                                                   `json:"cell_id"`
		Status                        SecureCellGovernmentAgentExecutionLaunchOrderStatus      `json:"status"`
		ActivationStatus              SecureCellGovernmentAgentExecutionLaunchActivationStatus `json:"activation_status"`
		CanStartNow                   bool                                                     `json:"can_start_now"`
		CanStartAfterOperatorReceipts bool                                                     `json:"can_start_after_operator_receipts"`
		CanStartAutonomous            bool                                                     `json:"can_start_autonomous"`
		LeaseMinutes                  int                                                      `json:"lease_minutes"`
		RuntimeMinutes                int                                                      `json:"runtime_minutes"`
		RequiredReturnReceipts        []string                                                 `json:"required_return_receipts,omitempty"`
		RequiredLaunchReceipts        []string                                                 `json:"required_launch_receipts,omitempty"`
		ConditionDigests              []string                                                 `json:"condition_digests,omitempty"`
		PackageDigest                 string                                                   `json:"package_digest"`
		CustodyDigest                 string                                                   `json:"custody_digest"`
		ActivationDigest              string                                                   `json:"activation_digest"`
		LaunchDigest                  string                                                   `json:"launch_digest"`
		ReceiptManifestDigest         string                                                   `json:"receipt_manifest_digest"`
		ReceiptValidationDigest       string                                                   `json:"receipt_validation_digest"`
	}{
		ActivationID:                  order.ActivationID,
		CustodyID:                     order.CustodyID,
		PackageID:                     order.PackageID,
		CellID:                        order.CellID,
		Status:                        order.Status,
		ActivationStatus:              order.ActivationStatus,
		CanStartNow:                   order.CanStartNow,
		CanStartAfterOperatorReceipts: order.CanStartAfterOperatorReceipts,
		CanStartAutonomous:            order.CanStartAutonomous,
		LeaseMinutes:                  order.LeaseMinutes,
		RuntimeMinutes:                order.RuntimeMinutes,
		RequiredReturnReceipts:        order.RequiredReturnReceipts,
		RequiredLaunchReceipts:        order.RequiredLaunchReceipts,
		ConditionDigests:              conditionDigests,
		PackageDigest:                 order.PackageDigest,
		CustodyDigest:                 order.CustodyDigest,
		ActivationDigest:              order.ActivationDigest,
		LaunchDigest:                  order.LaunchDigest,
		ReceiptManifestDigest:         order.ReceiptManifestDigest,
		ReceiptValidationDigest:       order.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
