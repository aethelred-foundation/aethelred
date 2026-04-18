package finance

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Treasury Workflow Controls
// ---------------------------------------------------------------------------

// OperationType categorizes treasury operations.
type OperationType string

const (
	OpTransfer       OperationType = "transfer"
	OpPayment        OperationType = "payment"
	OpFXTrade        OperationType = "fx_trade"
	OpSettlement     OperationType = "settlement"
	OpReconciliation OperationType = "reconciliation"
)

// OperationStatus tracks the lifecycle of a treasury operation.
type OperationStatus string

const (
	StatusPending        OperationStatus = "pending"
	StatusAwaitingApproval OperationStatus = "awaiting_approval"
	StatusApproved       OperationStatus = "approved"
	StatusExecuting      OperationStatus = "executing"
	StatusCompleted      OperationStatus = "completed"
	StatusRejected       OperationStatus = "rejected"
	StatusCancelled      OperationStatus = "cancelled"
)

// TreasuryOperation represents a single treasury workflow operation.
type TreasuryOperation struct {
	// ID uniquely identifies this operation.
	ID string `json:"id"`

	// Type categorizes the operation.
	Type OperationType `json:"type"`

	// Amount is the monetary amount.
	Amount float64 `json:"amount"`

	// Currency is the currency code.
	Currency string `json:"currency"`

	// Initiator is the person or system that started the operation.
	Initiator string `json:"initiator"`

	// Approvers lists the approval chain entries.
	Approvers []ApprovalEntry `json:"approvers"`

	// Status is the current operation status.
	Status OperationStatus `json:"status"`

	// Description provides context for the operation.
	Description string `json:"description"`

	// Counterparty is the other party in the operation.
	Counterparty string `json:"counterparty"`

	// CreatedAt is when the operation was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the operation was last updated.
	UpdatedAt time.Time `json:"updated_at"`

	// CompletedAt is when the operation completed (zero if not completed).
	CompletedAt time.Time `json:"completed_at,omitempty"`

	// SealID links to the sealed audit record.
	SealID string `json:"seal_id"`

	// Metadata holds operation-specific key-value data.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ApprovalEntry records a single approval or rejection.
type ApprovalEntry struct {
	// Approver is the person who approved or rejected.
	Approver string `json:"approver"`

	// Approved indicates whether this was an approval (true) or rejection (false).
	Approved bool `json:"approved"`

	// Timestamp is when the decision was made.
	Timestamp time.Time `json:"timestamp"`

	// Comments from the approver.
	Comments string `json:"comments,omitempty"`

	// Level is the approval level (1, 2, committee).
	Level int `json:"level"`
}

// ApprovalPolicy defines the thresholds and rules for operation approvals.
type ApprovalPolicy struct {
	// SingleThreshold is the maximum amount a single approver can authorize.
	SingleThreshold float64 `json:"single_threshold"`

	// DualThreshold is the amount above which dual approval is required.
	DualThreshold float64 `json:"dual_threshold"`

	// CommitteeThreshold is the amount requiring committee approval.
	CommitteeThreshold float64 `json:"committee_threshold"`

	// Approvers lists authorized approvers with their levels.
	Approvers map[string]int `json:"approvers"`

	// RequiredCommitteeSize is the number of approvals needed for committee-level.
	RequiredCommitteeSize int `json:"required_committee_size"`
}

// ApprovalStatus reports the current state of the approval chain.
type ApprovalStatus struct {
	// OperationID identifies the operation.
	OperationID string `json:"operation_id"`

	// RequiredApprovals is the number of approvals needed.
	RequiredApprovals int `json:"required_approvals"`

	// CurrentApprovals is the number of approvals received.
	CurrentApprovals int `json:"current_approvals"`

	// Rejections is the number of rejections.
	Rejections int `json:"rejections"`

	// FullyApproved indicates whether enough approvals have been collected.
	FullyApproved bool `json:"fully_approved"`

	// Entries lists all approval/rejection entries.
	Entries []ApprovalEntry `json:"entries"`
}

// TreasuryController manages treasury operations and approval workflows.
type TreasuryController struct {
	policy     ApprovalPolicy
	mu         sync.RWMutex
	operations map[string]*TreasuryOperation
}

// NewTreasuryController creates a new controller with the given approval policy.
func NewTreasuryController(policy ApprovalPolicy) *TreasuryController {
	if policy.RequiredCommitteeSize == 0 {
		policy.RequiredCommitteeSize = 3
	}
	return &TreasuryController{
		policy:     policy,
		operations: make(map[string]*TreasuryOperation),
	}
}

// ApprovalPolicy returns a defensive copy of the controller approval policy.
func (c *TreasuryController) ApprovalPolicy() ApprovalPolicy {
	if c == nil {
		return ApprovalPolicy{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := c.policy
	if len(c.policy.Approvers) > 0 {
		out.Approvers = make(map[string]int, len(c.policy.Approvers))
		for approver, level := range c.policy.Approvers {
			out.Approvers[approver] = level
		}
	}
	return out
}

// RestoreOperation rehydrates one persisted treasury operation back into the
// controller so approvals and state transitions can resume after restart.
func (c *TreasuryController) RestoreOperation(op *TreasuryOperation) error {
	if c == nil {
		return fmt.Errorf("controller is required")
	}
	if op == nil {
		return fmt.Errorf("operation is required")
	}
	if strings.TrimSpace(op.ID) == "" {
		return fmt.Errorf("operation ID is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.operations[op.ID] = cloneTreasuryOperation(op)
	return nil
}

// InitiateOperation starts a new treasury operation.
func (c *TreasuryController) InitiateOperation(_ context.Context, op *TreasuryOperation) error {
	if op == nil {
		return fmt.Errorf("operation is required")
	}
	if op.Initiator == "" {
		return fmt.Errorf("initiator is required")
	}
	if op.Amount <= 0 {
		return fmt.Errorf("amount must be positive")
	}
	if op.Currency == "" {
		return fmt.Errorf("currency is required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if op.ID == "" {
		op.ID = fmt.Sprintf("top-%d", time.Now().UnixNano())
	}
	op.CreatedAt = time.Now().UTC()
	op.UpdatedAt = op.CreatedAt

	if c.RequiresDualApproval(op) {
		op.Status = StatusAwaitingApproval
	} else {
		op.Status = StatusApproved
	}

	c.operations[op.ID] = op
	return nil
}

// ApproveOperation records an approval for an operation.
func (c *TreasuryController) ApproveOperation(_ context.Context, operationID string, approver string) error {
	if operationID == "" {
		return fmt.Errorf("operation ID is required")
	}
	if approver == "" {
		return fmt.Errorf("approver is required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	op, ok := c.operations[operationID]
	if !ok {
		return fmt.Errorf("operation not found: %s", operationID)
	}

	if op.Status != StatusAwaitingApproval {
		return fmt.Errorf("operation is not awaiting approval (status: %s)", op.Status)
	}

	// Check for duplicate approval
	for _, entry := range op.Approvers {
		if entry.Approver == approver {
			return fmt.Errorf("approver %s has already acted on this operation", approver)
		}
	}

	// Self-approval check
	if approver == op.Initiator {
		return fmt.Errorf("initiator cannot approve their own operation")
	}

	entry := ApprovalEntry{
		Approver:  approver,
		Approved:  true,
		Timestamp: time.Now().UTC(),
		Level:     1,
	}
	op.Approvers = append(op.Approvers, entry)
	op.UpdatedAt = time.Now().UTC()

	// Check if enough approvals collected
	approvalCount := 0
	for _, e := range op.Approvers {
		if e.Approved {
			approvalCount++
		}
	}

	required := c.requiredApprovals(op)
	if approvalCount >= required {
		op.Status = StatusApproved
	}

	return nil
}

// RequiresDualApproval checks whether an operation needs more than one approval.
func (c *TreasuryController) RequiresDualApproval(op *TreasuryOperation) bool {
	if op == nil {
		return false
	}
	return op.Amount > c.policy.SingleThreshold
}

// GetApprovalStatus returns the current approval status for an operation.
func (c *TreasuryController) GetApprovalStatus(_ context.Context, operationID string) (*ApprovalStatus, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	op, ok := c.operations[operationID]
	if !ok {
		return nil, fmt.Errorf("operation not found: %s", operationID)
	}

	approvals := 0
	rejections := 0
	for _, e := range op.Approvers {
		if e.Approved {
			approvals++
		} else {
			rejections++
		}
	}

	required := c.requiredApprovals(op)

	return &ApprovalStatus{
		OperationID:       operationID,
		RequiredApprovals: required,
		CurrentApprovals:  approvals,
		Rejections:        rejections,
		FullyApproved:     approvals >= required,
		Entries:           op.Approvers,
	}, nil
}

// GetOperation retrieves an operation by ID.
func (c *TreasuryController) GetOperation(_ context.Context, operationID string) (*TreasuryOperation, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	op, ok := c.operations[operationID]
	if !ok {
		return nil, fmt.Errorf("operation not found: %s", operationID)
	}
	return op, nil
}

func (c *TreasuryController) requiredApprovals(op *TreasuryOperation) int {
	if op.Amount > c.policy.CommitteeThreshold && c.policy.CommitteeThreshold > 0 {
		return c.policy.RequiredCommitteeSize
	}
	if op.Amount > c.policy.DualThreshold && c.policy.DualThreshold > 0 {
		return 2
	}
	if op.Amount > c.policy.SingleThreshold {
		return 1
	}
	return 0
}
