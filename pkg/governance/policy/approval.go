package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Approval types and statuses
// ---------------------------------------------------------------------------

// ApprovalType classifies the kind of approval workflow.
type ApprovalType int

const (
	// Single requires one approver.
	Single ApprovalType = iota

	// DualControl requires two independent approvers (four-eyes principle).
	DualControl

	// Committee requires a quorum of committee members.
	Committee

	// Hierarchical requires approval from progressively higher authorities.
	Hierarchical

	// BreakGlass is an emergency override with mandatory justification.
	BreakGlass
)

// String returns the human-readable label for an ApprovalType.
func (t ApprovalType) String() string {
	switch t {
	case Single:
		return "Single"
	case DualControl:
		return "DualControl"
	case Committee:
		return "Committee"
	case Hierarchical:
		return "Hierarchical"
	case BreakGlass:
		return "BreakGlass"
	default:
		return "Unknown"
	}
}

// ApprovalStatus tracks the lifecycle of an approval workflow.
type ApprovalStatus int

const (
	Pending ApprovalStatus = iota
	PartiallyApproved
	Approved
	Denied
	Expired
	BreakGlassOverride
)

// String returns the human-readable label for an ApprovalStatus.
func (s ApprovalStatus) String() string {
	switch s {
	case Pending:
		return "Pending"
	case PartiallyApproved:
		return "PartiallyApproved"
	case Approved:
		return "Approved"
	case Denied:
		return "Denied"
	case Expired:
		return "Expired"
	case BreakGlassOverride:
		return "BreakGlassOverride"
	default:
		return "Unknown"
	}
}

// ApproverDecision represents an individual approver's decision.
type ApproverDecision int

const (
	ApproverPending ApproverDecision = iota
	ApproverApproved
	ApproverDenied
)

// ---------------------------------------------------------------------------
// Approver and Workflow structs
// ---------------------------------------------------------------------------

// Approver represents a person or system that can approve a workflow step.
type Approver struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Role       string           `json:"role"`
	Authority  int              `json:"authority"`
	ApprovedAt *time.Time       `json:"approved_at,omitempty"`
	Decision   ApproverDecision `json:"decision"`
	Comment    string           `json:"comment,omitempty"`
}

// ApprovalWorkflow tracks the full lifecycle of an approval request.
type ApprovalWorkflow struct {
	ID         string         `json:"id"`
	RequestID  string         `json:"request_id"`
	Type       ApprovalType   `json:"type"`
	Approvers  []Approver     `json:"approvers"`
	Status     ApprovalStatus `json:"status"`
	Deadline   time.Time      `json:"deadline"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	AuditTrail []WorkflowAuditEntry `json:"audit_trail"`
}

// WorkflowAuditEntry records a single event in the workflow lifecycle.
type WorkflowAuditEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Details    string    `json:"details"`
	Hash       string    `json:"hash"`
}

// ---------------------------------------------------------------------------
// WorkflowManager
// ---------------------------------------------------------------------------

// WorkflowManager manages the lifecycle of approval workflows.
type WorkflowManager struct {
	mu        sync.RWMutex
	workflows map[string]*ApprovalWorkflow
}

// NewWorkflowManager creates a new WorkflowManager.
func NewWorkflowManager() *WorkflowManager {
	return &WorkflowManager{
		workflows: make(map[string]*ApprovalWorkflow),
	}
}

// CreateWorkflow creates a new approval workflow for a request.
func (wm *WorkflowManager) CreateWorkflow(_ context.Context, requestID string, approvalType ApprovalType, approvers []Approver, deadline time.Duration) (*ApprovalWorkflow, error) {
	if requestID == "" {
		return nil, fmt.Errorf("WorkflowManager.CreateWorkflow: %w: request ID cannot be empty", ErrInvalidInput)
	}
	if len(approvers) == 0 {
		return nil, fmt.Errorf("WorkflowManager.CreateWorkflow: %w: at least one approver is required", ErrInvalidInput)
	}

	// Validate minimum approvers for the type.
	switch approvalType {
	case DualControl:
		if len(approvers) < 2 {
			return nil, fmt.Errorf("dual control requires at least 2 approvers, got %d", len(approvers))
		}
	case Committee:
		if len(approvers) < 3 {
			return nil, fmt.Errorf("committee approval requires at least 3 approvers, got %d", len(approvers))
		}
	}

	now := time.Now().UTC()
	wf := &ApprovalWorkflow{
		ID:        uuid.New().String(),
		RequestID: requestID,
		Type:      approvalType,
		Approvers: approvers,
		Status:    Pending,
		Deadline:  now.Add(deadline),
		CreatedAt: now,
		UpdatedAt: now,
	}

	auditEntry := WorkflowAuditEntry{
		Timestamp: now,
		Actor:     "system",
		Action:    "workflow_created",
		Details:   fmt.Sprintf("type=%s, approvers=%d, deadline=%s", approvalType, len(approvers), deadline),
	}
	auditEntry.Hash = hashAuditEntry(auditEntry)
	wf.AuditTrail = append(wf.AuditTrail, auditEntry)

	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.workflows[wf.ID] = wf

	return wf, nil
}

// Approve records an approver's decision on a workflow.
func (wm *WorkflowManager) Approve(_ context.Context, workflowID, approverID string, decision ApproverDecision, comment string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	wf, ok := wm.workflows[workflowID]
	if !ok {
		return fmt.Errorf("WorkflowManager.Approve: %w: workflow %q", ErrApprovalFailed, workflowID)
	}

	if wf.Status == Approved || wf.Status == Denied || wf.Status == Expired {
		return fmt.Errorf("WorkflowManager.Approve: %w: workflow %q is in terminal state: %s", ErrApprovalFailed, workflowID, wf.Status)
	}

	// Check deadline.
	now := time.Now().UTC()
	if now.After(wf.Deadline) {
		wf.Status = Expired
		wf.UpdatedAt = now
		return fmt.Errorf("WorkflowManager.Approve: %w: workflow %q", ErrWorkflowExpired, workflowID)
	}

	// Find the approver.
	found := false
	for i := range wf.Approvers {
		if wf.Approvers[i].ID == approverID {
			if wf.Approvers[i].Decision != ApproverPending {
				return fmt.Errorf("WorkflowManager.Approve: %w: approver %q has already submitted a decision", ErrApprovalFailed, approverID)
			}
			wf.Approvers[i].Decision = decision
			wf.Approvers[i].ApprovedAt = &now
			wf.Approvers[i].Comment = comment
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("WorkflowManager.Approve: %w: approver %q not found in workflow %q", ErrApprovalFailed, approverID, workflowID)
	}

	// Record audit entry.
	decisionStr := "approved"
	if decision == ApproverDenied {
		decisionStr = "denied"
	}
	auditEntry := WorkflowAuditEntry{
		Timestamp: now,
		Actor:     approverID,
		Action:    "decision_submitted",
		Details:   fmt.Sprintf("decision=%s, comment=%s", decisionStr, comment),
	}
	auditEntry.Hash = hashAuditEntry(auditEntry)
	wf.AuditTrail = append(wf.AuditTrail, auditEntry)

	// Update workflow status.
	wf.UpdatedAt = now
	wm.updateWorkflowStatus(wf)

	return nil
}

// GetWorkflowStatus returns the current status of a workflow.
func (wm *WorkflowManager) GetWorkflowStatus(_ context.Context, workflowID string) (*ApprovalWorkflow, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	wf, ok := wm.workflows[workflowID]
	if !ok {
		return nil, fmt.Errorf("workflow %q not found", workflowID)
	}

	// Check for expiration on read.
	if wf.Status != Approved && wf.Status != Denied && time.Now().After(wf.Deadline) {
		wf.Status = Expired
	}

	return wf, nil
}

// ListPendingApprovals returns all workflows where the given approver has a pending decision.
func (wm *WorkflowManager) ListPendingApprovals(_ context.Context, approverID string) []*ApprovalWorkflow {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	var result []*ApprovalWorkflow
	now := time.Now()

	for _, wf := range wm.workflows {
		if wf.Status == Approved || wf.Status == Denied || wf.Status == Expired {
			continue
		}
		if now.After(wf.Deadline) {
			continue
		}
		for _, a := range wf.Approvers {
			if a.ID == approverID && a.Decision == ApproverPending {
				result = append(result, wf)
				break
			}
		}
	}
	return result
}

// EscalateWorkflow escalates a workflow that is approaching its deadline.
func (wm *WorkflowManager) EscalateWorkflow(_ context.Context, workflowID, reason string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	wf, ok := wm.workflows[workflowID]
	if !ok {
		return fmt.Errorf("workflow %q not found", workflowID)
	}

	if wf.Status == Approved || wf.Status == Denied || wf.Status == Expired {
		return fmt.Errorf("cannot escalate workflow in terminal state: %s", wf.Status)
	}

	now := time.Now().UTC()
	auditEntry := WorkflowAuditEntry{
		Timestamp: now,
		Actor:     "system",
		Action:    "workflow_escalated",
		Details:   fmt.Sprintf("reason=%s", reason),
	}
	auditEntry.Hash = hashAuditEntry(auditEntry)
	wf.AuditTrail = append(wf.AuditTrail, auditEntry)
	wf.UpdatedAt = now

	return nil
}

// CheckQuorum returns true if the workflow has received sufficient approvals.
func (wm *WorkflowManager) CheckQuorum(wf *ApprovalWorkflow) bool {
	if wf == nil {
		return false
	}

	approvedCount := 0
	for _, a := range wf.Approvers {
		if a.Decision == ApproverApproved {
			approvedCount++
		}
	}

	switch wf.Type {
	case Single:
		return approvedCount >= 1
	case DualControl:
		return approvedCount >= 2
	case Committee:
		// Majority required.
		quorum := (len(wf.Approvers) / 2) + 1
		return approvedCount >= quorum
	case Hierarchical:
		// All must approve.
		return approvedCount == len(wf.Approvers)
	case BreakGlass:
		return approvedCount >= 1
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Pre-built approval policies
// ---------------------------------------------------------------------------

// FinancialDualControl returns a dual-control approval rule for financial
// transactions above a threshold.
func FinancialDualControl(thresholdAmount string) *ApprovalRule {
	return NewApprovalRule(
		"financial_dual_control",
		DualControl,
		2,
		[]string{"financial_officer", "compliance_officer"},
		24*time.Hour,
		"Financial transactions above threshold require dual approval",
		[]Condition{
			{Field: "amount", Operator: GreaterThan, Value: thresholdAmount},
			{Field: "sector", Operator: Equals, Value: "finance"},
		},
	)
}

// DefenseCommittee returns a committee approval rule for defense-sector actions.
func DefenseCommittee() *ApprovalRule {
	return NewApprovalRule(
		"defense_committee",
		Committee,
		3,
		[]string{"security_officer", "commanding_officer", "compliance_officer"},
		48*time.Hour,
		"Defense sector actions require committee approval",
		[]Condition{
			{Field: "sector", Operator: Equals, Value: "defense"},
			{Field: "classification", Operator: In, Value: "secret,top_secret"},
		},
	)
}

// HealthcareConsent returns an approval rule for healthcare data access.
func HealthcareConsent() *ApprovalRule {
	return NewApprovalRule(
		"healthcare_consent",
		Single,
		1,
		[]string{"data_protection_officer", "treating_physician"},
		12*time.Hour,
		"Healthcare data access requires patient consent verification",
		[]Condition{
			{Field: "sector", Operator: Equals, Value: "healthcare"},
			{Field: "data_type", Operator: In, Value: "phi,patient_record"},
		},
	)
}

// CriticalChange returns a dual-control approval rule for critical system changes.
func CriticalChange() *ApprovalRule {
	return NewApprovalRule(
		"critical_change",
		DualControl,
		2,
		[]string{"platform_admin", "security_officer"},
		4*time.Hour,
		"Critical system changes require dual approval",
		[]Condition{
			{Field: "change_type", Operator: In, Value: "production_deploy,config_change,access_control"},
			{Field: "risk_level", Operator: In, Value: "high,critical"},
		},
	)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (wm *WorkflowManager) updateWorkflowStatus(wf *ApprovalWorkflow) {
	// Check for any denial first.
	for _, a := range wf.Approvers {
		if a.Decision == ApproverDenied {
			wf.Status = Denied
			return
		}
	}

	// Check quorum.
	if wm.CheckQuorum(wf) {
		wf.Status = Approved
		return
	}

	// Check if any have approved.
	for _, a := range wf.Approvers {
		if a.Decision == ApproverApproved {
			wf.Status = PartiallyApproved
			return
		}
	}

	wf.Status = Pending
}

func hashAuditEntry(entry WorkflowAuditEntry) string {
	data, _ := json.Marshal(struct {
		Timestamp string `json:"ts"`
		Actor     string `json:"actor"`
		Action    string `json:"action"`
		Details   string `json:"details"`
	}{
		Timestamp: entry.Timestamp.Format(time.RFC3339Nano),
		Actor:     entry.Actor,
		Action:    entry.Action,
		Details:   entry.Details,
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
