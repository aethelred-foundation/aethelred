package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ---------------------------------------------------------------------------
// Policy Service interface
// ---------------------------------------------------------------------------

// PolicyService defines the operations available for policy management.
type PolicyService interface {
	// EvaluateRequest evaluates an action against all applicable policies.
	EvaluateRequest(ctx context.Context, req *EvaluateAPIRequest) (*EvaluateAPIResponse, error)

	// GetPolicySet returns a policy set by ID.
	GetPolicySet(ctx context.Context, req *GetPolicySetRequest) (*GetPolicySetResponse, error)

	// ListPolicySets returns all registered policy sets.
	ListPolicySets(ctx context.Context) (*ListPolicySetsResponse, error)

	// GetWorkflowStatus returns the status of an approval workflow.
	GetWorkflowStatus(ctx context.Context, req *GetWorkflowRequest) (*GetWorkflowResponse, error)

	// SubmitApproval submits an approval decision.
	SubmitApproval(ctx context.Context, req *SubmitApprovalRequest) (*SubmitApprovalResponse, error)

	// GetBreakGlassStatus returns whether break-glass is active.
	GetBreakGlassStatus(ctx context.Context) (*BreakGlassStatusResponse, error)

	// InitiateBreakGlass starts a break-glass override.
	InitiateBreakGlass(ctx context.Context, req *InitiateBreakGlassRequest) (*InitiateBreakGlassResponse, error)

	// GetAuditLog returns the policy evaluation audit log.
	GetAuditLog(ctx context.Context) (*AuditLogResponse, error)
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

// EvaluateAPIRequest is the API-layer evaluation request.
type EvaluateAPIRequest struct {
	Actor    string            `json:"actor"`
	Action   string            `json:"action"`
	Resource string            `json:"resource"`
	Context  map[string]string `json:"context,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// EvaluateAPIResponse is the API-layer evaluation response.
type EvaluateAPIResponse struct {
	RequestID   string   `json:"request_id"`
	Decision    string   `json:"decision"`
	MatchedRules []string `json:"matched_rules"`
	Conditions  []string `json:"conditions,omitempty"`
	AuditTrail  string   `json:"audit_trail"`
	EvaluatedAt string   `json:"evaluated_at"`
}

// GetPolicySetRequest identifies a policy set.
type GetPolicySetRequest struct {
	ID string `json:"id"`
}

// GetPolicySetResponse contains a policy set's metadata.
type GetPolicySetResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
	RuleCount   int    `json:"rule_count"`
}

// ListPolicySetsResponse contains all policy sets.
type ListPolicySetsResponse struct {
	PolicySets []GetPolicySetResponse `json:"policy_sets"`
}

// GetWorkflowRequest identifies a workflow.
type GetWorkflowRequest struct {
	WorkflowID string `json:"workflow_id"`
}

// GetWorkflowResponse contains workflow status.
type GetWorkflowResponse struct {
	ID        string `json:"id"`
	RequestID string `json:"request_id"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	Deadline  string `json:"deadline"`
	Approvers int    `json:"approver_count"`
}

// SubmitApprovalRequest submits an approval decision.
type SubmitApprovalRequest struct {
	WorkflowID string `json:"workflow_id"`
	ApproverID string `json:"approver_id"`
	Decision   string `json:"decision"` // "approved" or "denied"
	Comment    string `json:"comment,omitempty"`
}

// SubmitApprovalResponse confirms the submission.
type SubmitApprovalResponse struct {
	WorkflowID string `json:"workflow_id"`
	Status     string `json:"status"`
}

// BreakGlassStatusResponse reports break-glass state.
type BreakGlassStatusResponse struct {
	Active      bool   `json:"active"`
	ActiveCount int    `json:"active_count"`
}

// InitiateBreakGlassRequest starts a break-glass override.
type InitiateBreakGlassRequest struct {
	Initiator        string   `json:"initiator"`
	Reason           string   `json:"reason"`
	Severity         string   `json:"severity"`
	DurationMinutes  int      `json:"duration_minutes"`
	AffectedPolicies []string `json:"affected_policies,omitempty"`
}

// InitiateBreakGlassResponse confirms break-glass initiation.
type InitiateBreakGlassResponse struct {
	EventID   string `json:"event_id"`
	ExpiresAt string `json:"expires_at"`
}

// AuditLogResponse contains audit entries.
type AuditLogResponse struct {
	Entries []AuditEntry `json:"entries"`
	Total   int          `json:"total"`
}

// ---------------------------------------------------------------------------
// HTTP API server
// ---------------------------------------------------------------------------

// PolicyServer implements the PolicyService over HTTP.
type PolicyServer struct {
	engine     *PolicyEngine
	workflows  *WorkflowManager
	breakGlass *BreakGlassController
}

// NewPolicyServer creates a new PolicyServer with the given components.
func NewPolicyServer(engine *PolicyEngine, workflows *WorkflowManager, breakGlass *BreakGlassController) *PolicyServer {
	return &PolicyServer{
		engine:     engine,
		workflows:  workflows,
		breakGlass: breakGlass,
	}
}

// RegisterRoutes registers HTTP handlers on the given mux.
func (s *PolicyServer) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/policy/evaluate", s.handleEvaluate)
	mux.HandleFunc("/api/v1/policy/sets", s.handleListPolicySets)
	mux.HandleFunc("/api/v1/policy/workflow/status", s.handleGetWorkflowStatus)
	mux.HandleFunc("/api/v1/policy/workflow/approve", s.handleSubmitApproval)
	mux.HandleFunc("/api/v1/policy/breakglass/status", s.handleBreakGlassStatus)
	mux.HandleFunc("/api/v1/policy/breakglass/initiate", s.handleInitiateBreakGlass)
	mux.HandleFunc("/api/v1/policy/audit", s.handleGetAuditLog)
}

func (s *PolicyServer) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req EvaluateAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	evalReq := &EvaluationRequest{
		Actor:    req.Actor,
		Action:   req.Action,
		Resource: req.Resource,
		Context:  req.Context,
		Metadata: req.Metadata,
	}

	result, err := s.engine.Evaluate(r.Context(), evalReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := EvaluateAPIResponse{
		RequestID:    result.RequestID,
		Decision:     result.Decision.String(),
		MatchedRules: result.MatchedRules,
		Conditions:   result.Conditions,
		AuditTrail:   result.AuditTrail,
		EvaluatedAt:  result.EvaluatedAt.Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *PolicyServer) handleListPolicySets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}

	sets := s.engine.ListPolicySets()
	var response ListPolicySetsResponse
	for _, ps := range sets {
		response.PolicySets = append(response.PolicySets, GetPolicySetResponse{
			ID:          ps.ID,
			Name:        ps.Name,
			Description: ps.Description,
			Priority:    ps.Priority,
			Enabled:     ps.Enabled,
			RuleCount:   len(ps.Rules),
		})
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *PolicyServer) handleGetWorkflowStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}

	workflowID := r.URL.Query().Get("workflow_id")
	if workflowID == "" {
		writeError(w, http.StatusBadRequest, "workflow_id query parameter required")
		return
	}

	wf, err := s.workflows.GetWorkflowStatus(r.Context(), workflowID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	resp := GetWorkflowResponse{
		ID:        wf.ID,
		RequestID: wf.RequestID,
		Type:      wf.Type.String(),
		Status:    wf.Status.String(),
		Deadline:  wf.Deadline.Format(time.RFC3339),
		Approvers: len(wf.Approvers),
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *PolicyServer) handleSubmitApproval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req SubmitApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	decision := ApproverApproved
	if req.Decision == "denied" {
		decision = ApproverDenied
	}

	if err := s.workflows.Approve(r.Context(), req.WorkflowID, req.ApproverID, decision, req.Comment); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	wf, _ := s.workflows.GetWorkflowStatus(r.Context(), req.WorkflowID)
	status := "unknown"
	if wf != nil {
		status = wf.Status.String()
	}

	writeJSON(w, http.StatusOK, SubmitApprovalResponse{
		WorkflowID: req.WorkflowID,
		Status:     status,
	})
}

func (s *PolicyServer) handleBreakGlassStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}

	active := s.breakGlass.IsBreakGlassActive(r.Context())
	activeEvents := s.breakGlass.GetActiveBreakGlass(r.Context())

	writeJSON(w, http.StatusOK, BreakGlassStatusResponse{
		Active:      active,
		ActiveCount: len(activeEvents),
	})
}

func (s *PolicyServer) handleInitiateBreakGlass(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req InitiateBreakGlassRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	severity := BreakGlassMedium
	switch req.Severity {
	case "low":
		severity = BreakGlassLow
	case "high":
		severity = BreakGlassHigh
	case "critical":
		severity = BreakGlassCritical
	}

	duration := time.Duration(req.DurationMinutes) * time.Minute
	event, err := s.breakGlass.InitiateBreakGlass(r.Context(), req.Initiator, req.Reason, severity, duration, req.AffectedPolicies)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, InitiateBreakGlassResponse{
		EventID:   event.ID,
		ExpiresAt: event.Timestamp.Add(event.Duration).Format(time.RFC3339),
	})
}

func (s *PolicyServer) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}

	entries := s.engine.GetAuditLog()
	writeJSON(w, http.StatusOK, AuditLogResponse{
		Entries: entries,
		Total:   len(entries),
	})
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message}) //nolint:errcheck
}
