// Package policy provides an enterprise policy evaluation engine with human
// approval workflows, dual control, and break-glass emergency overrides.
//
// The engine evaluates requests against layered policy rule sets, supporting
// sector-specific templates for finance, healthcare, defense, and autonomous
// mobility. Every evaluation is auditable, and policy decisions include full
// provenance trails suitable for regulatory examination.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

// Decision represents the outcome of a policy evaluation.
type Decision int

const (
	// Allow indicates the action is explicitly permitted.
	Allow Decision = iota

	// Deny indicates the action is explicitly denied.
	Deny

	// RequireApproval indicates the action needs single-approver sign-off.
	RequireApproval

	// RequireDualControl indicates the action needs two independent approvers.
	RequireDualControl

	// RequireCommittee indicates the action needs committee approval.
	RequireCommittee

	// Escalate indicates the request must be escalated to a higher authority.
	Escalate
)

// String returns the human-readable label for a Decision.
func (d Decision) String() string {
	switch d {
	case Allow:
		return "Allow"
	case Deny:
		return "Deny"
	case RequireApproval:
		return "RequireApproval"
	case RequireDualControl:
		return "RequireDualControl"
	case RequireCommittee:
		return "RequireCommittee"
	case Escalate:
		return "Escalate"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// EngineConfig holds configuration for the PolicyEngine.
type EngineConfig struct {
	// DefaultMode is the decision when no rules match. Defaults to Deny (fail-closed).
	DefaultMode Decision

	// AuditAllEvaluations records every evaluation, not just denials.
	AuditAllEvaluations bool

	// CacheTimeout is how long cached evaluation results remain valid.
	CacheTimeout time.Duration

	// MaxRulesPerPolicy caps the number of rules in a single PolicySet.
	MaxRulesPerPolicy int
}

// DefaultEngineConfig returns a secure-by-default configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		DefaultMode:         Deny,
		AuditAllEvaluations: true,
		CacheTimeout:        5 * time.Minute,
		MaxRulesPerPolicy:   1000,
	}
}

// ---------------------------------------------------------------------------
// Evaluation request and result
// ---------------------------------------------------------------------------

// EvaluationRequest encapsulates an action to be evaluated against policies.
type EvaluationRequest struct {
	// Actor is the entity performing the action (user ID, agent DID, etc.).
	Actor string

	// Action is the operation being performed (e.g., "deploy_model", "transfer_funds").
	Action string

	// Resource is the target of the action (e.g., model ID, account ID).
	Resource string

	// Context provides additional evaluation context (sector, environment, etc.).
	Context map[string]string

	// Metadata holds arbitrary key-value pairs for rule conditions.
	Metadata map[string]string
}

// EvaluationResult is the outcome of evaluating a request against all applicable policies.
type EvaluationResult struct {
	// Decision is the final policy decision.
	Decision Decision

	// MatchedRules lists the rule IDs that contributed to this decision.
	MatchedRules []string

	// RequiredApprovals describes any approvals needed (if Decision is RequireApproval/DualControl/Committee).
	RequiredApprovals []ApprovalRequirement

	// Conditions lists any conditions that must be satisfied for the decision to stand.
	Conditions []string

	// AuditTrail is a hash of the evaluation for tamper detection.
	AuditTrail string

	// EvaluatedAt is when the evaluation occurred.
	EvaluatedAt time.Time

	// RequestID is the unique identifier for this evaluation.
	RequestID string
}

// ApprovalRequirement describes a specific approval needed.
type ApprovalRequirement struct {
	Type      ApprovalType
	MinCount  int
	Roles     []string
	Deadline  time.Duration
	Reason    string
}

// ---------------------------------------------------------------------------
// Evaluation cache
// ---------------------------------------------------------------------------

type cacheEntry struct {
	result    *EvaluationResult
	expiresAt time.Time
}

// ---------------------------------------------------------------------------
// Policy Engine
// ---------------------------------------------------------------------------

// PolicyEngine evaluates requests against registered policy rule sets.
// It maintains an ordered set of PolicySets, evaluates them by priority,
// and produces auditable decisions.
type PolicyEngine struct {
	mu       sync.RWMutex
	config   EngineConfig
	policies map[string]*PolicySet
	cache    map[string]*cacheEntry
	records  []AuditEntry
}

// AuditEntry records a single policy evaluation for audit purposes.
type AuditEntry struct {
	RequestID   string            `json:"request_id"`
	Actor       string            `json:"actor"`
	Action      string            `json:"action"`
	Resource    string            `json:"resource"`
	Decision    string            `json:"decision"`
	MatchedRules []string         `json:"matched_rules"`
	Timestamp   time.Time         `json:"timestamp"`
	Hash        string            `json:"hash"`
	Context     map[string]string `json:"context,omitempty"`
}

// NewPolicyEngine creates a new PolicyEngine with the given configuration.
func NewPolicyEngine(config EngineConfig) *PolicyEngine {
	if config.MaxRulesPerPolicy == 0 {
		config.MaxRulesPerPolicy = 1000
	}
	if config.CacheTimeout == 0 {
		config.CacheTimeout = 5 * time.Minute
	}
	return &PolicyEngine{
		config:   config,
		policies: make(map[string]*PolicySet),
		cache:    make(map[string]*cacheEntry),
	}
}

// RegisterPolicySet adds a PolicySet to the engine. Returns an error if the
// set exceeds the configured MaxRulesPerPolicy limit.
func (e *PolicyEngine) RegisterPolicySet(ps *PolicySet) error {
	if ps == nil {
		return fmt.Errorf("PolicyEngine.RegisterPolicySet: %w: policy set cannot be nil", ErrInvalidInput)
	}
	if ps.ID == "" {
		return fmt.Errorf("PolicyEngine.RegisterPolicySet: %w: policy set ID cannot be empty", ErrInvalidInput)
	}
	if len(ps.Rules) > e.config.MaxRulesPerPolicy {
		return fmt.Errorf("PolicyEngine.RegisterPolicySet: %w: policy set %q has %d rules, exceeds maximum of %d",
			ErrInvalidInput, ps.ID, len(ps.Rules), e.config.MaxRulesPerPolicy)
	}

	// Validate rule ID uniqueness within the policy set.
	ruleIDs := make(map[string]bool, len(ps.Rules))
	for _, rule := range ps.Rules {
		if ruleIDs[rule.ID()] {
			return fmt.Errorf("PolicyEngine.RegisterPolicySet: %w: rule ID %q in policy set %q", ErrDuplicateRuleID, rule.ID(), ps.ID)
		}
		ruleIDs[rule.ID()] = true
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[ps.ID] = ps
	return nil
}

// UnregisterPolicySet removes a PolicySet by ID.
func (e *PolicyEngine) UnregisterPolicySet(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.policies, id)
}

// GetPolicySet returns a PolicySet by ID, or nil if not found.
func (e *PolicyEngine) GetPolicySet(id string) *PolicySet {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policies[id]
}

// ListPolicySets returns all registered PolicySets sorted by priority (descending).
func (e *PolicyEngine) ListPolicySets() []*PolicySet {
	e.mu.RLock()
	defer e.mu.RUnlock()

	sets := make([]*PolicySet, 0, len(e.policies))
	for _, ps := range e.policies {
		sets = append(sets, ps)
	}
	sort.Slice(sets, func(i, j int) bool {
		return sets[i].Priority > sets[j].Priority
	})
	return sets
}

// Evaluate evaluates a request against all applicable, enabled policy sets.
// Policy sets are evaluated in priority order (highest first). The first
// explicit Deny wins; otherwise the most restrictive decision is returned.
func (e *PolicyEngine) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResult, error) {
	if req == nil {
		return nil, fmt.Errorf("PolicyEngine.Evaluate: %w: evaluation request cannot be nil", ErrInvalidInput)
	}
	if req.Actor == "" {
		return nil, fmt.Errorf("PolicyEngine.Evaluate: %w: actor is required", ErrInvalidInput)
	}
	if req.Action == "" {
		return nil, fmt.Errorf("PolicyEngine.Evaluate: %w: action is required", ErrInvalidInput)
	}

	// Check cache.
	cacheKey := e.computeCacheKey(req)
	if cached := e.getCached(cacheKey); cached != nil {
		return cached, nil
	}

	requestID := uuid.New().String()
	now := time.Now().UTC()

	e.mu.RLock()
	// Collect and sort enabled policies by priority (descending).
	sortedPolicies := make([]*PolicySet, 0, len(e.policies))
	for _, ps := range e.policies {
		if ps.Enabled && e.policyApplies(ps, req) {
			sortedPolicies = append(sortedPolicies, ps)
		}
	}
	e.mu.RUnlock()

	sort.Slice(sortedPolicies, func(i, j int) bool {
		return sortedPolicies[i].Priority > sortedPolicies[j].Priority
	})

	// Evaluate rules across all applicable policies.
	finalDecision := e.config.DefaultMode
	var matchedRules []string
	var approvals []ApprovalRequirement
	var conditions []string
	explicitAllow := false

	for _, ps := range sortedPolicies {
		for _, rule := range ps.Rules {
			result := rule.Evaluate(req)
			if result == nil {
				continue
			}

			matchedRules = append(matchedRules, result.RuleID)

			switch result.Decision {
			case Deny:
				// Deny always wins immediately.
				evalResult := &EvaluationResult{
					Decision:     Deny,
					MatchedRules: append(matchedRules, result.RuleID),
					AuditTrail:   "", // Set below.
					EvaluatedAt:  now,
					RequestID:    requestID,
				}
				evalResult.AuditTrail = e.computeAuditHash(evalResult)
				e.recordEvaluation(req, evalResult)
				e.putCached(cacheKey, evalResult)
				return evalResult, nil

			case Allow:
				explicitAllow = true

			case RequireApproval, RequireDualControl, RequireCommittee, Escalate:
				// Take the most restrictive approval requirement.
				if result.Decision > finalDecision {
					finalDecision = result.Decision
				}
				if result.Approval != nil {
					approvals = append(approvals, *result.Approval)
				}
				if result.Condition != "" {
					conditions = append(conditions, result.Condition)
				}
			}
		}
	}

	if explicitAllow && finalDecision == e.config.DefaultMode && len(approvals) == 0 {
		finalDecision = Allow
	}

	evalResult := &EvaluationResult{
		Decision:          finalDecision,
		MatchedRules:      matchedRules,
		RequiredApprovals: approvals,
		Conditions:        conditions,
		EvaluatedAt:       now,
		RequestID:         requestID,
	}
	evalResult.AuditTrail = e.computeAuditHash(evalResult)

	e.recordEvaluation(req, evalResult)
	e.putCached(cacheKey, evalResult)

	return evalResult, nil
}

// GetAuditLog returns all recorded evaluation audit entries.
func (e *PolicyEngine) GetAuditLog() []AuditEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]AuditEntry, len(e.records))
	copy(out, e.records)
	return out
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// policyApplies checks whether a PolicySet's scope covers the request.
func (e *PolicyEngine) policyApplies(ps *PolicySet, req *EvaluationRequest) bool {
	if ps.Scope == nil {
		return true // No scope restriction means universal applicability.
	}

	if len(ps.Scope.Actions) > 0 && !containsString(ps.Scope.Actions, req.Action) {
		return false
	}
	if len(ps.Scope.Resources) > 0 && !containsString(ps.Scope.Resources, req.Resource) {
		return false
	}
	if len(ps.Scope.Actors) > 0 && !containsString(ps.Scope.Actors, req.Actor) {
		return false
	}
	if len(ps.Scope.Sectors) > 0 {
		sector := req.Context["sector"]
		if sector == "" || !containsString(ps.Scope.Sectors, sector) {
			return false
		}
	}
	return true
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func (e *PolicyEngine) computeCacheKey(req *EvaluationRequest) string {
	h := sha256.New()
	h.Write([]byte(req.Actor))
	h.Write([]byte(req.Action))
	h.Write([]byte(req.Resource))

	// Include sorted context keys.
	if len(req.Context) > 0 {
		keys := make([]string, 0, len(req.Context))
		for k := range req.Context {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k))
			h.Write([]byte(req.Context[k]))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (e *PolicyEngine) getCached(key string) *EvaluationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	entry, ok := e.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.result
}

func (e *PolicyEngine) putCached(key string, result *EvaluationResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cache[key] = &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(e.config.CacheTimeout),
	}
}

func (e *PolicyEngine) computeAuditHash(result *EvaluationResult) string {
	data, _ := json.Marshal(struct {
		Decision    string   `json:"decision"`
		Rules       []string `json:"rules"`
		EvaluatedAt string   `json:"evaluated_at"`
		RequestID   string   `json:"request_id"`
	}{
		Decision:    result.Decision.String(),
		Rules:       result.MatchedRules,
		EvaluatedAt: result.EvaluatedAt.Format(time.RFC3339Nano),
		RequestID:   result.RequestID,
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func (e *PolicyEngine) recordEvaluation(req *EvaluationRequest, result *EvaluationResult) {
	if !e.config.AuditAllEvaluations && result.Decision == Allow {
		return
	}

	entry := AuditEntry{
		RequestID:    result.RequestID,
		Actor:        req.Actor,
		Action:       req.Action,
		Resource:     req.Resource,
		Decision:     result.Decision.String(),
		MatchedRules: result.MatchedRules,
		Timestamp:    result.EvaluatedAt,
		Hash:         result.AuditTrail,
		Context:      req.Context,
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.records = append(e.records, entry)
}
