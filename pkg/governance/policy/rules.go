package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Rule interface and evaluation result
// ---------------------------------------------------------------------------

// Rule is the interface that all policy rules implement. A rule inspects an
// EvaluationRequest and either returns a RuleResult (it matched) or nil
// (it did not apply).
type Rule interface {
	// Evaluate inspects the request. Returns nil if the rule does not apply.
	Evaluate(req *EvaluationRequest) *RuleResult

	// ID returns the unique rule identifier.
	ID() string
}

// RuleResult is the outcome of a single rule evaluation.
type RuleResult struct {
	// RuleID is the rule that produced this result.
	RuleID string

	// Decision is the rule's verdict.
	Decision Decision

	// Approval is populated when the decision requires approval.
	Approval *ApprovalRequirement

	// Condition is an optional condition description.
	Condition string
}

// ---------------------------------------------------------------------------
// PolicySet — a named, prioritized collection of rules
// ---------------------------------------------------------------------------

// PolicySet is a named, ordered collection of rules with a priority and scope.
// Higher-priority sets are evaluated first by the engine.
type PolicySet struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Rules       []Rule  `json:"-"`
	Priority    int     `json:"priority"`
	Scope       *Scope  `json:"scope,omitempty"`
	Enabled     bool    `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Scope defines where a PolicySet applies. Empty slices mean "all".
type Scope struct {
	Sectors   []string `json:"sectors,omitempty"`
	Actions   []string `json:"actions,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Actors    []string `json:"actors,omitempty"`
}

// ---------------------------------------------------------------------------
// Condition — comparison primitives used by rules
// ---------------------------------------------------------------------------

// Operator enumerates comparison operators for conditions.
type Operator int

const (
	Equals Operator = iota
	NotEquals
	GreaterThan
	LessThan
	GreaterThanOrEqual
	LessThanOrEqual
	Contains
	In
	NotIn
	Matches
)

// String returns the human-readable label for an Operator.
func (o Operator) String() string {
	switch o {
	case Equals:
		return "=="
	case NotEquals:
		return "!="
	case GreaterThan:
		return ">"
	case LessThan:
		return "<"
	case GreaterThanOrEqual:
		return ">="
	case LessThanOrEqual:
		return "<="
	case Contains:
		return "contains"
	case In:
		return "in"
	case NotIn:
		return "not_in"
	case Matches:
		return "matches"
	default:
		return "unknown"
	}
}

// Condition is a single comparison that can be evaluated against a request.
type Condition struct {
	// Field is the key to look up in the request's Metadata or Context.
	Field string

	// Operator is the comparison to perform.
	Operator Operator

	// Value is the right-hand side of the comparison. For In/NotIn, use comma-separated values.
	Value string
}

// Evaluate checks whether the condition holds for the given request.
func (c *Condition) Evaluate(req *EvaluationRequest) bool {
	actual := c.resolveField(req)

	switch c.Operator {
	case Equals:
		return actual == c.Value
	case NotEquals:
		return actual != c.Value
	case GreaterThan:
		return compareNumeric(actual, c.Value) > 0
	case LessThan:
		return compareNumeric(actual, c.Value) < 0
	case GreaterThanOrEqual:
		return compareNumeric(actual, c.Value) >= 0
	case LessThanOrEqual:
		return compareNumeric(actual, c.Value) <= 0
	case Contains:
		return strings.Contains(actual, c.Value)
	case In:
		values := strings.Split(c.Value, ",")
		for _, v := range values {
			if strings.TrimSpace(v) == actual {
				return true
			}
		}
		return false
	case NotIn:
		values := strings.Split(c.Value, ",")
		for _, v := range values {
			if strings.TrimSpace(v) == actual {
				return false
			}
		}
		return true
	case Matches:
		matched, err := regexp.MatchString(c.Value, actual)
		return err == nil && matched
	default:
		return false
	}
}

func (c *Condition) resolveField(req *EvaluationRequest) string {
	// Check metadata first, then context.
	if req.Metadata != nil {
		if v, ok := req.Metadata[c.Field]; ok {
			return v
		}
	}
	if req.Context != nil {
		if v, ok := req.Context[c.Field]; ok {
			return v
		}
	}
	return ""
}

func compareNumeric(a, b string) int {
	af, aerr := strconv.ParseFloat(a, 64)
	bf, berr := strconv.ParseFloat(b, 64)
	if aerr != nil || berr != nil {
		return strings.Compare(a, b)
	}
	if af > bf {
		return 1
	}
	if af < bf {
		return -1
	}
	return 0
}

// ---------------------------------------------------------------------------
// AllowRule — explicitly allow actions matching conditions
// ---------------------------------------------------------------------------

// AllowRule allows requests that match all of its conditions.
type AllowRule struct {
	RuleID     string
	Name       string
	Conditions []Condition
}

// NewAllowRule creates a new AllowRule with a generated ID.
func NewAllowRule(name string, conditions []Condition) *AllowRule {
	return &AllowRule{
		RuleID:     uuid.New().String(),
		Name:       name,
		Conditions: conditions,
	}
}

func (r *AllowRule) ID() string { return r.RuleID }

func (r *AllowRule) Evaluate(req *EvaluationRequest) *RuleResult {
	if !allConditionsMet(r.Conditions, req) {
		return nil
	}
	return &RuleResult{
		RuleID:   r.RuleID,
		Decision: Allow,
	}
}

// ---------------------------------------------------------------------------
// DenyRule — explicitly deny actions matching conditions
// ---------------------------------------------------------------------------

// DenyRule denies requests that match all of its conditions.
type DenyRule struct {
	RuleID     string
	Name       string
	Reason     string
	Conditions []Condition
}

// NewDenyRule creates a new DenyRule with a generated ID.
func NewDenyRule(name, reason string, conditions []Condition) *DenyRule {
	return &DenyRule{
		RuleID:     uuid.New().String(),
		Name:       name,
		Reason:     reason,
		Conditions: conditions,
	}
}

func (r *DenyRule) ID() string { return r.RuleID }

func (r *DenyRule) Evaluate(req *EvaluationRequest) *RuleResult {
	if !allConditionsMet(r.Conditions, req) {
		return nil
	}
	return &RuleResult{
		RuleID:    r.RuleID,
		Decision:  Deny,
		Condition: fmt.Sprintf("denied: %s", r.Reason),
	}
}

// ---------------------------------------------------------------------------
// ApprovalRule — require approval (single, dual-control, committee)
// ---------------------------------------------------------------------------

// ApprovalRule requires approval when conditions are met.
type ApprovalRule struct {
	RuleID       string
	Name         string
	ApprovalType ApprovalType
	MinApprovers int
	Roles        []string
	Deadline     time.Duration
	Reason       string
	Conditions   []Condition
}

// NewApprovalRule creates a new ApprovalRule with a generated ID.
func NewApprovalRule(name string, approvalType ApprovalType, minApprovers int, roles []string, deadline time.Duration, reason string, conditions []Condition) *ApprovalRule {
	return &ApprovalRule{
		RuleID:       uuid.New().String(),
		Name:         name,
		ApprovalType: approvalType,
		MinApprovers: minApprovers,
		Roles:        roles,
		Deadline:     deadline,
		Reason:       reason,
		Conditions:   conditions,
	}
}

func (r *ApprovalRule) ID() string { return r.RuleID }

func (r *ApprovalRule) Evaluate(req *EvaluationRequest) *RuleResult {
	if !allConditionsMet(r.Conditions, req) {
		return nil
	}

	decision := RequireApproval
	switch r.ApprovalType {
	case DualControl:
		decision = RequireDualControl
	case Committee, Hierarchical:
		decision = RequireCommittee
	}

	return &RuleResult{
		RuleID:   r.RuleID,
		Decision: decision,
		Approval: &ApprovalRequirement{
			Type:     r.ApprovalType,
			MinCount: r.MinApprovers,
			Roles:    r.Roles,
			Deadline: r.Deadline,
			Reason:   r.Reason,
		},
	}
}

// ---------------------------------------------------------------------------
// ThresholdRule — apply based on numeric thresholds
// ---------------------------------------------------------------------------

// ThresholdRule triggers when a numeric field exceeds/falls below a threshold.
type ThresholdRule struct {
	RuleID        string
	Name          string
	Field         string
	Threshold     float64
	AboveDecision Decision
	BelowDecision Decision
	Approval      *ApprovalRequirement
}

// NewThresholdRule creates a new ThresholdRule with a generated ID.
func NewThresholdRule(name, field string, threshold float64, aboveDecision, belowDecision Decision) *ThresholdRule {
	return &ThresholdRule{
		RuleID:        uuid.New().String(),
		Name:          name,
		Field:         field,
		Threshold:     threshold,
		AboveDecision: aboveDecision,
		BelowDecision: belowDecision,
	}
}

func (r *ThresholdRule) ID() string { return r.RuleID }

func (r *ThresholdRule) Evaluate(req *EvaluationRequest) *RuleResult {
	raw := ""
	if req.Metadata != nil {
		raw = req.Metadata[r.Field]
	}
	if raw == "" && req.Context != nil {
		raw = req.Context[r.Field]
	}
	if raw == "" {
		return nil
	}

	val, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return nil
	}

	if val >= r.Threshold {
		result := &RuleResult{
			RuleID:   r.RuleID,
			Decision: r.AboveDecision,
		}
		if r.Approval != nil {
			result.Approval = r.Approval
		}
		return result
	}

	return &RuleResult{
		RuleID:   r.RuleID,
		Decision: r.BelowDecision,
	}
}

// ---------------------------------------------------------------------------
// TimeWindowRule — apply only during certain time windows
// ---------------------------------------------------------------------------

// TimeWindowRule applies its inner decision only during a specified time window.
type TimeWindowRule struct {
	RuleID         string
	Name           string
	StartHour      int // 0-23
	EndHour        int // 0-23
	Weekdays       []time.Weekday
	InsideDecision Decision
	OutsideDecision Decision
	Location       *time.Location
}

// NewTimeWindowRule creates a new TimeWindowRule. If location is nil, UTC is used.
func NewTimeWindowRule(name string, startHour, endHour int, weekdays []time.Weekday, inside, outside Decision, loc *time.Location) *TimeWindowRule {
	if loc == nil {
		loc = time.UTC
	}
	return &TimeWindowRule{
		RuleID:          uuid.New().String(),
		Name:            name,
		StartHour:       startHour,
		EndHour:         endHour,
		Weekdays:        weekdays,
		InsideDecision:  inside,
		OutsideDecision: outside,
		Location:        loc,
	}
}

func (r *TimeWindowRule) ID() string { return r.RuleID }

func (r *TimeWindowRule) Evaluate(req *EvaluationRequest) *RuleResult {
	now := time.Now().In(r.Location)
	hour := now.Hour()
	weekday := now.Weekday()

	inWindow := false
	if r.StartHour <= r.EndHour {
		inWindow = hour >= r.StartHour && hour < r.EndHour
	} else {
		// Wraps midnight (e.g., 22-06).
		inWindow = hour >= r.StartHour || hour < r.EndHour
	}

	if inWindow && len(r.Weekdays) > 0 {
		found := false
		for _, wd := range r.Weekdays {
			if wd == weekday {
				found = true
				break
			}
		}
		inWindow = found
	}

	if inWindow {
		return &RuleResult{
			RuleID:   r.RuleID,
			Decision: r.InsideDecision,
		}
	}
	return &RuleResult{
		RuleID:   r.RuleID,
		Decision: r.OutsideDecision,
	}
}

// ---------------------------------------------------------------------------
// ConditionRule — conditional logic (if X then Y)
// ---------------------------------------------------------------------------

// ConditionRule evaluates a set of conditions and applies a decision if all match,
// or an alternative if they do not.
type ConditionRule struct {
	RuleID       string
	Name         string
	Conditions   []Condition
	MatchResult  Decision
	NoMatchResult Decision
	Approval     *ApprovalRequirement
}

// NewConditionRule creates a new ConditionRule with a generated ID.
func NewConditionRule(name string, conditions []Condition, matchResult, noMatchResult Decision) *ConditionRule {
	return &ConditionRule{
		RuleID:        uuid.New().String(),
		Name:          name,
		Conditions:    conditions,
		MatchResult:   matchResult,
		NoMatchResult: noMatchResult,
	}
}

func (r *ConditionRule) ID() string { return r.RuleID }

func (r *ConditionRule) Evaluate(req *EvaluationRequest) *RuleResult {
	if allConditionsMet(r.Conditions, req) {
		result := &RuleResult{
			RuleID:   r.RuleID,
			Decision: r.MatchResult,
		}
		if r.Approval != nil {
			result.Approval = r.Approval
		}
		return result
	}
	// Only return NoMatchResult if it's not the default (Allow).
	if r.NoMatchResult != Allow {
		return &RuleResult{
			RuleID:   r.RuleID,
			Decision: r.NoMatchResult,
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func allConditionsMet(conditions []Condition, req *EvaluationRequest) bool {
	for _, c := range conditions {
		if !c.Evaluate(req) {
			return false
		}
	}
	return true
}
