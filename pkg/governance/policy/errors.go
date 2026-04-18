package policy

import "errors"

// Sentinel errors for the governance policy package. Use errors.Is() to check.
var (
	// ErrInvalidInput indicates that a function received an invalid argument.
	ErrInvalidInput = errors.New("invalid input")

	// ErrPolicyNotFound indicates that the requested policy set does not exist.
	ErrPolicyNotFound = errors.New("policy not found")

	// ErrRuleNotFound indicates that the requested rule does not exist.
	ErrRuleNotFound = errors.New("rule not found")

	// ErrEvaluationFailed indicates that a policy evaluation could not be completed.
	ErrEvaluationFailed = errors.New("evaluation failed")

	// ErrApprovalFailed indicates that an approval workflow operation failed.
	ErrApprovalFailed = errors.New("approval failed")

	// ErrWorkflowExpired indicates that an approval workflow has exceeded its deadline.
	ErrWorkflowExpired = errors.New("workflow expired")

	// ErrBreakGlassActive indicates that a break-glass override is currently active.
	ErrBreakGlassActive = errors.New("break-glass active")

	// ErrExceptionDenied indicates that a policy exception request was denied.
	ErrExceptionDenied = errors.New("exception denied")

	// ErrDuplicateRuleID indicates that a rule ID is already registered.
	ErrDuplicateRuleID = errors.New("duplicate rule ID")
)
