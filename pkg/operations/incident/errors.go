package incident

import "errors"

// Sentinel errors for the incident management package.
var (
	// ErrIncidentNotFound indicates the requested incident does not exist.
	ErrIncidentNotFound = errors.New("incident: not found")

	// ErrInvalidSeverity indicates an invalid severity level.
	ErrInvalidSeverity = errors.New("incident: invalid severity")

	// ErrKillSwitchFailed indicates a kill switch operation failed.
	ErrKillSwitchFailed = errors.New("incident: kill switch failed")

	// ErrRollbackFailed indicates a rollback operation failed.
	ErrRollbackFailed = errors.New("incident: rollback failed")

	// ErrDisclosureFailed indicates a disclosure operation failed.
	ErrDisclosureFailed = errors.New("incident: disclosure failed")

	// ErrRunbookFailed indicates a runbook execution failed.
	ErrRunbookFailed = errors.New("incident: runbook failed")

	// ErrInvalidTransition indicates an invalid status transition.
	ErrInvalidTransition = errors.New("incident: invalid status transition")
)
