package av

import "errors"

// Sentinel errors for the autonomous vehicle integration package.
var (
	// ErrInvalidTelemetry indicates telemetry data failed validation.
	ErrInvalidTelemetry = errors.New("av: invalid telemetry")

	// ErrSafetyViolation indicates a safety constraint was violated.
	ErrSafetyViolation = errors.New("av: safety violation")

	// ErrKillSwitchActive indicates the kill switch has been activated.
	ErrKillSwitchActive = errors.New("av: kill switch active")

	// ErrIncidentFailed indicates an incident operation failed.
	ErrIncidentFailed = errors.New("av: incident operation failed")

	// ErrODDViolation indicates an Operational Design Domain violation.
	ErrODDViolation = errors.New("av: ODD violation")

	// ErrNHTSAReportFailed indicates an NHTSA report submission failed.
	ErrNHTSAReportFailed = errors.New("av: NHTSA report failed")
)
