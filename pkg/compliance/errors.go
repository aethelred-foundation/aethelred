package compliance

import "errors"

// Sentinel errors for the compliance package. Use errors.Is() to check.
var (
	// ErrInvalidInput indicates that a function received an invalid argument.
	ErrInvalidInput = errors.New("invalid input")

	// ErrFrameworkNotFound indicates that the requested framework does not exist.
	ErrFrameworkNotFound = errors.New("framework not found")

	// ErrControlNotFound indicates that the requested control does not exist.
	ErrControlNotFound = errors.New("control not found")

	// ErrMappingNotFound indicates that no mapping exists for the given criteria.
	ErrMappingNotFound = errors.New("mapping not found")

	// ErrAssessmentFailed indicates that a compliance assessment could not be completed.
	ErrAssessmentFailed = errors.New("assessment failed")

	// ErrExportFailed indicates that an export operation could not be completed.
	ErrExportFailed = errors.New("export failed")

	// ErrInvalidCoverageLevel indicates an unrecognized coverage level string.
	ErrInvalidCoverageLevel = errors.New("invalid coverage level")
)
