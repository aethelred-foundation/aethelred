package assurance

import "errors"

// Sentinel errors for the assurance package. Callers can use errors.Is for
// stable classification across provider and verification paths.
var (
	ErrInvalidInput        = errors.New("invalid input")
	ErrJobNotFound         = errors.New("job not found")
	ErrProviderUnavailable = errors.New("provider unavailable")
	ErrEvidenceIncomplete  = errors.New("evidence incomplete")
	ErrVerificationFailed  = errors.New("verification failed")
	ErrExportFailed        = errors.New("export failed")
	ErrMonitoringFailed    = errors.New("monitoring failed")
)
