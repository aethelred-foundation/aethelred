package audit

import "errors"

// Sentinel errors for the audit package. Use errors.Is() to check.
var (
	// ErrInvalidInput indicates that a function received an invalid argument.
	ErrInvalidInput = errors.New("invalid input")

	// ErrUnauthorized indicates that the caller is not authorized to perform
	// the requested action.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrWriteDisabled indicates that mutating HTTP endpoints are intentionally
	// disabled by runtime policy.
	ErrWriteDisabled = errors.New("write disabled")

	// ErrTrustRegistryNotConfigured indicates that the enterprise trust
	// registry has not been provisioned yet.
	ErrTrustRegistryNotConfigured = errors.New("trust registry not configured")

	// ErrRecordNotFound indicates that the requested audit record does not exist.
	ErrRecordNotFound = errors.New("record not found")

	// ErrChainIntegrityFailed indicates that audit record chain verification failed.
	ErrChainIntegrityFailed = errors.New("chain integrity failed")

	// ErrBundleFailed indicates that an evidence bundle operation failed.
	ErrBundleFailed = errors.New("bundle failed")

	// ErrExportFailed indicates that an export operation could not be completed.
	ErrExportFailed = errors.New("export failed")

	// ErrRetentionViolation indicates that a retention policy constraint was violated.
	ErrRetentionViolation = errors.New("retention violation")

	// ErrCustodyViolation indicates that a chain-of-custody constraint was violated.
	ErrCustodyViolation = errors.New("custody violation")

	// ErrReplayFailed indicates that a computation replay operation failed.
	ErrReplayFailed = errors.New("replay failed")
)
