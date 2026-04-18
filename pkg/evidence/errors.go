package evidence

import "errors"

// Sentinel errors for the evidence package.
var (
	// ErrInvalidBundle indicates an evidence bundle failed validation.
	ErrInvalidBundle = errors.New("evidence: invalid bundle")

	// ErrBundleNotFinalized indicates the bundle is not yet finalized.
	ErrBundleNotFinalized = errors.New("evidence: bundle not finalized")

	// ErrSignatureInvalid indicates a cryptographic signature check failed.
	ErrSignatureInvalid = errors.New("evidence: invalid signature")

	// ErrChainBroken indicates the evidence chain integrity is broken.
	ErrChainBroken = errors.New("evidence: chain broken")

	// ErrCustodyViolation indicates a chain-of-custody violation.
	ErrCustodyViolation = errors.New("evidence: custody violation")

	// ErrVerificationFailed indicates an evidence verification operation failed.
	ErrVerificationFailed = errors.New("evidence: verification failed")
)
