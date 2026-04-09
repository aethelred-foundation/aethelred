package agent

import "errors"

// Sentinel errors for the protocol agent package. Use errors.Is() to check.
var (
	// ErrInvalidInput indicates that a function received an invalid argument.
	ErrInvalidInput = errors.New("invalid input")

	// ErrAgentNotFound indicates that the requested agent does not exist in the registry.
	ErrAgentNotFound = errors.New("agent not found")

	// ErrIdentityInvalid indicates that an agent identity failed verification.
	ErrIdentityInvalid = errors.New("identity invalid")

	// ErrCredentialExpired indicates that a verifiable credential has expired.
	ErrCredentialExpired = errors.New("credential expired")

	// ErrCredentialRevoked indicates that a verifiable credential has been revoked.
	ErrCredentialRevoked = errors.New("credential revoked")

	// ErrDelegationDepthExceeded indicates that a delegation chain exceeds the maximum depth.
	ErrDelegationDepthExceeded = errors.New("delegation depth exceeded")

	// ErrDelegationRevoked indicates that a delegation has been revoked.
	ErrDelegationRevoked = errors.New("delegation revoked")

	// ErrUnauthorized indicates that an agent action was not authorized.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrNegotiationFailed indicates that a trust negotiation session failed.
	ErrNegotiationFailed = errors.New("negotiation failed")

	// ErrReceiptInvalid indicates that an action receipt failed integrity verification.
	ErrReceiptInvalid = errors.New("receipt invalid")
)
