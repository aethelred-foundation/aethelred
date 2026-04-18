package sdk

import "errors"

// Sentinel errors for the seal SDK package. Use errors.Is() to check.
var (
	// ErrInvalidInput indicates that a function received an invalid argument.
	ErrInvalidInput = errors.New("invalid input")

	// ErrSealNotFound indicates that the requested seal does not exist.
	ErrSealNotFound = errors.New("seal not found")

	// ErrSealRevoked indicates that the seal has been revoked.
	ErrSealRevoked = errors.New("seal revoked")

	// ErrVerificationFailed indicates that seal verification did not pass.
	ErrVerificationFailed = errors.New("verification failed")

	// ErrInvalidAttestation indicates that a TEE attestation is malformed or untrusted.
	ErrInvalidAttestation = errors.New("invalid attestation")

	// ErrInvalidProof indicates that a zkML proof is malformed or uses an untrusted system.
	ErrInvalidProof = errors.New("invalid proof")

	// ErrExportFailed indicates that an export operation could not be completed.
	ErrExportFailed = errors.New("export failed")

	// ErrBatchFailed indicates that a batch operation encountered errors.
	ErrBatchFailed = errors.New("batch failed")

	// ErrC2PAConversionFailed indicates that C2PA manifest conversion failed.
	ErrC2PAConversionFailed = errors.New("c2pa conversion failed")
)
