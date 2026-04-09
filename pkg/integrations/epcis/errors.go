package epcis

import "errors"

// Sentinel errors for the EPCIS integration package.
var (
	// ErrInvalidEvent indicates an EPCIS event failed validation.
	ErrInvalidEvent = errors.New("epcis: invalid event")

	// ErrInvalidEPC indicates an EPC identifier is malformed.
	ErrInvalidEPC = errors.New("epcis: invalid EPC")

	// ErrCaptureFailed indicates an event capture operation failed.
	ErrCaptureFailed = errors.New("epcis: capture failed")

	// ErrSealFailed indicates a Digital Seal operation failed.
	ErrSealFailed = errors.New("epcis: seal operation failed")

	// ErrQueryFailed indicates an EPCIS query operation failed.
	ErrQueryFailed = errors.New("epcis: query failed")

	// ErrRecallFailed indicates a recall workflow operation failed.
	ErrRecallFailed = errors.New("epcis: recall failed")

	// ErrProvenanceFailed indicates a provenance chain operation failed.
	ErrProvenanceFailed = errors.New("epcis: provenance failed")
)
