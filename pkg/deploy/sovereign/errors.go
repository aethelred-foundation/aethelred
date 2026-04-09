package sovereign

import "errors"

// Sentinel errors for the sovereign deployment package.
var (
	// ErrInvalidDeployment indicates an invalid deployment specification.
	ErrInvalidDeployment = errors.New("sovereign: invalid deployment")

	// ErrRegionNotAllowed indicates the target region is not permitted.
	ErrRegionNotAllowed = errors.New("sovereign: region not allowed")

	// ErrDataResidencyViolation indicates a data residency constraint violation.
	ErrDataResidencyViolation = errors.New("sovereign: data residency violation")

	// ErrKMSFailed indicates a KMS operation failed.
	ErrKMSFailed = errors.New("sovereign: KMS operation failed")

	// ErrAirGapRequired indicates an air-gap is required but not present.
	ErrAirGapRequired = errors.New("sovereign: air-gap required")

	// ErrComplianceFailed indicates a compliance check failed.
	ErrComplianceFailed = errors.New("sovereign: compliance check failed")

	// ErrMaxDeploymentsReached indicates the maximum deployment count was reached.
	ErrMaxDeploymentsReached = errors.New("sovereign: max deployments reached")
)
