package finance

import "errors"

// Sentinel errors for the finance integration package.
var (
	// ErrSanctionsMatch indicates a sanctions screening match was found.
	ErrSanctionsMatch = errors.New("finance: sanctions match")

	// ErrDualApprovalRequired indicates dual approval is needed.
	ErrDualApprovalRequired = errors.New("finance: dual approval required")

	// ErrSelfApproval indicates an attempt at self-approval.
	ErrSelfApproval = errors.New("finance: self-approval not permitted")

	// ErrExceptionDenied indicates a compliance exception was denied.
	ErrExceptionDenied = errors.New("finance: exception denied")

	// ErrAuditChainBroken indicates the audit event chain integrity is broken.
	ErrAuditChainBroken = errors.New("finance: audit chain broken")

	// ErrReportFailed indicates a regulatory report generation failed.
	ErrReportFailed = errors.New("finance: report generation failed")

	// ErrInsufficientApproval indicates insufficient approval for the operation.
	ErrInsufficientApproval = errors.New("finance: insufficient approval")
)
