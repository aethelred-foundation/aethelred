package finance

import "errors"

// Sentinel errors for the finance integration package.
var (
	// ErrSanctionsMatch indicates a sanctions screening match was found.
	ErrSanctionsMatch = errors.New("finance: sanctions match")

	// ErrDualApprovalRequired indicates dual approval is needed.
	ErrDualApprovalRequired = errors.New("finance: dual approval required")

	// ErrPolicyDenied indicates a treasury release was denied by policy.
	ErrPolicyDenied = errors.New("finance: policy denied")

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

	// ErrReleaseRejected indicates the treasury release workflow was rejected.
	ErrReleaseRejected = errors.New("finance: treasury release rejected")

	// ErrReleaseNotFound indicates the requested treasury release workflow does not exist.
	ErrReleaseNotFound = errors.New("finance: treasury release not found")

	// ErrSettlementDenied indicates the policy-bound settlement rail denied the transfer.
	ErrSettlementDenied = errors.New("finance: settlement denied")

	// ErrSettlementRailUnavailable indicates no settlement rail is configured.
	ErrSettlementRailUnavailable = errors.New("finance: settlement rail unavailable")

	// ErrSettlementProviderUnavailable indicates the configured external settlement
	// provider or corridor is not operational.
	ErrSettlementProviderUnavailable = errors.New("finance: settlement provider unavailable")

	// ErrSettlementJurisdictionDenied indicates the requested jurisdiction is not
	// allowed for the settlement corridor.
	ErrSettlementJurisdictionDenied = errors.New("finance: settlement jurisdiction denied")

	// ErrSettlementCurrencyDenied indicates the requested settlement currency is
	// not permitted for the configured corridor.
	ErrSettlementCurrencyDenied = errors.New("finance: settlement currency denied")

	// ErrSettlementAmountExceeded indicates the amount exceeds the allowed
	// settlement corridor ceiling.
	ErrSettlementAmountExceeded = errors.New("finance: settlement amount exceeded")

	// ErrSettlementReasonRequired indicates the corridor requires an explicit
	// approved reason code before settlement may proceed.
	ErrSettlementReasonRequired = errors.New("finance: settlement reason required")
)
