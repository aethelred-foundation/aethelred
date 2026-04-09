package billing

import "errors"

// Sentinel errors for the billing package.
var (
	// ErrInvalidReservation indicates an invalid capacity reservation.
	ErrInvalidReservation = errors.New("billing: invalid reservation")

	// ErrInvalidInvoice indicates an invalid invoice.
	ErrInvalidInvoice = errors.New("billing: invalid invoice")

	// ErrBudgetExceeded indicates a budget threshold was exceeded.
	ErrBudgetExceeded = errors.New("billing: budget exceeded")

	// ErrDuplicateUsage indicates a duplicate usage record was submitted.
	ErrDuplicateUsage = errors.New("billing: duplicate usage")

	// ErrSettlementFailed indicates a settlement operation failed.
	ErrSettlementFailed = errors.New("billing: settlement failed")

	// ErrReconciliationFailed indicates a reconciliation operation failed.
	ErrReconciliationFailed = errors.New("billing: reconciliation failed")

	// ErrNegativeAmount indicates a monetary amount is negative.
	ErrNegativeAmount = errors.New("billing: negative amount")
)
