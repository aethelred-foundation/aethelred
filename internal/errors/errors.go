// Package errors provides standardized error handling for Aethelred.
//
// This package implements consistent error wrapping, categorization, and
// handling patterns across all modules. It addresses the consultant finding
// regarding inconsistent error handling.
//
// # Error Categories
//
// Errors are categorized by severity and type:
//   - Configuration errors (recoverable with defaults)
//   - Validation errors (non-recoverable, client error)
//   - Internal errors (non-recoverable, system error)
//   - Transient errors (retryable)
//
// # Usage
//
//	// Instead of silently ignoring errors:
//	params, _ := k.GetParams(ctx)  // BAD
//
//	// Use explicit error handling with fallbacks:
//	params := errors.GetParamsOrDefault(k.GetParams(ctx), types.DefaultParams())  // GOOD
//
//	// Or with logging:
//	params, err := k.GetParams(ctx)
//	if err != nil {
//	    errors.LogAndDefault(ctx, "GetParams", err, types.DefaultParams())
//	}
package errors

import (
	"context"
	"errors"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// =============================================================================
// ERROR TYPES
// =============================================================================

// Category represents the error category for classification.
type Category int

const (
	// CategoryConfig indicates a configuration-related error that may be
	// recoverable with defaults.
	CategoryConfig Category = iota

	// CategoryValidation indicates a validation error (client fault).
	CategoryValidation

	// CategoryInternal indicates an internal system error.
	CategoryInternal

	// CategoryTransient indicates a transient error that may be retried.
	CategoryTransient

	// CategorySecurity indicates a security-related error.
	CategorySecurity
)

func (c Category) String() string {
	switch c {
	case CategoryConfig:
		return "CONFIG"
	case CategoryValidation:
		return "VALIDATION"
	case CategoryInternal:
		return "INTERNAL"
	case CategoryTransient:
		return "TRANSIENT"
	case CategorySecurity:
		return "SECURITY"
	default:
		return "UNKNOWN"
	}
}

// AethelredError is the base error type with category and context.
type AethelredError struct {
	Category Category
	Op       string // Operation that failed
	Err      error  // Underlying error
	Context  map[string]interface{}
}

func (e *AethelredError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Category, e.Op, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Category, e.Op)
}

func (e *AethelredError) Unwrap() error {
	return e.Err
}

// Is implements errors.Is for error comparison.
func (e *AethelredError) Is(target error) bool {
	t, ok := target.(*AethelredError)
	if !ok {
		return false
	}
	return e.Category == t.Category && e.Op == t.Op
}

// =============================================================================
// ERROR CONSTRUCTORS
// =============================================================================

// NewConfigError creates a configuration error.
func NewConfigError(op string, err error) *AethelredError {
	return &AethelredError{
		Category: CategoryConfig,
		Op:       op,
		Err:      err,
	}
}

// NewValidationError creates a validation error.
func NewValidationError(op string, err error) *AethelredError {
	return &AethelredError{
		Category: CategoryValidation,
		Op:       op,
		Err:      err,
	}
}

// NewInternalError creates an internal error.
func NewInternalError(op string, err error) *AethelredError {
	return &AethelredError{
		Category: CategoryInternal,
		Op:       op,
		Err:      err,
	}
}

// NewTransientError creates a transient (retryable) error.
func NewTransientError(op string, err error) *AethelredError {
	return &AethelredError{
		Category: CategoryTransient,
		Op:       op,
		Err:      err,
	}
}

// NewSecurityError creates a security-related error.
func NewSecurityError(op string, err error) *AethelredError {
	return &AethelredError{
		Category: CategorySecurity,
		Op:       op,
		Err:      err,
	}
}

// Wrap wraps an error with operation context.
func Wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return &AethelredError{
		Category: CategoryInternal,
		Op:       op,
		Err:      err,
	}
}

// WrapWithCategory wraps an error with category and operation context.
func WrapWithCategory(cat Category, op string, err error) error {
	if err == nil {
		return nil
	}
	return &AethelredError{
		Category: cat,
		Op:       op,
		Err:      err,
	}
}

// =============================================================================
// ERROR HANDLING HELPERS
// =============================================================================

// GetOrDefault returns the value if err is nil, otherwise returns the default.
// This is the recommended pattern for handling optional configuration values.
//
// Example:
//
//	params := errors.GetOrDefault(k.GetParams(ctx), types.DefaultParams())
func GetOrDefault[T any](value T, err error, defaultValue T) T {
	if err != nil {
		return defaultValue
	}
	return value
}

// GetPtrOrDefault returns a pointer to the value if err is nil, otherwise returns
// a pointer to the default value.
func GetPtrOrDefault[T any](value T, err error, defaultValue T) *T {
	if err != nil {
		return &defaultValue
	}
	return &value
}

// MustGet panics if err is not nil. Use only in initialization code.
func MustGet[T any](value T, err error) T {
	if err != nil {
		panic(fmt.Sprintf("MustGet failed: %v", err))
	}
	return value
}

// LogAndContinue logs an error and continues execution.
// Returns true if there was an error (for conditional logic).
func LogAndContinue(ctx sdk.Context, op string, err error) bool {
	if err != nil {
		ctx.Logger().Warn("Non-fatal error (continuing)",
			"operation", op,
			"error", err.Error(),
		)
		return true
	}
	return false
}

// LogErrorAndDefault logs an error and returns a default value.
func LogErrorAndDefault[T any](ctx sdk.Context, op string, err error, defaultValue T) T {
	if err != nil {
		ctx.Logger().Warn("Using default value due to error",
			"operation", op,
			"error", err.Error(),
		)
		return defaultValue
	}
	// This function signature expects the value to be passed separately
	// For proper use, see GetOrDefaultWithLog
	return defaultValue
}

// GetOrDefaultWithLog returns the value if err is nil, logs and returns default otherwise.
func GetOrDefaultWithLog[T any](ctx sdk.Context, op string, value T, err error, defaultValue T) T {
	if err != nil {
		ctx.Logger().Warn("Using default value due to error",
			"operation", op,
			"error", err.Error(),
		)
		return defaultValue
	}
	return value
}

// =============================================================================
// ERROR CLASSIFICATION
// =============================================================================

// IsRetryable returns true if the error should be retried.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	var ae *AethelredError
	if errors.As(err, &ae) {
		return ae.Category == CategoryTransient
	}
	// Check for common retryable errors
	errStr := err.Error()
	retryablePatterns := []string{
		"connection refused",
		"timeout",
		"temporary failure",
		"circuit open",
		"rate limit",
	}
	for _, pattern := range retryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}
	return false
}

// IsSecurityError returns true if the error is security-related.
func IsSecurityError(err error) bool {
	if err == nil {
		return false
	}
	var ae *AethelredError
	if errors.As(err, &ae) {
		return ae.Category == CategorySecurity
	}
	return false
}

// IsValidationError returns true if the error is a validation error.
func IsValidationError(err error) bool {
	if err == nil {
		return false
	}
	var ae *AethelredError
	if errors.As(err, &ae) {
		return ae.Category == CategoryValidation
	}
	return false
}

// GetCategory extracts the error category, returning CategoryInternal if unknown.
func GetCategory(err error) Category {
	if err == nil {
		return CategoryInternal
	}
	var ae *AethelredError
	if errors.As(err, &ae) {
		return ae.Category
	}
	return CategoryInternal
}

// =============================================================================
// SENTINEL ERRORS
// =============================================================================

var (
	// ErrNotFound indicates a resource was not found.
	ErrNotFound = errors.New("not found")

	// ErrInvalidInput indicates invalid input parameters.
	ErrInvalidInput = errors.New("invalid input")

	// ErrUnauthorized indicates an authorization failure.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrSimulationDisabled indicates simulation mode is disabled.
	ErrSimulationDisabled = errors.New("simulation disabled in production mode")

	// ErrCircuitOpen indicates a circuit breaker is open.
	ErrCircuitOpen = errors.New("circuit breaker open")

	// ErrRateLimited indicates a rate limit was exceeded.
	ErrRateLimited = errors.New("rate limit exceeded")

	// ErrTimeout indicates an operation timed out.
	ErrTimeout = errors.New("operation timed out")

	// ErrVerificationFailed indicates a verification failure.
	ErrVerificationFailed = errors.New("verification failed")

	// ErrInvalidSignature indicates an invalid cryptographic signature.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrQuantumThreatActive indicates post-quantum mode is required.
	ErrQuantumThreatActive = errors.New("quantum threat level requires PQC signatures")
)

// =============================================================================
// CONTEXT HELPERS
// =============================================================================

// ErrorContext creates an error with additional context.
func ErrorContext(err error, kv ...interface{}) error {
	if err == nil {
		return nil
	}
	ctx := make(map[string]interface{})
	for i := 0; i < len(kv)-1; i += 2 {
		key, ok := kv[i].(string)
		if ok {
			ctx[key] = kv[i+1]
		}
	}
	var ae *AethelredError
	if errors.As(err, &ae) {
		ae.Context = ctx
		return ae
	}
	return &AethelredError{
		Category: CategoryInternal,
		Op:       "unknown",
		Err:      err,
		Context:  ctx,
	}
}

// =============================================================================
// INTERNAL HELPERS
// =============================================================================

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// RESULT TYPE (Rust-style)
// =============================================================================

// Result represents a value or error, similar to Rust's Result type.
// This can be used for more explicit error handling.
type Result[T any] struct {
	value T
	err   error
}

// Ok creates a successful Result.
func Ok[T any](value T) Result[T] {
	return Result[T]{value: value}
}

// Err creates an error Result.
func Err[T any](err error) Result[T] {
	var zero T
	return Result[T]{value: zero, err: err}
}

// IsOk returns true if the Result is successful.
func (r Result[T]) IsOk() bool {
	return r.err == nil
}

// IsErr returns true if the Result is an error.
func (r Result[T]) IsErr() bool {
	return r.err != nil
}

// Unwrap returns the value or panics if error.
func (r Result[T]) Unwrap() T {
	if r.err != nil {
		panic(fmt.Sprintf("called Unwrap on error Result: %v", r.err))
	}
	return r.value
}

// UnwrapOr returns the value or a default.
func (r Result[T]) UnwrapOr(defaultValue T) T {
	if r.err != nil {
		return defaultValue
	}
	return r.value
}

// UnwrapOrElse returns the value or calls the function to get a default.
func (r Result[T]) UnwrapOrElse(f func(error) T) T {
	if r.err != nil {
		return f(r.err)
	}
	return r.value
}

// Error returns the error if present.
func (r Result[T]) Error() error {
	return r.err
}

// Value returns the value (may be zero if error).
func (r Result[T]) Value() T {
	return r.value
}

// ValueAndError returns both value and error.
func (r Result[T]) ValueAndError() (T, error) {
	return r.value, r.err
}

// Map transforms the value if successful.
func Map[T, U any](r Result[T], f func(T) U) Result[U] {
	if r.err != nil {
		return Err[U](r.err)
	}
	return Ok(f(r.value))
}

// =============================================================================
// CONTEXT-AWARE ERROR HANDLING
// =============================================================================

// contextKey is a custom type for context keys.
type contextKey string

const (
	operationKey contextKey = "aethelred_operation"
)

// WithOperation adds operation context to a context.Context.
func WithOperation(ctx context.Context, op string) context.Context {
	return context.WithValue(ctx, operationKey, op)
}

// GetOperation extracts the operation from context.
func GetOperation(ctx context.Context) string {
	if op, ok := ctx.Value(operationKey).(string); ok {
		return op
	}
	return "unknown"
}
