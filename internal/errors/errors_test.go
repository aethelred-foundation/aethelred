package errors

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"cosmossdk.io/log"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// --- Category tests ---

func TestCategory_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		cat  Category
		want string
	}{
		{CategoryConfig, "CONFIG"},
		{CategoryValidation, "VALIDATION"},
		{CategoryInternal, "INTERNAL"},
		{CategoryTransient, "TRANSIENT"},
		{CategorySecurity, "SECURITY"},
		{Category(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.cat.String(); got != tt.want {
				t.Errorf("Category(%d).String() = %q, want %q", tt.cat, got, tt.want)
			}
		})
	}
}

// --- AethelredError tests ---

func TestAethelredError_Error_WithErr(t *testing.T) {
	t.Parallel()
	ae := &AethelredError{
		Category: CategoryInternal,
		Op:       "TestOp",
		Err:      errors.New("underlying"),
	}
	want := "[INTERNAL] TestOp: underlying"
	if got := ae.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestAethelredError_Error_NilErr(t *testing.T) {
	t.Parallel()
	ae := &AethelredError{
		Category: CategoryConfig,
		Op:       "LoadConfig",
	}
	want := "[CONFIG] LoadConfig"
	if got := ae.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestAethelredError_Unwrap(t *testing.T) {
	t.Parallel()
	inner := errors.New("inner")
	ae := &AethelredError{Category: CategoryInternal, Op: "op", Err: inner}
	if got := ae.Unwrap(); got != inner {
		t.Error("Unwrap did not return inner error")
	}
}

func TestAethelredError_Unwrap_Nil(t *testing.T) {
	t.Parallel()
	ae := &AethelredError{Category: CategoryInternal, Op: "op"}
	if got := ae.Unwrap(); got != nil {
		t.Error("Unwrap should return nil for nil Err")
	}
}

func TestAethelredError_Is(t *testing.T) {
	t.Parallel()
	a := &AethelredError{Category: CategoryValidation, Op: "validate"}
	b := &AethelredError{Category: CategoryValidation, Op: "validate"}
	c := &AethelredError{Category: CategoryInternal, Op: "validate"}
	d := &AethelredError{Category: CategoryValidation, Op: "other"}

	if !a.Is(b) {
		t.Error("expected a.Is(b) to be true")
	}
	if a.Is(c) {
		t.Error("expected a.Is(c) to be false (different category)")
	}
	if a.Is(d) {
		t.Error("expected a.Is(d) to be false (different op)")
	}
	if a.Is(errors.New("plain")) {
		t.Error("expected Is to be false for non-AethelredError")
	}
}

// --- Constructor tests ---

func TestNewConfigError(t *testing.T) {
	t.Parallel()
	err := NewConfigError("op", errors.New("e"))
	if err.Category != CategoryConfig || err.Op != "op" {
		t.Errorf("unexpected: %+v", err)
	}
}

func TestNewValidationError(t *testing.T) {
	t.Parallel()
	err := NewValidationError("op", errors.New("e"))
	if err.Category != CategoryValidation {
		t.Errorf("unexpected category: %v", err.Category)
	}
}

func TestNewInternalError(t *testing.T) {
	t.Parallel()
	err := NewInternalError("op", errors.New("e"))
	if err.Category != CategoryInternal {
		t.Errorf("unexpected category: %v", err.Category)
	}
}

func TestNewTransientError(t *testing.T) {
	t.Parallel()
	err := NewTransientError("op", errors.New("e"))
	if err.Category != CategoryTransient {
		t.Errorf("unexpected category: %v", err.Category)
	}
}

func TestNewSecurityError(t *testing.T) {
	t.Parallel()
	err := NewSecurityError("op", errors.New("e"))
	if err.Category != CategorySecurity {
		t.Errorf("unexpected category: %v", err.Category)
	}
}

// --- Wrap / WrapWithCategory tests ---

func TestWrap_Nil(t *testing.T) {
	t.Parallel()
	if got := Wrap("op", nil); got != nil {
		t.Error("Wrap(nil) should return nil")
	}
}

func TestWrap_NonNil(t *testing.T) {
	t.Parallel()
	err := Wrap("op", errors.New("e"))
	ae, ok := err.(*AethelredError)
	if !ok {
		t.Fatal("expected *AethelredError")
	}
	if ae.Category != CategoryInternal || ae.Op != "op" {
		t.Errorf("unexpected: %+v", ae)
	}
}

func TestWrapWithCategory_Nil(t *testing.T) {
	t.Parallel()
	if got := WrapWithCategory(CategorySecurity, "op", nil); got != nil {
		t.Error("expected nil")
	}
}

func TestWrapWithCategory_NonNil(t *testing.T) {
	t.Parallel()
	err := WrapWithCategory(CategoryTransient, "op", errors.New("e"))
	ae, ok := err.(*AethelredError)
	if !ok {
		t.Fatal("expected *AethelredError")
	}
	if ae.Category != CategoryTransient {
		t.Errorf("expected CategoryTransient, got %v", ae.Category)
	}
}

// --- GetOrDefault / GetPtrOrDefault / MustGet tests ---

func TestGetOrDefault(t *testing.T) {
	t.Parallel()
	if got := GetOrDefault(42, nil, 0); got != 42 {
		t.Errorf("expected 42, got %d", got)
	}
	if got := GetOrDefault(0, errors.New("e"), 99); got != 99 {
		t.Errorf("expected 99, got %d", got)
	}
}

func TestGetPtrOrDefault(t *testing.T) {
	t.Parallel()
	p := GetPtrOrDefault(42, nil, 0)
	if *p != 42 {
		t.Errorf("expected *p=42, got %d", *p)
	}
	p = GetPtrOrDefault(0, errors.New("e"), 99)
	if *p != 99 {
		t.Errorf("expected *p=99, got %d", *p)
	}
}

func TestMustGet_Success(t *testing.T) {
	t.Parallel()
	v := MustGet(42, nil)
	if v != 42 {
		t.Errorf("expected 42, got %d", v)
	}
}

func TestMustGet_Panics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	MustGet(0, errors.New("fail"))
}

// --- Classification tests ---

func TestIsRetryable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"transient aethelred error", NewTransientError("op", errors.New("e")), true},
		{"internal aethelred error", NewInternalError("op", errors.New("e")), false},
		{"connection refused", errors.New("connection refused"), true},
		{"timeout", errors.New("request timeout"), true},
		{"temporary failure", errors.New("temporary failure in resolution"), true},
		{"circuit open", errors.New("circuit open"), true},
		{"rate limit", errors.New("rate limit exceeded"), true},
		{"random error", errors.New("something bad"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsRetryable(tt.err); got != tt.want {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSecurityError(t *testing.T) {
	t.Parallel()
	if IsSecurityError(nil) {
		t.Error("expected false for nil")
	}
	if !IsSecurityError(NewSecurityError("op", errors.New("e"))) {
		t.Error("expected true for security error")
	}
	if IsSecurityError(NewInternalError("op", errors.New("e"))) {
		t.Error("expected false for internal error")
	}
	if IsSecurityError(errors.New("plain")) {
		t.Error("expected false for plain error")
	}
}

func TestIsValidationError(t *testing.T) {
	t.Parallel()
	if IsValidationError(nil) {
		t.Error("expected false for nil")
	}
	if !IsValidationError(NewValidationError("op", errors.New("e"))) {
		t.Error("expected true")
	}
	if IsValidationError(errors.New("plain")) {
		t.Error("expected false for plain error")
	}
}

func TestGetCategory(t *testing.T) {
	t.Parallel()
	if GetCategory(nil) != CategoryInternal {
		t.Error("nil should return CategoryInternal")
	}
	if GetCategory(NewSecurityError("op", nil)) != CategorySecurity {
		t.Error("expected CategorySecurity")
	}
	if GetCategory(errors.New("plain")) != CategoryInternal {
		t.Error("plain error should return CategoryInternal")
	}
}

// --- ErrorContext tests ---

func TestErrorContext_Nil(t *testing.T) {
	t.Parallel()
	if ErrorContext(nil, "key", "val") != nil {
		t.Error("expected nil")
	}
}

func TestErrorContext_AethelredError(t *testing.T) {
	t.Parallel()
	ae := NewInternalError("op", errors.New("e"))
	result := ErrorContext(ae, "module", "verify")
	ae2, ok := result.(*AethelredError)
	if !ok {
		t.Fatal("expected *AethelredError")
	}
	if ae2.Context["module"] != "verify" {
		t.Errorf("expected context module=verify, got %v", ae2.Context["module"])
	}
}

func TestErrorContext_PlainError(t *testing.T) {
	t.Parallel()
	result := ErrorContext(errors.New("plain"), "key", "val")
	ae, ok := result.(*AethelredError)
	if !ok {
		t.Fatal("expected *AethelredError")
	}
	if ae.Op != "unknown" {
		t.Errorf("expected op=unknown, got %q", ae.Op)
	}
	if ae.Context["key"] != "val" {
		t.Errorf("expected context key=val, got %v", ae.Context["key"])
	}
}

func TestErrorContext_OddKV(t *testing.T) {
	t.Parallel()
	// Odd number of kv items - the last one should be ignored
	result := ErrorContext(errors.New("e"), "key1", "val1", "key2")
	ae := result.(*AethelredError)
	if ae.Context["key1"] != "val1" {
		t.Error("expected key1=val1")
	}
}

// --- contains / containsHelper ---

func TestContains(t *testing.T) {
	t.Parallel()
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"hello world", "world", true},
		{"hello", "hello", true},
		{"hello", "world", false},
		{"", "", true},
		{"a", "", true},
		{"", "a", false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q in %q", tt.substr, tt.s), func(t *testing.T) {
			t.Parallel()
			if got := contains(tt.s, tt.substr); got != tt.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

// --- Result type tests ---

func TestResult_Ok(t *testing.T) {
	t.Parallel()
	r := Ok(42)
	if !r.IsOk() {
		t.Error("expected IsOk")
	}
	if r.IsErr() {
		t.Error("expected !IsErr")
	}
	if r.Unwrap() != 42 {
		t.Errorf("expected 42, got %v", r.Unwrap())
	}
	if r.Error() != nil {
		t.Error("expected nil error")
	}
	if r.Value() != 42 {
		t.Errorf("expected Value()=42")
	}
	v, err := r.ValueAndError()
	if v != 42 || err != nil {
		t.Errorf("unexpected ValueAndError: %v, %v", v, err)
	}
}

func TestResult_Err(t *testing.T) {
	t.Parallel()
	r := Err[int](errors.New("boom"))
	if r.IsOk() {
		t.Error("expected !IsOk")
	}
	if !r.IsErr() {
		t.Error("expected IsErr")
	}
	if r.Error() == nil {
		t.Error("expected non-nil error")
	}
}

func TestResult_Unwrap_Panics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	r := Err[int](errors.New("boom"))
	r.Unwrap()
}

func TestResult_UnwrapOr(t *testing.T) {
	t.Parallel()
	r := Err[int](errors.New("boom"))
	if got := r.UnwrapOr(99); got != 99 {
		t.Errorf("expected 99, got %d", got)
	}
	r2 := Ok(42)
	if got := r2.UnwrapOr(99); got != 42 {
		t.Errorf("expected 42, got %d", got)
	}
}

func TestResult_UnwrapOrElse(t *testing.T) {
	t.Parallel()
	r := Err[int](errors.New("boom"))
	got := r.UnwrapOrElse(func(err error) int { return 100 })
	if got != 100 {
		t.Errorf("expected 100, got %d", got)
	}
	r2 := Ok(42)
	got2 := r2.UnwrapOrElse(func(err error) int { return 100 })
	if got2 != 42 {
		t.Errorf("expected 42, got %d", got2)
	}
}

func TestMap_Ok(t *testing.T) {
	t.Parallel()
	r := Ok(10)
	mapped := Map(r, func(v int) string { return fmt.Sprintf("%d", v) })
	if !mapped.IsOk() {
		t.Error("expected IsOk")
	}
	if mapped.Unwrap() != "10" {
		t.Errorf("expected '10', got %q", mapped.Unwrap())
	}
}

func TestMap_Err(t *testing.T) {
	t.Parallel()
	r := Err[int](errors.New("fail"))
	mapped := Map(r, func(v int) string { return fmt.Sprintf("%d", v) })
	if !mapped.IsErr() {
		t.Error("expected IsErr")
	}
}

// --- Context helpers ---

func TestWithOperation_GetOperation(t *testing.T) {
	t.Parallel()
	ctx := WithOperation(context.Background(), "test_op")
	if got := GetOperation(ctx); got != "test_op" {
		t.Errorf("expected 'test_op', got %q", got)
	}
}

func TestGetOperation_Missing(t *testing.T) {
	t.Parallel()
	if got := GetOperation(context.Background()); got != "unknown" {
		t.Errorf("expected 'unknown', got %q", got)
	}
}

// --- ErrorContext edge cases ---

func TestErrorContext_NonStringKey(t *testing.T) {
	t.Parallel()
	// When a key is not a string, it should be skipped
	result := ErrorContext(errors.New("e"), 123, "val", "key2", "val2")
	ae := result.(*AethelredError)
	if ae.Context["key2"] != "val2" {
		t.Error("expected key2=val2")
	}
	// 123 is not a string key, so it should not appear
	if len(ae.Context) != 1 {
		t.Errorf("expected 1 context entry (non-string key skipped), got %d", len(ae.Context))
	}
}

func TestErrorContext_EmptyKV(t *testing.T) {
	t.Parallel()
	result := ErrorContext(errors.New("e"))
	ae := result.(*AethelredError)
	if len(ae.Context) != 0 {
		t.Error("expected empty context with no kv pairs")
	}
}

// --- GetCategory edge cases ---

func TestGetCategory_ConfigError(t *testing.T) {
	t.Parallel()
	if GetCategory(NewConfigError("op", nil)) != CategoryConfig {
		t.Error("expected CategoryConfig")
	}
}

func TestGetCategory_TransientError(t *testing.T) {
	t.Parallel()
	if GetCategory(NewTransientError("op", nil)) != CategoryTransient {
		t.Error("expected CategoryTransient")
	}
}

// --- Result additional methods ---

func TestResult_Value_Error(t *testing.T) {
	t.Parallel()
	r := Err[string](errors.New("fail"))
	if r.Value() != "" {
		t.Error("expected zero value for error result")
	}
	v, err := r.ValueAndError()
	if v != "" {
		t.Error("expected zero value")
	}
	if err == nil {
		t.Error("expected error")
	}
}

// --- IsRetryable with wrapped errors ---

func TestIsRetryable_WrappedTransient(t *testing.T) {
	t.Parallel()
	inner := NewTransientError("op", errors.New("e"))
	wrapped := fmt.Errorf("wrapper: %w", inner)
	if !IsRetryable(wrapped) {
		t.Error("wrapped transient error should be retryable")
	}
}

// --- contains edge cases ---

func TestContainsHelper_NoMatch(t *testing.T) {
	t.Parallel()
	if contains("abc", "xyz") {
		t.Error("expected false")
	}
}

func TestContainsHelper_SubstringAtEnd(t *testing.T) {
	t.Parallel()
	if !contains("hello world", "world") {
		t.Error("expected true for substring at end")
	}
}

func TestContainsHelper_SubstringAtStart(t *testing.T) {
	t.Parallel()
	if !contains("hello world", "hello") {
		t.Error("expected true for substring at start")
	}
}

// --- SDK Context-dependent tests ---

func newTestContext() sdk.Context {
	return sdk.NewContext(nil, cmtproto.Header{}, false, log.NewNopLogger())
}

func TestLogAndContinue_WithError(t *testing.T) {
	t.Parallel()
	ctx := newTestContext()
	hadError := LogAndContinue(ctx, "test-op", errors.New("some error"))
	if !hadError {
		t.Error("expected true when error is non-nil")
	}
}

func TestLogAndContinue_NilError(t *testing.T) {
	t.Parallel()
	ctx := newTestContext()
	hadError := LogAndContinue(ctx, "test-op", nil)
	if hadError {
		t.Error("expected false when error is nil")
	}
}

func TestLogErrorAndDefault_WithError(t *testing.T) {
	t.Parallel()
	ctx := newTestContext()
	result := LogErrorAndDefault(ctx, "test-op", errors.New("fail"), 42)
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestLogErrorAndDefault_NilError(t *testing.T) {
	t.Parallel()
	ctx := newTestContext()
	result := LogErrorAndDefault(ctx, "test-op", nil, 42)
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestGetOrDefaultWithLog_WithError(t *testing.T) {
	t.Parallel()
	ctx := newTestContext()
	result := GetOrDefaultWithLog(ctx, "test-op", 10, errors.New("fail"), 99)
	if result != 99 {
		t.Errorf("expected 99, got %d", result)
	}
}

func TestGetOrDefaultWithLog_NilError(t *testing.T) {
	t.Parallel()
	ctx := newTestContext()
	result := GetOrDefaultWithLog(ctx, "test-op", 10, nil, 99)
	if result != 10 {
		t.Errorf("expected 10, got %d", result)
	}
}

// --- Sentinel errors ---

func TestSentinelErrors(t *testing.T) {
	t.Parallel()
	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrNotFound", ErrNotFound},
		{"ErrInvalidInput", ErrInvalidInput},
		{"ErrUnauthorized", ErrUnauthorized},
		{"ErrSimulationDisabled", ErrSimulationDisabled},
		{"ErrCircuitOpen", ErrCircuitOpen},
		{"ErrRateLimited", ErrRateLimited},
		{"ErrTimeout", ErrTimeout},
		{"ErrVerificationFailed", ErrVerificationFailed},
		{"ErrInvalidSignature", ErrInvalidSignature},
		{"ErrQuantumThreatActive", ErrQuantumThreatActive},
	}
	for _, s := range sentinels {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			if s.err == nil {
				t.Errorf("%s is nil", s.name)
			}
			if s.err.Error() == "" {
				t.Errorf("%s has empty message", s.name)
			}
		})
	}
}
