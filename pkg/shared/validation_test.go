package shared

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ValidateNonEmpty
// ---------------------------------------------------------------------------

func TestValidateNonEmpty_Valid(t *testing.T) {
	t.Parallel()
	if err := ValidateNonEmpty("name", "alice"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateNonEmpty_Empty(t *testing.T) {
	t.Parallel()
	err := ValidateNonEmpty("name", "")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
	if !strings.Contains(err.Error(), "name") {
		t.Fatalf("error should mention field name: %v", err)
	}
}

func TestValidateNonEmpty_Whitespace(t *testing.T) {
	t.Parallel()
	// Whitespace is not empty (it is a non-zero-length string).
	if err := ValidateNonEmpty("field", " "); err != nil {
		t.Fatalf("whitespace should pass: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidateHashLength
// ---------------------------------------------------------------------------

func TestValidateHashLength_Valid(t *testing.T) {
	t.Parallel()
	hash := make([]byte, 32)
	if err := ValidateHashLength("model_hash", hash, 32); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateHashLength_TooShort(t *testing.T) {
	t.Parallel()
	hash := make([]byte, 16)
	err := ValidateHashLength("model_hash", hash, 32)
	if err == nil {
		t.Fatal("expected error for short hash")
	}
	if !strings.Contains(err.Error(), "32") {
		t.Fatalf("error should mention expected length: %v", err)
	}
}

func TestValidateHashLength_TooLong(t *testing.T) {
	t.Parallel()
	hash := make([]byte, 64)
	err := ValidateHashLength("output_hash", hash, 32)
	if err == nil {
		t.Fatal("expected error for long hash")
	}
}

func TestValidateHashLength_NilSlice(t *testing.T) {
	t.Parallel()
	err := ValidateHashLength("input_hash", nil, 32)
	if err == nil {
		t.Fatal("expected error for nil hash")
	}
}

func TestValidateHashLength_ZeroLength(t *testing.T) {
	t.Parallel()
	hash := make([]byte, 0)
	if err := ValidateHashLength("empty_hash", hash, 0); err != nil {
		t.Fatalf("zero-length hash with expected=0 should pass: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidatePositive
// ---------------------------------------------------------------------------

func TestValidatePositive_Valid(t *testing.T) {
	t.Parallel()
	if err := ValidatePositive("amount", 42.5); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePositive_Zero(t *testing.T) {
	t.Parallel()
	err := ValidatePositive("amount", 0)
	if err == nil {
		t.Fatal("expected error for zero")
	}
}

func TestValidatePositive_Negative(t *testing.T) {
	t.Parallel()
	err := ValidatePositive("balance", -10.0)
	if err == nil {
		t.Fatal("expected error for negative value")
	}
}

func TestValidatePositive_SmallPositive(t *testing.T) {
	t.Parallel()
	if err := ValidatePositive("epsilon", 0.0001); err != nil {
		t.Fatalf("small positive should pass: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidateNonNegative
// ---------------------------------------------------------------------------

func TestValidateNonNegative_Valid(t *testing.T) {
	t.Parallel()
	if err := ValidateNonNegative("count", 0); err != nil {
		t.Fatalf("zero should pass: %v", err)
	}
	if err := ValidateNonNegative("count", 100); err != nil {
		t.Fatalf("positive should pass: %v", err)
	}
}

func TestValidateNonNegative_Negative(t *testing.T) {
	t.Parallel()
	err := ValidateNonNegative("count", -1)
	if err == nil {
		t.Fatal("expected error for negative value")
	}
}

// ---------------------------------------------------------------------------
// ValidateLatitude
// ---------------------------------------------------------------------------

func TestValidateLatitude_Valid(t *testing.T) {
	t.Parallel()
	cases := []float64{0, 45.0, -45.0, 90.0, -90.0}
	for _, lat := range cases {
		if err := ValidateLatitude("lat", lat); err != nil {
			t.Fatalf("latitude %g should be valid: %v", lat, err)
		}
	}
}

func TestValidateLatitude_Invalid(t *testing.T) {
	t.Parallel()
	cases := []float64{90.1, -90.1, 180.0, -180.0}
	for _, lat := range cases {
		if err := ValidateLatitude("lat", lat); err == nil {
			t.Fatalf("latitude %g should be invalid", lat)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateLongitude
// ---------------------------------------------------------------------------

func TestValidateLongitude_Valid(t *testing.T) {
	t.Parallel()
	cases := []float64{0, 90.0, -90.0, 180.0, -180.0}
	for _, lon := range cases {
		if err := ValidateLongitude("lon", lon); err != nil {
			t.Fatalf("longitude %g should be valid: %v", lon, err)
		}
	}
}

func TestValidateLongitude_Invalid(t *testing.T) {
	t.Parallel()
	cases := []float64{180.1, -180.1, 360.0}
	for _, lon := range cases {
		if err := ValidateLongitude("lon", lon); err == nil {
			t.Fatalf("longitude %g should be invalid", lon)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateTimestamp
// ---------------------------------------------------------------------------

func TestValidateTimestamp_Valid(t *testing.T) {
	t.Parallel()
	if err := ValidateTimestamp("created_at", time.Now()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTimestamp_Zero(t *testing.T) {
	t.Parallel()
	err := ValidateTimestamp("created_at", time.Time{})
	if err == nil {
		t.Fatal("expected error for zero time")
	}
	if !strings.Contains(err.Error(), "created_at") {
		t.Fatalf("error should mention field: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidateMinLength
// ---------------------------------------------------------------------------

func TestValidateMinLength_Valid(t *testing.T) {
	t.Parallel()
	if err := ValidateMinLength("password", "secret123", 8); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMinLength_TooShort(t *testing.T) {
	t.Parallel()
	err := ValidateMinLength("password", "abc", 8)
	if err == nil {
		t.Fatal("expected error for short string")
	}
}

func TestValidateMinLength_ExactLength(t *testing.T) {
	t.Parallel()
	if err := ValidateMinLength("token", "12345678", 8); err != nil {
		t.Fatalf("exact length should pass: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidateMaxLength
// ---------------------------------------------------------------------------

func TestValidateMaxLength_Valid(t *testing.T) {
	t.Parallel()
	if err := ValidateMaxLength("name", "alice", 100); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMaxLength_TooLong(t *testing.T) {
	t.Parallel()
	err := ValidateMaxLength("name", "a very long string that exceeds the maximum", 10)
	if err == nil {
		t.Fatal("expected error for long string")
	}
}

// ---------------------------------------------------------------------------
// ValidateRange
// ---------------------------------------------------------------------------

func TestValidateRange_Valid(t *testing.T) {
	t.Parallel()
	if err := ValidateRange("score", 50, 0, 100); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRange_AtBoundaries(t *testing.T) {
	t.Parallel()
	if err := ValidateRange("score", 0, 0, 100); err != nil {
		t.Fatalf("min boundary should pass: %v", err)
	}
	if err := ValidateRange("score", 100, 0, 100); err != nil {
		t.Fatalf("max boundary should pass: %v", err)
	}
}

func TestValidateRange_OutOfRange(t *testing.T) {
	t.Parallel()
	if err := ValidateRange("score", -1, 0, 100); err == nil {
		t.Fatal("expected error for below-min value")
	}
	if err := ValidateRange("score", 101, 0, 100); err == nil {
		t.Fatal("expected error for above-max value")
	}
}

// ---------------------------------------------------------------------------
// ValidateSliceNotEmpty
// ---------------------------------------------------------------------------

func TestValidateSliceNotEmpty_Valid(t *testing.T) {
	t.Parallel()
	if err := ValidateSliceNotEmpty("items", []string{"a"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSliceNotEmpty_Empty(t *testing.T) {
	t.Parallel()
	err := ValidateSliceNotEmpty("items", []string{})
	if err == nil {
		t.Fatal("expected error for empty slice")
	}
}

func TestValidateSliceNotEmpty_NilSlice(t *testing.T) {
	t.Parallel()
	err := ValidateSliceNotEmpty("items", []int(nil))
	if err == nil {
		t.Fatal("expected error for nil slice")
	}
}

func TestValidateSliceNotEmpty_IntSlice(t *testing.T) {
	t.Parallel()
	if err := ValidateSliceNotEmpty("values", []int{1, 2, 3}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error message quality
// ---------------------------------------------------------------------------

func TestValidationErrors_ContainFieldNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		field string
		check func() error
	}{
		{"NonEmpty", "my_field", func() error { return ValidateNonEmpty("my_field", "") }},
		{"HashLength", "hash_field", func() error { return ValidateHashLength("hash_field", nil, 32) }},
		{"Positive", "amount_field", func() error { return ValidatePositive("amount_field", -1) }},
		{"NonNegative", "count_field", func() error { return ValidateNonNegative("count_field", -1) }},
		{"Latitude", "lat_field", func() error { return ValidateLatitude("lat_field", 200) }},
		{"Longitude", "lon_field", func() error { return ValidateLongitude("lon_field", 200) }},
		{"Timestamp", "ts_field", func() error { return ValidateTimestamp("ts_field", time.Time{}) }},
		{"MinLength", "short_field", func() error { return ValidateMinLength("short_field", "x", 5) }},
		{"MaxLength", "long_field", func() error { return ValidateMaxLength("long_field", "toolong", 3) }},
		{"Range", "range_field", func() error { return ValidateRange("range_field", 200, 0, 100) }},
		{"Slice", "slice_field", func() error { return ValidateSliceNotEmpty("slice_field", []string{}) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.check()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error %q should contain field name %q", err.Error(), tc.field)
			}
		})
	}
}
