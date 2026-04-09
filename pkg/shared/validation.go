package shared

import (
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Common validation helpers
// ---------------------------------------------------------------------------
//
// These validators are used across multiple Aethelred packages to enforce
// input constraints on API requests, configuration values, and data fields.
// Each function returns a descriptive error including the field name so that
// callers can surface validation failures without additional wrapping.
// ---------------------------------------------------------------------------

// ValidateNonEmpty returns an error if value is the empty string.
func ValidateNonEmpty(field, value string) error {
	if value == "" {
		return fmt.Errorf("validation: %s must not be empty", field)
	}
	return nil
}

// ValidateHashLength validates that hash is exactly expectedLen bytes.
// This is typically used to check SHA-256 hashes (32 bytes) or other
// fixed-length digests.
func ValidateHashLength(field string, hash []byte, expectedLen int) error {
	if len(hash) != expectedLen {
		return fmt.Errorf("validation: %s must be exactly %d bytes, got %d", field, expectedLen, len(hash))
	}
	return nil
}

// ValidatePositive validates that value is strictly greater than zero.
func ValidatePositive(field string, value float64) error {
	if value <= 0 {
		return fmt.Errorf("validation: %s must be positive, got %g", field, value)
	}
	return nil
}

// ValidateNonNegative validates that value is greater than or equal to zero.
func ValidateNonNegative(field string, value float64) error {
	if value < 0 {
		return fmt.Errorf("validation: %s must be non-negative, got %g", field, value)
	}
	return nil
}

// ValidateLatitude validates that lat is between -90 and 90 inclusive.
func ValidateLatitude(field string, lat float64) error {
	if lat < -90 || lat > 90 {
		return fmt.Errorf("validation: %s must be between -90 and 90, got %g", field, lat)
	}
	return nil
}

// ValidateLongitude validates that lon is between -180 and 180 inclusive.
func ValidateLongitude(field string, lon float64) error {
	if lon < -180 || lon > 180 {
		return fmt.Errorf("validation: %s must be between -180 and 180, got %g", field, lon)
	}
	return nil
}

// ValidateTimestamp validates that t is not the zero time.
func ValidateTimestamp(field string, t time.Time) error {
	if t.IsZero() {
		return fmt.Errorf("validation: %s must not be zero time", field)
	}
	return nil
}

// ValidateMinLength validates that s has at least minLen characters.
func ValidateMinLength(field, value string, minLen int) error {
	if len(value) < minLen {
		return fmt.Errorf("validation: %s must be at least %d characters, got %d", field, minLen, len(value))
	}
	return nil
}

// ValidateMaxLength validates that s has at most maxLen characters.
func ValidateMaxLength(field, value string, maxLen int) error {
	if len(value) > maxLen {
		return fmt.Errorf("validation: %s must be at most %d characters, got %d", field, maxLen, len(value))
	}
	return nil
}

// ValidateRange validates that value is between min and max inclusive.
func ValidateRange(field string, value, min, max float64) error {
	if value < min || value > max {
		return fmt.Errorf("validation: %s must be between %g and %g, got %g", field, min, max, value)
	}
	return nil
}

// ValidateSliceNotEmpty validates that a slice has at least one element.
func ValidateSliceNotEmpty[T any](field string, slice []T) error {
	if len(slice) == 0 {
		return fmt.Errorf("validation: %s must not be empty", field)
	}
	return nil
}
