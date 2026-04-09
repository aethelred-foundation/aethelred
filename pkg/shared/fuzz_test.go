package shared

import (
	"errors"
	"testing"
	"time"
)

func FuzzValidateNonEmpty(f *testing.F) {
	f.Add("field_name", "value")
	f.Add("field_name", "")
	f.Add("", "value")
	f.Add("", "")
	f.Add("x", "y")
	f.Add("field", "  ")

	f.Fuzz(func(t *testing.T, field, value string) {
		err := ValidateNonEmpty(field, value)
		if value == "" && err == nil {
			t.Errorf("expected error for empty value with field=%q", field)
		}
		if value != "" && err != nil {
			t.Errorf("unexpected error for non-empty value: %v", err)
		}
		// Must not panic.
	})
}

func FuzzRetry(f *testing.F) {
	f.Add(1, true)
	f.Add(3, false)
	f.Add(5, true)
	f.Add(0, false)
	f.Add(10, true)

	f.Fuzz(func(t *testing.T, attempts int, succeed bool) {
		// Cap attempts to avoid long-running fuzz iterations.
		if attempts > 10 {
			attempts = 10
		}

		callCount := 0
		fn := func() error {
			callCount++
			if succeed {
				return nil
			}
			return errors.New("fuzz error")
		}

		err := Retry(attempts, 1*time.Microsecond, fn)

		if attempts <= 0 {
			// Invalid attempts should return error.
			if err == nil {
				t.Error("expected error for non-positive attempts")
			}
			return
		}

		if succeed && err != nil {
			t.Errorf("expected success but got error: %v", err)
		}
		if !succeed && err == nil {
			t.Error("expected error but got nil")
		}
		// Must not panic.
	})
}
