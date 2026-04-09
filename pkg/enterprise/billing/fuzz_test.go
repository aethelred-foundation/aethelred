package billing

import (
	"math"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// FuzzAmountConversion
// ---------------------------------------------------------------------------

// FuzzAmountConversion fuzzes the dollar-to-cents-to-dollar round-trip
// conversion to verify precision and correctness.
//
// Invariants:
//   - NewAmountFromDollars(x).Dollars() approximately equals x (within rounding).
//   - NewAmountFromCents(c).Cents() exactly equals c.
//   - Addition is commutative: a.Add(b) == b.Add(a).
//   - No panics regardless of input.
func FuzzAmountConversion(f *testing.F) {
	// Seed corpus: typical, edge, extreme values
	f.Add(1.23, int64(123))
	f.Add(0.0, int64(0))
	f.Add(99.99, int64(9999))
	f.Add(-50.00, int64(-5000))
	f.Add(0.01, int64(1))
	f.Add(0.005, int64(1))   // rounds up
	f.Add(0.004, int64(0))   // rounds down
	f.Add(999999.99, int64(99999999))
	f.Add(-0.01, int64(-1))
	f.Add(1e10, int64(1e12)) // large value

	f.Fuzz(func(t *testing.T, dollars float64, cents int64) {
		// Skip NaN and Inf which break math operations
		if math.IsNaN(dollars) || math.IsInf(dollars, 0) {
			return
		}
		// Skip extremely large values that would overflow int64
		if dollars > 9e15 || dollars < -9e15 {
			return
		}

		// Invariant 1: dollar round-trip preserves value within 0.01
		amt := NewAmountFromDollars(dollars)
		roundTripped := amt.Dollars()
		diff := math.Abs(roundTripped - dollars)
		if diff > 0.01 {
			t.Errorf("round-trip drift too large: %.10f -> %d cents -> %.10f (diff=%.10f)",
				dollars, amt.Cents(), roundTripped, diff)
		}

		// Invariant 2: cents round-trip is exact
		amtFromCents := NewAmountFromCents(cents)
		if amtFromCents.Cents() != cents {
			t.Errorf("cents round-trip: got %d; want %d", amtFromCents.Cents(), cents)
		}

		// Invariant 3: addition is commutative
		a := NewAmountFromDollars(dollars)
		b := NewAmountFromCents(cents)
		if a.Add(b) != b.Add(a) {
			t.Errorf("Add not commutative: %d + %d != %d + %d",
				a.Cents(), b.Cents(), b.Cents(), a.Cents())
		}

		// Invariant 4: subtraction is inverse of addition
		sum := a.Add(b)
		if sum.Sub(b) != a {
			t.Errorf("Sub not inverse of Add: (%d + %d) - %d != %d",
				a.Cents(), b.Cents(), b.Cents(), a.Cents())
		}

		// Invariant 5: IsNegative is consistent
		if amt.Cents() < 0 && !amt.IsNegative() {
			t.Error("negative amount should report IsNegative=true")
		}
		if amt.Cents() >= 0 && amt.IsNegative() {
			t.Error("non-negative amount should report IsNegative=false")
		}

		// Invariant 6: IsZero is consistent
		if amt.Cents() == 0 && !amt.IsZero() {
			t.Error("zero amount should report IsZero=true")
		}
		if amt.Cents() != 0 && amt.IsZero() {
			t.Error("non-zero amount should report IsZero=false")
		}

		// Invariant 7: Mul by 1 is identity
		if amt.Mul(1) != amt {
			t.Error("Mul(1) should be identity")
		}

		// Invariant 8: Mul by 0 is zero
		if amt.Mul(0) != 0 {
			t.Error("Mul(0) should be zero")
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzUsageRecordValidation
// ---------------------------------------------------------------------------

// FuzzUsageRecordValidation fuzzes usage record fields to verify that
// validation correctly rejects invalid records.
//
// Invariants:
//   - Negative quantity is rejected.
//   - Zero quantity is rejected.
//   - Empty ID is rejected.
//   - Empty customer ID is rejected.
//   - Empty resource type is rejected.
//   - Valid records pass validation.
//   - No panics regardless of input.
func FuzzUsageRecordValidation(f *testing.F) {
	f.Add("rec-001", "cust-001", "compute_unit", 10.5)
	f.Add("", "", "", 0.0)
	f.Add("rec-002", "cust-002", "storage_byte", -1.0)
	f.Add("rec-003", "cust-003", "seal_creation", 0.001)
	f.Add("rec-004", "cust-004", "verification", 1e18)
	f.Add("\x00\xff", "\t\n", "\x80", -999.999)

	f.Fuzz(func(t *testing.T, id, customerID, resourceType string, quantity float64) {
		// Skip NaN and Inf
		if math.IsNaN(quantity) || math.IsInf(quantity, 0) {
			return
		}

		record := &UsageRecord{
			ID:           id,
			CustomerID:   customerID,
			ResourceType: ResourceType(resourceType),
			Quantity:     quantity,
			Unit:         "units",
			Timestamp:    time.Now().UTC(),
		}

		err := record.Validate()

		// Invariant 1: empty ID is rejected
		if id == "" {
			if err == nil {
				t.Error("empty ID must be rejected")
			}
			return
		}

		// Invariant 2: empty customer ID is rejected
		if customerID == "" {
			if err == nil {
				t.Error("empty customer ID must be rejected")
			}
			return
		}

		// Invariant 3: empty resource type is rejected
		if resourceType == "" {
			if err == nil {
				t.Error("empty resource type must be rejected")
			}
			return
		}

		// Invariant 4: non-positive quantity is rejected
		if quantity <= 0 {
			if err == nil {
				t.Errorf("non-positive quantity %f must be rejected", quantity)
			}
			return
		}

		// Invariant 5: valid record passes
		if err != nil {
			t.Errorf("valid record should pass validation: %v", err)
		}
	})
}
