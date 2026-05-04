package billing

import "math"

// Amount represents a monetary value in integer cents (1/100 of the base
// currency unit). Using int64 cents eliminates floating-point rounding errors
// that are unacceptable in financial calculations.
//
// Examples:
//
//	NewAmountFromDollars(1.23) => Amount(123)
//	Amount(4999).Dollars()     => 49.99
//	Amount(4999).Cents()       => 4999
type Amount int64

// NewAmountFromDollars converts a dollar amount to cents, rounding to the
// nearest cent to avoid floating-point drift.
func NewAmountFromDollars(d float64) Amount {
	return Amount(math.Round(d * 100))
}

// NewAmountFromCents creates an Amount from a cent value.
func NewAmountFromCents(c int64) Amount {
	return Amount(c)
}

// Dollars returns the amount as a floating-point dollar value.
func (a Amount) Dollars() float64 {
	return float64(a) / 100.0
}

// Cents returns the raw cent value.
func (a Amount) Cents() int64 {
	return int64(a)
}

// Add returns the sum of two amounts.
func (a Amount) Add(b Amount) Amount {
	return a + b
}

// Sub returns the difference of two amounts.
func (a Amount) Sub(b Amount) Amount {
	return a - b
}

// Mul returns the amount multiplied by a quantity.
func (a Amount) Mul(qty int64) Amount {
	return Amount(int64(a) * qty)
}

// MulFloat returns the amount multiplied by a floating-point factor,
// rounding to the nearest cent.
func (a Amount) MulFloat(factor float64) Amount {
	return Amount(math.Round(float64(a) * factor))
}

// IsNegative returns true if the amount is negative.
func (a Amount) IsNegative() bool {
	return a < 0
}

// IsZero returns true if the amount is zero.
func (a Amount) IsZero() bool {
	return a == 0
}
