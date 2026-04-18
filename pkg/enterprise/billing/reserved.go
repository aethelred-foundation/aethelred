// Package billing provides enterprise economics primitives for the Aethelred
// platform, including reserved capacity management, invoicing, spend controls,
// usage metering, and settlement with AETHEL token economics.
//
// The billing system supports fiat-denominated pricing with token settlement,
// enabling enterprises to commit capacity, track usage, and reconcile
// payments across both traditional and on-chain payment rails.
package billing

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Reservation tiers
// ---------------------------------------------------------------------------

// ReservationTier classifies the service level for reserved capacity.
type ReservationTier int

const (
	// Standard is the base tier with shared infrastructure.
	Standard ReservationTier = iota

	// Premium adds priority scheduling and enhanced SLAs.
	Premium

	// Enterprise adds dedicated support and custom SLAs.
	Enterprise

	// Dedicated provides fully isolated infrastructure.
	Dedicated
)

// String returns the human-readable label for a ReservationTier.
func (t ReservationTier) String() string {
	switch t {
	case Standard:
		return "Standard"
	case Premium:
		return "Premium"
	case Enterprise:
		return "Enterprise"
	case Dedicated:
		return "Dedicated"
	default:
		return "Unknown"
	}
}

// Multiplier returns the pricing multiplier for this tier relative to
// the base rate.
func (t ReservationTier) Multiplier() float64 {
	switch t {
	case Standard:
		return 1.0
	case Premium:
		return 1.5
	case Enterprise:
		return 2.0
	case Dedicated:
		return 3.0
	default:
		return 1.0
	}
}

// ---------------------------------------------------------------------------
// Reservation status
// ---------------------------------------------------------------------------

// ReservationStatus tracks the lifecycle of a reserved capacity commitment.
type ReservationStatus string

const (
	ReservationActive    ReservationStatus = "active"
	ReservationPending   ReservationStatus = "pending"
	ReservationExpired   ReservationStatus = "expired"
	ReservationCancelled ReservationStatus = "cancelled"
	ReservationSuspended ReservationStatus = "suspended"
)

// ---------------------------------------------------------------------------
// Reserved capacity
// ---------------------------------------------------------------------------

// ReservedCapacity represents a customer's committed capacity reservation
// on the Aethelred network.
type ReservedCapacity struct {
	// ID uniquely identifies this reservation.
	ID string `json:"id"`

	// CustomerID identifies the customer who owns this reservation.
	CustomerID string `json:"customer_id"`

	// Tier is the service level for this reservation.
	Tier ReservationTier `json:"tier"`

	// ComputeUnits is the number of reserved compute units.
	ComputeUnits int64 `json:"compute_units"`

	// Duration is the commitment period.
	Duration time.Duration `json:"duration"`

	// StartDate is when the reservation begins.
	StartDate time.Time `json:"start_date"`

	// EndDate is when the reservation expires.
	EndDate time.Time `json:"end_date"`

	// PricePerUnit is the fiat price per compute unit per month.
	PricePerUnit float64 `json:"price_per_unit"`

	// Currency is the fiat currency for pricing (e.g., "USD", "EUR", "GBP").
	Currency string `json:"currency"`

	// Status is the current reservation status.
	Status ReservationStatus `json:"status"`

	// Terms holds the contractual terms for this reservation.
	Terms ReservationTerms `json:"terms"`

	// CreatedAt is when the reservation was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the reservation was last modified.
	UpdatedAt time.Time `json:"updated_at"`

	// UsedUnits tracks cumulative usage against this reservation.
	UsedUnits int64 `json:"used_units"`
}

// ReservationTerms defines the contractual terms for a capacity reservation.
type ReservationTerms struct {
	// CommitmentPeriod is the minimum commitment duration.
	CommitmentPeriod time.Duration `json:"commitment_period"`

	// CancellationFee is the percentage fee for early cancellation (0-100).
	CancellationFee float64 `json:"cancellation_fee"`

	// OverageRate is the per-unit rate for usage exceeding the reservation.
	OverageRate float64 `json:"overage_rate"`

	// AutoRenewal enables automatic renewal at the end of the term.
	AutoRenewal bool `json:"auto_renewal"`

	// DiscountPercent is the discount applied for the commitment (0-100).
	DiscountPercent float64 `json:"discount_percent"`
}

// UtilizationReport shows usage relative to reserved capacity.
type UtilizationReport struct {
	// ReservationID identifies the reservation.
	ReservationID string `json:"reservation_id"`

	// Reserved is the total reserved compute units.
	Reserved int64 `json:"reserved"`

	// Used is the compute units consumed so far.
	Used int64 `json:"used"`

	// UtilizationPercent is (Used / Reserved) * 100.
	UtilizationPercent float64 `json:"utilization_percent"`

	// Overage is usage exceeding the reservation.
	Overage int64 `json:"overage"`

	// OverageCost is the fiat cost for overage usage.
	OverageCost float64 `json:"overage_cost"`

	// Period is the reporting period.
	Period time.Time `json:"period"`
}

// ReservationRequest is the input for creating a new reservation.
type ReservationRequest struct {
	// CustomerID identifies the customer.
	CustomerID string `json:"customer_id"`

	// Tier is the requested service level.
	Tier ReservationTier `json:"tier"`

	// ComputeUnits is the number of compute units to reserve.
	ComputeUnits int64 `json:"compute_units"`

	// Duration is the commitment period.
	Duration time.Duration `json:"duration"`

	// Currency is the fiat currency for pricing.
	Currency string `json:"currency"`

	// AutoRenewal enables automatic renewal.
	AutoRenewal bool `json:"auto_renewal"`
}

// Validate checks the reservation request for required fields.
func (r *ReservationRequest) Validate() error {
	if r.CustomerID == "" {
		return fmt.Errorf("customer ID is required")
	}
	if r.ComputeUnits <= 0 {
		return fmt.Errorf("compute units must be positive")
	}
	if r.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	if r.Currency == "" {
		return fmt.Errorf("currency is required")
	}
	return nil
}

// ReservationChange describes a modification to an existing reservation.
type ReservationChange struct {
	// NewComputeUnits is the updated compute unit count (0 = unchanged).
	NewComputeUnits int64 `json:"new_compute_units,omitempty"`

	// NewTier is the updated tier (nil = unchanged).
	NewTier *ReservationTier `json:"new_tier,omitempty"`

	// ExtendDuration extends the reservation by this amount.
	ExtendDuration time.Duration `json:"extend_duration,omitempty"`
}

// ---------------------------------------------------------------------------
// Reservation manager
// ---------------------------------------------------------------------------

// ReservationManager handles the lifecycle of reserved capacity commitments.
type ReservationManager struct {
	mu           sync.RWMutex
	reservations map[string]*ReservedCapacity

	// basePricePerUnit is the fiat price per compute unit per month (base tier).
	basePricePerUnit float64
}

// NewReservationManager creates a new reservation manager with the given
// base price per compute unit.
func NewReservationManager(basePricePerUnit float64) *ReservationManager {
	return &ReservationManager{
		reservations:     make(map[string]*ReservedCapacity),
		basePricePerUnit: basePricePerUnit,
	}
}

// CreateReservation creates a new reserved capacity commitment.
func (m *ReservationManager) CreateReservation(_ context.Context, request ReservationRequest) (*ReservedCapacity, error) {
	if err := request.Validate(); err != nil {
		return nil, fmt.Errorf("invalid reservation request: %w", err)
	}

	now := time.Now().UTC()

	// Calculate pricing
	pricePerUnit := m.basePricePerUnit * request.Tier.Multiplier()

	// Apply commitment discount (longer commitments get larger discounts)
	discount := calculateCommitmentDiscount(request.Duration)
	effectivePrice := pricePerUnit * (1.0 - discount/100.0)

	// Calculate overage rate (125% of reserved rate)
	overageRate := effectivePrice * 1.25

	reservation := &ReservedCapacity{
		ID:           fmt.Sprintf("res-%s-%d", request.CustomerID, now.UnixNano()),
		CustomerID:   request.CustomerID,
		Tier:         request.Tier,
		ComputeUnits: request.ComputeUnits,
		Duration:     request.Duration,
		StartDate:    now,
		EndDate:      now.Add(request.Duration),
		PricePerUnit: effectivePrice,
		Currency:     request.Currency,
		Status:       ReservationActive,
		Terms: ReservationTerms{
			CommitmentPeriod: request.Duration,
			CancellationFee:  calculateCancellationFee(request.Duration),
			OverageRate:      overageRate,
			AutoRenewal:      request.AutoRenewal,
			DiscountPercent:  discount,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	m.mu.Lock()
	m.reservations[reservation.ID] = reservation
	m.mu.Unlock()

	return reservation, nil
}

// ModifyReservation adjusts an existing reservation.
func (m *ReservationManager) ModifyReservation(_ context.Context, reservationID string, changes ReservationChange) (*ReservedCapacity, error) {
	if reservationID == "" {
		return nil, fmt.Errorf("reservation ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	res, ok := m.reservations[reservationID]
	if !ok {
		return nil, fmt.Errorf("reservation not found: %s", reservationID)
	}

	if res.Status != ReservationActive {
		return nil, fmt.Errorf("can only modify active reservations, current status: %s", res.Status)
	}

	if changes.NewComputeUnits > 0 {
		res.ComputeUnits = changes.NewComputeUnits
	}

	if changes.NewTier != nil {
		res.Tier = *changes.NewTier
		res.PricePerUnit = m.basePricePerUnit * changes.NewTier.Multiplier() *
			(1.0 - res.Terms.DiscountPercent/100.0)
	}

	if changes.ExtendDuration > 0 {
		res.EndDate = res.EndDate.Add(changes.ExtendDuration)
		res.Duration += changes.ExtendDuration
	}

	res.UpdatedAt = time.Now().UTC()
	return res, nil
}

// CancelReservation cancels an active reservation, applying any cancellation
// fees according to the reservation terms.
func (m *ReservationManager) CancelReservation(_ context.Context, reservationID string) (*ReservedCapacity, error) {
	if reservationID == "" {
		return nil, fmt.Errorf("reservation ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	res, ok := m.reservations[reservationID]
	if !ok {
		return nil, fmt.Errorf("reservation not found: %s", reservationID)
	}

	if res.Status == ReservationCancelled {
		return nil, fmt.Errorf("reservation is already cancelled")
	}

	res.Status = ReservationCancelled
	res.UpdatedAt = time.Now().UTC()

	return res, nil
}

// GetUtilization returns the current utilization report for a reservation.
func (m *ReservationManager) GetUtilization(_ context.Context, reservationID string) (*UtilizationReport, error) {
	if reservationID == "" {
		return nil, fmt.Errorf("reservation ID is required")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	res, ok := m.reservations[reservationID]
	if !ok {
		return nil, fmt.Errorf("reservation not found: %s", reservationID)
	}

	var utilizationPct float64
	if res.ComputeUnits > 0 {
		utilizationPct = float64(res.UsedUnits) / float64(res.ComputeUnits) * 100.0
	}

	var overage int64
	if res.UsedUnits > res.ComputeUnits {
		overage = res.UsedUnits - res.ComputeUnits
	}

	return &UtilizationReport{
		ReservationID:      reservationID,
		Reserved:           res.ComputeUnits,
		Used:               res.UsedUnits,
		UtilizationPercent: utilizationPct,
		Overage:            overage,
		OverageCost:        float64(overage) * res.Terms.OverageRate,
		Period:             time.Now().UTC(),
	}, nil
}

// GetReservation retrieves a reservation by ID.
func (m *ReservationManager) GetReservation(reservationID string) (*ReservedCapacity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res, ok := m.reservations[reservationID]
	if !ok {
		return nil, fmt.Errorf("reservation not found: %s", reservationID)
	}
	return res, nil
}

// RecordUsage increments the used units for a reservation.
func (m *ReservationManager) RecordUsage(reservationID string, units int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	res, ok := m.reservations[reservationID]
	if !ok {
		return fmt.Errorf("reservation not found: %s", reservationID)
	}

	if res.Status != ReservationActive {
		return fmt.Errorf("cannot record usage for non-active reservation")
	}

	res.UsedUnits += units
	res.UpdatedAt = time.Now().UTC()
	return nil
}

// ListReservations returns all reservations for a customer.
func (m *ReservationManager) ListReservations(customerID string) []*ReservedCapacity {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*ReservedCapacity
	for _, res := range m.reservations {
		if res.CustomerID == customerID {
			result = append(result, res)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func calculateCommitmentDiscount(duration time.Duration) float64 {
	months := duration.Hours() / (24 * 30)
	switch {
	case months >= 36:
		return 30.0
	case months >= 12:
		return 20.0
	case months >= 6:
		return 10.0
	case months >= 3:
		return 5.0
	default:
		return 0.0
	}
}

func calculateCancellationFee(duration time.Duration) float64 {
	months := duration.Hours() / (24 * 30)
	switch {
	case months >= 36:
		return 50.0
	case months >= 12:
		return 25.0
	case months >= 6:
		return 15.0
	default:
		return 10.0
	}
}
