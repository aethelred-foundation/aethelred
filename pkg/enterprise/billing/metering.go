package billing

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Resource types
// ---------------------------------------------------------------------------

// ResourceType identifies the category of metered resource.
type ResourceType string

const (
	ResourceComputeUnit   ResourceType = "compute_unit"
	ResourceStorageByte   ResourceType = "storage_byte"
	ResourceNetworkXfer   ResourceType = "network_transfer"
	ResourceSealCreation  ResourceType = "seal_creation"
	ResourceVerification  ResourceType = "verification"
	ResourceAuditQuery    ResourceType = "audit_query"
)

// UnitName returns the human-readable measurement unit for the resource type.
func (r ResourceType) UnitName() string {
	switch r {
	case ResourceComputeUnit:
		return "compute-units"
	case ResourceStorageByte:
		return "bytes"
	case ResourceNetworkXfer:
		return "bytes"
	case ResourceSealCreation:
		return "seals"
	case ResourceVerification:
		return "verifications"
	case ResourceAuditQuery:
		return "queries"
	default:
		return "units"
	}
}

// ---------------------------------------------------------------------------
// Usage record
// ---------------------------------------------------------------------------

// UsageRecord represents a single metered usage event.
type UsageRecord struct {
	// ID is the unique identifier for this record (used for idempotent dedup).
	ID string `json:"id"`

	// CustomerID identifies the customer.
	CustomerID string `json:"customer_id"`

	// ResourceType categorizes the resource consumed.
	ResourceType ResourceType `json:"resource_type"`

	// Quantity is the amount consumed.
	Quantity float64 `json:"quantity"`

	// Unit is the measurement unit (e.g., "compute-units", "bytes").
	Unit string `json:"unit"`

	// Timestamp is when the usage occurred.
	Timestamp time.Time `json:"timestamp"`

	// Metadata holds usage-specific key-value data (e.g., region, job ID).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Validate checks the usage record for required fields.
func (r *UsageRecord) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("UsageRecord.Validate: %w: ID is empty", ErrInvalidReservation)
	}
	if r.CustomerID == "" {
		return fmt.Errorf("UsageRecord.Validate: %w: customer ID is empty", ErrInvalidReservation)
	}
	if r.ResourceType == "" {
		return fmt.Errorf("UsageRecord.Validate: %w: resource type is empty", ErrInvalidReservation)
	}
	if r.Quantity <= 0 {
		return fmt.Errorf("UsageRecord.Validate: %w: quantity must be positive, got %f", ErrNegativeAmount, r.Quantity)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Usage summary
// ---------------------------------------------------------------------------

// ResourceUsage shows aggregated usage for a single resource type.
type ResourceUsage struct {
	// ResourceType is the resource category.
	ResourceType ResourceType `json:"resource_type"`

	// TotalQuantity is the total consumed.
	TotalQuantity float64 `json:"total_quantity"`

	// Unit is the measurement unit.
	Unit string `json:"unit"`

	// RecordCount is the number of individual usage events.
	RecordCount int `json:"record_count"`

	// EstimatedCost is the estimated fiat cost for this usage.
	EstimatedCost float64 `json:"estimated_cost"`
}

// UsageSummary aggregates usage data for a customer over a period.
type UsageSummary struct {
	// CustomerID identifies the customer.
	CustomerID string `json:"customer_id"`

	// Period is the summary period.
	Period BillingPeriod `json:"period"`

	// PeriodStart is when the period began.
	PeriodStart time.Time `json:"period_start"`

	// PeriodEnd is when the period ends.
	PeriodEnd time.Time `json:"period_end"`

	// ByResource breaks down usage by resource type.
	ByResource []ResourceUsage `json:"by_resource"`

	// TotalCost is the estimated total fiat cost for all usage.
	TotalCost float64 `json:"total_cost"`

	// PeakUsage records the peak concurrent usage during the period.
	PeakUsage float64 `json:"peak_usage"`

	// TotalRecords is the total number of usage records in the period.
	TotalRecords int `json:"total_records"`
}

// ---------------------------------------------------------------------------
// Metering service
// ---------------------------------------------------------------------------

// MeteringService records and aggregates usage events with idempotent
// deduplication by record ID.
type MeteringService struct {
	mu      sync.RWMutex
	records []UsageRecord
	seen    map[string]bool // tracks record IDs for dedup

	// unitPrices maps resource types to their per-unit fiat price.
	unitPrices map[ResourceType]float64
}

// NewMeteringService creates a new metering service with default unit prices.
func NewMeteringService() *MeteringService {
	return &MeteringService{
		records: make([]UsageRecord, 0),
		seen:    make(map[string]bool),
		unitPrices: map[ResourceType]float64{
			ResourceComputeUnit:  0.10,    // $0.10 per compute unit
			ResourceStorageByte:  0.000001, // $0.000001 per byte (~$1/GB)
			ResourceNetworkXfer:  0.000002, // $0.000002 per byte (~$2/GB)
			ResourceSealCreation: 0.05,    // $0.05 per seal
			ResourceVerification: 0.01,    // $0.01 per verification
			ResourceAuditQuery:   0.02,    // $0.02 per audit query
		},
	}
}

// SetUnitPrice configures the per-unit price for a resource type.
func (ms *MeteringService) SetUnitPrice(resourceType ResourceType, price float64) error {
	if price < 0 {
		return fmt.Errorf("MeteringService.SetUnitPrice: %w: price must be >= 0, got %f", ErrNegativeAmount, price)
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.unitPrices[resourceType] = price
	return nil
}

// RecordUsage records a usage event. It is idempotent: duplicate records
// (same ID) are silently ignored.
func (ms *MeteringService) RecordUsage(_ context.Context, record UsageRecord) error {
	if err := record.Validate(); err != nil {
		return fmt.Errorf("MeteringService.RecordUsage: %w", err)
	}

	// Set unit if not specified.
	if record.Unit == "" {
		record.Unit = record.ResourceType.UnitName()
	}

	// Set timestamp if not specified.
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now().UTC()
	}

	// TOCTOU fix: hold lock through dedup check AND record insertion.
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Dedup by record ID -- return sentinel error on duplicate.
	if ms.seen[record.ID] {
		return fmt.Errorf("MeteringService.RecordUsage: %w: record %s", ErrDuplicateUsage, record.ID)
	}

	ms.seen[record.ID] = true
	ms.records = append(ms.records, record)

	return nil
}

// GetUsageSummary produces an aggregated usage summary for a customer
// over the specified billing period.
func (ms *MeteringService) GetUsageSummary(_ context.Context, customerID string, period BillingPeriod) (*UsageSummary, error) {
	if customerID == "" {
		return nil, fmt.Errorf("MeteringService.GetUsageSummary: %w: customer ID is empty", ErrInvalidInvoice)
	}

	ms.mu.RLock()
	defer ms.mu.RUnlock()

	now := time.Now().UTC()
	periodStart := now.Add(-period.Duration())

	summary := &UsageSummary{
		CustomerID:  customerID,
		Period:      period,
		PeriodStart: periodStart,
		PeriodEnd:   now,
	}

	// Aggregate by resource type
	resourceMap := make(map[ResourceType]*ResourceUsage)

	var peakUsage float64

	for _, record := range ms.records {
		if record.CustomerID != customerID {
			continue
		}
		if record.Timestamp.Before(periodStart) {
			continue
		}

		summary.TotalRecords++

		ru, ok := resourceMap[record.ResourceType]
		if !ok {
			ru = &ResourceUsage{
				ResourceType: record.ResourceType,
				Unit:         record.Unit,
			}
			resourceMap[record.ResourceType] = ru
		}

		ru.TotalQuantity += record.Quantity
		ru.RecordCount++

		// Track peak for compute units
		if record.ResourceType == ResourceComputeUnit && record.Quantity > peakUsage {
			peakUsage = record.Quantity
		}
	}

	// Calculate costs and build result
	var totalCost float64
	for _, ru := range resourceMap {
		price, ok := ms.unitPrices[ru.ResourceType]
		if ok {
			ru.EstimatedCost = ru.TotalQuantity * price
		}
		totalCost += ru.EstimatedCost
		summary.ByResource = append(summary.ByResource, *ru)
	}

	summary.TotalCost = totalCost
	summary.PeakUsage = peakUsage

	return summary, nil
}

// GetRecords returns all usage records for a customer within the time range.
func (ms *MeteringService) GetRecords(customerID string, start, end time.Time) []UsageRecord {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	var result []UsageRecord
	for _, record := range ms.records {
		if record.CustomerID != customerID {
			continue
		}
		if !start.IsZero() && record.Timestamp.Before(start) {
			continue
		}
		if !end.IsZero() && record.Timestamp.After(end) {
			continue
		}
		result = append(result, record)
	}
	return result
}
