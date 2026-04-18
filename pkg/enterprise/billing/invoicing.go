package billing

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Invoice status
// ---------------------------------------------------------------------------

// InvoiceStatus tracks the lifecycle of an invoice.
type InvoiceStatus string

const (
	InvoiceDraft   InvoiceStatus = "draft"
	InvoicePending InvoiceStatus = "pending"
	InvoiceSent    InvoiceStatus = "sent"
	InvoicePaid    InvoiceStatus = "paid"
	InvoiceOverdue InvoiceStatus = "overdue"
	InvoiceVoided  InvoiceStatus = "voided"
)

// ---------------------------------------------------------------------------
// Billing period
// ---------------------------------------------------------------------------

// BillingPeriod defines the invoicing frequency.
type BillingPeriod int

const (
	// Monthly bills every calendar month.
	Monthly BillingPeriod = iota

	// Quarterly bills every three calendar months.
	Quarterly

	// Annual bills once per year.
	Annual
)

// String returns the human-readable label.
func (p BillingPeriod) String() string {
	switch p {
	case Monthly:
		return "Monthly"
	case Quarterly:
		return "Quarterly"
	case Annual:
		return "Annual"
	default:
		return "Unknown"
	}
}

// Duration returns the approximate duration of the billing period.
func (p BillingPeriod) Duration() time.Duration {
	switch p {
	case Monthly:
		return 30 * 24 * time.Hour
	case Quarterly:
		return 90 * 24 * time.Hour
	case Annual:
		return 365 * 24 * time.Hour
	default:
		return 30 * 24 * time.Hour
	}
}

// ---------------------------------------------------------------------------
// Line item category
// ---------------------------------------------------------------------------

// LineItemCategory classifies invoice line items.
type LineItemCategory string

const (
	CategoryReservedCapacity LineItemCategory = "reserved_capacity"
	CategoryOverage          LineItemCategory = "overage"
	CategoryCompute          LineItemCategory = "compute"
	CategoryStorage          LineItemCategory = "storage"
	CategoryNetwork          LineItemCategory = "network"
	CategorySealCreation     LineItemCategory = "seal_creation"
	CategoryVerification     LineItemCategory = "verification"
	CategoryAuditQuery       LineItemCategory = "audit_query"
	CategorySupport          LineItemCategory = "support"
	CategoryDiscount         LineItemCategory = "discount"
)

// ---------------------------------------------------------------------------
// Invoice types
// ---------------------------------------------------------------------------

// LineItem represents a single charge on an invoice.
type LineItem struct {
	// Description is a human-readable description of the charge.
	Description string `json:"description"`

	// Quantity is the number of units charged.
	Quantity float64 `json:"quantity"`

	// UnitPrice is the price per unit.
	UnitPrice float64 `json:"unit_price"`

	// Amount is the total charge (Quantity * UnitPrice).
	Amount float64 `json:"amount"`

	// Category classifies this line item.
	Category LineItemCategory `json:"category"`

	// Metadata holds additional key-value data.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Invoice represents an enterprise invoice for platform usage and services.
type Invoice struct {
	// ID uniquely identifies this invoice.
	ID string `json:"id"`

	// CustomerID identifies the billed customer.
	CustomerID string `json:"customer_id"`

	// Period identifies the billing period this invoice covers.
	Period time.Time `json:"period"`

	// PeriodType indicates the billing period frequency.
	PeriodType BillingPeriod `json:"period_type"`

	// LineItems contains all charges on this invoice.
	LineItems []LineItem `json:"line_items"`

	// Subtotal is the sum of all line item amounts before tax.
	Subtotal float64 `json:"subtotal"`

	// TaxRate is the applicable tax rate (0-100).
	TaxRate float64 `json:"tax_rate"`

	// Tax is the calculated tax amount.
	Tax float64 `json:"tax"`

	// Total is the final amount due (Subtotal + Tax).
	Total float64 `json:"total"`

	// Currency is the fiat currency code (e.g., "USD", "EUR").
	Currency string `json:"currency"`

	// Status is the current invoice status.
	Status InvoiceStatus `json:"status"`

	// DueDate is when payment is expected.
	DueDate time.Time `json:"due_date"`

	// CreatedAt is when the invoice was created.
	CreatedAt time.Time `json:"created_at"`

	// SentAt is when the invoice was sent (zero if not yet sent).
	SentAt time.Time `json:"sent_at,omitempty"`

	// PaidAt is when payment was received (zero if not yet paid).
	PaidAt time.Time `json:"paid_at,omitempty"`

	// PaidAmount is the amount actually paid.
	PaidAmount float64 `json:"paid_amount"`
}

// Payment records a payment against an invoice.
type Payment struct {
	// Amount is the payment amount.
	Amount float64 `json:"amount"`

	// Currency is the payment currency.
	Currency string `json:"currency"`

	// Method describes the payment method (e.g., "wire", "ach", "token").
	Method string `json:"method"`

	// Reference is the payment reference (transaction ID, check number, etc.).
	Reference string `json:"reference"`

	// PaidAt is when the payment was made.
	PaidAt time.Time `json:"paid_at"`
}

// ---------------------------------------------------------------------------
// Invoice manager
// ---------------------------------------------------------------------------

// InvoiceManager handles enterprise invoice generation, tracking, and
// payment recording.
type InvoiceManager struct {
	mu       sync.RWMutex
	invoices map[string]*Invoice

	// defaultTaxRate is the default tax rate applied to new invoices.
	defaultTaxRate float64

	// defaultPaymentTermsDays is the number of days after invoice creation
	// that payment is due.
	defaultPaymentTermsDays int

	// reservations provides access to reservation data for invoice generation.
	reservations *ReservationManager

	// metering provides access to usage data for invoice generation.
	metering *MeteringService
}

// NewInvoiceManager creates a new invoice manager.
func NewInvoiceManager(taxRate float64, paymentTermsDays int, reservations *ReservationManager, metering *MeteringService) *InvoiceManager {
	return &InvoiceManager{
		invoices:                make(map[string]*Invoice),
		defaultTaxRate:          taxRate,
		defaultPaymentTermsDays: paymentTermsDays,
		reservations:            reservations,
		metering:                metering,
	}
}

// GenerateInvoice creates an invoice for a customer covering the specified
// billing period. It aggregates charges from reservations and usage metering.
func (m *InvoiceManager) GenerateInvoice(_ context.Context, customerID string, period BillingPeriod) (*Invoice, error) {
	if customerID == "" {
		return nil, fmt.Errorf("InvoiceManager.GenerateInvoice: %w: customer ID is empty", ErrInvalidInvoice)
	}

	now := time.Now().UTC()

	invoice := &Invoice{
		ID:         fmt.Sprintf("inv-%s-%d", customerID, now.UnixNano()),
		CustomerID: customerID,
		Period:     now,
		PeriodType: period,
		Currency:   "USD",
		Status:     InvoiceDraft,
		TaxRate:    m.defaultTaxRate,
		DueDate:    now.AddDate(0, 0, m.defaultPaymentTermsDays),
		CreatedAt:  now,
	}

	// Add reservation charges
	if m.reservations != nil {
		reservations := m.reservations.ListReservations(customerID)
		for _, res := range reservations {
			if res.Status != ReservationActive {
				continue
			}

			// Calculate monthly charge
			monthlyCharge := float64(res.ComputeUnits) * res.PricePerUnit
			invoice.LineItems = append(invoice.LineItems, LineItem{
				Description: fmt.Sprintf("Reserved capacity: %s tier, %d units", res.Tier.String(), res.ComputeUnits),
				Quantity:    float64(res.ComputeUnits),
				UnitPrice:   res.PricePerUnit,
				Amount:      monthlyCharge,
				Category:    CategoryReservedCapacity,
				Metadata: map[string]string{
					"reservation_id": res.ID,
					"tier":           res.Tier.String(),
				},
			})

			// Add overage if applicable
			if res.UsedUnits > res.ComputeUnits {
				overage := res.UsedUnits - res.ComputeUnits
				overageCost := float64(overage) * res.Terms.OverageRate
				invoice.LineItems = append(invoice.LineItems, LineItem{
					Description: fmt.Sprintf("Overage: %d units above reservation", overage),
					Quantity:    float64(overage),
					UnitPrice:   res.Terms.OverageRate,
					Amount:      overageCost,
					Category:    CategoryOverage,
					Metadata: map[string]string{
						"reservation_id": res.ID,
					},
				})
			}

			invoice.Currency = res.Currency
		}
	}

	// Calculate totals
	var subtotal float64
	for _, item := range invoice.LineItems {
		subtotal += item.Amount
	}

	invoice.Subtotal = subtotal
	invoice.Tax = subtotal * (m.defaultTaxRate / 100.0)
	invoice.Total = invoice.Subtotal + invoice.Tax

	m.mu.Lock()
	m.invoices[invoice.ID] = invoice
	m.mu.Unlock()

	return invoice, nil
}

// SendInvoice marks an invoice as sent.
func (m *InvoiceManager) SendInvoice(_ context.Context, invoiceID string) error {
	if invoiceID == "" {
		return fmt.Errorf("invoice ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	inv, ok := m.invoices[invoiceID]
	if !ok {
		return fmt.Errorf("invoice not found: %s", invoiceID)
	}

	if inv.Status != InvoiceDraft && inv.Status != InvoicePending {
		return fmt.Errorf("can only send draft or pending invoices, current status: %s", inv.Status)
	}

	inv.Status = InvoiceSent
	inv.SentAt = time.Now().UTC()

	return nil
}

// RecordPayment records a payment against an invoice.
func (m *InvoiceManager) RecordPayment(_ context.Context, invoiceID string, payment Payment) error {
	if invoiceID == "" {
		return fmt.Errorf("invoice ID is required")
	}
	if payment.Amount <= 0 {
		return fmt.Errorf("payment amount must be positive")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	inv, ok := m.invoices[invoiceID]
	if !ok {
		return fmt.Errorf("invoice not found: %s", invoiceID)
	}

	if inv.Status == InvoiceVoided {
		return fmt.Errorf("cannot record payment for voided invoice")
	}

	inv.PaidAmount += payment.Amount
	inv.PaidAt = payment.PaidAt

	if inv.PaidAmount >= inv.Total {
		inv.Status = InvoicePaid
	}

	return nil
}

// VoidInvoice marks an invoice as voided.
func (m *InvoiceManager) VoidInvoice(_ context.Context, invoiceID string) error {
	if invoiceID == "" {
		return fmt.Errorf("invoice ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	inv, ok := m.invoices[invoiceID]
	if !ok {
		return fmt.Errorf("invoice not found: %s", invoiceID)
	}

	if inv.Status == InvoicePaid {
		return fmt.Errorf("cannot void a paid invoice")
	}

	inv.Status = InvoiceVoided
	return nil
}

// GetInvoice retrieves an invoice by ID.
func (m *InvoiceManager) GetInvoice(invoiceID string) (*Invoice, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	inv, ok := m.invoices[invoiceID]
	if !ok {
		return nil, fmt.Errorf("invoice not found: %s", invoiceID)
	}
	return inv, nil
}

// ListInvoices returns all invoices for a customer.
func (m *InvoiceManager) ListInvoices(customerID string) []*Invoice {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Invoice
	for _, inv := range m.invoices {
		if inv.CustomerID == customerID {
			result = append(result, inv)
		}
	}
	return result
}
