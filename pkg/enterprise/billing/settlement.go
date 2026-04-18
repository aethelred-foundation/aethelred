package billing

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Settlement status
// ---------------------------------------------------------------------------

// SettlementStatus tracks the lifecycle of a settlement.
type SettlementStatus string

const (
	SettlementPending    SettlementStatus = "pending"
	SettlementProcessing SettlementStatus = "processing"
	SettlementSettled    SettlementStatus = "settled"
	SettlementFailed     SettlementStatus = "failed"
	SettlementRefunded   SettlementStatus = "refunded"
)

// ---------------------------------------------------------------------------
// Settlement configuration
// ---------------------------------------------------------------------------

// SettlementConfig defines how invoice settlements are processed,
// including the relationship between fiat pricing and AETHEL token economics.
type SettlementConfig struct {
	// FiatCurrency is the base fiat currency for settlement (e.g., "USD").
	FiatCurrency string `json:"fiat_currency"`

	// TokenDenomination is the token used for on-chain settlement (e.g., "AETHEL").
	TokenDenomination string `json:"token_denomination"`

	// ExchangeRateProvider identifies the exchange rate source.
	ExchangeRateProvider string `json:"exchange_rate_provider"`

	// SettlementPeriod is the cycle for batch settlement processing.
	SettlementPeriod BillingPeriod `json:"settlement_period"`

	// MinSettlementAmount is the minimum fiat amount for settlement.
	MinSettlementAmount float64 `json:"min_settlement_amount"`

	// MaxSlippagePercent is the maximum acceptable exchange rate slippage.
	MaxSlippagePercent float64 `json:"max_slippage_percent"`
}

// Validate checks the settlement configuration.
func (c *SettlementConfig) Validate() error {
	if c.FiatCurrency == "" {
		return fmt.Errorf("fiat currency is required")
	}
	if c.TokenDenomination == "" {
		return fmt.Errorf("token denomination is required")
	}
	if c.MaxSlippagePercent <= 0 {
		return fmt.Errorf("max slippage percent must be positive")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Settlement types
// ---------------------------------------------------------------------------

// Settlement represents a single invoice settlement, recording the
// conversion from fiat to token value.
type Settlement struct {
	// ID uniquely identifies this settlement.
	ID string `json:"id"`

	// InvoiceID links to the settled invoice.
	InvoiceID string `json:"invoice_id"`

	// CustomerID identifies the customer.
	CustomerID string `json:"customer_id"`

	// FiatAmount is the fiat value being settled.
	FiatAmount float64 `json:"fiat_amount"`

	// FiatCurrency is the fiat currency code.
	FiatCurrency string `json:"fiat_currency"`

	// TokenAmount is the equivalent amount in AETHEL tokens.
	TokenAmount float64 `json:"token_amount"`

	// TokenDenomination is the token denomination.
	TokenDenomination string `json:"token_denomination"`

	// ExchangeRate is the fiat-to-token rate used for conversion.
	ExchangeRate float64 `json:"exchange_rate"`

	// Status is the current settlement status.
	Status SettlementStatus `json:"status"`

	// CreatedAt is when the settlement was initiated.
	CreatedAt time.Time `json:"created_at"`

	// SettledAt is when the settlement was confirmed (zero if not yet settled).
	SettledAt time.Time `json:"settled_at,omitempty"`

	// TxHash is the on-chain transaction hash (empty if not yet on-chain).
	TxHash string `json:"tx_hash,omitempty"`

	// FailureReason describes why a settlement failed (empty if successful).
	FailureReason string `json:"failure_reason,omitempty"`
}

// Discrepancy records a mismatch found during reconciliation.
type Discrepancy struct {
	// SettlementID identifies the settlement with the discrepancy.
	SettlementID string `json:"settlement_id"`

	// ExpectedFiat is the expected fiat amount.
	ExpectedFiat float64 `json:"expected_fiat"`

	// ActualFiat is the actual fiat amount settled.
	ActualFiat float64 `json:"actual_fiat"`

	// ExpectedTokens is the expected token amount.
	ExpectedTokens float64 `json:"expected_tokens"`

	// ActualTokens is the actual token amount settled.
	ActualTokens float64 `json:"actual_tokens"`

	// Description explains the discrepancy.
	Description string `json:"description"`
}

// ReconciliationReport summarizes the results of settlement reconciliation.
type ReconciliationReport struct {
	// Period is the reconciliation period.
	Period BillingPeriod `json:"period"`

	// PeriodStart is when the reconciliation period began.
	PeriodStart time.Time `json:"period_start"`

	// PeriodEnd is when the reconciliation period ended.
	PeriodEnd time.Time `json:"period_end"`

	// Settlements is the total number of settlements in the period.
	Settlements int `json:"settlements"`

	// SettledCount is the number of successfully settled items.
	SettledCount int `json:"settled_count"`

	// FailedCount is the number of failed settlements.
	FailedCount int `json:"failed_count"`

	// FiatTotal is the total fiat amount settled.
	FiatTotal float64 `json:"fiat_total"`

	// FiatCurrency is the fiat currency.
	FiatCurrency string `json:"fiat_currency"`

	// TokenTotal is the total token amount settled.
	TokenTotal float64 `json:"token_total"`

	// TokenDenomination is the token denomination.
	TokenDenomination string `json:"token_denomination"`

	// Discrepancies lists any mismatches found.
	Discrepancies []Discrepancy `json:"discrepancies"`

	// GeneratedAt is when the report was generated.
	GeneratedAt time.Time `json:"generated_at"`
}

// ---------------------------------------------------------------------------
// Settlement engine
// ---------------------------------------------------------------------------

// SettlementEngine processes invoice settlements, converting fiat-denominated
// invoices to AETHEL token settlements on the Aethelred network.
type SettlementEngine struct {
	config      SettlementConfig
	mu          sync.RWMutex
	settlements map[string]*Settlement
	invoices    *InvoiceManager

	// exchangeRate is the current fiat-to-token exchange rate.
	// In production this would be fetched from an oracle/exchange.
	exchangeRate float64
}

// NewSettlementEngine creates a new settlement engine.
func NewSettlementEngine(config SettlementConfig, invoices *InvoiceManager) (*SettlementEngine, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid settlement config: %w", err)
	}

	return &SettlementEngine{
		config:       config,
		settlements:  make(map[string]*Settlement),
		invoices:     invoices,
		exchangeRate: 1.0, // default 1:1 until set
	}, nil
}

// SetExchangeRate updates the fiat-to-token exchange rate.
func (se *SettlementEngine) SetExchangeRate(rate float64) error {
	if rate <= 0 {
		return fmt.Errorf("exchange rate must be positive")
	}

	se.mu.Lock()
	se.exchangeRate = rate
	se.mu.Unlock()

	return nil
}

// Settle initiates settlement for the specified invoice, converting the
// fiat amount to AETHEL tokens at the current exchange rate.
func (se *SettlementEngine) Settle(_ context.Context, invoiceID string) (*Settlement, error) {
	if invoiceID == "" {
		return nil, fmt.Errorf("invoice ID is required")
	}

	// Get the invoice
	var inv *Invoice
	if se.invoices != nil {
		var err error
		inv, err = se.invoices.GetInvoice(invoiceID)
		if err != nil {
			return nil, fmt.Errorf("invoice lookup failed: %w", err)
		}
	} else {
		return nil, fmt.Errorf("invoice manager not configured")
	}

	// Verify minimum amount
	if se.config.MinSettlementAmount > 0 && inv.Total < se.config.MinSettlementAmount {
		return nil, fmt.Errorf("invoice total %.2f is below minimum settlement amount %.2f",
			inv.Total, se.config.MinSettlementAmount)
	}

	se.mu.Lock()
	defer se.mu.Unlock()

	// Calculate token amount
	tokenAmount := inv.Total * se.exchangeRate

	now := time.Now().UTC()
	settlement := &Settlement{
		ID:                fmt.Sprintf("stl-%s-%d", invoiceID, now.UnixNano()),
		InvoiceID:         invoiceID,
		CustomerID:        inv.CustomerID,
		FiatAmount:        inv.Total,
		FiatCurrency:      inv.Currency,
		TokenAmount:       tokenAmount,
		TokenDenomination: se.config.TokenDenomination,
		ExchangeRate:      se.exchangeRate,
		Status:            SettlementProcessing,
		CreatedAt:         now,
	}

	// Simulate settlement (in production, this would submit an on-chain transaction)
	settlement.Status = SettlementSettled
	settlement.SettledAt = now
	settlement.TxHash = fmt.Sprintf("0x%s%d", invoiceID, now.UnixNano())

	se.settlements[settlement.ID] = settlement

	return settlement, nil
}

// GetSettlementStatus retrieves the current status of a settlement.
func (se *SettlementEngine) GetSettlementStatus(_ context.Context, settlementID string) (*Settlement, error) {
	if settlementID == "" {
		return nil, fmt.Errorf("settlement ID is required")
	}

	se.mu.RLock()
	defer se.mu.RUnlock()

	settlement, ok := se.settlements[settlementID]
	if !ok {
		return nil, fmt.Errorf("settlement not found: %s", settlementID)
	}

	return settlement, nil
}

// ReconcileSettlements performs reconciliation across all settlements
// in the specified period, checking for discrepancies.
func (se *SettlementEngine) ReconcileSettlements(_ context.Context, period BillingPeriod) (*ReconciliationReport, error) {
	se.mu.RLock()
	defer se.mu.RUnlock()

	now := time.Now().UTC()
	periodStart := now.Add(-period.Duration())

	report := &ReconciliationReport{
		Period:            period,
		PeriodStart:       periodStart,
		PeriodEnd:         now,
		FiatCurrency:      se.config.FiatCurrency,
		TokenDenomination: se.config.TokenDenomination,
		GeneratedAt:       now,
	}

	for _, s := range se.settlements {
		if s.CreatedAt.Before(periodStart) {
			continue
		}

		report.Settlements++

		switch s.Status {
		case SettlementSettled:
			report.SettledCount++
			report.FiatTotal += s.FiatAmount
			report.TokenTotal += s.TokenAmount

			// Check for exchange rate discrepancies
			expectedTokens := s.FiatAmount * s.ExchangeRate
			if abs(expectedTokens-s.TokenAmount) > 0.01 {
				report.Discrepancies = append(report.Discrepancies, Discrepancy{
					SettlementID:   s.ID,
					ExpectedFiat:   s.FiatAmount,
					ActualFiat:     s.FiatAmount,
					ExpectedTokens: expectedTokens,
					ActualTokens:   s.TokenAmount,
					Description:    "token amount does not match expected conversion",
				})
			}

		case SettlementFailed:
			report.FailedCount++
		}
	}

	return report, nil
}

// ListSettlements returns all settlements for a customer.
func (se *SettlementEngine) ListSettlements(customerID string) []*Settlement {
	se.mu.RLock()
	defer se.mu.RUnlock()

	var result []*Settlement
	for _, s := range se.settlements {
		if s.CustomerID == customerID {
			result = append(result, s)
		}
	}
	return result
}

// abs returns the absolute value of a float64.
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
