package billing

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Alert actions
// ---------------------------------------------------------------------------

// AlertAction defines what happens when a budget threshold is reached.
type AlertAction int

const (
	// Notify sends a notification to the customer.
	Notify AlertAction = iota

	// Throttle reduces resource allocation to slow spending.
	Throttle

	// Block prevents new resource consumption.
	Block

	// Escalate notifies an escalation contact or management.
	Escalate
)

// String returns the human-readable label for an AlertAction.
func (a AlertAction) String() string {
	switch a {
	case Notify:
		return "Notify"
	case Throttle:
		return "Throttle"
	case Block:
		return "Block"
	case Escalate:
		return "Escalate"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// Budget types
// ---------------------------------------------------------------------------

// AlertThreshold defines a spend threshold and the action to take when reached.
type AlertThreshold struct {
	// Percent is the budget percentage at which to trigger (0-100).
	Percent float64 `json:"percent"`

	// Action is what to do when this threshold is reached.
	Action AlertAction `json:"action"`

	// Triggered indicates whether this threshold has already been triggered
	// in the current period.
	Triggered bool `json:"triggered"`
}

// Budget defines a spending limit for a customer.
type Budget struct {
	// ID uniquely identifies this budget.
	ID string `json:"id"`

	// CustomerID identifies the customer.
	CustomerID string `json:"customer_id"`

	// Limit is the maximum spend amount for the period.
	Limit float64 `json:"limit"`

	// Currency is the fiat currency for the budget.
	Currency string `json:"currency"`

	// Period is the budget period.
	Period BillingPeriod `json:"period"`

	// CurrentSpend is the current spend within this period.
	CurrentSpend float64 `json:"current_spend"`

	// AlertThresholds defines the actions at various spend levels.
	AlertThresholds []AlertThreshold `json:"alert_thresholds"`

	// PeriodStart is when the current budget period started.
	PeriodStart time.Time `json:"period_start"`

	// CreatedAt is when the budget was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the budget was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// BudgetAlert represents a triggered budget alert.
type BudgetAlert struct {
	// BudgetID identifies the budget that triggered the alert.
	BudgetID string `json:"budget_id"`

	// CustomerID identifies the customer.
	CustomerID string `json:"customer_id"`

	// Threshold is the percentage threshold that was crossed.
	Threshold float64 `json:"threshold"`

	// CurrentSpend is the spend at the time of the alert.
	CurrentSpend float64 `json:"current_spend"`

	// Limit is the budget limit.
	Limit float64 `json:"limit"`

	// Action is the action associated with this alert.
	Action AlertAction `json:"action"`

	// Timestamp is when the alert was triggered.
	Timestamp time.Time `json:"timestamp"`
}

// BudgetCheckResult contains the outcome of a budget check.
type BudgetCheckResult struct {
	// Allowed indicates whether the spend is within budget.
	Allowed bool `json:"allowed"`

	// Remaining is the amount remaining in the budget.
	Remaining float64 `json:"remaining"`

	// Alerts contains any alerts triggered by this check.
	Alerts []BudgetAlert `json:"alerts"`

	// Action is the most restrictive action triggered.
	Action *AlertAction `json:"action,omitempty"`
}

// ---------------------------------------------------------------------------
// Spend report
// ---------------------------------------------------------------------------

// SpendCategoryBreakdown shows spend for a single category.
type SpendCategoryBreakdown struct {
	// Category is the spend category name.
	Category string `json:"category"`

	// Amount is the total spend in this category.
	Amount float64 `json:"amount"`

	// Percent is the category's share of total spend.
	Percent float64 `json:"percent"`
}

// SpendReport provides a detailed view of spending over a period.
type SpendReport struct {
	// CustomerID identifies the customer.
	CustomerID string `json:"customer_id"`

	// Period is the reporting period.
	Period BillingPeriod `json:"period"`

	// PeriodStart is when the reporting period began.
	PeriodStart time.Time `json:"period_start"`

	// PeriodEnd is when the reporting period ends.
	PeriodEnd time.Time `json:"period_end"`

	// TotalSpend is the total spend in the period.
	TotalSpend float64 `json:"total_spend"`

	// Currency is the fiat currency.
	Currency string `json:"currency"`

	// ByCategory breaks down spend by category.
	ByCategory []SpendCategoryBreakdown `json:"by_category"`

	// ByService breaks down spend by service type.
	ByService map[string]float64 `json:"by_service"`

	// Trend is the spend trend relative to the previous period
	// (positive means increasing, negative means decreasing).
	Trend float64 `json:"trend"`

	// Forecast is the projected spend for the full period based on
	// current run rate.
	Forecast float64 `json:"forecast"`

	// BudgetUtilization is the spend as a percentage of the budget (if set).
	BudgetUtilization float64 `json:"budget_utilization"`
}

// ---------------------------------------------------------------------------
// Spend controller
// ---------------------------------------------------------------------------

// SpendController manages budgets, spend tracking, and budget alerts.
type SpendController struct {
	mu      sync.RWMutex
	budgets map[string]*Budget
	alerts  []BudgetAlert
}

// NewSpendController creates a new spend controller.
func NewSpendController() *SpendController {
	return &SpendController{
		budgets: make(map[string]*Budget),
	}
}

// SetBudget creates or updates a spend budget for a customer.
func (sc *SpendController) SetBudget(_ context.Context, budget Budget) (*Budget, error) {
	if budget.CustomerID == "" {
		return nil, fmt.Errorf("customer ID is required")
	}
	if budget.Limit <= 0 {
		return nil, fmt.Errorf("budget limit must be positive")
	}
	if budget.Currency == "" {
		return nil, fmt.Errorf("currency is required")
	}

	now := time.Now().UTC()

	if budget.ID == "" {
		budget.ID = fmt.Sprintf("budget-%s-%d", budget.CustomerID, now.UnixNano())
	}
	if budget.PeriodStart.IsZero() {
		budget.PeriodStart = now
	}
	budget.CreatedAt = now
	budget.UpdatedAt = now

	sc.mu.Lock()
	sc.budgets[budget.ID] = &budget
	sc.mu.Unlock()

	return &budget, nil
}

// CheckBudget evaluates whether a proposed spend amount is within the
// customer's budget, triggering any alerts as thresholds are crossed.
func (sc *SpendController) CheckBudget(_ context.Context, customerID string, amount float64) (*BudgetCheckResult, error) {
	if customerID == "" {
		return nil, fmt.Errorf("customer ID is required")
	}
	if amount < 0 {
		return nil, fmt.Errorf("amount must be non-negative")
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	result := &BudgetCheckResult{
		Allowed: true,
	}

	// Find budgets for this customer
	for _, budget := range sc.budgets {
		if budget.CustomerID != customerID {
			continue
		}

		projectedSpend := budget.CurrentSpend + amount
		result.Remaining = budget.Limit - projectedSpend

		if result.Remaining < 0 {
			result.Remaining = 0
		}

		// Check thresholds
		spendPercent := (projectedSpend / budget.Limit) * 100.0

		for i := range budget.AlertThresholds {
			threshold := &budget.AlertThresholds[i]

			if spendPercent >= threshold.Percent && !threshold.Triggered {
				threshold.Triggered = true

				alert := BudgetAlert{
					BudgetID:     budget.ID,
					CustomerID:   customerID,
					Threshold:    threshold.Percent,
					CurrentSpend: projectedSpend,
					Limit:        budget.Limit,
					Action:       threshold.Action,
					Timestamp:    time.Now().UTC(),
				}

				result.Alerts = append(result.Alerts, alert)
				sc.alerts = append(sc.alerts, alert)

				// Track the most restrictive action
				if result.Action == nil || threshold.Action > *result.Action {
					action := threshold.Action
					result.Action = &action
				}

				// Block action prevents the spend
				if threshold.Action == Block && projectedSpend > budget.Limit {
					result.Allowed = false
				}
			}
		}

		// Update current spend
		if result.Allowed {
			budget.CurrentSpend = projectedSpend
			budget.UpdatedAt = time.Now().UTC()
		}
	}

	return result, nil
}

// GetSpendReport generates a detailed spend report for a customer.
func (sc *SpendController) GetSpendReport(_ context.Context, customerID string, period BillingPeriod) (*SpendReport, error) {
	if customerID == "" {
		return nil, fmt.Errorf("customer ID is required")
	}

	sc.mu.RLock()
	defer sc.mu.RUnlock()

	now := time.Now().UTC()

	report := &SpendReport{
		CustomerID:  customerID,
		Period:      period,
		PeriodStart: now.Add(-period.Duration()),
		PeriodEnd:   now,
		Currency:    "USD",
		ByService:   make(map[string]float64),
	}

	// Aggregate from budgets
	for _, budget := range sc.budgets {
		if budget.CustomerID != customerID {
			continue
		}

		report.TotalSpend = budget.CurrentSpend
		report.Currency = budget.Currency

		if budget.Limit > 0 {
			report.BudgetUtilization = (budget.CurrentSpend / budget.Limit) * 100.0
		}
	}

	// Calculate forecast based on run rate
	elapsed := now.Sub(report.PeriodStart)
	periodDuration := period.Duration()
	if elapsed > 0 && elapsed < periodDuration {
		runRate := report.TotalSpend / elapsed.Hours()
		report.Forecast = runRate * periodDuration.Hours()
	} else {
		report.Forecast = report.TotalSpend
	}

	return report, nil
}

// GetBudget retrieves a budget by ID.
func (sc *SpendController) GetBudget(budgetID string) (*Budget, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	budget, ok := sc.budgets[budgetID]
	if !ok {
		return nil, fmt.Errorf("budget not found: %s", budgetID)
	}
	return budget, nil
}

// GetAlerts returns all alerts triggered for a customer.
func (sc *SpendController) GetAlerts(customerID string) []BudgetAlert {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	var result []BudgetAlert
	for _, alert := range sc.alerts {
		if alert.CustomerID == customerID {
			result = append(result, alert)
		}
	}
	return result
}
