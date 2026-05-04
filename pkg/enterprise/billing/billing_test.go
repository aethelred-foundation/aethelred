package billing_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aethelred/aethelred/pkg/enterprise/billing"
)

// ---------------------------------------------------------------------------
// Reservation tests
// ---------------------------------------------------------------------------

func TestCreateReservation(t *testing.T) {
	mgr := billing.NewReservationManager(0.10)

	req := billing.ReservationRequest{
		CustomerID:   "cust-001",
		Tier:         billing.Standard,
		ComputeUnits: 1000,
		Duration:     365 * 24 * time.Hour, // 1 year
		Currency:     "USD",
		AutoRenewal:  true,
	}

	res, err := mgr.CreateReservation(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.ID == "" {
		t.Error("reservation ID is empty")
	}
	if res.CustomerID != "cust-001" {
		t.Errorf("expected customer cust-001, got %s", res.CustomerID)
	}
	if res.ComputeUnits != 1000 {
		t.Errorf("expected 1000 compute units, got %d", res.ComputeUnits)
	}
	if res.Status != billing.ReservationActive {
		t.Errorf("expected active status, got %s", res.Status)
	}
	if res.Currency != "USD" {
		t.Errorf("expected USD currency, got %s", res.Currency)
	}

	// Annual commitment should get 20% discount
	if res.Terms.DiscountPercent != 20.0 {
		t.Errorf("expected 20%% discount for annual commitment, got %.1f%%", res.Terms.DiscountPercent)
	}
	if res.Terms.AutoRenewal != true {
		t.Error("expected auto-renewal to be enabled")
	}
}

func TestCreateReservation_Validation(t *testing.T) {
	mgr := billing.NewReservationManager(0.10)

	tests := []struct {
		name string
		req  billing.ReservationRequest
	}{
		{
			name: "missing customer ID",
			req: billing.ReservationRequest{
				ComputeUnits: 100,
				Duration:     time.Hour,
				Currency:     "USD",
			},
		},
		{
			name: "zero compute units",
			req: billing.ReservationRequest{
				CustomerID:   "cust-001",
				ComputeUnits: 0,
				Duration:     time.Hour,
				Currency:     "USD",
			},
		},
		{
			name: "missing currency",
			req: billing.ReservationRequest{
				CustomerID:   "cust-001",
				ComputeUnits: 100,
				Duration:     time.Hour,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mgr.CreateReservation(context.Background(), tt.req)
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestReservationTierMultiplier(t *testing.T) {
	tests := []struct {
		tier       billing.ReservationTier
		multiplier float64
	}{
		{billing.Standard, 1.0},
		{billing.Premium, 1.5},
		{billing.Enterprise, 2.0},
		{billing.Dedicated, 3.0},
	}

	for _, tt := range tests {
		t.Run(tt.tier.String(), func(t *testing.T) {
			if tt.tier.Multiplier() != tt.multiplier {
				t.Errorf("expected multiplier %f, got %f", tt.multiplier, tt.tier.Multiplier())
			}
		})
	}
}

func TestModifyReservation(t *testing.T) {
	mgr := billing.NewReservationManager(0.10)

	req := billing.ReservationRequest{
		CustomerID:   "cust-001",
		Tier:         billing.Standard,
		ComputeUnits: 1000,
		Duration:     90 * 24 * time.Hour,
		Currency:     "USD",
	}

	res, err := mgr.CreateReservation(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	newTier := billing.Premium
	modified, err := mgr.ModifyReservation(context.Background(), res.ID, billing.ReservationChange{
		NewComputeUnits: 2000,
		NewTier:         &newTier,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if modified.ComputeUnits != 2000 {
		t.Errorf("expected 2000 compute units, got %d", modified.ComputeUnits)
	}
	if modified.Tier != billing.Premium {
		t.Errorf("expected Premium tier, got %s", modified.Tier.String())
	}
}

func TestCancelReservation(t *testing.T) {
	mgr := billing.NewReservationManager(0.10)

	req := billing.ReservationRequest{
		CustomerID:   "cust-001",
		Tier:         billing.Standard,
		ComputeUnits: 100,
		Duration:     30 * 24 * time.Hour,
		Currency:     "USD",
	}

	res, err := mgr.CreateReservation(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cancelled, err := mgr.CancelReservation(context.Background(), res.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cancelled.Status != billing.ReservationCancelled {
		t.Errorf("expected cancelled status, got %s", cancelled.Status)
	}

	// Double cancel should fail
	_, err = mgr.CancelReservation(context.Background(), res.ID)
	if err == nil {
		t.Fatal("expected error for double cancellation")
	}
}

func TestGetUtilization(t *testing.T) {
	mgr := billing.NewReservationManager(0.10)

	req := billing.ReservationRequest{
		CustomerID:   "cust-001",
		Tier:         billing.Standard,
		ComputeUnits: 1000,
		Duration:     30 * 24 * time.Hour,
		Currency:     "USD",
	}

	res, err := mgr.CreateReservation(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Record usage
	err = mgr.RecordUsage(res.ID, 500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	util, err := mgr.GetUtilization(context.Background(), res.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if util.Reserved != 1000 {
		t.Errorf("expected 1000 reserved, got %d", util.Reserved)
	}
	if util.Used != 500 {
		t.Errorf("expected 500 used, got %d", util.Used)
	}
	if util.UtilizationPercent != 50.0 {
		t.Errorf("expected 50%% utilization, got %.1f%%", util.UtilizationPercent)
	}
	if util.Overage != 0 {
		t.Errorf("expected 0 overage, got %d", util.Overage)
	}
}

func TestGetUtilization_WithOverage(t *testing.T) {
	mgr := billing.NewReservationManager(0.10)

	req := billing.ReservationRequest{
		CustomerID:   "cust-001",
		Tier:         billing.Standard,
		ComputeUnits: 100,
		Duration:     30 * 24 * time.Hour,
		Currency:     "USD",
	}

	res, err := mgr.CreateReservation(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = mgr.RecordUsage(res.ID, 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	util, err := mgr.GetUtilization(context.Background(), res.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if util.Overage != 50 {
		t.Errorf("expected 50 overage, got %d", util.Overage)
	}
	if util.OverageCost <= 0 {
		t.Error("expected positive overage cost")
	}
}

// ---------------------------------------------------------------------------
// Invoicing tests
// ---------------------------------------------------------------------------

func TestGenerateInvoice(t *testing.T) {
	resMgr := billing.NewReservationManager(0.10)
	metering := billing.NewMeteringService()
	invMgr := billing.NewInvoiceManager(10.0, 30, resMgr, metering)

	// Create a reservation first
	_, err := resMgr.CreateReservation(context.Background(), billing.ReservationRequest{
		CustomerID:   "cust-001",
		Tier:         billing.Standard,
		ComputeUnits: 1000,
		Duration:     365 * 24 * time.Hour,
		Currency:     "USD",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inv, err := invMgr.GenerateInvoice(context.Background(), "cust-001", billing.Monthly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if inv.ID == "" {
		t.Error("invoice ID is empty")
	}
	if inv.CustomerID != "cust-001" {
		t.Errorf("expected customer cust-001, got %s", inv.CustomerID)
	}
	if inv.Status != billing.InvoiceDraft {
		t.Errorf("expected draft status, got %s", inv.Status)
	}
	if len(inv.LineItems) == 0 {
		t.Error("expected at least one line item")
	}
	if inv.Subtotal <= 0 {
		t.Error("expected positive subtotal")
	}
	if inv.Total <= 0 {
		t.Error("expected positive total")
	}
}

func TestSendInvoice(t *testing.T) {
	invMgr := billing.NewInvoiceManager(0, 30, nil, nil)

	inv, err := invMgr.GenerateInvoice(context.Background(), "cust-001", billing.Monthly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = invMgr.SendInvoice(context.Background(), inv.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := invMgr.GetInvoice(inv.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if updated.Status != billing.InvoiceSent {
		t.Errorf("expected sent status, got %s", updated.Status)
	}
	if updated.SentAt.IsZero() {
		t.Error("expected SentAt to be set")
	}
}

func TestRecordPayment(t *testing.T) {
	resMgr := billing.NewReservationManager(0.10)
	invMgr := billing.NewInvoiceManager(0, 30, resMgr, nil)

	_, err := resMgr.CreateReservation(context.Background(), billing.ReservationRequest{
		CustomerID:   "cust-001",
		Tier:         billing.Standard,
		ComputeUnits: 100,
		Duration:     30 * 24 * time.Hour,
		Currency:     "USD",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inv, err := invMgr.GenerateInvoice(context.Background(), "cust-001", billing.Monthly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	payment := billing.Payment{
		Amount:    inv.Total,
		Currency:  "USD",
		Method:    "wire",
		Reference: "PAY-001",
		PaidAt:    time.Now().UTC(),
	}

	err = invMgr.RecordPayment(context.Background(), inv.ID, payment)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := invMgr.GetInvoice(inv.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if updated.Status != billing.InvoicePaid {
		t.Errorf("expected paid status, got %s", updated.Status)
	}
}

func TestVoidInvoice(t *testing.T) {
	invMgr := billing.NewInvoiceManager(0, 30, nil, nil)

	inv, err := invMgr.GenerateInvoice(context.Background(), "cust-001", billing.Monthly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = invMgr.VoidInvoice(context.Background(), inv.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := invMgr.GetInvoice(inv.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if updated.Status != billing.InvoiceVoided {
		t.Errorf("expected voided status, got %s", updated.Status)
	}
}

func TestBillingPeriodString(t *testing.T) {
	tests := []struct {
		period   billing.BillingPeriod
		expected string
	}{
		{billing.Monthly, "Monthly"},
		{billing.Quarterly, "Quarterly"},
		{billing.Annual, "Annual"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.period.String() != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.period.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Spend control tests
// ---------------------------------------------------------------------------

func TestSetBudget(t *testing.T) {
	sc := billing.NewSpendController()

	budget := billing.Budget{
		CustomerID: "cust-001",
		Limit:      10000.0,
		Currency:   "USD",
		Period:     billing.Monthly,
		AlertThresholds: []billing.AlertThreshold{
			{Percent: 50, Action: billing.Notify},
			{Percent: 80, Action: billing.Throttle},
			{Percent: 100, Action: billing.Block},
		},
	}

	result, err := sc.SetBudget(context.Background(), budget)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID == "" {
		t.Error("budget ID is empty")
	}
	if result.Limit != 10000.0 {
		t.Errorf("expected limit 10000, got %f", result.Limit)
	}
}

func TestSetBudget_Validation(t *testing.T) {
	sc := billing.NewSpendController()

	_, err := sc.SetBudget(context.Background(), billing.Budget{
		Limit:    1000,
		Currency: "USD",
	})
	if err == nil {
		t.Fatal("expected error for missing customer ID")
	}

	_, err = sc.SetBudget(context.Background(), billing.Budget{
		CustomerID: "cust-001",
		Limit:      0,
		Currency:   "USD",
	})
	if err == nil {
		t.Fatal("expected error for zero limit")
	}
}

func TestCheckBudget_WithinLimit(t *testing.T) {
	sc := billing.NewSpendController()

	_, err := sc.SetBudget(context.Background(), billing.Budget{
		CustomerID: "cust-001",
		Limit:      1000.0,
		Currency:   "USD",
		Period:     billing.Monthly,
		AlertThresholds: []billing.AlertThreshold{
			{Percent: 80, Action: billing.Notify},
			{Percent: 100, Action: billing.Block},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := sc.CheckBudget(context.Background(), "cust-001", 100.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Error("expected spend to be allowed within budget")
	}
	if result.Remaining != 900.0 {
		t.Errorf("expected 900 remaining, got %f", result.Remaining)
	}
}

func TestCheckBudget_AlertTriggered(t *testing.T) {
	sc := billing.NewSpendController()

	_, err := sc.SetBudget(context.Background(), billing.Budget{
		CustomerID: "cust-001",
		Limit:      1000.0,
		Currency:   "USD",
		Period:     billing.Monthly,
		AlertThresholds: []billing.AlertThreshold{
			{Percent: 50, Action: billing.Notify},
			{Percent: 80, Action: billing.Escalate},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Spend 600 (60% of budget)
	result, err := sc.CheckBudget(context.Background(), "cust-001", 600.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Error("expected spend to be allowed")
	}
	if len(result.Alerts) == 0 {
		t.Error("expected at least one alert for 60% spend")
	}

	// Verify alert
	foundNotify := false
	for _, alert := range result.Alerts {
		if alert.Action == billing.Notify {
			foundNotify = true
		}
	}
	if !foundNotify {
		t.Error("expected Notify alert at 50% threshold")
	}
}

func TestCheckBudget_BlockAction(t *testing.T) {
	sc := billing.NewSpendController()

	_, err := sc.SetBudget(context.Background(), billing.Budget{
		CustomerID: "cust-001",
		Limit:      100.0,
		Currency:   "USD",
		Period:     billing.Monthly,
		AlertThresholds: []billing.AlertThreshold{
			{Percent: 100, Action: billing.Block},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Try to spend more than the budget
	result, err := sc.CheckBudget(context.Background(), "cust-001", 150.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected spend to be blocked when exceeding budget")
	}
}

func TestGetSpendReport(t *testing.T) {
	sc := billing.NewSpendController()

	_, err := sc.SetBudget(context.Background(), billing.Budget{
		CustomerID: "cust-001",
		Limit:      10000.0,
		Currency:   "USD",
		Period:     billing.Monthly,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = sc.CheckBudget(context.Background(), "cust-001", 500.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	report, err := sc.GetSpendReport(context.Background(), "cust-001", billing.Monthly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.CustomerID != "cust-001" {
		t.Errorf("expected customer cust-001, got %s", report.CustomerID)
	}
	if report.TotalSpend != 500.0 {
		t.Errorf("expected total spend 500, got %f", report.TotalSpend)
	}
	if report.BudgetUtilization != 5.0 {
		t.Errorf("expected 5%% budget utilization, got %.1f%%", report.BudgetUtilization)
	}
}

func TestAlertActionString(t *testing.T) {
	tests := []struct {
		action   billing.AlertAction
		expected string
	}{
		{billing.Notify, "Notify"},
		{billing.Throttle, "Throttle"},
		{billing.Block, "Block"},
		{billing.Escalate, "Escalate"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.action.String() != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.action.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Metering tests
// ---------------------------------------------------------------------------

func TestRecordUsage(t *testing.T) {
	ms := billing.NewMeteringService()

	record := billing.UsageRecord{
		ID:           "usage-001",
		CustomerID:   "cust-001",
		ResourceType: billing.ResourceComputeUnit,
		Quantity:     100,
	}

	err := ms.RecordUsage(context.Background(), record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify dedup: recording same ID again should return ErrDuplicateUsage.
	err = ms.RecordUsage(context.Background(), record)
	if err == nil {
		t.Fatal("expected error on duplicate, got nil")
	}

	summary, err := ms.GetUsageSummary(context.Background(), "cust-001", billing.Monthly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only count once due to dedup
	if summary.TotalRecords != 1 {
		t.Errorf("expected 1 record (dedup), got %d", summary.TotalRecords)
	}
}

func TestRecordUsage_Validation(t *testing.T) {
	ms := billing.NewMeteringService()

	tests := []struct {
		name   string
		record billing.UsageRecord
	}{
		{
			name:   "missing ID",
			record: billing.UsageRecord{CustomerID: "cust-001", ResourceType: billing.ResourceComputeUnit, Quantity: 1},
		},
		{
			name:   "missing customer ID",
			record: billing.UsageRecord{ID: "u-1", ResourceType: billing.ResourceComputeUnit, Quantity: 1},
		},
		{
			name:   "missing resource type",
			record: billing.UsageRecord{ID: "u-1", CustomerID: "cust-001", Quantity: 1},
		},
		{
			name:   "zero quantity",
			record: billing.UsageRecord{ID: "u-1", CustomerID: "cust-001", ResourceType: billing.ResourceComputeUnit, Quantity: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ms.RecordUsage(context.Background(), tt.record)
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestGetUsageSummary(t *testing.T) {
	ms := billing.NewMeteringService()

	records := []billing.UsageRecord{
		{ID: "u-1", CustomerID: "cust-001", ResourceType: billing.ResourceComputeUnit, Quantity: 100},
		{ID: "u-2", CustomerID: "cust-001", ResourceType: billing.ResourceComputeUnit, Quantity: 200},
		{ID: "u-3", CustomerID: "cust-001", ResourceType: billing.ResourceSealCreation, Quantity: 50},
		{ID: "u-4", CustomerID: "cust-002", ResourceType: billing.ResourceComputeUnit, Quantity: 500},
	}

	for _, r := range records {
		if err := ms.RecordUsage(context.Background(), r); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	summary, err := ms.GetUsageSummary(context.Background(), "cust-001", billing.Monthly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.TotalRecords != 3 {
		t.Errorf("expected 3 records for cust-001, got %d", summary.TotalRecords)
	}
	if summary.TotalCost <= 0 {
		t.Error("expected positive total cost")
	}
	if len(summary.ByResource) != 2 {
		t.Errorf("expected 2 resource types, got %d", len(summary.ByResource))
	}
}

func TestResourceTypeUnitName(t *testing.T) {
	tests := []struct {
		rt       billing.ResourceType
		expected string
	}{
		{billing.ResourceComputeUnit, "compute-units"},
		{billing.ResourceStorageByte, "bytes"},
		{billing.ResourceSealCreation, "seals"},
		{billing.ResourceVerification, "verifications"},
		{billing.ResourceAuditQuery, "queries"},
	}

	for _, tt := range tests {
		t.Run(string(tt.rt), func(t *testing.T) {
			if tt.rt.UnitName() != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.rt.UnitName())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Settlement tests
// ---------------------------------------------------------------------------

func TestSettlement(t *testing.T) {
	resMgr := billing.NewReservationManager(0.10)
	invMgr := billing.NewInvoiceManager(0, 30, resMgr, nil)

	// Create reservation and invoice
	_, err := resMgr.CreateReservation(context.Background(), billing.ReservationRequest{
		CustomerID:   "cust-001",
		Tier:         billing.Standard,
		ComputeUnits: 100,
		Duration:     30 * 24 * time.Hour,
		Currency:     "USD",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inv, err := invMgr.GenerateInvoice(context.Background(), "cust-001", billing.Monthly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Create settlement engine
	config := billing.SettlementConfig{
		FiatCurrency:       "USD",
		TokenDenomination:  "AETHEL",
		ExchangeRateProvider: "internal",
		SettlementPeriod:   billing.Monthly,
		MaxSlippagePercent: 2.0,
	}

	engine, err := billing.NewSettlementEngine(config, invMgr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Set exchange rate: 1 USD = 10 AETHEL
	err = engine.SetExchangeRate(10.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Settle invoice
	settlement, err := engine.Settle(context.Background(), inv.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if settlement.ID == "" {
		t.Error("settlement ID is empty")
	}
	if settlement.InvoiceID != inv.ID {
		t.Errorf("expected invoice ID %s, got %s", inv.ID, settlement.InvoiceID)
	}
	if settlement.FiatAmount != inv.Total {
		t.Errorf("expected fiat amount %f, got %f", inv.Total, settlement.FiatAmount)
	}
	if settlement.TokenAmount != inv.Total*10.0 {
		t.Errorf("expected token amount %f, got %f", inv.Total*10.0, settlement.TokenAmount)
	}
	if settlement.TokenDenomination != "AETHEL" {
		t.Errorf("expected AETHEL denomination, got %s", settlement.TokenDenomination)
	}
	if settlement.Status != billing.SettlementSettled {
		t.Errorf("expected settled status, got %s", settlement.Status)
	}
	if settlement.TxHash == "" {
		t.Error("expected transaction hash")
	}
}

func TestSettlementConfig_Validation(t *testing.T) {
	_, err := billing.NewSettlementEngine(billing.SettlementConfig{
		TokenDenomination:  "AETHEL",
		MaxSlippagePercent: 1.0,
	}, nil)
	if err == nil {
		t.Fatal("expected error for missing fiat currency")
	}

	_, err = billing.NewSettlementEngine(billing.SettlementConfig{
		FiatCurrency:       "USD",
		MaxSlippagePercent: 1.0,
	}, nil)
	if err == nil {
		t.Fatal("expected error for missing token denomination")
	}
}

func TestGetSettlementStatus(t *testing.T) {
	resMgr := billing.NewReservationManager(0.10)
	invMgr := billing.NewInvoiceManager(0, 30, resMgr, nil)

	_, err := resMgr.CreateReservation(context.Background(), billing.ReservationRequest{
		CustomerID:   "cust-001",
		Tier:         billing.Standard,
		ComputeUnits: 100,
		Duration:     30 * 24 * time.Hour,
		Currency:     "USD",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inv, err := invMgr.GenerateInvoice(context.Background(), "cust-001", billing.Monthly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	config := billing.SettlementConfig{
		FiatCurrency:       "USD",
		TokenDenomination:  "AETHEL",
		MaxSlippagePercent: 2.0,
	}

	engine, err := billing.NewSettlementEngine(config, invMgr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	settlement, err := engine.Settle(context.Background(), inv.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	status, err := engine.GetSettlementStatus(context.Background(), settlement.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.ID != settlement.ID {
		t.Errorf("expected settlement ID %s, got %s", settlement.ID, status.ID)
	}
}

func TestGetSettlementStatus_NotFound(t *testing.T) {
	config := billing.SettlementConfig{
		FiatCurrency:       "USD",
		TokenDenomination:  "AETHEL",
		MaxSlippagePercent: 1.0,
	}

	engine, err := billing.NewSettlementEngine(config, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = engine.GetSettlementStatus(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent settlement")
	}
}

func TestReconcileSettlements(t *testing.T) {
	resMgr := billing.NewReservationManager(0.10)
	invMgr := billing.NewInvoiceManager(0, 30, resMgr, nil)

	_, err := resMgr.CreateReservation(context.Background(), billing.ReservationRequest{
		CustomerID:   "cust-001",
		Tier:         billing.Standard,
		ComputeUnits: 100,
		Duration:     30 * 24 * time.Hour,
		Currency:     "USD",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inv, err := invMgr.GenerateInvoice(context.Background(), "cust-001", billing.Monthly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	config := billing.SettlementConfig{
		FiatCurrency:       "USD",
		TokenDenomination:  "AETHEL",
		MaxSlippagePercent: 2.0,
		SettlementPeriod:   billing.Monthly,
	}

	engine, err := billing.NewSettlementEngine(config, invMgr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = engine.Settle(context.Background(), inv.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	report, err := engine.ReconcileSettlements(context.Background(), billing.Monthly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Settlements < 1 {
		t.Errorf("expected at least 1 settlement, got %d", report.Settlements)
	}
	if report.SettledCount < 1 {
		t.Errorf("expected at least 1 settled, got %d", report.SettledCount)
	}
	if report.FiatTotal <= 0 {
		t.Error("expected positive fiat total")
	}
	if report.TokenDenomination != "AETHEL" {
		t.Errorf("expected AETHEL denomination, got %s", report.TokenDenomination)
	}
}

func TestSetExchangeRate_Invalid(t *testing.T) {
	config := billing.SettlementConfig{
		FiatCurrency:       "USD",
		TokenDenomination:  "AETHEL",
		MaxSlippagePercent: 1.0,
	}

	engine, err := billing.NewSettlementEngine(config, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = engine.SetExchangeRate(0)
	if err == nil {
		t.Fatal("expected error for zero exchange rate")
	}

	err = engine.SetExchangeRate(-1)
	if err == nil {
		t.Fatal("expected error for negative exchange rate")
	}
}

// ---------------------------------------------------------------------------
// Edge-case, error-path, and concurrency tests
// ---------------------------------------------------------------------------

func TestAmount_Arithmetic(t *testing.T) {
	a := billing.NewAmountFromDollars(10.50) // 1050 cents
	b := billing.NewAmountFromDollars(3.25)  // 325 cents

	// Add
	sum := a.Add(b)
	if sum.Cents() != 1375 {
		t.Errorf("Add: expected 1375 cents, got %d", sum.Cents())
	}
	if sum.Dollars() != 13.75 {
		t.Errorf("Add: expected $13.75, got $%.2f", sum.Dollars())
	}

	// Sub
	diff := a.Sub(b)
	if diff.Cents() != 725 {
		t.Errorf("Sub: expected 725 cents, got %d", diff.Cents())
	}

	// Mul
	product := a.Mul(3)
	if product.Cents() != 3150 {
		t.Errorf("Mul: expected 3150 cents, got %d", product.Cents())
	}

	// MulFloat
	scaled := a.MulFloat(1.5)
	if scaled.Cents() != 1575 {
		t.Errorf("MulFloat: expected 1575 cents, got %d", scaled.Cents())
	}

	// Cents/Dollars
	c := billing.NewAmountFromCents(4999)
	if c.Dollars() != 49.99 {
		t.Errorf("Dollars: expected 49.99, got %.2f", c.Dollars())
	}
	if c.Cents() != 4999 {
		t.Errorf("Cents: expected 4999, got %d", c.Cents())
	}
}

func TestAmount_NegativePrice(t *testing.T) {
	neg := billing.NewAmountFromDollars(-5.00)
	if !neg.IsNegative() {
		t.Error("expected negative amount")
	}

	// Verify the sentinel error exists.
	if billing.ErrNegativeAmount == nil {
		t.Fatal("ErrNegativeAmount is nil")
	}
	if !errors.Is(billing.ErrNegativeAmount, billing.ErrNegativeAmount) {
		t.Fatal("errors.Is failed for ErrNegativeAmount")
	}
}

func TestAmount_ZeroQuantity(t *testing.T) {
	zero := billing.NewAmountFromCents(0)
	if !zero.IsZero() {
		t.Error("expected zero amount")
	}

	// Multiplying by zero.
	a := billing.NewAmountFromDollars(100.00)
	result := a.Mul(0)
	if !result.IsZero() {
		t.Errorf("expected zero after Mul(0), got %d", result.Cents())
	}
}

func TestAmount_PrecisionPreservation(t *testing.T) {
	// $1.23 * 100 should equal $123.00 exactly.
	a := billing.NewAmountFromDollars(1.23)
	result := a.Mul(100)
	if result.Dollars() != 123.00 {
		t.Errorf("precision lost: expected $123.00, got $%.2f", result.Dollars())
	}
	if result.Cents() != 12300 {
		t.Errorf("precision lost: expected 12300 cents, got %d", result.Cents())
	}
}

func TestReservation_ConcurrentCreation(t *testing.T) {
	mgr := billing.NewReservationManager(0.10)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := mgr.CreateReservation(ctx, billing.ReservationRequest{
				CustomerID:   fmt.Sprintf("cust-conc-%d", idx),
				Tier:         billing.Standard,
				ComputeUnits: 100,
				Duration:     30 * 24 * time.Hour,
				Currency:     "USD",
			})
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", idx, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Errorf("concurrent reservation error: %v", e)
	}
}

func TestReservation_CancelTerms(t *testing.T) {
	mgr := billing.NewReservationManager(0.10)
	ctx := context.Background()

	res, err := mgr.CreateReservation(ctx, billing.ReservationRequest{
		CustomerID:   "cust-cancel",
		Tier:         billing.Premium,
		ComputeUnits: 500,
		Duration:     365 * 24 * time.Hour,
		Currency:     "USD",
	})
	if err != nil {
		t.Fatalf("CreateReservation failed: %v", err)
	}

	cancelled, err := mgr.CancelReservation(ctx, res.ID)
	if err != nil {
		t.Fatalf("CancelReservation failed: %v", err)
	}
	if cancelled.Status != billing.ReservationCancelled {
		t.Errorf("expected cancelled status, got %s", cancelled.Status)
	}
}

func TestInvoice_ConcurrentPayments(t *testing.T) {
	resMgr := billing.NewReservationManager(0.10)
	invMgr := billing.NewInvoiceManager(0, 30, resMgr, nil)
	ctx := context.Background()

	_, err := resMgr.CreateReservation(ctx, billing.ReservationRequest{
		CustomerID:   "cust-pay",
		Tier:         billing.Standard,
		ComputeUnits: 100,
		Duration:     30 * 24 * time.Hour,
		Currency:     "USD",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inv, err := invMgr.GenerateInvoice(ctx, "cust-pay", billing.Monthly)
	if err != nil {
		t.Fatalf("GenerateInvoice failed: %v", err)
	}

	var wg sync.WaitGroup
	successCount := make(chan int, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payment := billing.Payment{
				Amount:    inv.Total,
				Currency:  "USD",
				Method:    "wire",
				Reference: fmt.Sprintf("PAY-%d", idx),
				PaidAt:    time.Now().UTC(),
			}
			err := invMgr.RecordPayment(ctx, inv.ID, payment)
			if err == nil {
				successCount <- 1
			}
		}(i)
	}
	wg.Wait()
	close(successCount)

	count := 0
	for range successCount {
		count++
	}
	// At least one payment should succeed.
	if count == 0 {
		t.Error("expected at least one successful payment")
	}
}

func TestInvoice_OverPayment(t *testing.T) {
	resMgr := billing.NewReservationManager(0.10)
	invMgr := billing.NewInvoiceManager(0, 30, resMgr, nil)
	ctx := context.Background()

	_, err := resMgr.CreateReservation(ctx, billing.ReservationRequest{
		CustomerID:   "cust-over",
		Tier:         billing.Standard,
		ComputeUnits: 100,
		Duration:     30 * 24 * time.Hour,
		Currency:     "USD",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inv, err := invMgr.GenerateInvoice(ctx, "cust-over", billing.Monthly)
	if err != nil {
		t.Fatalf("GenerateInvoice failed: %v", err)
	}

	// Pay more than total.
	payment := billing.Payment{
		Amount:    inv.Total * 2,
		Currency:  "USD",
		Method:    "wire",
		Reference: "PAY-OVER",
		PaidAt:    time.Now().UTC(),
	}

	err = invMgr.RecordPayment(ctx, inv.ID, payment)
	// May succeed or fail depending on implementation; we just ensure no panic.
	if err != nil {
		t.Logf("overpayment returned: %v", err)
	}
}

func TestSpend_BudgetExceeded(t *testing.T) {
	sc := billing.NewSpendController()
	ctx := context.Background()

	_, err := sc.SetBudget(ctx, billing.Budget{
		CustomerID: "cust-budget",
		Limit:      100.0,
		Currency:   "USD",
		Period:     billing.Monthly,
		AlertThresholds: []billing.AlertThreshold{
			{Percent: 100, Action: billing.Block},
		},
	})
	if err != nil {
		t.Fatalf("SetBudget failed: %v", err)
	}

	result, err := sc.CheckBudget(ctx, "cust-budget", 200.0)
	if err != nil {
		t.Fatalf("CheckBudget failed: %v", err)
	}
	if result.Allowed {
		t.Error("expected budget to be blocked")
	}

	// Verify ErrBudgetExceeded sentinel exists.
	if !errors.Is(billing.ErrBudgetExceeded, billing.ErrBudgetExceeded) {
		t.Fatal("errors.Is failed for ErrBudgetExceeded")
	}
}

func TestSpend_AlertThresholds(t *testing.T) {
	sc := billing.NewSpendController()
	ctx := context.Background()

	_, err := sc.SetBudget(ctx, billing.Budget{
		CustomerID: "cust-alerts",
		Limit:      1000.0,
		Currency:   "USD",
		Period:     billing.Monthly,
		AlertThresholds: []billing.AlertThreshold{
			{Percent: 50, Action: billing.Notify},
			{Percent: 80, Action: billing.Escalate},
			{Percent: 100, Action: billing.Block},
		},
	})
	if err != nil {
		t.Fatalf("SetBudget failed: %v", err)
	}

	// 50% spend.
	result, _ := sc.CheckBudget(ctx, "cust-alerts", 500.0)
	foundNotify := false
	for _, a := range result.Alerts {
		if a.Action == billing.Notify {
			foundNotify = true
		}
	}
	if !foundNotify {
		t.Error("expected Notify alert at 50%")
	}

	// 80% cumulative spend (500 + 300 = 800).
	result, _ = sc.CheckBudget(ctx, "cust-alerts", 300.0)
	foundEscalate := false
	for _, a := range result.Alerts {
		if a.Action == billing.Escalate {
			foundEscalate = true
		}
	}
	if !foundEscalate {
		t.Error("expected Escalate alert at 80%")
	}

	// Over 100% cumulative spend (800 + 300 = 1100).
	result, _ = sc.CheckBudget(ctx, "cust-alerts", 300.0)
	if result.Allowed {
		t.Error("expected budget block above 100%")
	}
}

func TestMetering_DuplicateUsage(t *testing.T) {
	ms := billing.NewMeteringService()
	ctx := context.Background()

	record := billing.UsageRecord{
		ID:           "usage-dup",
		CustomerID:   "cust-001",
		ResourceType: billing.ResourceComputeUnit,
		Quantity:     100,
	}

	err := ms.RecordUsage(ctx, record)
	if err != nil {
		t.Fatalf("first RecordUsage failed: %v", err)
	}

	err = ms.RecordUsage(ctx, record)
	if err == nil {
		t.Fatal("expected error on duplicate usage")
	}
	if !errors.Is(err, billing.ErrDuplicateUsage) {
		t.Fatalf("expected ErrDuplicateUsage, got %v", err)
	}
}

func TestMetering_ConcurrentRecording(t *testing.T) {
	ms := billing.NewMeteringService()
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			record := billing.UsageRecord{
				ID:           fmt.Sprintf("usage-conc-%d", idx),
				CustomerID:   "cust-conc",
				ResourceType: billing.ResourceComputeUnit,
				Quantity:     float64(idx + 1),
			}
			if err := ms.RecordUsage(ctx, record); err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", idx, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Errorf("concurrent metering error: %v", e)
	}

	summary, err := ms.GetUsageSummary(ctx, "cust-conc", billing.Monthly)
	if err != nil {
		t.Fatalf("GetUsageSummary failed: %v", err)
	}
	if summary.TotalRecords != 50 {
		t.Errorf("expected 50 records, got %d", summary.TotalRecords)
	}
}

func TestSettlement_FailedSettlement(t *testing.T) {
	config := billing.SettlementConfig{
		FiatCurrency:       "USD",
		TokenDenomination:  "AETHEL",
		MaxSlippagePercent: 1.0,
	}

	engine, err := billing.NewSettlementEngine(config, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Try to settle a non-existent invoice.
	_, err = engine.Settle(context.Background(), "nonexistent-invoice")
	if err == nil {
		t.Fatal("expected error for non-existent invoice")
	}
}

func TestSettlement_Reconciliation(t *testing.T) {
	resMgr := billing.NewReservationManager(0.10)
	invMgr := billing.NewInvoiceManager(0, 30, resMgr, nil)
	ctx := context.Background()

	_, err := resMgr.CreateReservation(ctx, billing.ReservationRequest{
		CustomerID:   "cust-recon",
		Tier:         billing.Standard,
		ComputeUnits: 100,
		Duration:     30 * 24 * time.Hour,
		Currency:     "USD",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inv, _ := invMgr.GenerateInvoice(ctx, "cust-recon", billing.Monthly)

	config := billing.SettlementConfig{
		FiatCurrency:       "USD",
		TokenDenomination:  "AETHEL",
		MaxSlippagePercent: 2.0,
		SettlementPeriod:   billing.Monthly,
	}

	engine, _ := billing.NewSettlementEngine(config, invMgr)
	_ = engine.SetExchangeRate(5.0)
	_, _ = engine.Settle(ctx, inv.ID)

	report, err := engine.ReconcileSettlements(ctx, billing.Monthly)
	if err != nil {
		t.Fatalf("ReconcileSettlements failed: %v", err)
	}
	if report.Settlements < 1 {
		t.Error("expected at least 1 settlement in reconciliation")
	}
}

func TestSettlement_ConcurrentSettlements(t *testing.T) {
	resMgr := billing.NewReservationManager(0.10)
	invMgr := billing.NewInvoiceManager(0, 30, resMgr, nil)
	ctx := context.Background()

	// Create multiple customers with invoices.
	invoiceIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		custID := fmt.Sprintf("cust-settle-%d", i)
		_, _ = resMgr.CreateReservation(ctx, billing.ReservationRequest{
			CustomerID:   custID,
			Tier:         billing.Standard,
			ComputeUnits: 100,
			Duration:     30 * 24 * time.Hour,
			Currency:     "USD",
		})
		inv, _ := invMgr.GenerateInvoice(ctx, custID, billing.Monthly)
		invoiceIDs[i] = inv.ID
	}

	config := billing.SettlementConfig{
		FiatCurrency:       "USD",
		TokenDenomination:  "AETHEL",
		MaxSlippagePercent: 2.0,
	}
	engine, _ := billing.NewSettlementEngine(config, invMgr)
	_ = engine.SetExchangeRate(10.0)

	var wg sync.WaitGroup
	for _, id := range invoiceIDs {
		wg.Add(1)
		go func(invID string) {
			defer wg.Done()
			_, _ = engine.Settle(ctx, invID)
		}(id)
	}
	wg.Wait()
}
