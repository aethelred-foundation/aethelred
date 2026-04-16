package finance

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/enterprise/billing"
	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// TreasurySettlementRail executes and previews policy-bound treasury
// settlements.
type TreasurySettlementRail interface {
	Quote(ctx context.Context, req TreasurySettlementRequest) (*TreasurySettlementQuote, error)
	Settle(ctx context.Context, req TreasurySettlementRequest) (*evidence.ValueSettlementEvidence, error)
}

// TreasurySettlementRequest describes one treasury settlement leg after
// execution has been attested, or one preview before settlement is committed.
type TreasurySettlementRequest struct {
	WorkflowID      string
	Operation       *TreasuryOperation
	Counterparty    string
	Beneficiary     string
	Jurisdiction    string
	ReasonCode      string
	PolicyReceipt   *policy.SignedPolicyReceipt
	ExecutionSealID string
	Metadata        map[string]string
}

// TreasurySettlementQuote projects the settlement corridor and admissibility
// outcome without mutating state.
type TreasurySettlementQuote struct {
	QuoteID           string            `json:"quote_id"`
	Eligible          bool              `json:"eligible"`
	ProviderID        string            `json:"provider_id"`
	ProviderStatus    string            `json:"provider_status"`
	CorridorID        string            `json:"corridor_id"`
	Network           string            `json:"network"`
	Method            string            `json:"method"`
	Counterparty      string            `json:"counterparty"`
	Beneficiary       string            `json:"beneficiary"`
	Jurisdiction      string            `json:"jurisdiction"`
	ReasonCode        string            `json:"reason_code"`
	FiatAmount        float64           `json:"fiat_amount"`
	FiatCurrency      string            `json:"fiat_currency"`
	TokenAmount       float64           `json:"token_amount"`
	TokenDenomination string            `json:"token_denomination"`
	ExchangeRate      float64           `json:"exchange_rate"`
	BudgetAllowed     bool              `json:"budget_allowed"`
	BudgetRemaining   float64           `json:"budget_remaining,omitempty"`
	BudgetAction      string            `json:"budget_action,omitempty"`
	Requirements      map[string]string `json:"requirements,omitempty"`
	Violations        []string          `json:"violations,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	GeneratedAt       time.Time         `json:"generated_at"`
}

// PolicyBoundSettlementConfig configures the default regulated settlement rail.
type PolicyBoundSettlementConfig struct {
	ProviderID            string
	ProviderStatus        string
	CorridorID            string
	Network               string
	Method                string
	CustomerID            string
	BudgetID              string
	FiatCurrency          string
	TokenDenomination     string
	ExchangeRate          float64
	AllowedCounterparties []string
	AllowedJurisdictions  []string
	AllowedCurrencies     []string
	RequiredReasonCodes   []string
	MaxFiatAmount         float64
	SpendController       *billing.SpendController
	Metadata              map[string]string
}

// PolicyBoundSettlementRail is an enterprise-grade settlement rail with
// provider/corridor policy, counterparty control, and spend-limit preview.
type PolicyBoundSettlementRail struct {
	config PolicyBoundSettlementConfig
}

// NewPolicyBoundSettlementRail creates a default settlement rail.
func NewPolicyBoundSettlementRail(config PolicyBoundSettlementConfig) *PolicyBoundSettlementRail {
	if strings.TrimSpace(config.ProviderID) == "" {
		config.ProviderID = "aethelred.settlement.default"
	}
	if strings.TrimSpace(config.ProviderStatus) == "" {
		config.ProviderStatus = "active"
	}
	if strings.TrimSpace(config.CorridorID) == "" {
		config.CorridorID = "global-usd-stablecoin"
	}
	if strings.TrimSpace(config.Network) == "" {
		config.Network = "aethelred"
	}
	if strings.TrimSpace(config.Method) == "" {
		config.Method = "stablecoin"
	}
	if strings.TrimSpace(config.TokenDenomination) == "" {
		config.TokenDenomination = "USDC"
	}
	if strings.TrimSpace(config.FiatCurrency) == "" {
		config.FiatCurrency = "USD"
	}
	if config.ExchangeRate <= 0 {
		config.ExchangeRate = 1.0
	}
	config.AllowedCounterparties = trimmedStrings(config.AllowedCounterparties)
	config.AllowedJurisdictions = trimmedStrings(config.AllowedJurisdictions)
	config.AllowedCurrencies = upperTrimmedStrings(config.AllowedCurrencies)
	config.RequiredReasonCodes = trimmedStrings(config.RequiredReasonCodes)
	config.Metadata = cloneStringMap(config.Metadata)
	return &PolicyBoundSettlementRail{config: config}
}

// Quote evaluates the configured corridor and returns a side-effect-free
// admissibility projection for the requested settlement.
func (r *PolicyBoundSettlementRail) Quote(ctx context.Context, req TreasurySettlementRequest) (*TreasurySettlementQuote, error) {
	return r.quote(ctx, req)
}

// Settle enforces counterparty, corridor, and spend controls, then emits
// canonical settlement evidence.
func (r *PolicyBoundSettlementRail) Settle(ctx context.Context, req TreasurySettlementRequest) (*evidence.ValueSettlementEvidence, error) {
	if r == nil {
		return nil, ErrSettlementRailUnavailable
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("finance/settlement: settlement policy receipt is required")
	}
	if strings.TrimSpace(req.PolicyReceipt.ID) == "" || strings.TrimSpace(req.PolicyReceipt.ContentHash) == "" {
		return nil, fmt.Errorf("finance/settlement: settlement policy receipt is missing required fields")
	}
	if !strings.EqualFold(req.PolicyReceipt.Decision, policy.Allow.String()) {
		return nil, fmt.Errorf("%w: settlement policy decision %q", ErrSettlementDenied, req.PolicyReceipt.Decision)
	}

	quote, err := r.quote(ctx, req)
	if err != nil {
		return nil, err
	}
	if !quote.Eligible {
		if providerUnavailable(quote.ProviderStatus) {
			return nil, fmt.Errorf("%w: provider %q status %q", ErrSettlementProviderUnavailable, quote.ProviderID, quote.ProviderStatus)
		}
		return nil, fmt.Errorf("%w: %s", ErrSettlementDenied, strings.Join(quote.Violations, "; "))
	}

	metadata := cloneStringMap(req.Metadata)
	if metadata == nil {
		metadata = make(map[string]string)
	}
	for key, value := range quote.Metadata {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			metadata[key] = value
		}
	}
	metadata["provider_id"] = quote.ProviderID
	metadata["provider_status"] = quote.ProviderStatus
	metadata["corridor_id"] = quote.CorridorID
	metadata["budget_allowed"] = fmt.Sprintf("%t", quote.BudgetAllowed)
	if quote.BudgetRemaining != 0 {
		metadata["budget_remaining"] = fmt.Sprintf("%.2f", quote.BudgetRemaining)
	}
	if strings.TrimSpace(quote.BudgetAction) != "" {
		metadata["budget_action"] = quote.BudgetAction
	}

	if r.config.SpendController != nil && strings.TrimSpace(r.config.CustomerID) != "" {
		budgetResult, err := r.config.SpendController.CheckBudget(ctx, r.config.CustomerID, quote.FiatAmount)
		if err != nil {
			return nil, fmt.Errorf("finance/settlement: budget check failed: %w", err)
		}
		metadata["budget_allowed"] = fmt.Sprintf("%t", budgetResult.Allowed)
		metadata["budget_remaining"] = fmt.Sprintf("%.2f", budgetResult.Remaining)
		if budgetResult.Action != nil {
			metadata["budget_action"] = budgetResult.Action.String()
		}
		if !budgetResult.Allowed {
			return nil, fmt.Errorf("%w: budget controls blocked settlement", ErrSettlementDenied)
		}
	}

	now := time.Now().UTC()
	settlement := &evidence.ValueSettlementEvidence{
		SettlementID:      fmt.Sprintf("stl-%s-%d", req.Operation.ID, now.UnixNano()),
		WorkflowID:        strings.TrimSpace(req.WorkflowID),
		Network:           quote.Network,
		Method:            quote.Method,
		Counterparty:      quote.Counterparty,
		Beneficiary:       quote.Beneficiary,
		FiatAmount:        quote.FiatAmount,
		FiatCurrency:      quote.FiatCurrency,
		TokenAmount:       quote.TokenAmount,
		TokenDenomination: quote.TokenDenomination,
		ExchangeRate:      quote.ExchangeRate,
		Status:            "settled",
		ReasonCode:        quote.ReasonCode,
		Reference:         req.Operation.ID,
		TxHash:            fmt.Sprintf("0x%s%d", req.Operation.ID, now.UnixNano()),
		PolicyReceiptID:   req.PolicyReceipt.ID,
		PolicyReceiptHash: req.PolicyReceipt.ContentHash,
		SealID:            strings.TrimSpace(req.ExecutionSealID),
		SettledAt:         now.Format(time.RFC3339Nano),
		Metadata:          metadata,
	}
	if err := settlement.Normalize(); err != nil {
		return nil, err
	}
	return settlement, nil
}

func (r *PolicyBoundSettlementRail) quote(ctx context.Context, req TreasurySettlementRequest) (*TreasurySettlementQuote, error) {
	if r == nil {
		return nil, ErrSettlementRailUnavailable
	}
	if req.Operation == nil {
		return nil, fmt.Errorf("finance/settlement: operation is required")
	}
	if req.Operation.Amount <= 0 {
		return nil, fmt.Errorf("finance/settlement: amount must be positive")
	}

	counterparty := strings.TrimSpace(req.Counterparty)
	if counterparty == "" {
		counterparty = strings.TrimSpace(req.Operation.Counterparty)
	}
	if counterparty == "" {
		return nil, fmt.Errorf("finance/settlement: counterparty is required")
	}
	fiatCurrency := strings.ToUpper(strings.TrimSpace(firstNonEmpty(req.Operation.Currency, r.config.FiatCurrency)))
	if fiatCurrency == "" {
		return nil, fmt.Errorf("finance/settlement: currency is required")
	}
	jurisdiction := strings.TrimSpace(req.Jurisdiction)
	if jurisdiction == "" {
		jurisdiction = "global"
	}
	reasonCode := strings.TrimSpace(req.ReasonCode)
	if reasonCode == "" {
		reasonCode = "treasury_release"
	}

	metadata := cloneStringMap(req.Metadata)
	if metadata == nil {
		metadata = make(map[string]string)
	}
	for key, value := range r.config.Metadata {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			metadata[key] = value
		}
	}
	metadata["provider_id"] = r.config.ProviderID
	metadata["provider_status"] = normalizeSettlementProviderStatus(r.config.ProviderStatus)
	metadata["corridor_id"] = r.config.CorridorID
	metadata["jurisdiction"] = jurisdiction

	quote := &TreasurySettlementQuote{
		QuoteID:           fmt.Sprintf("stq-%s-%d", req.Operation.ID, time.Now().UTC().UnixNano()),
		ProviderID:        r.config.ProviderID,
		ProviderStatus:    normalizeSettlementProviderStatus(r.config.ProviderStatus),
		CorridorID:        r.config.CorridorID,
		Network:           r.config.Network,
		Method:            r.config.Method,
		Counterparty:      counterparty,
		Beneficiary:       firstNonEmpty(strings.TrimSpace(req.Beneficiary), counterparty),
		Jurisdiction:      jurisdiction,
		ReasonCode:        reasonCode,
		FiatAmount:        req.Operation.Amount,
		FiatCurrency:      fiatCurrency,
		TokenAmount:       req.Operation.Amount * r.config.ExchangeRate,
		TokenDenomination: r.config.TokenDenomination,
		ExchangeRate:      r.config.ExchangeRate,
		BudgetAllowed:     true,
		Requirements: map[string]string{
			"provider_id":        r.config.ProviderID,
			"provider_status":    normalizeSettlementProviderStatus(r.config.ProviderStatus),
			"corridor_id":        r.config.CorridorID,
			"network":            r.config.Network,
			"method":             r.config.Method,
			"token_denomination": r.config.TokenDenomination,
		},
		Metadata:    metadata,
		GeneratedAt: time.Now().UTC(),
	}

	var violations []string
	if providerUnavailable(quote.ProviderStatus) {
		violations = append(violations, fmt.Sprintf("%s: provider %q status %q", ErrSettlementProviderUnavailable.Error(), quote.ProviderID, quote.ProviderStatus))
	}
	if len(r.config.AllowedJurisdictions) > 0 && !containsFold(r.config.AllowedJurisdictions, jurisdiction) {
		violations = append(violations, fmt.Sprintf("%s: jurisdiction %q is not enabled for corridor %q", ErrSettlementJurisdictionDenied.Error(), jurisdiction, quote.CorridorID))
	}
	if len(r.config.AllowedCurrencies) > 0 && !containsFold(r.config.AllowedCurrencies, fiatCurrency) {
		violations = append(violations, fmt.Sprintf("%s: currency %q is not enabled for corridor %q", ErrSettlementCurrencyDenied.Error(), fiatCurrency, quote.CorridorID))
	}
	if len(r.config.AllowedCounterparties) > 0 && !containsFold(r.config.AllowedCounterparties, counterparty) {
		violations = append(violations, fmt.Sprintf("%s: counterparty %q is not allowlisted", ErrSettlementDenied.Error(), counterparty))
	}
	if r.config.MaxFiatAmount > 0 && req.Operation.Amount > r.config.MaxFiatAmount {
		violations = append(violations, fmt.Sprintf("%s: %.2f exceeds corridor ceiling %.2f", ErrSettlementAmountExceeded.Error(), req.Operation.Amount, r.config.MaxFiatAmount))
	}
	if len(r.config.RequiredReasonCodes) > 0 && !containsFold(r.config.RequiredReasonCodes, reasonCode) {
		violations = append(violations, fmt.Sprintf("%s: reason code %q is not approved for corridor %q", ErrSettlementReasonRequired.Error(), reasonCode, quote.CorridorID))
	}

	if preview, ok, err := r.previewBudget(ctx, quote.FiatAmount); err != nil {
		return nil, err
	} else if ok {
		quote.BudgetAllowed = preview.allowed
		quote.BudgetRemaining = preview.remaining
		quote.BudgetAction = preview.action
		if preview.limit > 0 {
			quote.Requirements["budget_limit"] = fmt.Sprintf("%.2f", preview.limit)
		}
		if !preview.allowed {
			violations = append(violations, fmt.Sprintf("%s: projected budget remaining %.2f", ErrSettlementDenied.Error(), preview.remaining))
		}
	}

	quote.Violations = violations
	quote.Eligible = len(violations) == 0
	return quote, nil
}

type settlementBudgetPreview struct {
	allowed   bool
	remaining float64
	action    string
	limit     float64
}

func (r *PolicyBoundSettlementRail) previewBudget(_ context.Context, amount float64) (*settlementBudgetPreview, bool, error) {
	if r.config.SpendController == nil {
		return nil, false, nil
	}
	if strings.TrimSpace(r.config.BudgetID) != "" {
		budget, err := r.config.SpendController.GetBudget(strings.TrimSpace(r.config.BudgetID))
		if err != nil {
			return nil, false, fmt.Errorf("finance/settlement: budget preview failed: %w", err)
		}
		projectedSpend := budget.CurrentSpend + amount
		remaining := budget.Limit - projectedSpend
		if remaining < 0 {
			remaining = 0
		}
		action := ""
		spendPercent := 0.0
		if budget.Limit > 0 {
			spendPercent = (projectedSpend / budget.Limit) * 100.0
		}
		for _, threshold := range budget.AlertThresholds {
			if spendPercent >= threshold.Percent {
				action = threshold.Action.String()
			}
		}
		return &settlementBudgetPreview{
			allowed:   projectedSpend <= budget.Limit,
			remaining: remaining,
			action:    action,
			limit:     budget.Limit,
		}, true, nil
	}
	return nil, false, nil
}

func normalizeSettlementProviderStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		return "active"
	}
	return status
}

func providerUnavailable(status string) bool {
	switch normalizeSettlementProviderStatus(status) {
	case "active":
		return false
	default:
		return true
	}
}

func containsFold(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

func upperTrimmedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, value := range in {
		if trimmed := strings.ToUpper(strings.TrimSpace(value)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func trimmedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, value := range in {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
