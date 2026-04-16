package evidence

import (
	"fmt"
	"strings"
)

// ValueSettlementEvidence captures a policy-bound machine-to-machine value
// transfer tied to a regulated workflow.
type ValueSettlementEvidence struct {
	ID                string            `json:"id"`
	SettlementID      string            `json:"settlement_id"`
	WorkflowID        string            `json:"workflow_id,omitempty"`
	Network           string            `json:"network,omitempty"`
	Method            string            `json:"method,omitempty"`
	Counterparty      string            `json:"counterparty,omitempty"`
	Beneficiary       string            `json:"beneficiary,omitempty"`
	FiatAmount        float64           `json:"fiat_amount"`
	FiatCurrency      string            `json:"fiat_currency,omitempty"`
	TokenAmount       float64           `json:"token_amount"`
	TokenDenomination string            `json:"token_denomination,omitempty"`
	ExchangeRate      float64           `json:"exchange_rate,omitempty"`
	Status            string            `json:"status"`
	ReasonCode        string            `json:"reason_code,omitempty"`
	Reference         string            `json:"reference,omitempty"`
	TxHash            string            `json:"tx_hash,omitempty"`
	PolicyReceiptID   string            `json:"policy_receipt_id"`
	PolicyReceiptHash string            `json:"policy_receipt_hash"`
	SealID            string            `json:"seal_id,omitempty"`
	SettledAt         string            `json:"settled_at"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// Normalize validates and fills deterministic defaults for settlement
// evidence.
func (vs *ValueSettlementEvidence) Normalize() error {
	if vs == nil {
		return fmt.Errorf("evidence/value_settlement: nil settlement")
	}
	vs.SettlementID = strings.TrimSpace(vs.SettlementID)
	vs.WorkflowID = strings.TrimSpace(vs.WorkflowID)
	vs.Network = strings.TrimSpace(vs.Network)
	vs.Method = strings.TrimSpace(vs.Method)
	vs.Counterparty = strings.TrimSpace(vs.Counterparty)
	vs.Beneficiary = strings.TrimSpace(vs.Beneficiary)
	vs.FiatCurrency = strings.TrimSpace(vs.FiatCurrency)
	vs.TokenDenomination = strings.TrimSpace(vs.TokenDenomination)
	vs.Status = strings.TrimSpace(vs.Status)
	vs.ReasonCode = strings.TrimSpace(vs.ReasonCode)
	vs.Reference = strings.TrimSpace(vs.Reference)
	vs.TxHash = strings.TrimSpace(vs.TxHash)
	vs.PolicyReceiptID = strings.TrimSpace(vs.PolicyReceiptID)
	vs.PolicyReceiptHash = strings.TrimSpace(vs.PolicyReceiptHash)
	vs.SealID = strings.TrimSpace(vs.SealID)
	vs.SettledAt = strings.TrimSpace(vs.SettledAt)
	vs.Metadata = cloneStringMapPreserve(vs.Metadata)

	if vs.SettlementID == "" {
		return fmt.Errorf("evidence/value_settlement: settlement ID is required")
	}
	if vs.FiatAmount <= 0 {
		return fmt.Errorf("evidence/value_settlement: fiat amount must be positive")
	}
	if vs.FiatCurrency == "" {
		return fmt.Errorf("evidence/value_settlement: fiat currency is required")
	}
	if vs.TokenAmount <= 0 {
		return fmt.Errorf("evidence/value_settlement: token amount must be positive")
	}
	if vs.TokenDenomination == "" {
		return fmt.Errorf("evidence/value_settlement: token denomination is required")
	}
	if vs.Status == "" {
		return fmt.Errorf("evidence/value_settlement: status is required")
	}
	if vs.PolicyReceiptID == "" {
		return fmt.Errorf("evidence/value_settlement: policy receipt ID is required")
	}
	if vs.PolicyReceiptHash == "" {
		return fmt.Errorf("evidence/value_settlement: policy receipt hash is required")
	}
	if vs.SettledAt == "" {
		return fmt.Errorf("evidence/value_settlement: settled_at is required")
	}
	if vs.ID == "" {
		vs.ID = "value-settlement:" + vs.SettlementID
	}
	return nil
}
