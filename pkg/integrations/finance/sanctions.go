// Package finance provides integration types and services for financial
// controls including sanctions screening, treasury workflow management,
// SOX-ready audit trails, exception handling, and regulatory reporting.
package finance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Sanctions Screening
// ---------------------------------------------------------------------------

// SanctionsList identifies a specific sanctions list.
type SanctionsList string

const (
	SanctionsOFAC_SDN  SanctionsList = "OFAC_SDN"
	SanctionsOFAC_SSI  SanctionsList = "OFAC_SSI"
	SanctionsEU        SanctionsList = "EU_SANCTIONS"
	SanctionsUN        SanctionsList = "UN_SANCTIONS"
	SanctionsUK        SanctionsList = "UK_SANCTIONS"
)

// SanctionsConfig holds configuration for the sanctions screening service.
type SanctionsConfig struct {
	// ScreeningProvider is the external screening service identifier.
	ScreeningProvider string `json:"screening_provider"`

	// DefaultLists is the set of lists to screen against by default.
	DefaultLists []SanctionsList `json:"default_lists"`

	// CacheTimeout is how long screening results are cached.
	CacheTimeout time.Duration `json:"cache_timeout"`

	// BlockOnMatch determines whether transactions are blocked on a match.
	BlockOnMatch bool `json:"block_on_match"`

	// MatchThreshold is the minimum similarity score to flag a match (0-100).
	MatchThreshold int `json:"match_threshold"`
}

// ScreeningEntity represents an entity to be screened.
type ScreeningEntity struct {
	// Name is the entity name to screen.
	Name string `json:"name"`

	// EntityType is the entity type (individual, organization, vessel).
	EntityType string `json:"entity_type"`

	// Country is the entity's country of registration or nationality.
	Country string `json:"country"`

	// Identifiers holds additional identifiers (passport, tax ID, etc.).
	Identifiers map[string]string `json:"identifiers,omitempty"`

	// Address is the entity's address.
	Address string `json:"address,omitempty"`

	// DateOfBirth for individual entities.
	DateOfBirth string `json:"date_of_birth,omitempty"`
}

// ScreeningTransaction represents a transaction to be screened.
type ScreeningTransaction struct {
	// TransactionID is the unique transaction identifier.
	TransactionID string `json:"transaction_id"`

	// Amount is the transaction amount.
	Amount float64 `json:"amount"`

	// Currency is the currency code (e.g. "USD").
	Currency string `json:"currency"`

	// Originator is the sending entity.
	Originator ScreeningEntity `json:"originator"`

	// Beneficiary is the receiving entity.
	Beneficiary ScreeningEntity `json:"beneficiary"`

	// OriginatorCountry is the originator's country.
	OriginatorCountry string `json:"originator_country"`

	// BeneficiaryCountry is the beneficiary's country.
	BeneficiaryCountry string `json:"beneficiary_country"`

	// Purpose describes the transaction purpose.
	Purpose string `json:"purpose"`
}

// SanctionsMatch represents a potential match against a sanctions list.
type SanctionsMatch struct {
	// ListName identifies which sanctions list matched.
	ListName SanctionsList `json:"list_name"`

	// MatchedName is the name from the sanctions list.
	MatchedName string `json:"matched_name"`

	// MatchScore is the similarity score (0-100).
	MatchScore int `json:"match_score"`

	// ListEntryID is the identifier in the sanctions list.
	ListEntryID string `json:"list_entry_id"`

	// MatchType is the type of match (exact, fuzzy, alias).
	MatchType string `json:"match_type"`

	// Details provides additional information about the match.
	Details string `json:"details"`
}

// ScreeningResult holds the outcome of a sanctions screening.
type ScreeningResult struct {
	// Clear indicates no matches were found.
	Clear bool `json:"clear"`

	// Matches lists all potential sanctions matches.
	Matches []SanctionsMatch `json:"matches"`

	// RiskScore is the overall risk score (0-100).
	RiskScore int `json:"risk_score"`

	// Lists identifies which lists were screened.
	Lists []SanctionsList `json:"lists"`

	// Timestamp is when the screening was performed.
	Timestamp time.Time `json:"timestamp"`

	// SealID links to the sealed screening record.
	SealID string `json:"seal_id"`

	// EntityName is the entity that was screened.
	EntityName string `json:"entity_name"`

	// TransactionID is the transaction if transaction screening.
	TransactionID string `json:"transaction_id,omitempty"`
}

// SanctionsService manages sanctions screening operations.
type SanctionsService struct {
	config  SanctionsConfig
	mu      sync.RWMutex
	results map[string]*ScreeningResult
}

// NewSanctionsService creates a new sanctions screening service.
func NewSanctionsService(config SanctionsConfig) *SanctionsService {
	if len(config.DefaultLists) == 0 {
		config.DefaultLists = []SanctionsList{SanctionsOFAC_SDN, SanctionsEU, SanctionsUN}
	}
	if config.MatchThreshold == 0 {
		config.MatchThreshold = 85
	}
	return &SanctionsService{
		config:  config,
		results: make(map[string]*ScreeningResult),
	}
}

// Config returns a defensive copy of the screening configuration.
func (s *SanctionsService) Config() SanctionsConfig {
	if s == nil {
		return SanctionsConfig{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := s.config
	out.DefaultLists = append([]SanctionsList(nil), s.config.DefaultLists...)
	return out
}

// ScreenEntity screens an entity against sanctions lists.
func (s *SanctionsService) ScreenEntity(_ context.Context, entity ScreeningEntity) (*ScreeningResult, error) {
	if entity.Name == "" {
		return nil, fmt.Errorf("entity name is required")
	}

	result := &ScreeningResult{
		Clear:      true,
		Lists:      s.config.DefaultLists,
		Timestamp:  time.Now().UTC(),
		EntityName: entity.Name,
	}

	// Simulated screening logic — in production this calls an external provider.
	// Check against known sanctioned patterns for demonstration.
	lowerName := strings.ToLower(entity.Name)
	if strings.Contains(lowerName, "sanctioned") || strings.Contains(lowerName, "blocked") {
		result.Clear = false
		result.RiskScore = 95
		result.Matches = append(result.Matches, SanctionsMatch{
			ListName:    SanctionsOFAC_SDN,
			MatchedName: entity.Name,
			MatchScore:  95,
			MatchType:   "exact",
			Details:     "Entity name matches sanctions list entry",
		})
	}

	// Seal the result
	result.SealID = s.sealResult(result)

	s.mu.Lock()
	s.results[result.SealID] = result
	s.mu.Unlock()

	return result, nil
}

// ScreenTransaction screens a transaction against sanctions lists.
func (s *SanctionsService) ScreenTransaction(ctx context.Context, tx ScreeningTransaction) (*ScreeningResult, error) {
	if tx.TransactionID == "" {
		return nil, fmt.Errorf("transaction ID is required")
	}

	// Screen both originator and beneficiary
	origResult, err := s.ScreenEntity(ctx, tx.Originator)
	if err != nil {
		return nil, fmt.Errorf("originator screening failed: %w", err)
	}

	beneResult, err := s.ScreenEntity(ctx, tx.Beneficiary)
	if err != nil {
		return nil, fmt.Errorf("beneficiary screening failed: %w", err)
	}

	// Combine results
	result := &ScreeningResult{
		Clear:         origResult.Clear && beneResult.Clear,
		Lists:         s.config.DefaultLists,
		Timestamp:     time.Now().UTC(),
		EntityName:    fmt.Sprintf("%s -> %s", tx.Originator.Name, tx.Beneficiary.Name),
		TransactionID: tx.TransactionID,
	}

	result.Matches = append(result.Matches, origResult.Matches...)
	result.Matches = append(result.Matches, beneResult.Matches...)

	if origResult.RiskScore > beneResult.RiskScore {
		result.RiskScore = origResult.RiskScore
	} else {
		result.RiskScore = beneResult.RiskScore
	}

	result.SealID = s.sealResult(result)

	s.mu.Lock()
	s.results[result.SealID] = result
	s.mu.Unlock()

	return result, nil
}

// SealScreeningResult seals a screening result as evidence.
func (s *SanctionsService) SealScreeningResult(_ context.Context, result *ScreeningResult) (string, error) {
	if result == nil {
		return "", fmt.Errorf("result is required")
	}

	sealID := s.sealResult(result)
	result.SealID = sealID

	s.mu.Lock()
	s.results[sealID] = result
	s.mu.Unlock()

	return sealID, nil
}

// GetScreeningResult retrieves a screening result by seal ID.
func (s *SanctionsService) GetScreeningResult(_ context.Context, sealID string) (*ScreeningResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result, ok := s.results[sealID]
	if !ok {
		return nil, fmt.Errorf("screening result not found: %s", sealID)
	}
	return result, nil
}

func (s *SanctionsService) sealResult(result *ScreeningResult) string {
	h := sha256.New()
	h.Write([]byte(result.EntityName))
	h.Write([]byte(result.Timestamp.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte(fmt.Sprintf("%d", result.RiskScore)))
	for _, m := range result.Matches {
		h.Write([]byte(m.MatchedName))
	}
	return "seal-scr-" + hex.EncodeToString(h.Sum(nil))[:16]
}
