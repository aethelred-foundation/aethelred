package finance

import (
	"context"
	"testing"
)

// ---------------------------------------------------------------------------
// FuzzSanctionsEntityScreening
// ---------------------------------------------------------------------------

// FuzzSanctionsEntityScreening fuzzes entity names through the sanctions
// screening service to verify robustness.
//
// Invariants:
//   - No panics regardless of entity name.
//   - Empty names produce an error.
//   - Non-empty names always return a result with a valid seal ID.
//   - Entities containing "sanctioned" or "blocked" are flagged.
func FuzzSanctionsEntityScreening(f *testing.F) {
	// Seed corpus
	f.Add("Acme Corporation", "organization", "US")
	f.Add("", "", "")
	f.Add("John Doe", "individual", "GB")
	f.Add("Sanctioned Entity LLC", "organization", "IR")
	f.Add("Blocked Person", "individual", "KP")
	f.Add("Normal Business", "organization", "DE")
	f.Add("\x00\xff\t\n", "unknown", "XX")
	f.Add("a]b[c{d}e", "individual", "")

	f.Fuzz(func(t *testing.T, name, entityType, country string) {
		svc := NewSanctionsService(SanctionsConfig{
			MatchThreshold: 85,
			BlockOnMatch:   true,
		})

		entity := ScreeningEntity{
			Name:       name,
			EntityType: entityType,
			Country:    country,
		}

		result, err := svc.ScreenEntity(context.Background(), entity)

		// Invariant 1: empty name returns error
		if name == "" {
			if err == nil {
				t.Error("empty entity name must produce error")
			}
			return
		}

		// Invariant 2: non-empty name succeeds
		if err != nil {
			t.Fatalf("unexpected error for entity %q: %v", name, err)
		}

		// Invariant 3: result has a seal ID
		if result.SealID == "" {
			t.Error("screening result must have a seal ID")
		}

		// Invariant 4: result has a timestamp
		if result.Timestamp.IsZero() {
			t.Error("screening result must have a timestamp")
		}

		// Invariant 5: entity name is recorded
		if result.EntityName != name {
			t.Errorf("entity name = %q; want %q", result.EntityName, name)
		}

		// Invariant 6: "sanctioned" or "blocked" names are flagged
		if containsCaseInsensitive(name, "sanctioned") || containsCaseInsensitive(name, "blocked") {
			if result.Clear {
				t.Errorf("entity %q should be flagged (not clear)", name)
			}
			if len(result.Matches) == 0 {
				t.Errorf("entity %q should have at least one match", name)
			}
			if result.RiskScore == 0 {
				t.Errorf("entity %q should have non-zero risk score", name)
			}
		}
	})
}

// containsCaseInsensitive checks if s contains substr (case-insensitive).
func containsCaseInsensitive(s, substr string) bool {
	if len(substr) == 0 || len(s) < len(substr) {
		return false
	}
	// Simple ASCII-only lowercase comparison
	lower := func(c byte) byte {
		if c >= 'A' && c <= 'Z' {
			return c + 32
		}
		return c
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if lower(s[i+j]) != lower(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// FuzzAmountArithmetic
// ---------------------------------------------------------------------------

// FuzzAmountArithmetic fuzzes financial amount operations through the
// sanctions service to verify transaction screening handles arbitrary
// amounts without overflow or panic.
//
// Invariants:
//   - No panics regardless of input amounts.
//   - Empty transaction ID produces error.
//   - Valid transactions always produce a result.
//   - The result correctly identifies screened parties.
func FuzzAmountArithmetic(f *testing.F) {
	f.Add("tx-001", 100.50, "USD", "Alice Corp", "Bob Inc")
	f.Add("", 0.0, "", "", "")
	f.Add("tx-002", -999999.99, "EUR", "Sender", "Receiver")
	f.Add("tx-003", 1e18, "JPY", "Big Bank", "Small Corp")
	f.Add("tx-004", 0.001, "BTC", "Sanctioned Entity", "Normal Corp")
	f.Add("tx-005", 1e-10, "USD", "", "")

	f.Fuzz(func(t *testing.T, txID string, amount float64, currency, origName, beneName string) {
		svc := NewSanctionsService(SanctionsConfig{
			MatchThreshold: 85,
		})

		tx := ScreeningTransaction{
			TransactionID: txID,
			Amount:        amount,
			Currency:      currency,
			Originator: ScreeningEntity{
				Name:       origName,
				EntityType: "organization",
			},
			Beneficiary: ScreeningEntity{
				Name:       beneName,
				EntityType: "organization",
			},
		}

		result, err := svc.ScreenTransaction(context.Background(), tx)

		// Invariant 1: empty transaction ID produces error
		if txID == "" {
			if err == nil {
				t.Error("empty transaction ID must produce error")
			}
			return
		}

		// Invariant 2: empty originator or beneficiary name produces error
		if origName == "" || beneName == "" {
			if err == nil {
				t.Error("empty party name must produce error")
			}
			return
		}

		// Invariant 3: valid transaction succeeds
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Invariant 4: result has seal ID and transaction ID
		if result.SealID == "" {
			t.Error("result must have seal ID")
		}
		if result.TransactionID != txID {
			t.Errorf("transaction ID = %q; want %q", result.TransactionID, txID)
		}

		// Invariant 5: Clear flag is consistent with matches
		if result.Clear && len(result.Matches) > 0 {
			t.Error("result marked clear but has matches")
		}
		if !result.Clear && len(result.Matches) == 0 {
			t.Error("result not clear but has no matches")
		}
	})
}
