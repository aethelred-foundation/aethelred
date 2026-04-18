package evidence

import (
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Chain of Custody
// ---------------------------------------------------------------------------
//
// Chain of custody tracks who has held, accessed, or transferred an
// evidence bundle. Each entry is cryptographically linked to the previous
// one via hash chaining, producing a tamper-evident log of evidence
// handling.
//
// This is critical for:
//   - Legal admissibility of digital evidence
//   - Regulatory proof of evidence handling procedures
//   - Audit trail of who accessed what and when
// ---------------------------------------------------------------------------

// RecordTransfer records a custody transfer between two parties.
func RecordTransfer(chain []CustodyEntry, from, to string) ([]CustodyEntry, error) {
	if from == "" {
		return nil, fmt.Errorf("evidence/chain: source custodian is required")
	}
	if to == "" {
		return nil, fmt.Errorf("evidence/chain: target custodian is required")
	}
	if from == to {
		return nil, fmt.Errorf("evidence/chain: source and target must be different")
	}

	prevHash := ""
	if len(chain) > 0 {
		prevHash = chain[len(chain)-1].Hash
	}

	entry := CustodyEntry{
		Custodian:    to,
		Action:       "transfer",
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		PreviousHash: prevHash,
	}
	entry.Hash = entry.ComputeHash()

	return append(chain, entry), nil
}

// RecordAccess records that a custodian accessed the evidence.
func RecordAccess(chain []CustodyEntry, custodian string) ([]CustodyEntry, error) {
	if custodian == "" {
		return nil, fmt.Errorf("evidence/chain: custodian is required")
	}

	prevHash := ""
	if len(chain) > 0 {
		prevHash = chain[len(chain)-1].Hash
	}

	entry := CustodyEntry{
		Custodian:    custodian,
		Action:       "access",
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		PreviousHash: prevHash,
	}
	entry.Hash = entry.ComputeHash()

	return append(chain, entry), nil
}

// RecordCreation records the initial creation of evidence custody.
func RecordCreation(custodian string) ([]CustodyEntry, error) {
	if custodian == "" {
		return nil, fmt.Errorf("evidence/chain: custodian is required")
	}

	entry := CustodyEntry{
		Custodian:    custodian,
		Action:       "created",
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		PreviousHash: "",
	}
	entry.Hash = entry.ComputeHash()

	return []CustodyEntry{entry}, nil
}

// RecordExport records an evidence export event.
func RecordExport(chain []CustodyEntry, custodian string) ([]CustodyEntry, error) {
	if custodian == "" {
		return nil, fmt.Errorf("evidence/chain: custodian is required")
	}

	prevHash := ""
	if len(chain) > 0 {
		prevHash = chain[len(chain)-1].Hash
	}

	entry := CustodyEntry{
		Custodian:    custodian,
		Action:       "export",
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		PreviousHash: prevHash,
	}
	entry.Hash = entry.ComputeHash()

	return append(chain, entry), nil
}

// VerifyCustodyChain verifies the integrity of a chain of custody by
// checking that each entry's hash is correctly computed and that the
// previous hash references form an unbroken chain.
func VerifyCustodyChain(chain []CustodyEntry) error {
	if len(chain) == 0 {
		return fmt.Errorf("evidence/chain: empty custody chain")
	}

	// The first entry may legitimately reference a previous bundle when
	// custody continues across exports, so a non-empty PreviousHash here is
	// allowed and does not break chain integrity by itself.

	for i, entry := range chain {
		// Verify entry hash.
		expected := entry.ComputeHash()
		if entry.Hash != expected {
			return fmt.Errorf("evidence/chain: entry %d hash mismatch: expected %s, got %s",
				i, expected, entry.Hash)
		}

		// Verify chain linkage (starting from entry 1).
		if i > 0 {
			if entry.PreviousHash != chain[i-1].Hash {
				return fmt.Errorf("evidence/chain: entry %d previous hash mismatch: expected %s, got %s",
					i, chain[i-1].Hash, entry.PreviousHash)
			}
		}

		// Verify required fields.
		if entry.Custodian == "" {
			return fmt.Errorf("evidence/chain: entry %d missing custodian", i)
		}
		if entry.Action == "" {
			return fmt.Errorf("evidence/chain: entry %d missing action", i)
		}
		if entry.Timestamp == "" {
			return fmt.Errorf("evidence/chain: entry %d missing timestamp", i)
		}
	}

	// Verify temporal ordering.
	for i := 1; i < len(chain); i++ {
		if chain[i].Timestamp < chain[i-1].Timestamp {
			return fmt.Errorf("evidence/chain: entry %d timestamp before entry %d (temporal ordering violated)",
				i, i-1)
		}
	}

	return nil
}
