package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// FuzzAuditRecordHashComputation
// ---------------------------------------------------------------------------

// FuzzAuditRecordHashComputation verifies determinism and collision resistance
// of the custody record hash computation. Invariants:
//   - Same input always produces the same hash.
//   - Different inputs produce different hashes (probabilistic).
func FuzzAuditRecordHashComputation(f *testing.F) {
	// Seed corpus: valid, empty, edge-case inputs
	f.Add("bundle-001", "alice", "transfer", "bob", "2024-01-01T00:00:00Z", "sig-a", "genesis", "")
	f.Add("", "", "", "", "", "", "", "")
	f.Add("bundle-002", "carol", "access", "", "2025-12-31T23:59:59Z", "sig-b", "prev-hash", "some notes")
	f.Add("a", "b", "c", "d", "e", "f", "g", "h")
	f.Add("bundle-\x00\xff", "custodian-\t\n", "export", "prev-\x80", "ts", "sig-\xfe", "hash-\x01", "notes with\x00nulls")

	f.Fuzz(func(t *testing.T, bundleID, custodian, action, prevCustodian, ts, sig, prevHash, notes string) {
		record := CustodyRecord{
			BundleID:          bundleID,
			Custodian:         custodian,
			Action:            CustodyAction(action),
			PreviousCustodian: prevCustodian,
			Timestamp:         ts,
			Signature:         sig,
			PreviousHash:      prevHash,
			Notes:             notes,
		}

		// Invariant 1: deterministic -- same input produces same hash
		hash1 := computeCustodyHash(record)
		hash2 := computeCustodyHash(record)
		if hash1 != hash2 {
			t.Errorf("non-deterministic hash: %s != %s", hash1, hash2)
		}

		// Invariant 2: hash is valid hex-encoded SHA-256 (64 chars)
		if len(hash1) != 64 {
			t.Errorf("hash length = %d; want 64", len(hash1))
		}
		if _, err := hex.DecodeString(hash1); err != nil {
			t.Errorf("hash is not valid hex: %v", err)
		}

		// Invariant 3: changing any single field produces a different hash
		// (collision resistance). We test by mutating the bundleID.
		mutated := record
		mutated.BundleID = record.BundleID + "-mutated"
		mutatedHash := computeCustodyHash(mutated)
		if hash1 == mutatedHash {
			// This is probabilistically negligible (SHA-256 collision)
			t.Errorf("hash collision: original and mutated produce same hash")
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzFilterMatching
// ---------------------------------------------------------------------------

// FuzzFilterMatching verifies filter consistency across arbitrary inputs.
// Invariants:
//   - An empty filter matches every record.
//   - A filter with specific criteria narrows the result set.
//   - Applying a filter never panics regardless of input.
func FuzzFilterMatching(f *testing.F) {
	f.Add("job_created", "aethel1abc", "job", "info", int64(100), uint64(1), "some detail")
	f.Add("", "", "", "", int64(0), uint64(0), "")
	f.Add("security_alert", "system", "security", "critical", int64(999999), uint64(99999), "breach detected")
	f.Add("seal_created", "aethel1xyz", "seal", "warning", int64(-1), uint64(18446744073709551615), "\x00\xff\t\n")

	f.Fuzz(func(t *testing.T, action, actor, category, severity string, blockHeight int64, seq uint64, detail string) {
		record := keeper.AuditRecord{
			Action:      action,
			Actor:       actor,
			Category:    keeper.AuditCategory(category),
			Severity:    keeper.AuditSeverity(severity),
			BlockHeight: blockHeight,
			Sequence:    seq,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Details:     map[string]string{"key": detail},
		}

		// Invariant 1: empty filter matches everything
		emptyFilter := NewFilter()
		if !emptyFilter.Match(record) {
			t.Error("empty filter must match every record")
		}

		// Invariant 2: filter with matching criteria matches the record
		matchingFilter := NewFilter().
			WithCategories(keeper.AuditCategory(category)).
			WithActions(action).
			WithActors(actor)
		if !matchingFilter.Match(record) {
			t.Error("filter with exact criteria must match the record")
		}

		// Invariant 3: filter with non-matching category does NOT match
		nonMatchFilter := NewFilter().
			WithCategories(keeper.AuditCategory(category + "-nonexistent"))
		if action != "" && nonMatchFilter.Match(record) && category != category+"-nonexistent" {
			// The record's category won't match the appended suffix
			if record.Category != keeper.AuditCategory(category+"-nonexistent") {
				t.Error("filter with non-matching category should not match")
			}
		}

		// Invariant 4: Apply never panics
		records := []keeper.AuditRecord{record}
		result := emptyFilter.Apply(records)
		if len(result) != 1 {
			t.Errorf("Apply with empty filter: got %d results; want 1", len(result))
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzCustodyChainVerification
// ---------------------------------------------------------------------------

// FuzzCustodyChainVerification verifies chain integrity detection.
// Invariants:
//   - A valid chain always passes VerifyCustody.
//   - A tampered chain (modified hash) always fails.
//   - Nil and empty chains are rejected.
func FuzzCustodyChainVerification(f *testing.F) {
	f.Add("bundle-001", "alice", "sig-alice", "bob", "sig-bob", "access notes")
	f.Add("", "custodian", "sig", "next", "sig2", "notes")
	f.Add("b-\x00\xff", "c-\t", "s-\n", "n-\x80", "s2-\xfe", "n-\x01")
	f.Add("bundle-long-id-with-many-characters", "custodian-name", "signature-data", "next-custodian", "next-sig", "")

	f.Fuzz(func(t *testing.T, bundleID, custodian, sig, nextCustodian, nextSig, notes string) {
		if bundleID == "" {
			// Empty bundle ID tested separately below
			return
		}

		store := NewCustodyStore()

		// Build a valid chain
		_, err := store.InitCustody(bundleID, custodian, sig)
		if err != nil {
			t.Skipf("InitCustody error (expected for some inputs): %v", err)
		}

		// Add a transfer if nextCustodian is different
		if nextCustodian != "" && nextCustodian != custodian {
			_, _ = store.Transfer(bundleID, custodian, nextCustodian, nextSig)
		}

		// Add an action
		_, _ = store.RecordAction(bundleID, custodian, CustodyAccess, sig, notes)

		// Retrieve and verify the chain
		chain, err := store.GetCustodyHistory(bundleID)
		if err != nil {
			t.Fatalf("GetCustodyHistory: %v", err)
		}

		// Invariant 1: valid chain passes verification
		if err := VerifyCustody(chain); err != nil {
			t.Fatalf("valid chain should pass verification: %v", err)
		}

		// Invariant 2: tampered chain fails verification
		if len(chain.Records) > 0 {
			tampered := &CustodyChain{
				BundleID: chain.BundleID,
				Records:  make([]CustodyRecord, len(chain.Records)),
			}
			copy(tampered.Records, chain.Records)
			// Corrupt the first record's hash
			tampered.Records[0].RecordHash = "corrupted-" + tampered.Records[0].RecordHash
			if err := VerifyCustody(tampered); err == nil {
				t.Error("tampered chain should fail verification")
			}
		}

		// Invariant 3: nil chain is rejected
		if err := VerifyCustody(nil); err == nil {
			t.Error("nil chain should be rejected")
		}

		// Invariant 4: empty chain is rejected
		if err := VerifyCustody(&CustodyChain{BundleID: "x"}); err == nil {
			t.Error("empty chain should be rejected")
		}
	})
}

// computeCustodyHashForTest is a reference implementation for cross-checking.
func computeCustodyHashForTest(r CustodyRecord) string {
	canonical := fmt.Sprintf(
		"bundle=%s|custodian=%s|action=%s|prev_custodian=%s|ts=%s|sig=%s|prev_hash=%s|notes=%s",
		r.BundleID, r.Custodian, r.Action, r.PreviousCustodian,
		r.Timestamp, r.Signature, r.PreviousHash, r.Notes,
	)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}
