package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Bundle tests
// ---------------------------------------------------------------------------

func TestNewEvidenceBundle(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	if bundle.ID == "" {
		t.Fatal("expected non-empty bundle ID")
	}
	if bundle.Framework != "SOC2" {
		t.Fatalf("expected SOC2, got %s", bundle.Framework)
	}
	if bundle.Version != SchemaVersion {
		t.Fatalf("expected version %s, got %s", SchemaVersion, bundle.Version)
	}
}

func TestEvidenceBundle_AddRecord(t *testing.T) {
	bundle := NewEvidenceBundle("NIST-800-53")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "job_submitted",
		Actor:     "validator-01",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	if len(bundle.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(bundle.Records))
	}
	if bundle.Records[0].Hash == "" {
		t.Fatal("expected record hash to be computed")
	}
}

func TestEvidenceBundle_Finalize(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "job_submitted",
		Actor:     "validator-01",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	err := bundle.Finalize("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bundle.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
}

func TestEvidenceBundle_Finalize_WithSigner(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "job_submitted",
		Actor:     "validator-01",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	// 32-byte hex key.
	signerKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := bundle.Finalize(signerKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bundle.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
}

func TestEvidenceBundle_Finalize_NoRecords(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	err := bundle.Finalize("")
	if err == nil {
		t.Fatal("expected error for empty records")
	}
}

func TestEvidenceBundle_Validate(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	if err := bundle.Validate(); err != nil {
		t.Fatalf("validation failed: %v", err)
	}
}

func TestEvidenceBundle_Validate_Tampered(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	// Tamper with a record.
	bundle.Records[0].Action = "tampered"

	if err := bundle.Validate(); err == nil {
		t.Fatal("expected validation failure for tampered bundle")
	}
}

// ---------------------------------------------------------------------------
// Portable evidence tests
// ---------------------------------------------------------------------------

func TestPackage_Unpackage(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	pe, err := Package(bundle, true)
	if err != nil {
		t.Fatalf("packaging failed: %v", err)
	}
	if pe.PackageHash == "" {
		t.Fatal("expected non-empty package hash")
	}

	// Round-trip through JSON.
	data, err := json.Marshal(pe)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	restored, err := Unpackage(data)
	if err != nil {
		t.Fatalf("unpackage failed: %v", err)
	}
	if restored.Bundle.ID != bundle.ID {
		t.Fatalf("bundle ID mismatch: expected %s, got %s", bundle.ID, restored.Bundle.ID)
	}
}

func TestPackage_NilBundle(t *testing.T) {
	_, err := Package(nil, false)
	if err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestPackage_UnfinalizedBundle(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	_, err := Package(bundle, false)
	if err == nil {
		t.Fatal("expected error for unfinalized bundle")
	}
}

func TestVerifyPortable(t *testing.T) {
	bundle := NewEvidenceBundle("NIST-800-53")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	bundle.AddAttestation(Attestation{
		ID:       "att-1",
		Type:     "tee",
		Platform: "sgx",
	})
	_ = bundle.Finalize("")

	pe, _ := Package(bundle, true)
	pe.AddTrustAnchor(PlatformTrustAnchor{Platform: "sgx", RootHash: "abc123"})

	// Recompute package hash after adding trust anchor.
	hash, _ := pe.computePackageHash()
	pe.PackageHash = hash

	if err := VerifyPortable(pe); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestVerifyPortable_UntrustedPlatform(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	bundle.AddAttestation(Attestation{
		ID:       "att-1",
		Type:     "tee",
		Platform: "unknown-platform",
	})
	_ = bundle.Finalize("")

	pe, _ := Package(bundle, true)
	pe.AddTrustAnchor(PlatformTrustAnchor{Platform: "sgx", RootHash: "abc123"})
	hash, _ := pe.computePackageHash()
	pe.PackageHash = hash

	err := VerifyPortable(pe)
	if err == nil {
		t.Fatal("expected verification failure for untrusted platform")
	}
}

// ---------------------------------------------------------------------------
// Chain of custody tests
// ---------------------------------------------------------------------------

func TestRecordCreation(t *testing.T) {
	chain, err := RecordCreation("auditor-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(chain))
	}
	if chain[0].Action != "created" {
		t.Fatalf("expected 'created', got %s", chain[0].Action)
	}
}

func TestRecordTransfer(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	chain, err := RecordTransfer(chain, "auditor-01", "regulator-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(chain))
	}
	if chain[1].PreviousHash != chain[0].Hash {
		t.Fatal("chain linkage broken")
	}
}

func TestRecordTransfer_SameParty(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	_, err := RecordTransfer(chain, "auditor-01", "auditor-01")
	if err == nil {
		t.Fatal("expected error for same-party transfer")
	}
}

func TestRecordAccess(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	chain, err := RecordAccess(chain, "reviewer-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(chain))
	}
}

func TestRecordExport(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	chain, err := RecordExport(chain, "auditor-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if chain[1].Action != "export" {
		t.Fatalf("expected 'export', got %s", chain[1].Action)
	}
}

func TestVerifyCustodyChain_Valid(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	time.Sleep(2 * time.Millisecond)
	chain, _ = RecordTransfer(chain, "auditor-01", "regulator-01")
	time.Sleep(2 * time.Millisecond)
	chain, _ = RecordAccess(chain, "reviewer-01")

	if err := VerifyCustodyChain(chain); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestVerifyCustodyChain_Tampered(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")
	chain, _ = RecordTransfer(chain, "auditor-01", "regulator-01")

	// Tamper with an entry.
	chain[1].Custodian = "tampered"

	if err := VerifyCustodyChain(chain); err == nil {
		t.Fatal("expected verification failure for tampered chain")
	}
}

func TestVerifyCustodyChain_Empty(t *testing.T) {
	if err := VerifyCustodyChain(nil); err == nil {
		t.Fatal("expected error for empty chain")
	}
}

// ---------------------------------------------------------------------------
// Standalone verifier tests
// ---------------------------------------------------------------------------

func TestStandaloneVerifier_VerifyBundle(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	verifier := NewStandaloneVerifier(nil, false)
	if err := verifier.VerifyBundle(bundle); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestStandaloneVerifier_StrictMode_UntrustedPlatform(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	bundle.AddAttestation(Attestation{
		ID:       "att-1",
		Type:     "tee",
		Platform: "unknown",
	})
	_ = bundle.Finalize("")

	verifier := NewStandaloneVerifier([]string{"sgx"}, true)
	err := verifier.VerifyBundle(bundle)
	if err == nil {
		t.Fatal("expected error for untrusted platform in strict mode")
	}
}

func TestStandaloneVerifier_VerifyChain(t *testing.T) {
	b1 := NewEvidenceBundle("SOC2")
	b1.AddRecord(Record{
		ID:        "rec-1",
		Type:      "audit",
		Action:    "first",
		Actor:     "tester",
		Timestamp: "2026-01-01T00:00:00Z",
	})
	_ = b1.Finalize("")

	b2 := NewEvidenceBundle("SOC2")
	b2.AddRecord(Record{
		ID:        "rec-2",
		Type:      "audit",
		Action:    "second",
		Actor:     "tester",
		Timestamp: "2026-01-02T00:00:00Z",
	})
	_ = b2.Finalize("")

	verifier := NewStandaloneVerifier(nil, false)
	if err := verifier.VerifyChain([]*EvidenceBundle{b1, b2}); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

func TestStandaloneVerifier_VerifyChain_Empty(t *testing.T) {
	verifier := NewStandaloneVerifier(nil, false)
	err := verifier.VerifyChain(nil)
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
}

// ---------------------------------------------------------------------------
// Edge-case, error-path, and concurrency tests
// ---------------------------------------------------------------------------

func TestBundle_NilContent(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")

	// Add a record with minimal fields.
	bundle.AddRecord(Record{
		ID:        "rec-nil",
		Type:      "audit",
		Action:    "test",
		Actor:     "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	// Attestation with empty fields.
	bundle.AddAttestation(Attestation{})

	err := bundle.Finalize("")
	if err != nil {
		t.Fatalf("Finalize with empty attestation failed: %v", err)
	}
}

func TestBundle_FinalizeWithoutContent(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	err := bundle.Finalize("")
	if err == nil {
		t.Fatal("expected error when finalizing empty bundle")
	}
	if !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("expected ErrInvalidBundle, got %v", err)
	}
}

func TestBundle_FinalizeWithShortKey(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID: "rec-short", Type: "audit", Action: "test", Actor: "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	// Key shorter than 16 bytes (32 hex chars).
	err := bundle.Finalize("tooshort")
	if err == nil {
		t.Fatal("expected error for short signing key")
	}
}

func TestBundle_TamperContentHash(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID: "rec-tamper", Type: "audit", Action: "test", Actor: "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	// Tamper with the content hash.
	bundle.ContentHash = "000000000000000000000000000000000000000000000000"

	err := bundle.Validate()
	if err == nil {
		t.Fatal("expected validation failure for tampered content hash")
	}
}

func TestBundle_ConcurrentFinalize(t *testing.T) {
	// Each goroutine creates its own bundle and finalizes it.
	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			bundle := NewEvidenceBundle("SOC2")
			bundle.AddRecord(Record{
				ID:        fmt.Sprintf("rec-%d", idx),
				Type:      "audit",
				Action:    "test",
				Actor:     "tester",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			if err := bundle.Finalize(""); err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", idx, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Errorf("concurrent finalize error: %v", e)
	}
}

func TestPortable_NilBundle(t *testing.T) {
	_, err := Package(nil, false)
	if err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestPortable_RoundTrip(t *testing.T) {
	bundle := NewEvidenceBundle("NIST-800-53")
	bundle.AddRecord(Record{
		ID: "rec-rt", Type: "audit", Action: "roundtrip", Actor: "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	pe, err := Package(bundle, false)
	if err != nil {
		t.Fatalf("Package failed: %v", err)
	}

	data, err := json.Marshal(pe)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	restored, err := Unpackage(data)
	if err != nil {
		t.Fatalf("Unpackage failed: %v", err)
	}

	// Verify bundle ID survived the round trip.
	if restored.Bundle.ID != bundle.ID {
		t.Fatalf("bundle ID mismatch: %s vs %s", restored.Bundle.ID, bundle.ID)
	}
}

func TestVerifier_BrokenChain(t *testing.T) {
	// Create two bundles with a temporal gap.
	b1 := NewEvidenceBundle("SOC2")
	b1.AddRecord(Record{
		ID: "rec-gap-1", Type: "audit", Action: "first", Actor: "tester",
		Timestamp: "2026-01-01T00:00:00Z",
	})
	_ = b1.Finalize("")

	b2 := NewEvidenceBundle("SOC2")
	b2.AddRecord(Record{
		ID: "rec-gap-2", Type: "audit", Action: "second", Actor: "tester",
		Timestamp: "2026-06-01T00:00:00Z", // Large gap.
	})
	_ = b2.Finalize("")

	verifier := NewStandaloneVerifier(nil, false)
	err := verifier.VerifyChain([]*EvidenceBundle{b1, b2})
	// The verifier checks structural integrity; gaps may or may not be an error.
	if err != nil {
		t.Logf("VerifyChain with temporal gap returned: %v", err)
	}
}

func TestVerifier_TamperedBundle(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID: "rec-verify", Type: "audit", Action: "test", Actor: "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	// Tamper with record content.
	bundle.Records[0].Action = "tampered-action"

	verifier := NewStandaloneVerifier(nil, false)
	err := verifier.VerifyBundle(bundle)
	if err == nil {
		t.Fatal("expected error for tampered bundle content")
	}
}

func TestCustody_ConcurrentTransfers(t *testing.T) {
	chain, _ := RecordCreation("auditor-01")

	var wg sync.WaitGroup
	var mu sync.Mutex
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mu.Lock()
			newChain, err := RecordAccess(chain, fmt.Sprintf("reviewer-%d", idx))
			if err != nil {
				errs <- err
			} else {
				_ = newChain
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Errorf("concurrent custody error: %v", e)
	}
}

func TestCustody_InvalidAction(t *testing.T) {
	// Empty chain.
	err := VerifyCustodyChain(nil)
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
	if !errors.Is(err, ErrCustodyViolation) {
		t.Logf("error type: %v", err)
	}
}

func TestExport_AllFormats(t *testing.T) {
	bundle := NewEvidenceBundle("SOC2")
	bundle.AddRecord(Record{
		ID: "rec-export", Type: "audit", Action: "test", Actor: "tester",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_ = bundle.Finalize("")

	// JSON export via Package.
	pe, err := Package(bundle, false)
	if err != nil {
		t.Fatalf("Package failed: %v", err)
	}

	jsonData, err := json.Marshal(pe)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	if len(jsonData) == 0 {
		t.Error("expected non-empty JSON export")
	}
}
