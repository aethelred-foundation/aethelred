package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInMemoryControlLedgerStore_SaveGetList(t *testing.T) {
	store := NewInMemoryControlLedgerStore()

	ledgerA := newStoreTestControlLedger(t, "alpha")
	ledgerB := newStoreTestControlLedger(t, "beta")

	if err := store.Save(context.Background(), ledgerB); err != nil {
		t.Fatalf("save beta ledger: %v", err)
	}
	if err := store.Save(context.Background(), ledgerA); err != nil {
		t.Fatalf("save alpha ledger: %v", err)
	}

	got, err := store.Get(context.Background(), ledgerA.Bundle.ID)
	if err != nil {
		t.Fatalf("get alpha ledger: %v", err)
	}
	if got.Bundle.ID != ledgerA.Bundle.ID {
		t.Fatalf("expected ledger id %q, got %q", ledgerA.Bundle.ID, got.Bundle.ID)
	}
	if got.Bundle.ContentHash == "" {
		t.Fatal("expected stored ledger to be finalized")
	}
	got.Metadata["workflow"] = "tampered"
	got.Bundle.Metadata["workflow"] = "tampered"

	gotAgain, err := store.Get(context.Background(), ledgerA.Bundle.ID)
	if err != nil {
		t.Fatalf("get alpha ledger again: %v", err)
	}
	if gotAgain.Metadata["workflow"] != "treasury_release_alpha" {
		t.Fatalf("expected stored metadata to remain unchanged, got %q", gotAgain.Metadata["workflow"])
	}

	list, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list ledgers: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 ledgers, got %d", len(list))
	}
	if list[0].Bundle.ID > list[1].Bundle.ID {
		t.Fatalf("expected deterministic ledger ordering, got %q then %q", list[0].Bundle.ID, list[1].Bundle.ID)
	}
}

func TestFileControlLedgerStore_SaveGetList(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileControlLedgerStore(dir)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}

	ledger := newStoreTestControlLedger(t, "persisted")
	if err := store.Save(context.Background(), ledger); err != nil {
		t.Fatalf("save ledger: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ledger.Bundle.ID+".json")); err != nil {
		t.Fatalf("expected ledger file to exist: %v", err)
	}

	got, err := store.Get(context.Background(), ledger.Bundle.ID)
	if err != nil {
		t.Fatalf("get ledger: %v", err)
	}
	if got.Bundle.ID != ledger.Bundle.ID {
		t.Fatalf("expected ledger id %q, got %q", ledger.Bundle.ID, got.Bundle.ID)
	}
	if got.Bundle.ContentHash == "" {
		t.Fatal("expected file-backed ledger to be finalized")
	}
	got.Controls[0].ControlName = "tampered"

	gotAgain, err := store.Get(context.Background(), ledger.Bundle.ID)
	if err != nil {
		t.Fatalf("get ledger again: %v", err)
	}
	if gotAgain.Controls[0].ControlName != "Treasury Release Approval" {
		t.Fatalf("expected stored control name to remain unchanged, got %q", gotAgain.Controls[0].ControlName)
	}

	list, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list ledgers: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 ledger, got %d", len(list))
	}
	if list[0].Bundle.ID != ledger.Bundle.ID {
		t.Fatalf("expected listed ledger id %q, got %q", ledger.Bundle.ID, list[0].Bundle.ID)
	}
}

func TestControlLedgerStores_RejectUnsafeLedgerIDs(t *testing.T) {
	fileStore, err := NewFileControlLedgerStore(t.TempDir())
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}

	stores := []struct {
		name  string
		store ControlLedgerStore
	}{
		{name: "in-memory", store: NewInMemoryControlLedgerStore()},
		{name: "file", store: fileStore},
	}

	for _, tt := range stores {
		t.Run(tt.name, func(t *testing.T) {
			ledger := newStoreTestControlLedger(t, "unsafe")
			ledger.Bundle.ID = "../escape"

			err := tt.store.Save(context.Background(), ledger)
			if !errors.Is(err, ErrInvalidControlLedgerID) {
				t.Fatalf("expected invalid ledger id error from save, got %v", err)
			}

			_, err = tt.store.Get(context.Background(), "../escape")
			if !errors.Is(err, ErrInvalidControlLedgerID) {
				t.Fatalf("expected invalid ledger id error from get, got %v", err)
			}
		})
	}
}

func newStoreTestControlLedger(t *testing.T, suffix string) *ControlLedger {
	t.Helper()

	ledger := NewControlLedger("Finance Control Ledger")
	ledger.Bundle.ID = "ledger-" + suffix
	ledger.WithMetadata("workflow", "treasury_release_"+suffix)
	ledger.WithMetadata("jurisdiction", "UAE")
	ledger.AddRecord(Record{
		ID:        "record-" + suffix,
		Type:      "governance",
		Action:    "payments.release.authorized",
		Actor:     "did:aethelred:agent-" + suffix,
		Timestamp: "2026-04-14T10:00:00Z",
	})
	ledger.AddAgentPassport(AgentPassportEvidence{
		DID:              "did:aethelred:agent-" + suffix,
		Issuer:           "did:aethelred:issuer-001",
		PublicKeyHash:    "pubkey-" + suffix,
		HumanOwner:       "owner-" + suffix,
		JurisdictionTags: []string{"UAE"},
		AllowedTools:     []string{"payments.release"},
		IssuedAt:         "2026-04-14T10:00:00Z",
	})
	ledger.AddPolicyReceipt(PolicyReceiptEvidence{
		ID:          "receipt-" + suffix,
		RequestID:   "req-" + suffix,
		Actor:       "did:aethelred:agent-" + suffix,
		Action:      "payments.release",
		Resource:    "acct:treasury-main",
		Decision:    "allow",
		AuditTrail:  "trace-" + suffix,
		Signer:      "did:aethelred:policy-gateway-1",
		ContentHash: "hash-" + suffix,
		EvaluatedAt: "2026-04-14T10:01:00Z",
	})
	ledger.AddSeal(Seal{
		SealID:         "seal-" + suffix,
		JobID:          "job-" + suffix,
		OutputHash:     "out-" + suffix,
		ValidatorCount: 4,
		BlockHeight:    123,
		Timestamp:      "2026-04-14T10:02:00Z",
	})
	ledger.AddTraceLink(TraceLink{
		ID:                "link-" + suffix,
		AgentDID:          "did:aethelred:agent-" + suffix,
		PolicyReceiptID:   "receipt-" + suffix,
		PolicyReceiptHash: "hash-" + suffix,
		SealID:            "seal-" + suffix,
		OutputHash:        "out-" + suffix,
		LinkedAt:          "2026-04-14T10:03:00Z",
		Description:       "Treasury approval trace chain",
	})

	if err := ledger.AddControl(LedgerControl{
		ControlID:   "CTRL-" + suffix,
		ControlName: "Treasury Release Approval",
		Status:      ControlSatisfied,
		Description: "Release requires policy and execution proof.",
		EvidenceRefs: ControlEvidenceRefs{
			RecordIDs:        []string{"record-" + suffix},
			PolicyReceiptIDs: []string{"receipt-" + suffix},
			SealIDs:          []string{"seal-" + suffix},
			TraceLinkIDs:     []string{"link-" + suffix},
		},
	}); err != nil {
		t.Fatalf("add control: %v", err)
	}

	return ledger
}
