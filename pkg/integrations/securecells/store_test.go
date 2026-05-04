package securecells

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInMemorySecureCellStore_SaveGetAndClone(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewInMemorySecureCellStore()
	record := &SecureCellRecord{
		CellID: "cell-in-memory",
		Request: SecureCellRequest{
			Name: "In-Memory Cell",
		},
		Result: &SecureCellResult{
			CellID:    "cell-in-memory",
			Name:      "In-Memory Cell",
			Status:    SecureCellStatusActive,
			CreatedAt: time.Date(2026, 4, 18, 10, 0, 0, 0, time.UTC),
			UpdatedAt: time.Date(2026, 4, 18, 10, 1, 0, 0, time.UTC),
		},
		StoredAt: time.Date(2026, 4, 18, 10, 2, 0, 0, time.UTC),
	}

	if err := store.Save(ctx, record); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	got, err := store.Get(ctx, record.CellID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.CellID != record.CellID || got.Result == nil || got.Result.Status != SecureCellStatusActive {
		t.Fatalf("unexpected stored record: %+v", got)
	}

	got.Result.Status = SecureCellStatusPaused
	reloaded, err := store.Get(ctx, record.CellID)
	if err != nil {
		t.Fatalf("Get after local mutation failed: %v", err)
	}
	if reloaded.Result.Status != SecureCellStatusActive {
		t.Fatalf("expected cloned store result to remain active, got %+v", reloaded.Result)
	}
}

func TestFileSecureCellStore_SaveListGetAndRejectUnsafeIDs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewFileSecureCellStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSecureCellStore failed: %v", err)
	}

	older := &SecureCellRecord{
		CellID: "cell-older",
		Request: SecureCellRequest{
			Name: "Older Cell",
		},
		Result: &SecureCellResult{
			CellID:    "cell-older",
			Status:    SecureCellStatusActive,
			UpdatedAt: time.Date(2026, 4, 18, 9, 0, 0, 0, time.UTC),
		},
		StoredAt: time.Date(2026, 4, 18, 9, 5, 0, 0, time.UTC),
	}
	newer := &SecureCellRecord{
		CellID: "cell-newer",
		Request: SecureCellRequest{
			Name: "Newer Cell",
		},
		Result: &SecureCellResult{
			CellID:    "cell-newer",
			Status:    SecureCellStatusPaused,
			UpdatedAt: time.Date(2026, 4, 18, 10, 0, 0, 0, time.UTC),
		},
		StoredAt: time.Date(2026, 4, 18, 10, 5, 0, 0, time.UTC),
	}

	if err := store.Save(ctx, older); err != nil {
		t.Fatalf("Save older failed: %v", err)
	}
	if err := store.Save(ctx, newer); err != nil {
		t.Fatalf("Save newer failed: %v", err)
	}

	items, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected two stored records, got %+v", items)
	}
	if items[0].CellID != newer.CellID || items[1].CellID != older.CellID {
		t.Fatalf("expected most-recent-first order, got %+v", items)
	}

	got, err := store.Get(ctx, newer.CellID)
	if err != nil {
		t.Fatalf("Get newer failed: %v", err)
	}
	if got.Result == nil || got.Result.Status != SecureCellStatusPaused {
		t.Fatalf("unexpected newer result: %+v", got)
	}

	if _, err := store.Get(ctx, "missing-cell"); !errors.Is(err, ErrCellNotFound) {
		t.Fatalf("expected ErrCellNotFound for missing record, got %v", err)
	}
	if err := store.Save(ctx, &SecureCellRecord{
		CellID: "../escape",
		Result: &SecureCellResult{CellID: "../escape", Status: SecureCellStatusActive},
	}); !errors.Is(err, ErrCellNotFound) {
		t.Fatalf("expected unsafe ID save to fail with ErrCellNotFound, got %v", err)
	}
}
