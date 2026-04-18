package finance

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestFileTreasuryReleaseStore_SaveGetList(t *testing.T) {
	t.Parallel()

	store, err := NewFileTreasuryReleaseStore(t.TempDir())
	if err != nil {
		t.Fatalf("create file treasury release store: %v", err)
	}

	record := &TreasuryReleaseRecord{
		WorkflowID: "trl-store-1",
		Request: TreasuryReleaseRequest{
			Operation: &TreasuryOperation{
				ID:           "trl-store-1",
				Type:         OpPayment,
				Amount:       4200,
				Currency:     "USD",
				Initiator:    "treasury.bot",
				Counterparty: "Trusted Vendor",
			},
			Jurisdiction: "UAE",
			ReasonCode:   "vendor_payment",
		},
		Result: &TreasuryReleaseResult{
			WorkflowID: "trl-store-1",
			Status:     ReleaseStatusPendingApproval,
			Operation: &TreasuryOperation{
				ID:           "trl-store-1",
				Type:         OpPayment,
				Amount:       4200,
				Currency:     "USD",
				Initiator:    "treasury.bot",
				Counterparty: "Trusted Vendor",
			},
			CreatedAt: time.Now().UTC().Add(-5 * time.Minute),
			UpdatedAt: time.Now().UTC(),
		},
	}

	if err := store.Save(context.Background(), record); err != nil {
		t.Fatalf("save treasury release record: %v", err)
	}

	got, err := store.Get(context.Background(), "trl-store-1")
	if err != nil {
		t.Fatalf("get treasury release record: %v", err)
	}
	if got.Result == nil || got.Result.WorkflowID != "trl-store-1" {
		t.Fatalf("unexpected stored result: %+v", got.Result)
	}

	items, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list treasury release records: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 record, got %d", len(items))
	}

	if _, err := filepath.Abs("trl-store-1"); err != nil {
		t.Fatalf("sanity check abs path failed: %v", err)
	}
}

func TestTreasuryReleaseWorkflow_BuildTrustPack(t *testing.T) {
	t.Parallel()

	workflow, _, _, identity := newTestTreasuryReleaseWorkflow(t, ApprovalPolicy{
		SingleThreshold:    10000,
		DualThreshold:      50000,
		CommitteeThreshold: 250000,
	})

	result, err := workflow.InitiateRelease(context.Background(), TreasuryReleaseRequest{
		Identity:     identity,
		Resource:     "acct:treasury-main",
		Jurisdiction: "UAE",
		ReasonCode:   "vendor_payment",
		Operation: &TreasuryOperation{
			ID:           "trl-pack-1",
			Type:         OpPayment,
			Amount:       4200,
			Currency:     "USD",
			Initiator:    "treasury.bot",
			Description:  "Trust-pack runtime sample",
			Counterparty: "Trusted Vendor",
		},
		Beneficiary: ScreeningEntity{
			Name:       "Trusted Vendor",
			EntityType: "organization",
			Country:    "UAE",
		},
	})
	if err != nil {
		t.Fatalf("initiate release: %v", err)
	}
	if result.Status != ReleaseStatusCompleted {
		t.Fatalf("expected completed workflow, got %s", result.Status)
	}

	pack, err := workflow.BuildTrustPack(context.Background(), FinanceTrustPackOptions{
		OperatorSurfaces: []FinanceOperatorSurface{{
			ID:     "release_list",
			Method: "GET",
			Path:   "/api/v1/finance/treasury/releases",
		}},
	})
	if err != nil {
		t.Fatalf("build trust pack: %v", err)
	}
	if pack.Workflow.PolicySetID == "" || pack.Workflow.Framework == "" {
		t.Fatalf("expected workflow summary, got %+v", pack.Workflow)
	}
	if pack.Runtime.TotalWorkflows != 1 || pack.Runtime.CompletedWorkflows != 1 {
		t.Fatalf("unexpected runtime summary: %+v", pack.Runtime)
	}
	if len(pack.Controls) < 5 {
		t.Fatalf("expected finance controls, got %+v", pack.Controls)
	}
	if len(pack.Regulators) == 0 {
		t.Fatalf("expected regulator templates, got %+v", pack.Regulators)
	}
	if len(pack.OperatorSurfaces) != 1 {
		t.Fatalf("expected operator surface passthrough, got %+v", pack.OperatorSurfaces)
	}
}
