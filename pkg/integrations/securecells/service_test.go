package securecells

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
	"github.com/aethelred/aethelred/pkg/seal/sdk"
)

type mockSecureCellSealer struct {
	count int
}

func (m *mockSecureCellSealer) CreateSeal(_ context.Context, req sdk.SealRequest) (*sdk.SealResponse, error) {
	m.count++
	return &sdk.SealResponse{
		SealID:       fmt.Sprintf("seal-secure-cell-%d", m.count),
		Timestamp:    time.Now().UTC(),
		BlockHeight:  int64(200 + m.count),
		Purpose:      req.Purpose,
		ValidatorSet: []string{"validator-a", "validator-b"},
	}, nil
}

func TestService_CreateCellActiveHappyPath(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, store, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Cross-Bank Review Cell",
		Purpose:       "counterparty event review",
		Resource:      "cell:counterparty-review",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "bank_a_reviewer"},
			{Identity: participantB, Role: "bank_b_reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "counterparty"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	if result.Status != SecureCellStatusActive {
		t.Fatalf("expected active secure cell, got %s", result.Status)
	}
	if result.CreationReceipt == nil || result.ActivationReceipt == nil {
		t.Fatal("expected both creation and activation policy receipts")
	}
	if result.ReceiptChain == nil || len(result.ReceiptChain.Receipts) != 2 {
		t.Fatalf("expected a two-step receipt chain, got %+v", result.ReceiptChain)
	}
	if result.ExecutionSeal == nil || result.ExecutionSeal.SealID == "" {
		t.Fatal("expected an execution seal")
	}
	if result.ControlLedger == nil {
		t.Fatal("expected a control ledger")
	}
	if result.ControlLedger.Summary.TotalPassports != 3 {
		t.Fatalf("expected 3 passports in the control ledger, got %d", result.ControlLedger.Summary.TotalPassports)
	}
	if result.ControlLedger.Summary.TotalPolicyReceipts != 2 {
		t.Fatalf("expected 2 policy receipts in the control ledger, got %d", result.ControlLedger.Summary.TotalPolicyReceipts)
	}
	if !controlLedgerHasControl(result.ControlLedger, "CELL-CONF-01") {
		t.Fatalf("expected confidential-collaboration control in ledger, got %+v", result.ControlLedger.Controls)
	}
	if result.PortablePackage == nil || result.PortablePackage.PackageHash == "" {
		t.Fatal("expected a portable control-ledger package")
	}
	if result.PortablePackage.Signature == nil {
		t.Fatal("expected the portable package to be signed")
	}
	if result.PortablePackage.AuditAnchor == nil {
		t.Fatal("expected the portable package to be anchored")
	}
	if err := evidence.VerifyPortableControlLedgerPackage(result.PortablePackage); err != nil {
		t.Fatalf("VerifyPortableControlLedgerPackage failed: %v", err)
	}

	stored, err := store.Get(ctx, result.ControlLedger.Bundle.ID)
	if err != nil {
		t.Fatalf("expected stored control ledger, got error: %v", err)
	}
	if stored.Bundle.ContentHash != result.ControlLedger.Bundle.ContentHash {
		t.Fatalf("stored ledger hash mismatch: got %q want %q", stored.Bundle.ContentHash, result.ControlLedger.Bundle.ContentHash)
	}

	loaded, err := service.GetCell(ctx, result.CellID)
	if err != nil {
		t.Fatalf("GetCell failed: %v", err)
	}
	if loaded.CellID != result.CellID || loaded.Status != SecureCellStatusActive {
		t.Fatalf("unexpected loaded secure cell: %+v", loaded)
	}
}

func TestService_CreateCellRejectsWhenConfidentialComputeDisabled(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, _ := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Rejected Review Cell",
		Purpose:       "confidential compute denied path",
		Resource:      "cell:rejected",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			RequireConfidentialCompute: boolPtr(false),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	if result.Status != SecureCellStatusRejected {
		t.Fatalf("expected rejected secure cell, got %s", result.Status)
	}
	if result.CreationReceipt == nil {
		t.Fatal("expected a creation receipt for denied create flow")
	}
	if result.CreationReceipt.Decision != policy.Deny.String() {
		t.Fatalf("expected a deny creation receipt, got %q", result.CreationReceipt.Decision)
	}
	if result.ActivationReceipt != nil || result.PortablePackage != nil || result.ControlLedger != nil {
		t.Fatalf("did not expect final artifacts on denied create flow, got %+v", result)
	}
}

func TestService_CreateCellDerivesDistinctIDsForDistinctRequests(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	first, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Joint Review Cell",
		Purpose:       "shared title",
		Resource:      "cell:uae",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "uae_reviewer"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("first CreateCell failed: %v", err)
	}

	second, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Joint Review Cell",
		Purpose:       "shared title",
		Resource:      "cell:uk",
		Jurisdiction:  "UK",
		Participants: []SecureCellParticipant{
			{Identity: participantB, Role: "uk_reviewer"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("second CreateCell failed: %v", err)
	}

	if first.CellID == second.CellID {
		t.Fatalf("expected distinct secure cell IDs for distinct requests, got %q", first.CellID)
	}
}

func TestService_AdmitMemberRegeneratesLifecycleEvidence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, store, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Cross-Bank Review Cell",
		Purpose:       "counterparty event review",
		Resource:      "cell:counterparty-review",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "bank_a_reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "counterparty"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	admitted, err := service.AdmitMember(ctx, result.CellID, SecureCellAdmissionRequest{
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
			Metadata: map[string]string{"phase": "expansion"},
		},
		Reason:   "approved analyst onboarded",
		Metadata: map[string]string{"ticket": "SC-ADMIT-01"},
	})
	if err != nil {
		t.Fatalf("AdmitMember failed: %v", err)
	}

	if admitted.Status != SecureCellStatusActive {
		t.Fatalf("expected active secure cell after admit, got %s", admitted.Status)
	}
	if len(admitted.Participants) != 2 {
		t.Fatalf("expected 2 active participants after admit, got %d", len(admitted.Participants))
	}
	if len(admitted.Transitions) != 3 {
		t.Fatalf("expected 3 transitions after admit, got %d", len(admitted.Transitions))
	}
	last := admitted.Transitions[len(admitted.Transitions)-1]
	if last.Action != "secure_cell.member_admitted" {
		t.Fatalf("expected member_admitted transition, got %+v", last)
	}
	if last.TargetDID != participantB.AgentID() || last.ParticipantStatusAfter != SecureCellParticipantStatusActive {
		t.Fatalf("unexpected admit transition target/state: %+v", last)
	}
	if admitted.ControlLedger == nil || admitted.PortablePackage == nil {
		t.Fatal("expected regenerated control ledger and portable package")
	}
	if admitted.ControlLedger.Summary.TotalPassports != 3 {
		t.Fatalf("expected 3 passports after admit, got %d", admitted.ControlLedger.Summary.TotalPassports)
	}
	if admitted.ControlLedger.Summary.TotalPolicyReceipts != 3 {
		t.Fatalf("expected 3 policy receipts after admit, got %d", admitted.ControlLedger.Summary.TotalPolicyReceipts)
	}
	if admitted.ControlLedger.Summary.TotalSeals != 2 {
		t.Fatalf("expected 2 seals after admit, got %d", admitted.ControlLedger.Summary.TotalSeals)
	}
	if !controlLedgerHasControl(admitted.ControlLedger, "CELL-LIFE-01") {
		t.Fatalf("expected lifecycle control in ledger, got %+v", admitted.ControlLedger.Controls)
	}
	if err := evidence.VerifyPortableControlLedgerPackage(admitted.PortablePackage); err != nil {
		t.Fatalf("VerifyPortableControlLedgerPackage failed: %v", err)
	}

	stored, err := store.Get(ctx, admitted.ControlLedger.Bundle.ID)
	if err != nil {
		t.Fatalf("expected stored control ledger, got error: %v", err)
	}
	if stored.Bundle.ContentHash != admitted.ControlLedger.Bundle.ContentHash {
		t.Fatalf("stored ledger hash mismatch: got %q want %q", stored.Bundle.ContentHash, admitted.ControlLedger.Bundle.ContentHash)
	}
}

func TestService_QuarantineAndRevokeMemberPreserveLifecycleEvidence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Contained Review Cell",
		Purpose:       "counterparty event review",
		Resource:      "cell:containment-review",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "bank_a_reviewer"},
			{Identity: participantB, Role: "bank_b_reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "counterparty"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	quarantined, err := service.QuarantineMember(ctx, result.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID: participantA.AgentID(),
		Reason:         "suspicious exfiltration alert",
		Metadata:       map[string]string{"incident": "IR-42"},
	})
	if err != nil {
		t.Fatalf("QuarantineMember failed: %v", err)
	}
	if quarantined.Status != SecureCellStatusQuarantined {
		t.Fatalf("expected quarantined secure cell, got %s", quarantined.Status)
	}
	if len(quarantined.Transitions) != 3 {
		t.Fatalf("expected 3 transitions after quarantine, got %d", len(quarantined.Transitions))
	}
	if quarantined.Transitions[len(quarantined.Transitions)-1].Action != "secure_cell.member_quarantined" {
		t.Fatalf("expected quarantine transition, got %+v", quarantined.Transitions[len(quarantined.Transitions)-1])
	}
	if !controlLedgerHasControl(quarantined.ControlLedger, "CELL-CONT-01") {
		t.Fatalf("expected containment control in ledger, got %+v", quarantined.ControlLedger.Controls)
	}

	revoked, err := service.RevokeMember(ctx, result.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID: participantA.AgentID(),
		Reason:         "confirmed policy breach",
		Metadata:       map[string]string{"incident": "IR-42", "resolution": "revoked"},
	})
	if err != nil {
		t.Fatalf("RevokeMember failed while cell quarantined: %v", err)
	}

	if revoked.Status != SecureCellStatusActive {
		t.Fatalf("expected cell to return active after revoke with one active member remaining, got %s", revoked.Status)
	}
	if len(revoked.Transitions) != 4 {
		t.Fatalf("expected 4 transitions after revoke, got %d", len(revoked.Transitions))
	}
	last := revoked.Transitions[len(revoked.Transitions)-1]
	if last.Action != "secure_cell.member_revoked" {
		t.Fatalf("expected revoke transition, got %+v", last)
	}
	if last.CellStatusBefore != SecureCellStatusQuarantined || last.CellStatusAfter != SecureCellStatusActive {
		t.Fatalf("unexpected revoke cell status transition: %+v", last)
	}
	if revoked.ControlLedger.Summary.TotalPolicyReceipts != 4 {
		t.Fatalf("expected 4 policy receipts after revoke flow, got %d", revoked.ControlLedger.Summary.TotalPolicyReceipts)
	}
	if revoked.ControlLedger.Summary.TotalSeals != 3 {
		t.Fatalf("expected 3 seals after revoke flow, got %d", revoked.ControlLedger.Summary.TotalSeals)
	}
	if err := evidence.VerifyPortableControlLedgerPackage(revoked.PortablePackage); err != nil {
		t.Fatalf("VerifyPortableControlLedgerPackage failed: %v", err)
	}
}

func TestService_AdmitMemberRejectedWhileCellQuarantined(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Incident Cell",
		Purpose:       "counterparty event review",
		Resource:      "cell:incident-review",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "bank_a_reviewer"},
		},
		Policy: SecureCellPolicy{
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	if _, err := service.QuarantineMember(ctx, result.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID: participantA.AgentID(),
		Reason:         "containment triggered",
	}); err != nil {
		t.Fatalf("QuarantineMember failed: %v", err)
	}

	_, err = service.AdmitMember(ctx, result.CellID, SecureCellAdmissionRequest{
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason: "admit while quarantined",
	})
	if !errors.Is(err, ErrCellImmutable) {
		t.Fatalf("expected ErrCellImmutable when admitting while quarantined, got %v", err)
	}
}

func TestService_ReleaseAndExpireQuarantinedMembers(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Release Cell",
		Purpose:       "containment release review",
		Resource:      "cell:release-review",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "bank_a_reviewer"},
			{Identity: participantB, Role: "bank_b_reviewer"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	futureExpiry := time.Now().UTC().Add(30 * time.Minute)
	quarantined, err := service.QuarantineMember(ctx, result.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID:      participantA.AgentID(),
		Reason:              "temporary hold",
		QuarantineExpiresAt: &futureExpiry,
	})
	if err != nil {
		t.Fatalf("QuarantineMember failed: %v", err)
	}
	state := mustSecureCellParticipantState(t, quarantined, participantA.AgentID())
	if state.QuarantineExpiresAt == nil || !state.QuarantineExpiresAt.Equal(futureExpiry) {
		t.Fatalf("expected quarantine expiry to be preserved, got %+v", state)
	}

	released, err := service.ReleaseMember(ctx, result.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID: participantA.AgentID(),
		Reason:         "manual clearance approved",
	})
	if err != nil {
		t.Fatalf("ReleaseMember failed: %v", err)
	}
	if released.Status != SecureCellStatusActive {
		t.Fatalf("expected active cell after release, got %s", released.Status)
	}
	last := released.Transitions[len(released.Transitions)-1]
	if last.Action != "secure_cell.member_released" {
		t.Fatalf("expected member_released transition, got %+v", last)
	}
	state = mustSecureCellParticipantState(t, released, participantA.AgentID())
	if state.QuarantineExpiresAt != nil || state.ReleasedAt == nil {
		t.Fatalf("expected released participant to clear quarantine and record release time, got %+v", state)
	}

	pastExpiry := time.Now().UTC().Add(-5 * time.Minute)
	if _, err := service.QuarantineMember(ctx, result.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID:      participantA.AgentID(),
		Reason:              "re-check required",
		QuarantineExpiresAt: &pastExpiry,
	}); err != nil {
		t.Fatalf("second QuarantineMember failed: %v", err)
	}

	expired, err := service.ExpireQuarantinedMembers(ctx, result.CellID, time.Now().UTC(), SecureCellLifecycleRequest{
		Reason:   "expiry sweep",
		Metadata: map[string]string{"sweep": "nightly"},
	})
	if err != nil {
		t.Fatalf("ExpireQuarantinedMembers failed: %v", err)
	}
	if expired.Status != SecureCellStatusActive {
		t.Fatalf("expected active cell after expiry release, got %s", expired.Status)
	}
	last = expired.Transitions[len(expired.Transitions)-1]
	if last.Action != "secure_cell.quarantine_expired" {
		t.Fatalf("expected quarantine_expired transition, got %+v", last)
	}
	if last.Metadata["release_mode"] != "expiry" {
		t.Fatalf("expected expiry release metadata, got %+v", last.Metadata)
	}
}

func TestService_PauseResumeTerminateCellLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Governance Cell",
		Purpose:       "governance review",
		Resource:      "cell:governance-review",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "bank_a_reviewer"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	paused, err := service.PauseCell(ctx, result.CellID, SecureCellLifecycleRequest{
		Reason:   "incident bridge in progress",
		Metadata: map[string]string{"ticket": "SC-PAUSE-01"},
	})
	if err != nil {
		t.Fatalf("PauseCell failed: %v", err)
	}
	if paused.Status != SecureCellStatusPaused || paused.PausedFromStatus != SecureCellStatusActive {
		t.Fatalf("expected paused cell with active resume target, got %+v", paused)
	}
	if paused.Transitions[len(paused.Transitions)-1].Action != "secure_cell.paused" {
		t.Fatalf("expected paused transition, got %+v", paused.Transitions[len(paused.Transitions)-1])
	}

	_, err = service.AdmitMember(ctx, result.CellID, SecureCellAdmissionRequest{
		Participant: SecureCellParticipant{Identity: participantB, Role: "bank_b_reviewer"},
		Reason:      "should fail while paused",
	})
	if !errors.Is(err, ErrCellImmutable) {
		t.Fatalf("expected ErrCellImmutable when admitting while paused, got %v", err)
	}

	resumed, err := service.ResumeCell(ctx, result.CellID, SecureCellLifecycleRequest{
		Reason: "incident resolved",
	})
	if err != nil {
		t.Fatalf("ResumeCell failed: %v", err)
	}
	if resumed.Status != SecureCellStatusActive || resumed.PausedFromStatus != "" {
		t.Fatalf("expected resumed active cell, got %+v", resumed)
	}
	if resumed.Transitions[len(resumed.Transitions)-1].Action != "secure_cell.resumed" {
		t.Fatalf("expected resumed transition, got %+v", resumed.Transitions[len(resumed.Transitions)-1])
	}

	terminated, err := service.TerminateCell(ctx, result.CellID, SecureCellLifecycleRequest{
		Reason: "collaboration permanently closed",
	})
	if err != nil {
		t.Fatalf("TerminateCell failed: %v", err)
	}
	if terminated.Status != SecureCellStatusTerminated || terminated.TerminatedAt == nil {
		t.Fatalf("expected terminated cell, got %+v", terminated)
	}
	if terminated.Transitions[len(terminated.Transitions)-1].Action != "secure_cell.terminated" {
		t.Fatalf("expected terminated transition, got %+v", terminated.Transitions[len(terminated.Transitions)-1])
	}

	_, err = service.QuarantineMember(ctx, result.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID: participantA.AgentID(),
		Reason:         "should fail after terminate",
	})
	if !errors.Is(err, ErrCellImmutable) {
		t.Fatalf("expected ErrCellImmutable after terminate, got %v", err)
	}
}

func TestService_ListCellsFiltersByLifecycleState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	activeCell, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Active Cell",
		Purpose:       "active review",
		Resource:      "cell:active-review",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "bank_a_reviewer"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell active failed: %v", err)
	}

	quarantinedCell, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Quarantined Cell",
		Purpose:       "containment review",
		Resource:      "cell:quarantine-review",
		Jurisdiction:  "UK",
		Participants: []SecureCellParticipant{
			{Identity: participantB, Role: "bank_b_reviewer"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell quarantined failed: %v", err)
	}
	if _, err := service.QuarantineMember(ctx, quarantinedCell.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID: participantB.AgentID(),
		Reason:         "containment triggered",
	}); err != nil {
		t.Fatalf("QuarantineMember failed: %v", err)
	}

	if _, err := service.PauseCell(ctx, activeCell.CellID, SecureCellLifecycleRequest{Reason: "incident bridge"}); err != nil {
		t.Fatalf("PauseCell failed: %v", err)
	}

	summaries, err := service.ListCells(ctx, SecureCellListFilter{
		Statuses: []SecureCellStatus{SecureCellStatusQuarantined},
	})
	if err != nil {
		t.Fatalf("ListCells failed: %v", err)
	}
	if len(summaries) != 1 || summaries[0].CellID != quarantinedCell.CellID {
		t.Fatalf("expected only quarantined cell, got %+v", summaries)
	}

	summaries, err = service.ListCells(ctx, SecureCellListFilter{
		Statuses:       []SecureCellStatus{SecureCellStatusPaused},
		ParticipantDID: participantA.AgentID(),
	})
	if err != nil {
		t.Fatalf("ListCells filtered failed: %v", err)
	}
	if len(summaries) != 1 || summaries[0].CellID != activeCell.CellID {
		t.Fatalf("expected paused active cell summary, got %+v", summaries)
	}
	if summaries[0].PausedFromStatus != SecureCellStatusActive {
		t.Fatalf("expected paused_from_status active, got %+v", summaries[0])
	}
}

func TestService_ListExpiringQuarantinesReturnsExpiredMembers(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Expiry Cell",
		Purpose:       "expiry review",
		Resource:      "cell:expiry-review",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "bank_a_reviewer"},
			{Identity: participantB, Role: "bank_b_reviewer"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	expiredAt := time.Now().UTC().Add(-15 * time.Minute)
	futureAt := time.Now().UTC().Add(30 * time.Minute)
	if _, err := service.QuarantineMember(ctx, result.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID:      participantA.AgentID(),
		Reason:              "expired hold",
		QuarantineExpiresAt: &expiredAt,
	}); err != nil {
		t.Fatalf("QuarantineMember A failed: %v", err)
	}
	if _, err := service.ReleaseMember(ctx, result.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID: participantA.AgentID(),
		Reason:         "manual release",
	}); err != nil {
		t.Fatalf("ReleaseMember A failed: %v", err)
	}
	if _, err := service.QuarantineMember(ctx, result.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID:      participantA.AgentID(),
		Reason:              "expired hold again",
		QuarantineExpiresAt: &expiredAt,
	}); err != nil {
		t.Fatalf("second QuarantineMember A failed: %v", err)
	}
	if _, err := service.QuarantineMember(ctx, result.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID:      participantB.AgentID(),
		Reason:              "future hold",
		QuarantineExpiresAt: &futureAt,
	}); err != nil {
		t.Fatalf("QuarantineMember B failed: %v", err)
	}

	items, err := service.ListExpiringQuarantines(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("ListExpiringQuarantines failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 expiring quarantine, got %+v", items)
	}
	if items[0].ParticipantDID != participantA.AgentID() || items[0].CellID != result.CellID {
		t.Fatalf("unexpected expiring quarantine projection: %+v", items[0])
	}
}

func newTestSecureCellService(t *testing.T) (*Service, evidence.ControlLedgerStore, *agent.AgentIdentity, *agent.AgentIdentity, *agent.AgentIdentity) {
	t.Helper()

	policySignerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate policy signer key: %v", err)
	}
	packageSigningKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	store := evidence.NewInMemoryControlLedgerStore()
	sealer := &mockSecureCellSealer{}

	service, err := NewService(ServiceConfig{
		PolicySignerKey:         policySignerKey,
		PolicySigner:            "did:aethelred:secure-cells-policy",
		CredentialIssuerKey:     policySignerKey,
		CredentialIssuer:        "did:aethelred:secure-cells-issuer",
		Sealer:                  sealer,
		LedgerStore:             store,
		PackageSigningKey:       packageSigningKey,
		PackageSigner:           "validator:secure-cells",
		IncludeVerificationKeys: true,
		PackageAnchorer: func(_ context.Context, pkg *evidence.PortableControlLedgerPackage) error {
			anchor := &evidence.PortableControlLedgerPackageAuditAnchor{
				Sequence:    1,
				Action:      "control_ledger_package_anchored",
				BlockHeight: 1,
				Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
				Actor:       "validator:secure-cells",
				Details:     pkg.AnchorDetails(),
			}
			anchor.RecordHash = anchor.ComputeHash()
			pkg.AuditAnchor = anchor
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	owner := mustSecureCellIdentity(t, "owner", []string{"UAE", "UK"})
	participantA := mustSecureCellIdentity(t, "participant-a", []string{"UAE", "UK"})
	participantB := mustSecureCellIdentity(t, "participant-b", []string{"UAE", "UK"})
	return service, store, owner, participantA, participantB
}

func mustSecureCellIdentity(t *testing.T, label string, jurisdictions []string) *agent.AgentIdentity {
	t.Helper()

	sponsorDID := "did:aethelred:" + label + "-sponsor"
	identity, _, err := agent.NewEnterpriseAgentIdentity([]agent.Capability{
		{Name: secureCellTool, Version: "v1"},
	}, agent.EnterpriseIdentityOptions{
		SponsorChain: []agent.SponsorRecord{
			{
				SponsorDID:        sponsorDID,
				SponsorName:       label + " sponsor",
				Jurisdiction:      jurisdictions[0],
				Role:              "operator",
				LiabilityAccepted: true,
				SignedAt:          time.Now().UTC(),
			},
		},
		Liability: &agent.LiabilityProfile{
			HumanOwner:      label + "@example.com",
			BusinessUnit:    "regulated-autonomy",
			SponsorOfRecord: sponsorDID,
			IncidentContact: "soc@example.com",
			LiabilityModel:  "enterprise-accountable",
		},
		JurisdictionTags: jurisdictions,
		AllowedTools:     []string{secureCellTool},
		Metadata: map[string]string{
			"team": label,
		},
	})
	if err != nil {
		t.Fatalf("NewEnterpriseAgentIdentity failed: %v", err)
	}
	return identity
}

func controlLedgerHasControl(ledger *evidence.ControlLedger, controlID string) bool {
	if ledger == nil {
		return false
	}
	for _, control := range ledger.Controls {
		if control.ControlID == controlID {
			return true
		}
	}
	return false
}

func mustSecureCellParticipantState(t *testing.T, result *SecureCellResult, participantDID string) SecureCellParticipantState {
	t.Helper()
	if result == nil {
		t.Fatal("secure cell result is required")
	}
	for _, participant := range result.Participants {
		if participant.ParticipantDID == participantDID {
			return participant
		}
	}
	t.Fatalf("participant %q not found in %+v", participantDID, result.Participants)
	return SecureCellParticipantState{}
}
