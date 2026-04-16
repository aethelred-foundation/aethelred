package securecells

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
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

type capturingSecureCellEvents struct {
	mu     sync.Mutex
	events []SecureCellLifecycleEvent
}

func (c *capturingSecureCellEvents) Publish(_ context.Context, event SecureCellLifecycleEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
}

func (c *capturingSecureCellEvents) Events() []SecureCellLifecycleEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]SecureCellLifecycleEvent, len(c.events))
	copy(out, c.events)
	return out
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

func TestService_SessionLifecycleAndSharedOutputs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Collaboration Cell",
		Purpose:       "session-based collaboration",
		Resource:      "cell:collaboration",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
			{Identity: participantB, Role: "reviewer_b"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, result.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Morning Risk Review",
		Purpose:         "cross-bank escalation review",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "review window opened",
		Metadata:        map[string]string{"room": "A3"},
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	if len(started.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %+v", started.Sessions)
	}
	session := started.Sessions[0]
	if session.Status != SecureCellSessionStatusActive {
		t.Fatalf("expected active session, got %+v", session)
	}
	if !controlLedgerHasControl(started.ControlLedger, "CELL-SESS-01") {
		t.Fatalf("expected session control in ledger, got %+v", started.ControlLedger.Controls)
	}

	shared, err := service.ShareOutput(ctx, result.CellID, SecureCellSessionShareRequest{
		ActorDID:       participantA.AgentID(),
		SessionID:      session.ID,
		Name:           "Escalation Memo",
		ArtifactType:   "memo",
		Classification: "decisioning",
		Summary:        "counterparty exception memo",
		SharedWith:     []string{participantB.AgentID()},
		Reason:         "memo circulated for review",
		Metadata:       map[string]string{"ticket": "SC-SHARE-01"},
	})
	if err != nil {
		t.Fatalf("ShareOutput failed: %v", err)
	}
	if len(shared.SharedOutputs) != 1 {
		t.Fatalf("expected 1 shared output, got %+v", shared.SharedOutputs)
	}
	output := shared.SharedOutputs[0]
	if output.SessionID != session.ID || output.IntegrityHash == "" {
		t.Fatalf("unexpected shared output: %+v", output)
	}
	if len(output.ChainOfCustody) < 2 {
		t.Fatalf("expected custody chain on shared output, got %+v", output.ChainOfCustody)
	}
	if output.PolicyReceiptID == "" || output.SealID == "" || output.TraceLinkID == "" {
		t.Fatalf("expected policy/seal/trace provenance on shared output, got %+v", output)
	}
	if !controlLedgerHasControl(shared.ControlLedger, "CELL-SHARE-01") {
		t.Fatalf("expected share control in ledger, got %+v", shared.ControlLedger.Controls)
	}
	if err := evidence.VerifyPortableControlLedgerPackage(shared.PortablePackage); err != nil {
		t.Fatalf("VerifyPortableControlLedgerPackage failed: %v", err)
	}

	closed, err := service.CloseSession(ctx, result.CellID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "review closed",
	}, session.ID)
	if err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}
	closedSession, ok := mustSecureCellSession(t, closed, session.ID)
	if !ok || closedSession.Status != SecureCellSessionStatusClosed || closedSession.ClosedAt == nil {
		t.Fatalf("expected closed session, got %+v", closedSession)
	}
	last := closed.Transitions[len(closed.Transitions)-1]
	if last.Action != "secure_cell.session_closed" || last.SessionID != session.ID {
		t.Fatalf("expected session_closed transition, got %+v", last)
	}
}

func TestService_SharingRejectedForClosedSession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Closed Session Cell",
		Purpose:       "session shutdown guard",
		Resource:      "cell:session-closed",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
			{Identity: participantB, Role: "reviewer_b"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, result.CellID, SecureCellSessionStartRequest{
		ActorDID: owner.AgentID(),
		Name:     "One Shot Session",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session, ok := mustSecureCellSession(t, started, started.Sessions[0].ID)
	if !ok {
		t.Fatalf("expected session in result, got %+v", started.Sessions)
	}
	if _, err := service.CloseSession(ctx, result.CellID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "done",
	}, session.ID); err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}

	_, err = service.ShareOutput(ctx, result.CellID, SecureCellSessionShareRequest{
		ActorDID:       participantA.AgentID(),
		SessionID:      session.ID,
		Name:           "Late Memo",
		ArtifactType:   "memo",
		Classification: "confidential",
		SharedWith:     []string{participantB.AgentID()},
	})
	if !errors.Is(err, ErrSessionNotActive) {
		t.Fatalf("expected ErrSessionNotActive, got %v", err)
	}
}

func TestService_SessionGovernanceAndExchangeLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Governed Session Cell",
		Purpose:       "room-level governance",
		Resource:      "cell:session-governance",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
			{Identity: participantB, Role: "reviewer_b"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, result.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Incident Pod",
		Purpose:         "narrow incident room",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "room opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session, ok := mustSecureCellSession(t, started, started.Sessions[0].ID)
	if !ok {
		t.Fatalf("expected session in result, got %+v", started.Sessions)
	}
	if len(session.ParticipantDIDs) != 1 || session.ParticipantDIDs[0] != participantA.AgentID() {
		t.Fatalf("expected single-member session, got %+v", session)
	}

	withMember, err := service.AddSessionMember(ctx, result.CellID, SecureCellSessionMemberTransitionRequest{
		ParticipantDID: participantB.AgentID(),
		ActorDID:       owner.AgentID(),
		Reason:         "reviewer admitted",
		Metadata:       map[string]string{"ticket": "SC-SESS-ADD-01"},
	}, session.ID)
	if err != nil {
		t.Fatalf("AddSessionMember failed: %v", err)
	}
	session, ok = mustSecureCellSession(t, withMember, session.ID)
	if !ok || len(session.ParticipantDIDs) != 2 {
		t.Fatalf("expected two-member session, got %+v", session)
	}

	exchanged, err := service.RecordExchange(ctx, result.CellID, SecureCellSessionExchangeRequest{
		ActorDID:       participantA.AgentID(),
		SessionID:      session.ID,
		Name:           "Risk Note",
		ExchangeType:   "message",
		Classification: "decisioning",
		Summary:        "live escalation note",
		Recipients:     []string{participantB.AgentID()},
		Reason:         "risk note sent",
		Metadata:       map[string]string{"ticket": "SC-SESS-XCHG-01"},
	})
	if err != nil {
		t.Fatalf("RecordExchange failed: %v", err)
	}
	if len(exchanged.SessionExchanges) != 1 {
		t.Fatalf("expected 1 session exchange, got %+v", exchanged.SessionExchanges)
	}
	exchange := exchanged.SessionExchanges[0]
	if exchange.SessionID != session.ID || exchange.PolicyReceiptID == "" || exchange.SealID == "" || exchange.TraceLinkID == "" {
		t.Fatalf("expected evidence-bearing exchange, got %+v", exchange)
	}
	if !controlLedgerHasControl(exchanged.ControlLedger, "CELL-MSG-01") {
		t.Fatalf("expected session exchange control in ledger, got %+v", exchanged.ControlLedger.Controls)
	}

	paused, err := service.PauseSession(ctx, result.CellID, session.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "room frozen",
	})
	if err != nil {
		t.Fatalf("PauseSession failed: %v", err)
	}
	session, ok = mustSecureCellSession(t, paused, session.ID)
	if !ok || session.Status != SecureCellSessionStatusPaused {
		t.Fatalf("expected paused session, got %+v", session)
	}

	_, err = service.RecordExchange(ctx, result.CellID, SecureCellSessionExchangeRequest{
		ActorDID:       participantA.AgentID(),
		SessionID:      session.ID,
		Name:           "Late Note",
		ExchangeType:   "message",
		Classification: "decisioning",
		Recipients:     []string{participantB.AgentID()},
	})
	if !errors.Is(err, ErrSessionNotActive) {
		t.Fatalf("expected ErrSessionNotActive while paused, got %v", err)
	}

	resumed, err := service.ResumeSession(ctx, result.CellID, session.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "room reopened",
	})
	if err != nil {
		t.Fatalf("ResumeSession failed: %v", err)
	}
	session, ok = mustSecureCellSession(t, resumed, session.ID)
	if !ok || session.Status != SecureCellSessionStatusActive {
		t.Fatalf("expected active session after resume, got %+v", session)
	}

	quarantined, err := service.QuarantineSession(ctx, result.CellID, session.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "session containment",
	})
	if err != nil {
		t.Fatalf("QuarantineSession failed: %v", err)
	}
	session, ok = mustSecureCellSession(t, quarantined, session.ID)
	if !ok || session.Status != SecureCellSessionStatusQuarantined || session.QuarantinedAt == nil {
		t.Fatalf("expected quarantined session, got %+v", session)
	}
	if quarantined.Status != SecureCellStatusActive {
		t.Fatalf("expected parent cell to remain active, got %s", quarantined.Status)
	}

	trimmed, err := service.RemoveSessionMember(ctx, result.CellID, SecureCellSessionMemberTransitionRequest{
		ParticipantDID: participantB.AgentID(),
		ActorDID:       owner.AgentID(),
		Reason:         "reduce blast radius",
		Metadata:       map[string]string{"ticket": "SC-SESS-RM-01"},
	}, session.ID)
	if err != nil {
		t.Fatalf("RemoveSessionMember failed: %v", err)
	}
	session, ok = mustSecureCellSession(t, trimmed, session.ID)
	if !ok || len(session.ParticipantDIDs) != 1 || session.ParticipantDIDs[0] != participantA.AgentID() {
		t.Fatalf("expected session membership trimmed to participant A, got %+v", session)
	}
	last := trimmed.Transitions[len(trimmed.Transitions)-1]
	if last.Action != "secure_cell.session_member_removed" {
		t.Fatalf("expected session_member_removed transition, got %+v", last)
	}
}

func TestService_SessionThreadLifecycleAndExchangeContainment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Threaded Session Cell",
		Purpose:       "thread-scoped containment",
		Resource:      "cell:thread-governance",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
			{Identity: participantB, Role: "reviewer_b"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, result.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Credit Review",
		Purpose:         "shared review room",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		DataClasses:     []string{"confidential", "decisioning"},
		Reason:          "session opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session, ok := mustSecureCellSession(t, started, started.Sessions[0].ID)
	if !ok {
		t.Fatalf("expected started session, got %+v", started.Sessions)
	}

	threaded, err := service.StartThread(ctx, result.CellID, SecureCellSessionThreadStartRequest{
		SessionID:       session.ID,
		ActorDID:        owner.AgentID(),
		Name:            "Escalation Thread",
		Purpose:         "high-risk substream",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "targeted workstream opened",
		Metadata:        map[string]string{"ticket": "SC-THREAD-01"},
	})
	if err != nil {
		t.Fatalf("StartThread failed: %v", err)
	}
	thread, ok := mustSecureCellThread(t, threaded, threaded.Threads[0].ID)
	if !ok {
		t.Fatalf("expected started thread, got %+v", threaded.Threads)
	}
	if thread.Status != SecureCellThreadStatusActive || len(thread.ParticipantDIDs) != 1 || thread.ParticipantDIDs[0] != participantA.AgentID() {
		t.Fatalf("expected active single-participant thread, got %+v", thread)
	}
	if !controlLedgerHasControl(threaded.ControlLedger, "CELL-THREAD-01") {
		t.Fatalf("expected thread control in ledger, got %+v", threaded.ControlLedger.Controls)
	}

	messaged, err := service.PostThreadMessage(ctx, result.CellID, SecureCellThreadMessageRequest{
		ThreadID:       thread.ID,
		ActorDID:       participantA.AgentID(),
		Name:           "Escalation Update",
		ExchangeType:   "message",
		Classification: "decisioning",
		Resource:       "secure-cell:thread:message:update",
		Summary:        "risk threshold breached",
		Recipients:     []string{participantA.AgentID()},
		Reason:         "thread update sent",
		Metadata:       map[string]string{"ticket": "SC-THREAD-MSG-01"},
	})
	if err != nil {
		t.Fatalf("PostThreadMessage failed: %v", err)
	}
	if len(messaged.SessionExchanges) != 1 {
		t.Fatalf("expected 1 thread exchange, got %+v", messaged.SessionExchanges)
	}
	exchange := messaged.SessionExchanges[0]
	if exchange.ThreadID != thread.ID || exchange.PolicyReceiptID == "" || exchange.SealID == "" || exchange.TraceLinkID == "" {
		t.Fatalf("expected evidence-bearing thread exchange, got %+v", exchange)
	}
	thread, ok = mustSecureCellThread(t, messaged, thread.ID)
	if !ok || len(thread.ExchangeIDs) != 1 || thread.ExchangeIDs[0] != exchange.ID {
		t.Fatalf("expected thread exchange linked into thread state, got %+v", thread)
	}
	if !controlLedgerHasControl(messaged.ControlLedger, "CELL-THREAD-MSG-01") {
		t.Fatalf("expected thread message control in ledger, got %+v", messaged.ControlLedger.Controls)
	}

	quarantined, err := service.QuarantineThread(ctx, result.CellID, session.ID, thread.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "contain substream",
		Metadata: map[string]string{"ticket": "SC-THREAD-Q-01"},
	})
	if err != nil {
		t.Fatalf("QuarantineThread failed: %v", err)
	}
	thread, ok = mustSecureCellThread(t, quarantined, thread.ID)
	if !ok || thread.Status != SecureCellThreadStatusQuarantined || thread.QuarantinedAt == nil {
		t.Fatalf("expected quarantined thread, got %+v", thread)
	}
	if quarantined.Status != SecureCellStatusActive {
		t.Fatalf("expected parent cell to remain active, got %s", quarantined.Status)
	}
	session, ok = mustSecureCellSession(t, quarantined, session.ID)
	if !ok || session.Status != SecureCellSessionStatusActive {
		t.Fatalf("expected parent session to remain active, got %+v", session)
	}

	_, err = service.PostThreadMessage(ctx, result.CellID, SecureCellThreadMessageRequest{
		ThreadID:       thread.ID,
		ActorDID:       participantA.AgentID(),
		Name:           "Blocked Update",
		ExchangeType:   "message",
		Classification: "decisioning",
		Recipients:     []string{participantA.AgentID()},
	})
	if !errors.Is(err, ErrThreadNotActive) {
		t.Fatalf("expected ErrThreadNotActive while thread quarantined, got %v", err)
	}

	resumed, err := service.ResumeThread(ctx, result.CellID, session.ID, thread.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "substream restored",
	})
	if err != nil {
		t.Fatalf("ResumeThread failed: %v", err)
	}
	thread, ok = mustSecureCellThread(t, resumed, thread.ID)
	if !ok || thread.Status != SecureCellThreadStatusActive {
		t.Fatalf("expected active thread after resume, got %+v", thread)
	}

	closed, err := service.CloseThread(ctx, result.CellID, session.ID, thread.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "substream complete",
	})
	if err != nil {
		t.Fatalf("CloseThread failed: %v", err)
	}
	thread, ok = mustSecureCellThread(t, closed, thread.ID)
	if !ok || thread.Status != SecureCellThreadStatusClosed || thread.ClosedAt == nil {
		t.Fatalf("expected closed thread, got %+v", thread)
	}
	last := closed.Transitions[len(closed.Transitions)-1]
	if last.Action != "secure_cell.session_thread_closed" {
		t.Fatalf("expected session_thread_closed transition, got %+v", last)
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

func TestService_PublishesLifecycleEventsWithTruthfulActors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	publisher := &capturingSecureCellEvents{}
	service, _, owner, participantA, participantB := newTestSecureCellServiceWithPublisher(t, publisher.Publish)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Evented Cell",
		Purpose:       "event publication",
		Resource:      "cell:evented",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}
	if got := len(publisher.Events()); got != 1 {
		t.Fatalf("expected 1 published event after create, got %d", got)
	}

	operatorDID := "did:aethelred:ops-analyst"
	admitted, err := service.AdmitMember(ctx, result.CellID, SecureCellAdmissionRequest{
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "reviewer_b",
		},
		ActorDID: operatorDID,
		Reason:   "evidence-bearing onboarding",
	})
	if err != nil {
		t.Fatalf("AdmitMember failed: %v", err)
	}

	events := publisher.Events()
	if got := len(events); got != 2 {
		t.Fatalf("expected 2 published events after admit, got %d", got)
	}
	last := events[len(events)-1]
	if last.Action != "secure_cell.member_admitted" || last.Actor != operatorDID {
		t.Fatalf("unexpected published event: %+v", last)
	}
	if last.ControlLedgerID == "" || last.PortablePackageHash == "" || !last.PortablePackageSigned || !last.PortablePackageAnchored {
		t.Fatalf("expected packaged event metadata, got %+v", last)
	}
	if transition := admitted.Transitions[len(admitted.Transitions)-1]; transition.Actor != operatorDID {
		t.Fatalf("expected truthful transition actor %q, got %+v", operatorDID, transition)
	}
}

func TestService_BulkContainmentTransitionsReturnPartialResults(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Bulk Cell",
		Purpose:       "bulk incident response",
		Resource:      "cell:bulk-response",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
			{Identity: participantB, Role: "reviewer_b"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	expiry := time.Now().UTC().Add(10 * time.Minute)
	bulk, err := service.BulkQuarantineMembers(ctx, result.CellID, SecureCellBulkMemberTransitionRequest{
		ParticipantDIDs:     []string{participantA.AgentID(), participantB.AgentID(), participantB.AgentID(), "did:aethelred:missing"},
		ActorDID:            "did:aethelred:incident-commander",
		Reason:              "bulk containment",
		QuarantineExpiresAt: &expiry,
		Metadata:            map[string]string{"playbook": "SC-BULK-01"},
	})
	if err != nil {
		t.Fatalf("BulkQuarantineMembers failed: %v", err)
	}
	if bulk.RequestedCount != 3 || bulk.SucceededCount != 2 || bulk.FailedCount != 1 {
		t.Fatalf("unexpected bulk containment result: %+v", bulk)
	}
	if bulk.FinalState == nil || bulk.FinalState.Status != SecureCellStatusQuarantined {
		t.Fatalf("expected quarantined final state, got %+v", bulk.FinalState)
	}
	stateA := mustSecureCellParticipantState(t, bulk.FinalState, participantA.AgentID())
	stateB := mustSecureCellParticipantState(t, bulk.FinalState, participantB.AgentID())
	if stateA.Status != SecureCellParticipantStatusQuarantined || stateB.Status != SecureCellParticipantStatusQuarantined {
		t.Fatalf("expected both participants quarantined, got %+v %+v", stateA, stateB)
	}

	released, err := service.BulkReleaseMembers(ctx, result.CellID, SecureCellBulkMemberTransitionRequest{
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		ActorDID:        "did:aethelred:incident-commander",
		Reason:          "bulk release",
	})
	if err != nil {
		t.Fatalf("BulkReleaseMembers failed: %v", err)
	}
	if released.SucceededCount != 2 || released.FinalState == nil || released.FinalState.Status != SecureCellStatusActive {
		t.Fatalf("unexpected bulk release result: %+v", released)
	}
}

func TestService_SweepExpiredQuarantinesUsesAutomatedActor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)
	automatedActor := "system:secure-cells-expiry-sweeper"

	cellA, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Expiry Sweep A",
		Purpose:       "expiry automation",
		Resource:      "cell:sweep-a",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell A failed: %v", err)
	}
	cellB, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Expiry Sweep B",
		Purpose:       "expiry automation",
		Resource:      "cell:sweep-b",
		Jurisdiction:  "UK",
		Participants: []SecureCellParticipant{
			{Identity: participantB, Role: "reviewer_b"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell B failed: %v", err)
	}

	expiredAt := time.Now().UTC().Add(-time.Minute)
	if _, err := service.QuarantineMember(ctx, cellA.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID:      participantA.AgentID(),
		Reason:              "expired containment A",
		QuarantineExpiresAt: &expiredAt,
	}); err != nil {
		t.Fatalf("QuarantineMember A failed: %v", err)
	}
	if _, err := service.QuarantineMember(ctx, cellB.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID:      participantB.AgentID(),
		Reason:              "expired containment B",
		QuarantineExpiresAt: &expiredAt,
	}); err != nil {
		t.Fatalf("QuarantineMember B failed: %v", err)
	}

	report, err := service.SweepExpiredQuarantines(ctx, time.Now().UTC(), SecureCellLifecycleRequest{
		ActorDID: automatedActor,
		Reason:   "automated quarantine expiry sweep",
		Metadata: map[string]string{"mode": "automated"},
	})
	if err != nil {
		t.Fatalf("SweepExpiredQuarantines failed: %v", err)
	}
	if report.CellsMutated != 2 || report.ParticipantsReleased != 2 {
		t.Fatalf("unexpected sweep report: %+v", report)
	}

	reloadedA, err := service.GetCell(ctx, cellA.CellID)
	if err != nil {
		t.Fatalf("GetCell A failed: %v", err)
	}
	reloadedB, err := service.GetCell(ctx, cellB.CellID)
	if err != nil {
		t.Fatalf("GetCell B failed: %v", err)
	}
	if reloadedA.Status != SecureCellStatusActive || reloadedB.Status != SecureCellStatusActive {
		t.Fatalf("expected both cells active after sweep, got %+v %+v", reloadedA.Status, reloadedB.Status)
	}
	if got := reloadedA.Transitions[len(reloadedA.Transitions)-1].Actor; got != automatedActor {
		t.Fatalf("expected automated actor on expiry transition, got %q", got)
	}
}

func newTestSecureCellService(t *testing.T) (*Service, evidence.ControlLedgerStore, *agent.AgentIdentity, *agent.AgentIdentity, *agent.AgentIdentity) {
	t.Helper()
	return newTestSecureCellServiceWithPublisher(t, nil)
}

func newTestSecureCellServiceWithPublisher(t *testing.T, publisher SecureCellEventPublisher) (*Service, evidence.ControlLedgerStore, *agent.AgentIdentity, *agent.AgentIdentity, *agent.AgentIdentity) {
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
		EventPublisher: publisher,
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

func mustSecureCellSession(t *testing.T, result *SecureCellResult, sessionID string) (SecureCellSession, bool) {
	t.Helper()
	if result == nil {
		t.Fatal("secure cell result is required")
	}
	for _, session := range result.Sessions {
		if session.ID == sessionID {
			return session, true
		}
	}
	return SecureCellSession{}, false
}

func mustSecureCellThread(t *testing.T, result *SecureCellResult, threadID string) (SecureCellSessionThread, bool) {
	t.Helper()
	if result == nil {
		t.Fatal("secure cell result is required")
	}
	for _, thread := range result.Threads {
		if thread.ID == threadID {
			return thread, true
		}
	}
	return SecureCellSessionThread{}, false
}
