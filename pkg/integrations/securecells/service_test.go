package securecells

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aethelred/aethelred/pkg/confidential"
	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
	"github.com/aethelred/aethelred/pkg/seal/sdk"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockSecureCellSealer struct {
	count int
}

type mockSecureCellConfidentialAttestor struct {
	signingKey *ecdsa.PrivateKey
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
		Attestations: append([]*sealtypes.TEEAttestation(nil), req.TEEAttestations...),
		ValidatorSet: []string{"validator-a", "validator-b"},
	}, nil
}

func (m *mockSecureCellConfidentialAttestor) Attest(_ context.Context, req confidential.AttestationRequest) ([]*sealtypes.TEEAttestation, error) {
	measurement := sha256.Sum256(req.OutputHash)
	attestation := &sealtypes.TEEAttestation{
		ValidatorAddress: "did:aethelred:secure-cells-policy",
		Platform:         "aws-nitro",
		EnclaveId:        "secure-cells-enclave-test",
		Measurement:      measurement[:],
		Timestamp:        timestamppb.New(time.Now().UTC()),
	}
	envelope := confidential.BuildQuoteEnvelope(req, attestation, []byte("secure-cells-test-quote"), []byte("secure-cells-user-data"), []byte("secure-cells-nonce"), time.Now().UTC())
	quote, err := confidential.EncodeQuoteEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	attestation.Quote = quote

	h := sha256.New()
	h.Write([]byte(attestation.GetValidatorAddress()))
	h.Write([]byte(attestation.GetPlatform()))
	h.Write([]byte(attestation.GetEnclaveId()))
	h.Write(attestation.GetMeasurement())
	h.Write(attestation.GetQuote())
	sig, err := ecdsa.SignASN1(rand.Reader, m.signingKey, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	attestation.Signature = sig
	return []*sealtypes.TEEAttestation{attestation}, nil
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
	if result.ConfidentialExecution == nil || !result.ConfidentialExecution.Verified {
		t.Fatalf("expected verified confidential execution summary, got %+v", result.ConfidentialExecution)
	}
	if len(result.ExecutionAttestations) != 1 {
		t.Fatalf("expected 1 execution attestation, got %d", len(result.ExecutionAttestations))
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

func TestService_ThreadDecisionLifecyclePreservesEvidence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Decision Cell",
		Purpose:       "thread decision lifecycle",
		Resource:      "cell:thread-decision-governance",
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
		Name:            "Decision Room",
		Purpose:         "decision session",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		DataClasses:     []string{"confidential", "decisioning"},
		Reason:          "session opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[0]

	threaded, err := service.StartThread(ctx, result.CellID, SecureCellSessionThreadStartRequest{
		SessionID:       session.ID,
		ActorDID:        owner.AgentID(),
		Name:            "Approval Thread",
		Purpose:         "decision workstream",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "thread opened",
	})
	if err != nil {
		t.Fatalf("StartThread failed: %v", err)
	}
	thread := threaded.Threads[0]

	messaged, err := service.PostThreadMessage(ctx, result.CellID, SecureCellThreadMessageRequest{
		SessionID:      session.ID,
		ThreadID:       thread.ID,
		ActorDID:       participantA.AgentID(),
		Name:           "Decision Input",
		ExchangeType:   "message",
		Classification: "decisioning",
		Summary:        "risk threshold breached",
		Recipients:     []string{participantA.AgentID()},
		Reason:         "supporting evidence submitted",
	})
	if err != nil {
		t.Fatalf("PostThreadMessage failed: %v", err)
	}
	exchange := messaged.SessionExchanges[0]

	created, err := service.CreateThreadDecision(ctx, result.CellID, SecureCellThreadDecisionRequest{
		SessionID:          session.ID,
		ThreadID:           thread.ID,
		ActorDID:           participantA.AgentID(),
		Title:              "Freeze Counterparty Exposure",
		Summary:            "breach requires temporary trading freeze",
		Classification:     "decisioning",
		RelatedExchangeIDs: []string{exchange.ID},
		Reason:             "decision proposed",
		Metadata:           map[string]string{"ticket": "SC-DECIDE-01"},
	})
	if err != nil {
		t.Fatalf("CreateThreadDecision failed: %v", err)
	}
	decision, ok := mustSecureCellDecision(t, created, created.Decisions[0].ID)
	if !ok {
		t.Fatalf("expected created decision, got %+v", created.Decisions)
	}
	if decision.Status != SecureCellThreadDecisionStatusOpen || len(decision.RelatedExchangeIDs) != 1 || decision.RelatedExchangeIDs[0] != exchange.ID {
		t.Fatalf("expected open linked decision, got %+v", decision)
	}
	thread, ok = mustSecureCellThread(t, created, thread.ID)
	if !ok || len(thread.DecisionIDs) != 1 || thread.DecisionIDs[0] != decision.ID {
		t.Fatalf("expected thread decision linkage, got %+v", thread)
	}
	if !controlLedgerHasControl(created.ControlLedger, "CELL-DECIDE-01") {
		t.Fatalf("expected decision control in ledger, got %+v", created.ControlLedger.Controls)
	}

	approved, err := service.ApproveThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "decision approved",
	})
	if err != nil {
		t.Fatalf("ApproveThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, approved, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusApproved || decision.ApprovedAt == nil {
		t.Fatalf("expected approved decision, got %+v", decision)
	}

	quarantined, err := service.QuarantineThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "decision contained",
	})
	if err != nil {
		t.Fatalf("QuarantineThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, quarantined, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusQuarantined || decision.QuarantinedAt == nil {
		t.Fatalf("expected quarantined decision, got %+v", decision)
	}

	resumed, err := service.ResumeThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "decision restored",
	})
	if err != nil {
		t.Fatalf("ResumeThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, resumed, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusApproved {
		t.Fatalf("expected approved decision after resume, got %+v", decision)
	}

	closed, err := service.CloseThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "decision finalized",
	})
	if err != nil {
		t.Fatalf("CloseThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, closed, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusClosed || decision.ClosedAt == nil {
		t.Fatalf("expected closed decision, got %+v", decision)
	}
	last := closed.Transitions[len(closed.Transitions)-1]
	if last.Action != "secure_cell.session_thread_decision_closed" || last.DecisionID != decision.ID {
		t.Fatalf("expected thread decision close transition, got %+v", last)
	}
}

func TestService_ThreadDecisionThresholdCommentsAndArtifactContainment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Decision Artifact Cell",
		Purpose:       "decision-native governance",
		Resource:      "cell:decision-artifact-governance",
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
		Name:            "Decision Session",
		Purpose:         "artifact review",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		DataClasses:     []string{"confidential", "decisioning"},
		Reason:          "session opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[0]

	shared, err := service.ShareOutput(ctx, result.CellID, SecureCellSessionShareRequest{
		SessionID:      session.ID,
		ActorDID:       participantA.AgentID(),
		Name:           "Exposure Snapshot",
		ArtifactType:   "decision_packet",
		Classification: "decisioning",
		Summary:        "exposure snapshot for approval vote",
		SharedWith:     []string{participantB.AgentID()},
		Reason:         "supporting decision packet shared",
	})
	if err != nil {
		t.Fatalf("ShareOutput failed: %v", err)
	}
	sharedOutput := shared.SharedOutputs[0]

	threaded, err := service.StartThread(ctx, result.CellID, SecureCellSessionThreadStartRequest{
		SessionID:       session.ID,
		ActorDID:        owner.AgentID(),
		Name:            "Decision Thread",
		Purpose:         "approval workstream",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "thread opened",
	})
	if err != nil {
		t.Fatalf("StartThread failed: %v", err)
	}
	thread := threaded.Threads[0]

	created, err := service.CreateThreadDecision(ctx, result.CellID, SecureCellThreadDecisionRequest{
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		ActorDID:             participantA.AgentID(),
		Title:                "Freeze Counterparty Exposure",
		Summary:              "threshold approval required before containment",
		Classification:       "decisioning",
		ApprovalThreshold:    2,
		EligibleApproverDIDs: []string{owner.AgentID(), participantA.AgentID()},
		RelatedOutputIDs:     []string{sharedOutput.ID},
		Reason:               "decision proposed",
		Metadata:             map[string]string{"ticket": "SC-DECIDE-THRESHOLD-01"},
	})
	if err != nil {
		t.Fatalf("CreateThreadDecision failed: %v", err)
	}
	decision, ok := mustSecureCellDecision(t, created, created.Decisions[0].ID)
	if !ok {
		t.Fatalf("expected created decision, got %+v", created.Decisions)
	}
	if decision.ApprovalThreshold != 2 || len(decision.EligibleApproverDIDs) != 2 {
		t.Fatalf("expected thresholded decision, got %+v", decision)
	}

	firstVote, err := service.ApproveThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "first approval vote",
		Metadata: map[string]string{"ticket": "SC-DECIDE-VOTE-01"},
	})
	if err != nil {
		t.Fatalf("ApproveThreadDecision first vote failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, firstVote, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusOpen || len(decision.ApprovalVotes) != 1 {
		t.Fatalf("expected open decision after first vote, got %+v", decision)
	}
	if firstVote.Transitions[len(firstVote.Transitions)-1].Action != "secure_cell.session_thread_decision_voted" {
		t.Fatalf("expected vote transition, got %+v", firstVote.Transitions[len(firstVote.Transitions)-1])
	}

	commented, err := service.CommentThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellThreadDecisionCommentRequest{
		ActorDID: participantA.AgentID(),
		Comment:  "documented rationale for containment",
		Reason:   "commented rationale",
		Metadata: map[string]string{"ticket": "SC-DECIDE-COMMENT-01"},
	})
	if err != nil {
		t.Fatalf("CommentThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, commented, decision.ID)
	if !ok || len(decision.Comments) != 1 || decision.Comments[0].SealID == "" || decision.Comments[0].TraceLinkID == "" {
		t.Fatalf("expected evidence-bearing decision comment, got %+v", decision)
	}

	contained, err := service.ContainThreadDecisionOutputs(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "contain decision-linked outputs",
		Metadata: map[string]string{"ticket": "SC-DECIDE-CONTAIN-01"},
	})
	if err != nil {
		t.Fatalf("ContainThreadDecisionOutputs failed: %v", err)
	}
	output, ok := mustSecureCellSharedOutput(t, contained, sharedOutput.ID)
	if !ok || output.ContainmentStatus != SecureCellArtifactContainmentStatusContained || output.ContainmentSealID == "" || output.ContainmentTraceLinkID == "" {
		t.Fatalf("expected contained shared output with evidence, got %+v", output)
	}
	if contained.Transitions[len(contained.Transitions)-1].Action != "secure_cell.session_thread_decision_outputs_contained" {
		t.Fatalf("expected artifact containment transition, got %+v", contained.Transitions[len(contained.Transitions)-1])
	}

	released, err := service.ReleaseThreadDecisionOutputs(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "release decision-linked outputs",
		Metadata: map[string]string{"ticket": "SC-DECIDE-RELEASE-01"},
	})
	if err != nil {
		t.Fatalf("ReleaseThreadDecisionOutputs failed: %v", err)
	}
	output, ok = mustSecureCellSharedOutput(t, released, sharedOutput.ID)
	if !ok || output.ContainmentStatus != SecureCellArtifactContainmentStatusReleased || output.ReleasedAt == nil {
		t.Fatalf("expected released shared output, got %+v", output)
	}

	secondVote, err := service.ApproveThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: participantA.AgentID(),
		Reason:   "second approval vote",
		Metadata: map[string]string{"ticket": "SC-DECIDE-VOTE-02"},
	})
	if err != nil {
		t.Fatalf("ApproveThreadDecision second vote failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, secondVote, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusApproved || len(decision.ApprovalVotes) != 2 || decision.ApprovedAt == nil {
		t.Fatalf("expected approved thresholded decision, got %+v", decision)
	}
	if !controlLedgerHasControl(secondVote.ControlLedger, "CELL-DECIDE-VOTE-01") || !controlLedgerHasControl(secondVote.ControlLedger, "CELL-DECIDE-COMMENT-01") || !controlLedgerHasControl(secondVote.ControlLedger, "CELL-DECIDE-CONT-01") {
		t.Fatalf("expected decision vote/comment/containment controls, got %+v", secondVote.ControlLedger.Controls)
	}
}

func TestService_ThreadDecisionDelegationRoleQuorumAndOutcomes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Decision Deliberation Cell",
		Purpose:       "role-aware decision governance",
		Resource:      "cell:decision-deliberation-governance",
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
		Name:            "Deliberation Session",
		Purpose:         "role-aware review",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		DataClasses:     []string{"confidential", "decisioning"},
		Reason:          "session opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[0]

	shared, err := service.ShareOutput(ctx, result.CellID, SecureCellSessionShareRequest{
		SessionID:      session.ID,
		ActorDID:       participantA.AgentID(),
		Name:           "Exposure Review Packet",
		ArtifactType:   "decision_packet",
		Classification: "decisioning",
		Summary:        "packet for deliberation and final outcome",
		SharedWith:     []string{participantB.AgentID()},
		Reason:         "supporting packet shared",
	})
	if err != nil {
		t.Fatalf("ShareOutput failed: %v", err)
	}
	sharedOutput := shared.SharedOutputs[0]

	threaded, err := service.StartThread(ctx, result.CellID, SecureCellSessionThreadStartRequest{
		SessionID:       session.ID,
		ActorDID:        owner.AgentID(),
		Name:            "Deliberation Thread",
		Purpose:         "role-aware approval workstream",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "thread opened",
	})
	if err != nil {
		t.Fatalf("StartThread failed: %v", err)
	}
	thread := threaded.Threads[0]

	created, err := service.CreateThreadDecision(ctx, result.CellID, SecureCellThreadDecisionRequest{
		SessionID:             session.ID,
		ThreadID:              thread.ID,
		ActorDID:              owner.AgentID(),
		Title:                 "Freeze Counterparty Exposure",
		Summary:               "requires owner vote plus reviewer_b quorum",
		Classification:        "decisioning",
		ApprovalThreshold:     2,
		EligibleApproverDIDs:  []string{owner.AgentID()},
		RequiredApproverRoles: []string{"owner", "reviewer_b"},
		RelatedOutputIDs:      []string{sharedOutput.ID},
		Reason:                "decision proposed",
		Metadata:              map[string]string{"ticket": "SC-DELIB-01"},
	})
	if err != nil {
		t.Fatalf("CreateThreadDecision failed: %v", err)
	}
	decision, ok := mustSecureCellDecision(t, created, created.Decisions[0].ID)
	if !ok {
		t.Fatalf("expected created decision, got %+v", created.Decisions)
	}
	if len(decision.RequiredApproverRoles) != 2 {
		t.Fatalf("expected required approver roles, got %+v", decision.RequiredApproverRoles)
	}

	delegated, err := service.DelegateThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellThreadDecisionDelegationRequest{
		ActorDID:  owner.AgentID(),
		TargetDID: participantA.AgentID(),
		Reason:    "delegate first-line review",
		Metadata:  map[string]string{"ticket": "SC-DELIB-02"},
	})
	if err != nil {
		t.Fatalf("DelegateThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, delegated, decision.ID)
	if !ok || len(decision.Delegations) != 1 || decision.Delegations[0].Mode != SecureCellThreadDecisionDelegationModeDelegate {
		t.Fatalf("expected delegated decision, got %+v", decision)
	}

	ownerVote, err := service.ApproveThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "owner approved",
		Metadata: map[string]string{"ticket": "SC-DELIB-03"},
	})
	if err != nil {
		t.Fatalf("ApproveThreadDecision owner vote failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, ownerVote, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusOpen || len(decision.ApprovalVotes) != 1 || decision.ApprovalVotes[0].ActorRole != "owner" {
		t.Fatalf("expected open decision after owner vote, got %+v", decision)
	}

	delegateVote, err := service.ApproveThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: participantA.AgentID(),
		Reason:   "delegate approved",
		Metadata: map[string]string{"ticket": "SC-DELIB-04"},
	})
	if err != nil {
		t.Fatalf("ApproveThreadDecision delegated vote failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, delegateVote, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusOpen || len(decision.ApprovalVotes) != 2 {
		t.Fatalf("expected open decision until reviewer_b votes, got %+v", decision)
	}
	if remaining := secureCellDecisionMissingRequiredRoles(decision); len(remaining) != 1 || remaining[0] != "reviewer_b" {
		t.Fatalf("expected reviewer_b to remain outstanding, got %+v", remaining)
	}

	escalated, err := service.EscalateThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellThreadDecisionDelegationRequest{
		ActorDID:  owner.AgentID(),
		TargetDID: participantB.AgentID(),
		Reason:    "escalate to reviewer_b",
		Metadata:  map[string]string{"ticket": "SC-DELIB-05"},
	})
	if err != nil {
		t.Fatalf("EscalateThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, escalated, decision.ID)
	if !ok || len(decision.Delegations) != 2 || decision.Delegations[1].Mode != SecureCellThreadDecisionDelegationModeEscalate {
		t.Fatalf("expected escalated decision, got %+v", decision)
	}

	finalVote, err := service.ApproveThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: participantB.AgentID(),
		Reason:   "reviewer_b approved",
		Metadata: map[string]string{"ticket": "SC-DELIB-06"},
	})
	if err != nil {
		t.Fatalf("ApproveThreadDecision reviewer_b vote failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, finalVote, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusApproved || decision.ApprovedAt == nil || len(decision.ApprovalVotes) != 3 {
		t.Fatalf("expected approved role-quorum decision, got %+v", decision)
	}
	if remaining := secureCellDecisionMissingRequiredRoles(decision); len(remaining) != 0 {
		t.Fatalf("expected all required roles satisfied, got %+v", remaining)
	}

	outcomeResult, err := service.PublishThreadDecisionOutcome(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellThreadDecisionOutcomeRequest{
		ActorDID:         owner.AgentID(),
		Title:            "Exposure Freeze Outcome",
		Summary:          "portable bundle of the approved freeze decision",
		Classification:   "decisioning",
		OutcomeType:      "resolution_bundle",
		RelatedOutputIDs: []string{sharedOutput.ID},
		Reason:           "publish governed outcome bundle",
		Metadata:         map[string]string{"ticket": "SC-DELIB-07"},
	})
	if err != nil {
		t.Fatalf("PublishThreadDecisionOutcome failed: %v", err)
	}
	outcome, ok := mustSecureCellDecisionOutcome(t, outcomeResult, decision.ID)
	if !ok || outcome.SealID == "" || outcome.TraceLinkID == "" || outcome.IntegrityHash == "" {
		t.Fatalf("expected evidence-bearing decision outcome, got %+v", outcome)
	}
	decision, ok = mustSecureCellDecision(t, outcomeResult, decision.ID)
	if !ok || len(decision.OutcomeIDs) != 1 || decision.OutcomeIDs[0] != outcome.ID {
		t.Fatalf("expected linked decision outcome ids, got %+v", decision)
	}
	if !controlLedgerHasControl(outcomeResult.ControlLedger, "CELL-DECIDE-ROUTE-01") || !controlLedgerHasControl(outcomeResult.ControlLedger, "CELL-DECIDE-OUTCOME-01") {
		t.Fatalf("expected decision routing and outcome controls, got %+v", outcomeResult.ControlLedger.Controls)
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

func TestService_VoteThreadDecisionHandlesDissentAndQuorumRecovery(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Dissent Cell",
		Purpose:       "deliberation recovery",
		Resource:      "cell:dissent-recovery",
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
		ActorDID:        owner.AgentID(),
		Name:            "Dissent Session",
		Purpose:         "quorum recovery",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		Reason:          "session opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[0]

	threaded, err := service.StartThread(ctx, result.CellID, SecureCellSessionThreadStartRequest{
		SessionID:       session.ID,
		ActorDID:        owner.AgentID(),
		Name:            "Dissent Thread",
		Purpose:         "decision recovery",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"confidential"},
		Reason:          "thread opened",
	})
	if err != nil {
		t.Fatalf("StartThread failed: %v", err)
	}
	thread := threaded.Threads[0]

	created, err := service.CreateThreadDecision(ctx, result.CellID, SecureCellThreadDecisionRequest{
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		ActorDID:             owner.AgentID(),
		Title:                "Freeze Exposure",
		Summary:              "records explicit dissent and quorum recovery",
		Classification:       "confidential",
		ApprovalThreshold:    1,
		EligibleApproverDIDs: []string{owner.AgentID(), participantA.AgentID()},
		Reason:               "decision proposed",
		Metadata:             map[string]string{"ticket": "SC-DELIB-DISSENT-01"},
	})
	if err != nil {
		t.Fatalf("CreateThreadDecision failed: %v", err)
	}
	decision, ok := mustSecureCellDecision(t, created, created.Decisions[0].ID)
	if !ok {
		t.Fatalf("expected created decision, got %+v", created.Decisions)
	}

	abstained, err := service.AbstainThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: participantA.AgentID(),
		Reason:   "need escalation context",
		Metadata: map[string]string{"ticket": "SC-DELIB-DISSENT-02"},
	})
	if err != nil {
		t.Fatalf("AbstainThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, abstained, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusOpen || len(decision.ApprovalVotes) != 1 || decision.ApprovalVotes[0].Choice != SecureCellThreadDecisionVoteChoiceAbstain {
		t.Fatalf("expected open decision after abstain, got %+v", decision)
	}

	rejected, err := service.RejectThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "owner rejects pending escalation",
		Metadata: map[string]string{"ticket": "SC-DELIB-DISSENT-03"},
	})
	if err != nil {
		t.Fatalf("RejectThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, rejected, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusQuorumFailed || decision.QuorumFailedAt == nil || decision.QuorumFailedBy != owner.AgentID() || len(decision.ApprovalVotes) != 2 {
		t.Fatalf("expected quorum-failed decision after reject, got %+v", decision)
	}
	if decision.ApprovalVotes[1].Choice != SecureCellThreadDecisionVoteChoiceReject {
		t.Fatalf("expected reject vote to persist, got %+v", decision.ApprovalVotes)
	}

	reopened, err := service.EscalateThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellThreadDecisionDelegationRequest{
		ActorDID:  owner.AgentID(),
		TargetDID: participantB.AgentID(),
		Reason:    "escalate to fresh approver",
		Metadata:  map[string]string{"ticket": "SC-DELIB-DISSENT-04"},
	})
	if err != nil {
		t.Fatalf("EscalateThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, reopened, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusOpen || decision.QuorumFailedAt != nil || decision.QuorumFailedBy != "" {
		t.Fatalf("expected decision to reopen after escalation restores quorum, got %+v", decision)
	}

	approved, err := service.ApproveThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: participantB.AgentID(),
		Reason:   "escalated approver approved",
		Metadata: map[string]string{"ticket": "SC-DELIB-DISSENT-05"},
	})
	if err != nil {
		t.Fatalf("ApproveThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, approved, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusApproved || decision.ApprovedAt == nil || len(decision.ApprovalVotes) != 3 {
		t.Fatalf("expected approved decision after quorum recovery, got %+v", decision)
	}
}

func TestService_CreateThreadDecisionAppliesExplicitGovernanceRules(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Governance Rules Cell",
		Purpose:       "explicit decision governance",
		Resource:      "cell:governance-rules",
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
		ActorDID:        owner.AgentID(),
		Name:            "Governance Session",
		Purpose:         "decision rule enforcement",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		Reason:          "session opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[0]

	threaded, err := service.StartThread(ctx, result.CellID, SecureCellSessionThreadStartRequest{
		SessionID:       session.ID,
		ActorDID:        owner.AgentID(),
		Name:            "Governance Thread",
		Purpose:         "dual-control deliberation",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"confidential"},
		Reason:          "thread opened",
	})
	if err != nil {
		t.Fatalf("StartThread failed: %v", err)
	}
	thread := threaded.Threads[0]

	escalationDueAt := time.Now().UTC().Add(1 * time.Hour).Truncate(time.Second)
	resolutionDueAt := escalationDueAt.Add(2 * time.Hour)
	created, err := service.CreateThreadDecision(ctx, result.CellID, SecureCellThreadDecisionRequest{
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		ActorDID:             owner.AgentID(),
		Title:                "Freeze Exposure",
		Summary:              "dual-control decision with explicit automation fields",
		Classification:       "confidential",
		GovernanceTemplate:   "dual_control",
		ApprovalThreshold:    2,
		EligibleApproverDIDs: []string{owner.AgentID(), participantA.AgentID()},
		AutoEscalateToDID:    participantB.AgentID(),
		EscalationDueAt:      &escalationDueAt,
		ResolutionDueAt:      &resolutionDueAt,
		Reason:               "decision proposed",
		Metadata:             map[string]string{"ticket": "SC-DEC-GOV-RULES-01"},
	})
	if err != nil {
		t.Fatalf("CreateThreadDecision failed: %v", err)
	}
	decision, ok := mustSecureCellDecision(t, created, created.Decisions[0].ID)
	if !ok {
		t.Fatalf("expected created decision, got %+v", created.Decisions)
	}
	if decision.GovernanceTemplate != "dual_control" {
		t.Fatalf("expected dual_control template, got %+v", decision)
	}
	if len(decision.AllowedVoteChoices) != 2 || decision.AllowedVoteChoices[0] != SecureCellThreadDecisionVoteChoiceApprove || decision.AllowedVoteChoices[1] != SecureCellThreadDecisionVoteChoiceReject {
		t.Fatalf("expected dual-control vote choices, got %+v", decision.AllowedVoteChoices)
	}
	if len(decision.RejectorRoles) != 1 || decision.RejectorRoles[0] != "owner" {
		t.Fatalf("expected owner-only rejectors, got %+v", decision.RejectorRoles)
	}
	if len(decision.ReopenRoles) != 1 || decision.ReopenRoles[0] != "owner" {
		t.Fatalf("expected owner-only reopen roles, got %+v", decision.ReopenRoles)
	}
	if decision.AutoEscalateToDID != participantB.AgentID() || decision.EscalationDueAt == nil || decision.ResolutionDueAt == nil {
		t.Fatalf("expected explicit automation fields on decision, got %+v", decision)
	}

	if _, err := service.AbstainThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: participantA.AgentID(),
		Reason:   "abstain should be blocked by template",
	}); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("expected abstain to be denied by dual-control template, got %v", err)
	}

	if _, err := service.RejectThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: participantA.AgentID(),
		Reason:   "non-owner reject should be blocked",
	}); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("expected reviewer reject to be denied by role policy, got %v", err)
	}

	rejected, err := service.RejectThreadDecision(ctx, result.CellID, session.ID, thread.ID, decision.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "owner reject collapses dual-control quorum",
	})
	if err != nil {
		t.Fatalf("RejectThreadDecision failed: %v", err)
	}
	decision, ok = mustSecureCellDecision(t, rejected, decision.ID)
	if !ok || decision.Status != SecureCellThreadDecisionStatusQuorumFailed || decision.QuorumFailedBy != owner.AgentID() || len(decision.ApprovalVotes) != 1 {
		t.Fatalf("expected quorum-failed decision after owner reject, got %+v", decision)
	}
	if decision.ApprovalVotes[0].Choice != SecureCellThreadDecisionVoteChoiceReject {
		t.Fatalf("expected persisted reject vote, got %+v", decision.ApprovalVotes)
	}
}

func TestService_CreateThreadDecisionAppliesSectorSLATemplate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)
	compliance := mustSecureCellIdentity(t, "participant-c", []string{"UAE"})

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Treasury Review Cell",
		Purpose:       "regulated payment release",
		Resource:      "cell:treasury-release",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "treasury_reviewer"},
			{Identity: participantB, Role: "treasury_manager"},
			{Identity: compliance, Role: "compliance_officer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "payment"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, result.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Treasury Approval",
		Purpose:         "release review",
		ParticipantDIDs: []string{participantA.AgentID()},
		Reason:          "session opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[0]

	threaded, err := service.StartThread(ctx, result.CellID, SecureCellSessionThreadStartRequest{
		SessionID:       session.ID,
		ActorDID:        owner.AgentID(),
		Name:            "Release Thread",
		Purpose:         "govern payment release",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"confidential"},
		Reason:          "thread opened",
	})
	if err != nil {
		t.Fatalf("StartThread failed: %v", err)
	}
	thread := threaded.Threads[0]

	created, err := service.CreateThreadDecision(ctx, result.CellID, SecureCellThreadDecisionRequest{
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		ActorDID:             owner.AgentID(),
		Title:                "Release Treasury Payment",
		Summary:              "use finance pack defaults",
		Classification:       "confidential",
		SectorPolicyPack:     "finance",
		EligibleApproverDIDs: []string{owner.AgentID(), participantA.AgentID()},
		Reason:               "decision proposed",
		Metadata:             map[string]string{"ticket": "SC-DEC-SLA-FIN-01"},
	})
	if err != nil {
		t.Fatalf("CreateThreadDecision failed: %v", err)
	}
	decision, ok := mustSecureCellDecision(t, created, created.Decisions[0].ID)
	if !ok {
		t.Fatalf("expected created decision, got %+v", created.Decisions)
	}
	if decision.GovernanceTemplate != "dual_control" || decision.SLATemplate != "finance_payment_release" || decision.SectorPolicyPack != "finance" {
		t.Fatalf("expected finance SLA template to resolve onto decision, got %+v", decision)
	}
	if decision.ApprovalThreshold != 2 {
		t.Fatalf("expected finance pack approval threshold, got %+v", decision)
	}
	if len(decision.RequiredApproverRoles) != 1 || decision.RequiredApproverRoles[0] != "treasury_reviewer" {
		t.Fatalf("expected finance pack required roles, got %+v", decision.RequiredApproverRoles)
	}
	if len(decision.EscalationLadder) != 2 {
		t.Fatalf("expected two finance escalation tiers, got %+v", decision.EscalationLadder)
	}
	if decision.EscalationLadder[0].TargetDID != participantB.AgentID() || decision.EscalationLadder[1].TargetDID != compliance.AgentID() {
		t.Fatalf("expected ladder to resolve manager/compliance targets, got %+v", decision.EscalationLadder)
	}
	if decision.ResolutionDueAt == nil || !decision.ResolutionDueAt.After(decision.ProposedAt) {
		t.Fatalf("expected SLA-derived resolution deadline, got %+v", decision)
	}

	templates, err := service.ListDecisionSLATemplates(ctx, SecureCellDecisionSLATemplateFilter{SectorPolicyPack: "finance"})
	if err != nil {
		t.Fatalf("ListDecisionSLATemplates failed: %v", err)
	}
	if len(templates) < 2 {
		t.Fatalf("expected finance template catalog entries, got %+v", templates)
	}
	if templates[0].SectorPolicyPack != "finance" {
		t.Fatalf("expected finance pack catalog entries, got %+v", templates)
	}
}

func TestService_SweepDecisionGovernanceEscalatesAndClosesExpiredDecisions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Governance Automation Cell",
		Purpose:       "deadline automation",
		Resource:      "cell:governance-automation",
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
		ActorDID:        owner.AgentID(),
		Name:            "Automation Session",
		Purpose:         "deadline-managed decisions",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		Reason:          "session opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[0]

	threaded, err := service.StartThread(ctx, result.CellID, SecureCellSessionThreadStartRequest{
		SessionID:       session.ID,
		ActorDID:        owner.AgentID(),
		Name:            "Automation Thread",
		Purpose:         "deadline automation path",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"confidential"},
		Reason:          "thread opened",
	})
	if err != nil {
		t.Fatalf("StartThread failed: %v", err)
	}
	thread := threaded.Threads[0]

	now := time.Now().UTC().Truncate(time.Second)
	escalationDueAt := now.Add(-5 * time.Minute)
	resolutionDueAt := now.Add(45 * time.Minute)
	escalationDecisionResult, err := service.CreateThreadDecision(ctx, result.CellID, SecureCellThreadDecisionRequest{
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		ActorDID:             owner.AgentID(),
		Title:                "Escalate Exposure Review",
		Summary:              "should auto-escalate to reviewer_b",
		Classification:       "confidential",
		ApprovalThreshold:    1,
		EligibleApproverDIDs: []string{owner.AgentID(), participantA.AgentID(), participantB.AgentID()},
		AutoEscalateToDID:    participantB.AgentID(),
		EscalationDueAt:      &escalationDueAt,
		ResolutionDueAt:      &resolutionDueAt,
		Reason:               "decision proposed",
		Metadata:             map[string]string{"ticket": "SC-DEC-SWEEP-ESCALATE"},
	})
	if err != nil {
		t.Fatalf("CreateThreadDecision escalate case failed: %v", err)
	}
	escalationDecisionID := escalationDecisionResult.Decisions[len(escalationDecisionResult.Decisions)-1].ID

	closeDueAt := now.Add(-2 * time.Minute)
	closureDecisionResult, err := service.CreateThreadDecision(ctx, result.CellID, SecureCellThreadDecisionRequest{
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		ActorDID:             owner.AgentID(),
		Title:                "Close Stale Review",
		Summary:              "should auto-close after resolution due time",
		Classification:       "confidential",
		ApprovalThreshold:    1,
		EligibleApproverDIDs: []string{owner.AgentID(), participantA.AgentID()},
		ResolutionDueAt:      &closeDueAt,
		Reason:               "decision proposed",
		Metadata:             map[string]string{"ticket": "SC-DEC-SWEEP-CLOSE"},
	})
	if err != nil {
		t.Fatalf("CreateThreadDecision close case failed: %v", err)
	}
	closureDecisionID := closureDecisionResult.Decisions[len(closureDecisionResult.Decisions)-1].ID

	sweepActor := "did:aethelred:automation-sweeper"
	report, err := service.SweepDecisionGovernance(ctx, now, SecureCellLifecycleRequest{
		ActorDID: sweepActor,
		Reason:   "automated decision governance sweep",
		Metadata: map[string]string{"ticket": "SC-DEC-SWEEP-01"},
	})
	if err != nil {
		t.Fatalf("SweepDecisionGovernance failed: %v", err)
	}
	if report.CellsScanned != 1 || report.DecisionsScanned != 2 || report.DecisionsEscalated != 1 || report.DecisionsClosed != 1 || report.CellsMutated != 1 {
		t.Fatalf("unexpected sweep report: %+v", report)
	}
	if len(report.Actions) != 2 {
		t.Fatalf("expected two sweep actions, got %+v", report.Actions)
	}

	after, err := service.GetCell(ctx, result.CellID)
	if err != nil {
		t.Fatalf("GetCell failed: %v", err)
	}

	escalatedDecision, ok := mustSecureCellDecision(t, after, escalationDecisionID)
	if !ok {
		t.Fatalf("expected escalated decision in state, got %+v", after.Decisions)
	}
	if len(escalatedDecision.Delegations) != 1 || escalatedDecision.Delegations[0].Mode != SecureCellThreadDecisionDelegationModeEscalate || escalatedDecision.Delegations[0].ToActorDID != participantB.AgentID() {
		t.Fatalf("expected automated escalation delegation, got %+v", escalatedDecision.Delegations)
	}
	if escalatedDecision.Delegations[0].Metadata["automated_actor"] != sweepActor || escalatedDecision.Delegations[0].Metadata["decision_sweep_action"] != "escalate" {
		t.Fatalf("expected automated escalation metadata, got %+v", escalatedDecision.Delegations[0].Metadata)
	}

	closedDecision, ok := mustSecureCellDecision(t, after, closureDecisionID)
	if !ok {
		t.Fatalf("expected closed decision in state, got %+v", after.Decisions)
	}
	if closedDecision.Status != SecureCellThreadDecisionStatusClosed || closedDecision.ClosedAt == nil || closedDecision.ClosedBy != owner.AgentID() {
		t.Fatalf("expected automated close to finalize stale decision, got %+v", closedDecision)
	}
	last := after.Transitions[len(after.Transitions)-1]
	if last.Action != "secure_cell.session_thread_decision_closed" && last.Action != "secure_cell.session_thread_decision_escalated" {
		t.Fatalf("expected automated decision transitions in audit trail, got %+v", last)
	}
}

func TestService_ListOverdueDecisionsAndAutomationActions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	result, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Operator Decision Cell",
		Purpose:       "operator sla visibility",
		Resource:      "cell:operator-decision-views",
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
		ActorDID:        owner.AgentID(),
		Name:            "Operator Session",
		Purpose:         "operator overdue visibility",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		Reason:          "session opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[0]

	threaded, err := service.StartThread(ctx, result.CellID, SecureCellSessionThreadStartRequest{
		SessionID:       session.ID,
		ActorDID:        owner.AgentID(),
		Name:            "Operator Thread",
		Purpose:         "operator overdue visibility",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"confidential"},
		Reason:          "thread opened",
	})
	if err != nil {
		t.Fatalf("StartThread failed: %v", err)
	}
	thread := threaded.Threads[0]

	now := time.Now().UTC().Truncate(time.Second)
	firstTierDueAt := now.Add(-15 * time.Minute)
	secondTierDueAt := now.Add(30 * time.Minute)
	resolutionDueAt := now.Add(90 * time.Minute)
	ladderDecisionResult, err := service.CreateThreadDecision(ctx, result.CellID, SecureCellThreadDecisionRequest{
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		ActorDID:             owner.AgentID(),
		Title:                "Escalate Exposure Review",
		Summary:              "should appear overdue for tier_1",
		Classification:       "confidential",
		ApprovalThreshold:    1,
		EligibleApproverDIDs: []string{owner.AgentID(), participantA.AgentID(), participantB.AgentID()},
		EscalationLadder: []SecureCellDecisionEscalationTier{
			{
				TierID:    "tier_1",
				TargetDID: participantA.AgentID(),
				DueAt:     &firstTierDueAt,
				Reason:    "reviewer_a deadline reached",
			},
			{
				TierID:    "tier_2",
				TargetDID: participantB.AgentID(),
				DueAt:     &secondTierDueAt,
				Reason:    "reviewer_b deadline reached",
			},
		},
		ResolutionDueAt: &resolutionDueAt,
		Reason:          "decision proposed",
		Metadata:        map[string]string{"ticket": "SC-OP-OVERDUE-01"},
	})
	if err != nil {
		t.Fatalf("CreateThreadDecision ladder case failed: %v", err)
	}
	ladderDecisionID := ladderDecisionResult.Decisions[len(ladderDecisionResult.Decisions)-1].ID

	closeDueAt := now.Add(-5 * time.Minute)
	closeDecisionResult, err := service.CreateThreadDecision(ctx, result.CellID, SecureCellThreadDecisionRequest{
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		ActorDID:             owner.AgentID(),
		Title:                "Close Stale Decision",
		Summary:              "should appear overdue for closure",
		Classification:       "confidential",
		ApprovalThreshold:    1,
		EligibleApproverDIDs: []string{owner.AgentID(), participantA.AgentID()},
		ResolutionDueAt:      &closeDueAt,
		Reason:               "decision proposed",
		Metadata:             map[string]string{"ticket": "SC-OP-OVERDUE-02"},
	})
	if err != nil {
		t.Fatalf("CreateThreadDecision close case failed: %v", err)
	}
	closeDecisionID := closeDecisionResult.Decisions[len(closeDecisionResult.Decisions)-1].ID

	overdue, err := service.ListOverdueDecisions(ctx, SecureCellOverdueDecisionFilter{
		CellID: result.CellID,
		Before: &now,
	})
	if err != nil {
		t.Fatalf("ListOverdueDecisions failed: %v", err)
	}
	if len(overdue) != 2 {
		t.Fatalf("expected 2 overdue decisions, got %+v", overdue)
	}
	if overdue[0].DecisionID != ladderDecisionID || overdue[0].AutomationAction != "escalate" || overdue[0].TierID != "tier_1" || overdue[0].TargetDID != participantA.AgentID() {
		t.Fatalf("expected first overdue item to be tier_1 escalation, got %+v", overdue[0])
	}
	if overdue[1].DecisionID != closeDecisionID || overdue[1].AutomationAction != "close" || overdue[1].OverdueReason != "resolution_due" {
		t.Fatalf("expected second overdue item to be overdue close, got %+v", overdue[1])
	}

	_, err = service.SweepDecisionGovernance(ctx, now, SecureCellLifecycleRequest{
		ActorDID: "did:aethelred:automation-sweeper",
		Reason:   "automated decision governance sweep",
		Metadata: map[string]string{"ticket": "SC-OP-OVERDUE-SWEEP"},
	})
	if err != nil {
		t.Fatalf("SweepDecisionGovernance failed: %v", err)
	}

	remaining, err := service.ListOverdueDecisions(ctx, SecureCellOverdueDecisionFilter{
		CellID: result.CellID,
		Before: &now,
	})
	if err != nil {
		t.Fatalf("ListOverdueDecisions after sweep failed: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected overdue queue to clear after sweep, got %+v", remaining)
	}

	actions, err := service.ListDecisionAutomationActions(ctx, SecureCellDecisionAutomationActionFilter{
		CellID: result.CellID,
	})
	if err != nil {
		t.Fatalf("ListDecisionAutomationActions failed: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("expected 2 automation actions, got %+v", actions)
	}

	actionByDecision := make(map[string]SecureCellDecisionAutomationActionRecord, len(actions))
	for _, action := range actions {
		actionByDecision[action.DecisionID] = action
	}
	ladderAction, ok := actionByDecision[ladderDecisionID]
	if !ok || ladderAction.Action != "secure_cell.session_thread_decision_escalated" || ladderAction.TierID != "tier_1" || ladderAction.TargetDID != participantA.AgentID() || ladderAction.Trigger != "escalation_tier_due" {
		t.Fatalf("expected ladder automation action metadata, got %+v", ladderAction)
	}
	closeAction, ok := actionByDecision[closeDecisionID]
	if !ok || closeAction.Action != "secure_cell.session_thread_decision_closed" || closeAction.Trigger != "resolution_due" {
		t.Fatalf("expected close automation action metadata, got %+v", closeAction)
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

func TestService_LoadsPersistedRunsFromWorkflowStore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workflowStore := NewInMemorySecureCellStore()
	service, _, owner, participantA, _ := newTestSecureCellServiceWithWorkflowStore(t, workflowStore, nil)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Persistent Federation Cell",
		Purpose:       "restart-safe collaboration",
		Resource:      "cell:persistent-federation",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	restarted, _, _, _, _ := newTestSecureCellServiceWithWorkflowStore(t, workflowStore, nil)
	if got := restarted.runCount(); got != 1 {
		t.Fatalf("expected one persisted run after restart, got %d", got)
	}

	loaded, err := restarted.GetCell(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetCell after restart failed: %v", err)
	}
	if loaded.CellID != created.CellID || loaded.Status != SecureCellStatusActive {
		t.Fatalf("unexpected reloaded secure cell: %+v", loaded)
	}
	if loaded.ControlLedger == nil || loaded.PortablePackage == nil || loaded.ExecutionSeal == nil {
		t.Fatalf("expected reloaded evidence chain, got %+v", loaded)
	}
	if err := evidence.VerifyPortableControlLedgerPackage(loaded.PortablePackage); err != nil {
		t.Fatalf("VerifyPortableControlLedgerPackage after restart failed: %v", err)
	}
}

func TestService_FederationInvitationAcceptsCrossOrgParticipant(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Cross-Org Federation Cell",
		Purpose:       "federated regulated collaboration",
		Resource:      "cell:federation-active",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
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

	sponsorOfRecord := secureCellFederationSponsor(participantB)
	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  sponsorOfRecord,
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		Reason:           "cross-org invite approved",
		Metadata:         map[string]string{"ticket": "SC-FED-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}

	if len(invited.FederationInvitations) != 1 {
		t.Fatalf("expected one pending federation invitation, got %+v", invited.FederationInvitations)
	}
	invitation := invited.FederationInvitations[0]
	if invitation.Status != SecureCellFederationInvitationStatusPending {
		t.Fatalf("expected pending invitation, got %+v", invitation)
	}
	if !controlLedgerHasControl(invited.ControlLedger, "CELL-FED-01") {
		t.Fatalf("expected federation control after invitation, got %+v", invited.ControlLedger.Controls)
	}

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
			Metadata: map[string]string{"bank": "b"},
		},
		Reason:   "joined federated review cell",
		Metadata: map[string]string{"ticket": "SC-FED-02"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}

	if len(accepted.Participants) != 2 {
		t.Fatalf("expected second live participant after federation accept, got %+v", accepted.Participants)
	}
	state := mustSecureCellParticipantState(t, accepted, participantB.AgentID())
	if state.Status != SecureCellParticipantStatusActive {
		t.Fatalf("expected active participant state after federation accept, got %+v", state)
	}
	if len(accepted.FederationOrganizations) != 3 {
		t.Fatalf("expected owner + initial participant + joined org, got %+v", accepted.FederationOrganizations)
	}

	orgID := secureCellFederationOrganizationID(sponsorOfRecord)
	orgIdx, org := findSecureCellFederationOrganization(accepted.FederationOrganizations, orgID)
	if org == nil {
		t.Fatalf("expected joined federation organization %q", orgID)
	}
	if accepted.FederationOrganizations[orgIdx].Status != SecureCellFederationOrganizationStatusActive {
		t.Fatalf("expected active federation organization, got %+v", accepted.FederationOrganizations[orgIdx])
	}
	if got := accepted.FederationOrganizations[orgIdx].ParticipantDIDs; len(got) != 1 || got[0] != participantB.AgentID() {
		t.Fatalf("expected joined participant DID on federation org, got %+v", got)
	}
	if accepted.FederationInvitations[0].Status != SecureCellFederationInvitationStatusAccepted {
		t.Fatalf("expected accepted invitation, got %+v", accepted.FederationInvitations[0])
	}
	if len(accepted.FederationContracts) != 1 {
		t.Fatalf("expected one active federation contract, got %+v", accepted.FederationContracts)
	}
	if contract := accepted.FederationContracts[0]; contract.Status != SecureCellFederationContractStatusActive || contract.InvitationID != invitation.ID || contract.PolicyReceiptID == "" {
		t.Fatalf("expected active evidence-bearing federation contract, got %+v", contract)
	}
	if got := accepted.Transitions[len(accepted.Transitions)-1].Action; got != "secure_cell.federation_joined" {
		t.Fatalf("expected final federation join transition, got %q", got)
	}
	if !controlLedgerHasControl(accepted.ControlLedger, "CELL-FED-01") {
		t.Fatalf("expected federation control after accept, got %+v", accepted.ControlLedger.Controls)
	}
	if !controlLedgerHasControl(accepted.ControlLedger, "CELL-FED-02") {
		t.Fatalf("expected federation contract control after accept, got %+v", accepted.ControlLedger.Controls)
	}
	if err := evidence.VerifyPortableControlLedgerPackage(accepted.PortablePackage); err != nil {
		t.Fatalf("VerifyPortableControlLedgerPackage failed: %v", err)
	}
}

func TestService_RevokeFederationInvitationMarksOrganizationRevoked(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Cross-Org Federation Revocation",
		Purpose:       "federation revoke path",
		Resource:      "cell:federation-revoke",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
		},
		Policy: SecureCellPolicy{RequireConfidentialCompute: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		Reason:           "cross-org invite revoked later",
		Metadata:         map[string]string{"ticket": "SC-FED-03"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}

	revoked, err := service.RevokeFederationInvitation(ctx, created.CellID, invited.FederationInvitations[0].ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "counterparty not cleared",
		Metadata: map[string]string{"ticket": "SC-FED-04"},
	})
	if err != nil {
		t.Fatalf("RevokeFederationInvitation failed: %v", err)
	}

	if revoked.FederationInvitations[0].Status != SecureCellFederationInvitationStatusRevoked {
		t.Fatalf("expected revoked invitation, got %+v", revoked.FederationInvitations[0])
	}
	orgID := secureCellFederationOrganizationID(secureCellFederationSponsor(participantB))
	orgIdx, org := findSecureCellFederationOrganization(revoked.FederationOrganizations, orgID)
	if org == nil {
		t.Fatalf("expected federation organization %q", orgID)
	}
	if revoked.FederationOrganizations[orgIdx].Status != SecureCellFederationOrganizationStatusRevoked {
		t.Fatalf("expected revoked federation organization, got %+v", revoked.FederationOrganizations[orgIdx])
	}
	if got := revoked.Transitions[len(revoked.Transitions)-1].Action; got != "secure_cell.federation_invitation_revoked" {
		t.Fatalf("expected final federation revoke transition, got %q", got)
	}
}

func TestService_FederationOperatorViewsAndTrustArtifacts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)
	participantC := mustSecureCellIdentity(t, "participant-c", []string{"UAE", "UK"})

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Operator Cell",
		Purpose:       "operator federation packaging",
		Resource:      "cell:federation-operator",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
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

	acceptedInvite, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		Reason:           "accepted counterparty join",
		Metadata:         map[string]string{"ticket": "SC-FED-PACK-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation accepted path failed: %v", err)
	}
	acceptedInvitationID := acceptedInvite.FederationInvitations[len(acceptedInvite.FederationInvitations)-1].ID
	if _, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: acceptedInvitationID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
			Metadata: map[string]string{"bank": "b"},
		},
		Reason:   "joined operator federation cell",
		Metadata: map[string]string{"ticket": "SC-FED-PACK-02"},
	}); err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}

	revokedInvite, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantC),
		OrganizationName: secureCellFederationOrganizationName(participantC),
		Jurisdiction:     "UK",
		ExpectedDID:      participantC.AgentID(),
		Role:             "bank_c_reviewer",
		Reason:           "revoked counterparty join",
		Metadata:         map[string]string{"ticket": "SC-FED-PACK-03"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation revoked path failed: %v", err)
	}
	revokedInvitationID := revokedInvite.FederationInvitations[len(revokedInvite.FederationInvitations)-1].ID
	if _, err := service.RevokeFederationInvitation(ctx, created.CellID, revokedInvitationID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "counterparty withdrawn",
		Metadata: map[string]string{"ticket": "SC-FED-PACK-04"},
	}); err != nil {
		t.Fatalf("RevokeFederationInvitation failed: %v", err)
	}

	orgItems, err := service.ListFederationOrganizations(ctx, SecureCellFederationOrganizationFilter{
		CellID: created.CellID,
	})
	if err != nil {
		t.Fatalf("ListFederationOrganizations failed: %v", err)
	}
	if len(orgItems) != 4 {
		t.Fatalf("expected owner + local participant + accepted org + revoked org, got %+v", orgItems)
	}

	acceptedOrgID := secureCellFederationOrganizationID(secureCellFederationSponsor(participantB))
	acceptedFound := false
	for _, item := range orgItems {
		if item.OrganizationID != acceptedOrgID {
			continue
		}
		acceptedFound = true
		if item.Status != SecureCellFederationOrganizationStatusActive || item.ParticipantCount != 1 || item.AcceptedInvitationCount != 1 {
			t.Fatalf("expected active accepted organization summary, got %+v", item)
		}
		if len(item.ParticipantDIDs) != 1 || item.ParticipantDIDs[0] != participantB.AgentID() {
			t.Fatalf("expected participant DID on organization summary, got %+v", item.ParticipantDIDs)
		}
	}
	if !acceptedFound {
		t.Fatalf("expected accepted organization %q in operator list", acceptedOrgID)
	}

	filteredOrgItems, err := service.ListFederationOrganizations(ctx, SecureCellFederationOrganizationFilter{
		CellID:         created.CellID,
		ParticipantDID: participantB.AgentID(),
	})
	if err != nil {
		t.Fatalf("ListFederationOrganizations filtered failed: %v", err)
	}
	if len(filteredOrgItems) != 1 || filteredOrgItems[0].OrganizationID != acceptedOrgID {
		t.Fatalf("expected only accepted organization for participant filter, got %+v", filteredOrgItems)
	}

	invitationItems, err := service.ListFederationInvitations(ctx, SecureCellFederationInvitationFilter{
		CellID: created.CellID,
	})
	if err != nil {
		t.Fatalf("ListFederationInvitations failed: %v", err)
	}
	if len(invitationItems) != 2 {
		t.Fatalf("expected two federation invitations, got %+v", invitationItems)
	}

	contractItems, err := service.ListFederationContracts(ctx, SecureCellFederationContractFilter{
		CellID:         created.CellID,
		OrganizationID: acceptedOrgID,
	})
	if err != nil {
		t.Fatalf("ListFederationContracts failed: %v", err)
	}
	if len(contractItems) != 1 {
		t.Fatalf("expected one federation contract, got %+v", contractItems)
	}
	if contractItems[0].Status != SecureCellFederationContractStatusActive || contractItems[0].InvitationID != acceptedInvitationID {
		t.Fatalf("expected active contract summary for accepted invitation, got %+v", contractItems[0])
	}

	trustPack, err := service.BuildFederationOrganizationTrustPack(ctx, created.CellID, acceptedOrgID, SecureCellFederationOrganizationTrustPackOptions{
		OperatorSurfaces: []SecureCellFederationOperatorSurface{
			{ID: "federation-overview", Method: "GET", Path: "/api/v1/secure-cells/" + created.CellID + "/federation"},
		},
	})
	if err != nil {
		t.Fatalf("BuildFederationOrganizationTrustPack failed: %v", err)
	}
	if trustPack.Organization.OrganizationID != acceptedOrgID || len(trustPack.Participants) != 1 || len(trustPack.Invitations) != 1 {
		t.Fatalf("expected organization-specific trust pack, got %+v", trustPack)
	}
	if len(trustPack.Contracts) != 1 || trustPack.Contracts[0].ContractID == "" {
		t.Fatalf("expected contract projection in trust pack, got %+v", trustPack.Contracts)
	}
	if trustPack.Assurance == nil || trustPack.Assurance.Organization.OrganizationID != acceptedOrgID {
		t.Fatalf("expected assurance summary in trust pack, got %+v", trustPack.Assurance)
	}
	if trustPack.Assurance.FindingCount != 1 || trustPack.Assurance.CriticalFindingCount != 1 || len(trustPack.Assurance.Findings) != 1 || trustPack.Assurance.Findings[0].Category != SecureCellFederationAssuranceCategoryCounterpartyAssuranceMissing {
		t.Fatalf("expected reciprocal-assurance missing finding in baseline trust pack, got %+v", trustPack.Assurance)
	}
	if len(trustPack.CounterpartyAssurance) != 0 {
		t.Fatalf("expected no imported counterparty assurance in baseline trust pack, got %+v", trustPack.CounterpartyAssurance)
	}
	if !trustPack.PortablePackageSigned || !trustPack.PortablePackageAnchored || trustPack.ControlLedgerID == "" || trustPack.ControlLedgerHash == "" {
		t.Fatalf("expected anchored and signed trust pack evidence, got %+v", trustPack)
	}
	if len(trustPack.Controls) == 0 || trustPack.Controls[0].ControlID != "CELL-FED-01" {
		t.Fatalf("expected federation control in trust pack, got %+v", trustPack.Controls)
	}
	if len(trustPack.OperatorSurfaces) != 1 || trustPack.OperatorSurfaces[0].ID != "federation-overview" {
		t.Fatalf("expected custom operator surface in trust pack, got %+v", trustPack.OperatorSurfaces)
	}

	contractBundle, err := service.BuildFederationContractBundle(ctx, created.CellID, contractItems[0].ContractID, SecureCellFederationContractBundleOptions{
		OperatorSurfaces: []SecureCellFederationOperatorSurface{
			{ID: "federation-contract-detail", Method: "GET", Path: "/api/v1/secure-cells/" + created.CellID + "/federation/contracts/" + contractItems[0].ContractID},
		},
	})
	if err != nil {
		t.Fatalf("BuildFederationContractBundle failed: %v", err)
	}
	if contractBundle.Contract.ContractID != contractItems[0].ContractID || contractBundle.Invitation == nil || contractBundle.Invitation.InvitationID != acceptedInvitationID {
		t.Fatalf("expected contract bundle tied to accepted invitation, got %+v", contractBundle)
	}
	if len(contractBundle.OperatorSurfaces) != 1 || contractBundle.OperatorSurfaces[0].ID != "federation-contract-detail" {
		t.Fatalf("expected operator surfaces in contract bundle, got %+v", contractBundle.OperatorSurfaces)
	}

	bundle, err := service.BuildFederationInvitationBundle(ctx, created.CellID, revokedInvitationID)
	if err != nil {
		t.Fatalf("BuildFederationInvitationBundle failed: %v", err)
	}
	if bundle.Invitation.InvitationID != revokedInvitationID || bundle.Invitation.Status != SecureCellFederationInvitationStatusRevoked {
		t.Fatalf("expected revoked invitation bundle, got %+v", bundle)
	}
	if bundle.Organization.OrganizationID != secureCellFederationOrganizationID(secureCellFederationSponsor(participantC)) {
		t.Fatalf("expected revoked organization in invitation bundle, got %+v", bundle.Organization)
	}
	if bundle.Contract != nil {
		t.Fatalf("expected no active contract on revoked invitation bundle, got %+v", bundle.Contract)
	}
	if !bundle.PortablePackageSigned || !bundle.PortablePackageAnchored || bundle.ControlLedgerID == "" || bundle.ControlLedgerHash == "" {
		t.Fatalf("expected portable evidence on invitation bundle, got %+v", bundle)
	}
}

func TestService_FederationAssuranceDetectsExposureAndSuspendsContract(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Assurance Cell",
		Purpose:       "continuous federation assurance",
		Resource:      "cell:federation-assurance",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		ExpectedDID:      participantB.AgentID(),
		Reason:           "invite counterparty into assurance cell",
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitationID := invited.FederationInvitations[len(invited.FederationInvitations)-1].ID

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitationID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "counterparty_reviewer",
		},
		Reason: "counterparty accepted assurance invitation",
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	if len(accepted.FederationContracts) != 1 {
		t.Fatalf("expected one federation contract, got %+v", accepted.FederationContracts)
	}
	contractID := accepted.FederationContracts[0].ID
	orgID := secureCellFederationOrganizationID(secureCellFederationSponsor(participantB))

	drifted, err := service.RevokeMember(ctx, created.CellID, SecureCellMemberTransitionRequest{
		ParticipantDID: participantB.AgentID(),
		ActorDID:       owner.AgentID(),
		Reason:         "federated participant credential revoked",
		Metadata:       map[string]string{"incident": "FED-ASSURE-01"},
	})
	if err != nil {
		t.Fatalf("RevokeMember failed: %v", err)
	}
	if len(drifted.FederationContracts) != 1 || drifted.FederationContracts[0].Status != SecureCellFederationContractStatusActive {
		t.Fatalf("expected contract to remain active before assurance sweep, got %+v", drifted.FederationContracts)
	}

	findings, err := service.ListFederationAssuranceFindings(ctx, SecureCellFederationAssuranceFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
	})
	if err != nil {
		t.Fatalf("ListFederationAssuranceFindings failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected federation assurance findings after participant revoke")
	}
	var continuityFound bool
	for _, finding := range findings {
		if finding.ContractID == contractID && finding.Category == SecureCellFederationAssuranceCategoryParticipantContinuity && finding.Severity == SecureCellFederationAssuranceSeverityCritical && finding.AutoContainmentEligible {
			continuityFound = true
			break
		}
	}
	if !continuityFound {
		t.Fatalf("expected critical participant continuity finding for contract %q, got %+v", contractID, findings)
	}

	report, err := service.BuildFederationAssuranceReport(ctx, created.CellID, orgID, SecureCellFederationAssuranceReportOptions{})
	if err != nil {
		t.Fatalf("BuildFederationAssuranceReport failed: %v", err)
	}
	if report == nil || report.Organization.OrganizationID != orgID || report.CriticalFindingCount == 0 || report.AutoContainmentEligibleCount == 0 {
		t.Fatalf("expected assurance report with critical findings, got %+v", report)
	}

	sweep, err := service.SweepFederationAssurance(ctx, time.Now().UTC(), SecureCellLifecycleRequest{
		ActorDID: "did:aethelred:automation-sweeper",
		Reason:   "automated federation assurance sweep",
		Metadata: map[string]string{"ticket": "FED-ASSURE-SWEEP"},
	})
	if err != nil {
		t.Fatalf("SweepFederationAssurance failed: %v", err)
	}
	if sweep.ContractsSuspended != 1 {
		t.Fatalf("expected one contract suspension from assurance sweep, got %+v", sweep)
	}

	final, err := service.GetCell(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetCell failed: %v", err)
	}
	_, finalContract := findSecureCellFederationContract(final.FederationContracts, contractID)
	if finalContract == nil || finalContract.Status != SecureCellFederationContractStatusSuspended {
		t.Fatalf("expected contract %q to be suspended after assurance sweep, got %+v", contractID, final.FederationContracts)
	}

	actions, err := service.ListFederationAssuranceActions(ctx, SecureCellFederationAssuranceActionFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ContractID:     contractID,
	})
	if err != nil {
		t.Fatalf("ListFederationAssuranceActions failed: %v", err)
	}
	if len(actions) != 1 || actions[0].ContractID != contractID || actions[0].Action != "suspend_contract" || actions[0].FindingID == "" {
		t.Fatalf("expected one assurance containment action, got %+v", actions)
	}
}

func TestService_FederationCounterpartyAssuranceBundleIntakeAndDriftContainment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Reciprocal Assurance Cell",
		Purpose:       "reciprocal federation assurance intake",
		Resource:      "cell:federation-reciprocal-assurance",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		ExpectedDID:      participantB.AgentID(),
		Reason:           "invite reciprocal counterparty",
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitationID := invited.FederationInvitations[len(invited.FederationInvitations)-1].ID

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitationID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "counterparty_reviewer",
		},
		Reason: "counterparty accepted reciprocal assurance invitation",
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	if len(accepted.FederationContracts) != 1 {
		t.Fatalf("expected one federation contract, got %+v", accepted.FederationContracts)
	}
	contractID := accepted.FederationContracts[0].ID
	orgID := secureCellFederationOrganizationID(secureCellFederationSponsor(participantB))

	bundle, err := service.BuildFederationAssuranceBundle(ctx, created.CellID, orgID, SecureCellFederationAssuranceBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationAssuranceBundle failed: %v", err)
	}
	if bundle.Signature == nil || bundle.ContentHash == "" || bundle.Organization.OrganizationID != orgID {
		t.Fatalf("expected signed federation assurance bundle for org %q, got %+v", orgID, bundle)
	}

	intakeResult, err := service.IngestFederationAssuranceBundle(ctx, created.CellID, orgID, SecureCellFederationAssuranceIntakeRequest{
		ActorDID: owner.AgentID(),
		Bundle:   bundle,
		Reason:   "ingest reciprocal assurance bundle",
	})
	if err != nil {
		t.Fatalf("IngestFederationAssuranceBundle valid failed: %v", err)
	}
	if len(intakeResult.FederationCounterpartyAssurance) != 1 || intakeResult.FederationCounterpartyAssurance[0].Status != SecureCellFederationCounterpartyAssuranceStatusVerified {
		t.Fatalf("expected verified counterparty assurance snapshot, got %+v", intakeResult.FederationCounterpartyAssurance)
	}

	items, err := service.ListFederationCounterpartyAssurance(ctx, SecureCellFederationCounterpartyAssuranceFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		Status:         SecureCellFederationCounterpartyAssuranceStatusVerified,
	})
	if err != nil {
		t.Fatalf("ListFederationCounterpartyAssurance verified failed: %v", err)
	}
	if len(items) != 1 || items[0].BundleID != bundle.ID || !items[0].Verified {
		t.Fatalf("expected one verified counterparty assurance summary, got %+v", items)
	}

	tampered := secureCellCloneFederationAssuranceBundle(*bundle)
	tampered.Assurance.CriticalFindingCount = 3
	tampered.Assurance.FindingCount = 3
	tampered.Assurance.Findings = append(tampered.Assurance.Findings, SecureCellFederationAssuranceFinding{
		ID:       "tampered-finding",
		CellID:   tampered.CellID,
		Severity: SecureCellFederationAssuranceSeverityCritical,
		Category: SecureCellFederationAssuranceCategoryPolicyDrift,
		Summary:  "tampered critical finding",
	})

	invalidResult, err := service.IngestFederationAssuranceBundle(ctx, created.CellID, orgID, SecureCellFederationAssuranceIntakeRequest{
		ActorDID: owner.AgentID(),
		Bundle:   &tampered,
		Reason:   "ingest tampered reciprocal assurance bundle",
	})
	if err != nil {
		t.Fatalf("IngestFederationAssuranceBundle invalid failed: %v", err)
	}
	if len(invalidResult.FederationCounterpartyAssurance) != 2 {
		t.Fatalf("expected two counterparty assurance snapshots after tampered ingest, got %+v", invalidResult.FederationCounterpartyAssurance)
	}
	latestSnapshot := invalidResult.FederationCounterpartyAssurance[len(invalidResult.FederationCounterpartyAssurance)-1]
	if latestSnapshot.Status != SecureCellFederationCounterpartyAssuranceStatusInvalid || latestSnapshot.Verified {
		t.Fatalf("expected latest counterparty assurance snapshot to be invalid, got %+v", latestSnapshot)
	}

	invalidItems, err := service.ListFederationCounterpartyAssurance(ctx, SecureCellFederationCounterpartyAssuranceFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		Status:         SecureCellFederationCounterpartyAssuranceStatusInvalid,
	})
	if err != nil {
		t.Fatalf("ListFederationCounterpartyAssurance invalid failed: %v", err)
	}
	if len(invalidItems) != 1 || invalidItems[0].BundleID != tampered.ID || len(invalidItems[0].ContractIDs) == 0 || invalidItems[0].ContractIDs[0] != contractID {
		t.Fatalf("expected invalid counterparty assurance summary tied to contract %q, got %+v", contractID, invalidItems)
	}

	findings, err := service.ListFederationAssuranceFindings(ctx, SecureCellFederationAssuranceFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ContractID:     contractID,
	})
	if err != nil {
		t.Fatalf("ListFederationAssuranceFindings failed: %v", err)
	}
	var invalidFound bool
	for _, finding := range findings {
		if finding.ContractID == contractID && finding.Category == SecureCellFederationAssuranceCategoryCounterpartyAssuranceInvalid && finding.Severity == SecureCellFederationAssuranceSeverityCritical && finding.AutoContainmentEligible {
			invalidFound = true
			break
		}
	}
	if !invalidFound {
		t.Fatalf("expected invalid counterparty assurance finding for contract %q, got %+v", contractID, findings)
	}

	trustPack, err := service.BuildFederationOrganizationTrustPack(ctx, created.CellID, orgID, SecureCellFederationOrganizationTrustPackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationOrganizationTrustPack failed: %v", err)
	}
	if trustPack.Assurance == nil || trustPack.Assurance.CriticalFindingCount == 0 {
		t.Fatalf("expected trust pack assurance summary to capture critical findings, got %+v", trustPack.Assurance)
	}
	if len(trustPack.CounterpartyAssurance) == 0 || trustPack.CounterpartyAssurance[0].Status != SecureCellFederationCounterpartyAssuranceStatusInvalid {
		t.Fatalf("expected trust pack to surface invalid counterparty assurance, got %+v", trustPack.CounterpartyAssurance)
	}

	sweep, err := service.SweepFederationAssurance(ctx, time.Now().UTC(), SecureCellLifecycleRequest{
		ActorDID: "did:aethelred:automation-sweeper",
		Reason:   "automated reciprocal assurance sweep",
		Metadata: map[string]string{"ticket": "FED-RECIPROCAL-01"},
	})
	if err != nil {
		t.Fatalf("SweepFederationAssurance failed: %v", err)
	}
	if sweep.ContractsSuspended != 1 {
		t.Fatalf("expected one contract suspension from reciprocal assurance sweep, got %+v", sweep)
	}

	final, err := service.GetCell(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetCell failed: %v", err)
	}
	_, finalContract := findSecureCellFederationContract(final.FederationContracts, contractID)
	if finalContract == nil || finalContract.Status != SecureCellFederationContractStatusSuspended {
		t.Fatalf("expected contract %q to be suspended after reciprocal assurance sweep, got %+v", contractID, final.FederationContracts)
	}
}

func TestService_FederationIncidentBulletinIntakeAndContainment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Incident Cell",
		Purpose:       "reciprocal federation incident containment",
		Resource:      "cell:federation-incidents",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Federated Incident Session",
		Purpose:         "exchange under monitored federation",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"confidential"},
		Reason:          "open incident-capable collaboration room",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session, ok := mustSecureCellSession(t, started, started.Sessions[len(started.Sessions)-1].ID)
	if !ok {
		t.Fatalf("expected session, got %+v", started.Sessions)
	}

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "counterparty_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite reciprocal incident counterparty",
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitationID := invited.FederationInvitations[len(invited.FederationInvitations)-1].ID

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID:           invitationID,
		ActorDID:               participantB.AgentID(),
		Participant:            SecureCellParticipant{Identity: participantB, Role: "counterparty_reviewer"},
		OfferedSessionScopeIDs: []string{session.ID},
		OfferedDataClasses:     []string{"confidential"},
		OfferedActions:         []string{"share_output", "session_exchange"},
		Reason:                 "counterparty accepted federated incident collaboration",
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	if len(accepted.FederationContracts) != 1 {
		t.Fatalf("expected one federation contract, got %+v", accepted.FederationContracts)
	}
	contractID := accepted.FederationContracts[0].ID
	orgID := secureCellFederationOrganizationID(secureCellFederationSponsor(participantB))

	withMember, err := service.AddSessionMember(ctx, created.CellID, SecureCellSessionMemberTransitionRequest{
		ParticipantDID: participantB.AgentID(),
		ActorDID:       owner.AgentID(),
		Reason:         "admit federated participant into scoped session",
	}, session.ID)
	if err != nil {
		t.Fatalf("AddSessionMember failed: %v", err)
	}
	if _, ok := mustSecureCellSession(t, withMember, session.ID); !ok {
		t.Fatalf("expected updated session after federated member admit, got %+v", withMember.Sessions)
	}

	shared, err := service.ShareOutput(ctx, created.CellID, SecureCellSessionShareRequest{
		ActorDID:       participantB.AgentID(),
		SessionID:      session.ID,
		Name:           "Counterparty Evidence Packet",
		ArtifactType:   "document",
		Classification: "confidential",
		Resource:       "secure-cell:incident-packet",
		Summary:        "counterparty shared sensitive incident packet",
		SharedWith:     []string{participantA.AgentID()},
		IntegrityHash:  "sha256:incident-packet",
		Reason:         "share regulated incident packet",
		Metadata:       map[string]string{"scenario": "federation_incident"},
	})
	if err != nil {
		t.Fatalf("ShareOutput failed: %v", err)
	}
	sharedOutput, ok := mustSecureCellSharedOutput(t, shared, shared.SharedOutputs[len(shared.SharedOutputs)-1].ID)
	if !ok {
		t.Fatalf("expected shared output, got %+v", shared.SharedOutputs)
	}
	if !secureCellStringSliceContains(sharedOutput.FederationOrgIDs, orgID) || !secureCellStringSliceContains(sharedOutput.FederationContractIDs, contractID) {
		t.Fatalf("expected shared output to bind to federation org %q and contract %q, got %+v", orgID, contractID, sharedOutput)
	}

	exchanged, err := service.RecordExchange(ctx, created.CellID, SecureCellSessionExchangeRequest{
		ActorDID:       participantB.AgentID(),
		SessionID:      session.ID,
		Name:           "Counterparty Incident Exchange",
		ExchangeType:   "message",
		Classification: "confidential",
		Resource:       "secure-cell:incident-exchange",
		Summary:        "counterparty exchanged sensitive incident details",
		Recipients:     []string{participantA.AgentID()},
		IntegrityHash:  "sha256:incident-exchange",
		Reason:         "exchange regulated incident details",
		Metadata:       map[string]string{"scenario": "federation_incident"},
	})
	if err != nil {
		t.Fatalf("RecordExchange failed: %v", err)
	}
	var sessionExchange SecureCellSessionExchange
	for _, item := range exchanged.SessionExchanges {
		if item.ID == exchanged.SessionExchanges[len(exchanged.SessionExchanges)-1].ID {
			sessionExchange = item
			break
		}
	}
	if sessionExchange.ID == "" {
		t.Fatalf("expected session exchange, got %+v", exchanged.SessionExchanges)
	}
	if !secureCellStringSliceContains(sessionExchange.FederationOrgIDs, orgID) || !secureCellStringSliceContains(sessionExchange.FederationContractIDs, contractID) {
		t.Fatalf("expected session exchange to bind to federation org %q and contract %q, got %+v", orgID, contractID, sessionExchange)
	}

	published, err := service.PublishFederationIncident(ctx, created.CellID, orgID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityCritical,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Counterparty exchange is now considered compromised",
		Description:              "Reciprocal bulletin should suspend the contract and contain scoped artifacts.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		SharedOutputIDs:          []string{sharedOutput.ID},
		SessionExchangeIDs:       []string{sessionExchange.ID},
		AutoContainmentRequested: true,
		Reason:                   "publish reciprocal incident bulletin",
		Metadata:                 map[string]string{"ticket": "FED-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	if len(published.FederationIncidents) != 1 {
		t.Fatalf("expected one local federation incident, got %+v", published.FederationIncidents)
	}
	incidentID := published.FederationIncidents[0].ID

	localIncidents, err := service.ListFederationIncidents(ctx, SecureCellFederationIncidentFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		Status:         SecureCellFederationIncidentStatusOpen,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidents failed: %v", err)
	}
	if len(localIncidents) != 1 || localIncidents[0].IncidentID != incidentID {
		t.Fatalf("expected one open federation incident summary, got %+v", localIncidents)
	}

	bulletin, err := service.BuildFederationIncidentBulletin(ctx, created.CellID, orgID, SecureCellFederationIncidentBulletinOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentBulletin failed: %v", err)
	}
	if bulletin.Signature == nil || bulletin.ContentHash == "" || len(bulletin.Incidents) != 1 || bulletin.Incidents[0].IncidentID != incidentID {
		t.Fatalf("expected signed bulletin with one incident, got %+v", bulletin)
	}

	intakeResult, err := service.IngestFederationIncidentBulletin(ctx, created.CellID, orgID, SecureCellFederationIncidentBulletinIntakeRequest{
		ActorDID: owner.AgentID(),
		Bulletin: bulletin,
		Reason:   "ingest reciprocal federation incident bulletin",
	})
	if err != nil {
		t.Fatalf("IngestFederationIncidentBulletin failed: %v", err)
	}
	if len(intakeResult.FederationCounterpartyIncidents) != 1 || intakeResult.FederationCounterpartyIncidents[0].Status != SecureCellFederationCounterpartyIncidentStatusVerified {
		t.Fatalf("expected verified counterparty incident bulletin, got %+v", intakeResult.FederationCounterpartyIncidents)
	}

	counterpartyItems, err := service.ListFederationCounterpartyIncidents(ctx, SecureCellFederationCounterpartyIncidentFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		Status:         SecureCellFederationCounterpartyIncidentStatusVerified,
	})
	if err != nil {
		t.Fatalf("ListFederationCounterpartyIncidents failed: %v", err)
	}
	if len(counterpartyItems) != 1 || counterpartyItems[0].BulletinID != bulletin.ID || counterpartyItems[0].OpenIncidentCount != 1 {
		t.Fatalf("expected one verified counterparty incident summary, got %+v", counterpartyItems)
	}

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	if len(responses) < 2 {
		t.Fatalf("expected local and counterparty incident responses, got %+v", responses)
	}
	var localResponseID, counterpartyResponseID string
	for _, item := range responses {
		switch item.SourceType {
		case SecureCellFederationIncidentResponseSourceLocalIncident:
			localResponseID = item.ResponseID
		case SecureCellFederationIncidentResponseSourceCounterpartyIncident:
			counterpartyResponseID = item.ResponseID
		}
	}
	if localResponseID == "" || counterpartyResponseID == "" {
		t.Fatalf("expected both local and counterparty response IDs, got %+v", responses)
	}

	reportDueAt := time.Now().UTC().Add(2 * time.Hour)
	plannedReportResult, err := service.CreateFederationIncidentReport(ctx, created.CellID, counterpartyResponseID, SecureCellFederationIncidentReportPlanRequest{
		ActorDID:         participantB.AgentID(),
		Regulator:        "uk-ico",
		Jurisdiction:     "UK",
		Framework:        "uk-gdpr",
		ReportType:       "breach_notification",
		Summary:          "Counterparty planned regulator notification for coordinated incident response",
		Description:      "The counterparty is preparing a regulator-facing notification linked to the bilateral incident response.",
		RequiredSections: []string{"scope", "impact", "containment"},
		EvidenceIDs:      []string{incidentID},
		DueAt:            &reportDueAt,
		Reason:           "plan coordinated regulator notification",
		Metadata:         map[string]string{"ticket": "FED-REPORT-PLAN-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationIncidentReport failed: %v", err)
	}

	reportItems, err := service.ListFederationIncidentReports(ctx, SecureCellFederationIncidentReportFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ResponseID:     counterpartyResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReports failed: %v", err)
	}
	if len(reportItems) != 1 || reportItems[0].Status != SecureCellFederationIncidentReportStatusPendingSubmission {
		t.Fatalf("expected one pending federation incident report, got %+v", reportItems)
	}
	reportID := reportItems[0].ReportID

	overdueReportAt := reportDueAt.Add(time.Hour)
	overdueReports, err := service.ListOverdueFederationIncidentReports(ctx, SecureCellOverdueFederationIncidentReportFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ResponseID:     counterpartyResponseID,
		Before:         &overdueReportAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentReports failed: %v", err)
	}
	if len(overdueReports) != 1 || overdueReports[0].ReportID != reportID {
		t.Fatalf("expected one overdue federation incident report, got %+v", overdueReports)
	}

	_, err = service.SubmitFederationIncidentReport(ctx, created.CellID, reportID, SecureCellFederationIncidentReportSubmitRequest{
		ActorDID:            participantB.AgentID(),
		SubmissionReference: "ico-2026-0001",
		Summary:             "Counterparty submitted regulator notification for bilateral incident response",
		Description:         "The counterparty submitted a regulator-ready notification package with scoped evidence.",
		EvidenceIDs:         []string{plannedReportResult.ControlLedger.Bundle.ID},
		Reason:              "submit coordinated regulator notification",
		Metadata:            map[string]string{"ticket": "FED-REPORT-SUBMIT-01"},
	})
	if err != nil {
		t.Fatalf("SubmitFederationIncidentReport failed: %v", err)
	}

	_, err = service.AcknowledgeFederationIncidentReport(ctx, created.CellID, reportID, SecureCellFederationIncidentReportAcknowledgeRequest{
		ActorDID:                 owner.AgentID(),
		AcknowledgingParty:       SecureCellFederationIncidentResponsePartyLocalOrg,
		AcknowledgementReference: "local-intake-ack-0001",
		Reason:                   "acknowledge counterparty regulator notification",
		Metadata:                 map[string]string{"ticket": "FED-REPORT-ACK-01"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeFederationIncidentReport failed: %v", err)
	}

	reportItems, err = service.ListFederationIncidentReports(ctx, SecureCellFederationIncidentReportFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ResponseID:     counterpartyResponseID,
		Status:         SecureCellFederationIncidentReportStatusAcknowledged,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReports after acknowledgement failed: %v", err)
	}
	if len(reportItems) != 1 || reportItems[0].ReportID != reportID || reportItems[0].AcknowledgedBy != owner.AgentID() {
		t.Fatalf("expected one acknowledged federation incident report, got %+v", reportItems)
	}

	counterpartyResponseWithReport, err := service.GetFederationIncidentResponse(ctx, created.CellID, counterpartyResponseID)
	if err != nil {
		t.Fatalf("GetFederationIncidentResponse after report acknowledgement failed: %v", err)
	}
	if len(counterpartyResponseWithReport.IncidentReports) != 1 || counterpartyResponseWithReport.IncidentReports[0].ID != reportID || counterpartyResponseWithReport.IncidentReports[0].Status != SecureCellFederationIncidentReportStatusAcknowledged {
		t.Fatalf("expected acknowledged report on counterparty response, got %+v", counterpartyResponseWithReport.IncidentReports)
	}

	reportBundle, err := service.BuildFederationIncidentReportBundle(ctx, created.CellID, reportID, SecureCellFederationIncidentReportBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentReportBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentReportBundle(reportBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentReportBundle failed: %v", err)
	}
	if reportBundle.ReportSummary.ReportID != reportID || reportBundle.ReportSummary.Status != SecureCellFederationIncidentReportStatusAcknowledged || reportBundle.ResponseSummary.ReportCount != 1 || reportBundle.ResponseSummary.AcknowledgedReportCount != 1 {
		t.Fatalf("expected acknowledged federation incident report bundle projection, got %+v", reportBundle.ReportSummary)
	}
	if reportBundle.ResponseBundleHash == "" || reportBundle.Signature == nil {
		t.Fatalf("expected signed federation incident report bundle with response linkage, got %+v", reportBundle)
	}

	reportIntakeResult, err := service.IngestFederationIncidentReportBundle(ctx, created.CellID, orgID, SecureCellFederationIncidentReportBundleIntakeRequest{
		ActorDID: owner.AgentID(),
		Bundle:   reportBundle,
		Reason:   "ingest reciprocal incident report bundle",
		Metadata: map[string]string{"ticket": "FED-REPORT-INTAKE-01"},
	})
	if err != nil {
		t.Fatalf("IngestFederationIncidentReportBundle failed: %v", err)
	}
	if len(reportIntakeResult.FederationCounterpartyIncidentReports) != 1 || reportIntakeResult.FederationCounterpartyIncidentReports[0].Status != SecureCellFederationCounterpartyIncidentReportStatusVerified {
		t.Fatalf("expected one verified counterparty incident report snapshot, got %+v", reportIntakeResult.FederationCounterpartyIncidentReports)
	}
	counterpartyReportItems, err := service.ListFederationCounterpartyIncidentReports(ctx, SecureCellFederationCounterpartyIncidentReportFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		Status:         SecureCellFederationCounterpartyIncidentReportStatusVerified,
	})
	if err != nil {
		t.Fatalf("ListFederationCounterpartyIncidentReports failed: %v", err)
	}
	if len(counterpartyReportItems) != 1 || counterpartyReportItems[0].ReportID != reportID || counterpartyReportItems[0].ReconciliationStatus != SecureCellFederationIncidentReportReconciliationStatusAligned {
		t.Fatalf("expected one aligned verified counterparty incident report summary, got %+v", counterpartyReportItems)
	}
	reconciliations, err := service.ListFederationIncidentReportReconciliations(ctx, SecureCellFederationIncidentReportReconciliationFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		IncidentID:     incidentID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportReconciliations failed: %v", err)
	}
	if len(reconciliations) != 1 || reconciliations[0].LocalReportID != reportID || reconciliations[0].Status != SecureCellFederationIncidentReportReconciliationStatusAligned {
		t.Fatalf("expected one aligned incident report reconciliation summary, got %+v", reconciliations)
	}
	if !controlLedgerHasControl(reportIntakeResult.ControlLedger, "CELL-FED-07") {
		t.Fatalf("expected control ledger to include reciprocal incident reporting control, got %+v", reportIntakeResult.ControlLedger.Controls)
	}

	acknowledged, err := service.AcknowledgeFederationIncidentResponse(ctx, created.CellID, counterpartyResponseID, SecureCellFederationIncidentResponseAcknowledgeRequest{
		ActorDID: owner.AgentID(),
		Reason:   "local incident desk acknowledged counterparty incident",
		Metadata: map[string]string{"ticket": "FED-RESP-ACK-01"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeFederationIncidentResponse failed: %v", err)
	}
	ackResponse, err := service.GetFederationIncidentResponse(ctx, created.CellID, counterpartyResponseID)
	if err != nil {
		t.Fatalf("GetFederationIncidentResponse after acknowledge failed: %v", err)
	}
	if ackResponse.AcknowledgedBy != owner.AgentID() || ackResponse.Status != SecureCellFederationIncidentResponseStatusAcknowledged {
		t.Fatalf("expected acknowledged counterparty response, got %+v", ackResponse)
	}

	_, err = service.AttestFederationIncidentRemediation(ctx, created.CellID, counterpartyResponseID, SecureCellFederationIncidentRemediationAttestationRequest{
		ActorDID:    owner.AgentID(),
		Summary:     "Local controls rotated and counterparty incident intake completed",
		Description: "The local organization rotated scoped secrets, validated containment, and documented remediation.",
		EvidenceIDs: []string{acknowledged.ControlLedger.Bundle.ID},
		Reason:      "submit bilateral remediation evidence",
		Metadata:    map[string]string{"ticket": "FED-RESP-REMEDIATE-01"},
	})
	if err != nil {
		t.Fatalf("AttestFederationIncidentRemediation failed: %v", err)
	}
	finalCounterpartyResponse, err := service.GetFederationIncidentResponse(ctx, created.CellID, counterpartyResponseID)
	if err != nil {
		t.Fatalf("GetFederationIncidentResponse after remediation failed: %v", err)
	}
	if finalCounterpartyResponse.Status != SecureCellFederationIncidentResponseStatusRemediated || len(finalCounterpartyResponse.RemediationAttestations) != 1 {
		t.Fatalf("expected remediated counterparty response with attestation, got %+v", finalCounterpartyResponse)
	}

	remediations, err := service.ListFederationIncidentRemediations(ctx, SecureCellFederationIncidentRemediationFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ResponseID:     counterpartyResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentRemediations failed: %v", err)
	}
	if len(remediations) != 1 || remediations[0].ResponseID != counterpartyResponseID {
		t.Fatalf("expected one remediation attestation summary, got %+v", remediations)
	}

	verified, err := service.VerifyFederationIncidentRemediation(ctx, created.CellID, counterpartyResponseID, SecureCellFederationIncidentRemediationVerificationRequest{
		ActorDID:              participantB.AgentID(),
		ReviewingParty:        SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Decision:              SecureCellFederationIncidentRemediationVerificationDecisionAccepted,
		VerifiedAttestationID: remediations[0].AttestationID,
		Summary:               "Counterparty verified local remediation evidence",
		Description:           "The counterparty reviewed the local remediation attestation and accepted the coordinated response state.",
		EvidenceIDs:           []string{remediations[0].AttestationID},
		Reason:                "verify bilateral remediation evidence",
		Metadata:              map[string]string{"ticket": "FED-RESP-VERIFY-01"},
	})
	if err != nil {
		t.Fatalf("VerifyFederationIncidentRemediation failed: %v", err)
	}
	verifiedCounterpartyResponse, err := service.GetFederationIncidentResponse(ctx, created.CellID, counterpartyResponseID)
	if err != nil {
		t.Fatalf("GetFederationIncidentResponse after verification failed: %v", err)
	}
	if verifiedCounterpartyResponse.Status != SecureCellFederationIncidentResponseStatusRemediated || verifiedCounterpartyResponse.VerifiedBy != participantB.AgentID() || len(verifiedCounterpartyResponse.RemediationVerifications) != 1 {
		t.Fatalf("expected verified remediated counterparty response, got %+v", verifiedCounterpartyResponse)
	}

	verifications, err := service.ListFederationIncidentVerifications(ctx, SecureCellFederationIncidentVerificationFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ResponseID:     counterpartyResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentVerifications failed: %v", err)
	}
	if len(verifications) != 1 || verifications[0].ResponseID != counterpartyResponseID || verifications[0].Decision != SecureCellFederationIncidentRemediationVerificationDecisionAccepted {
		t.Fatalf("expected one accepted remediation verification summary, got %+v", verifications)
	}

	overdueAt := time.Now().UTC().Add(72 * time.Hour)
	overdue, err := service.ListOverdueFederationIncidentResponses(ctx, SecureCellOverdueFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		Before:         &overdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentResponses failed: %v", err)
	}
	if len(overdue) == 0 {
		t.Fatalf("expected overdue local incident response before automated sweep, got %+v", overdue)
	}

	responseSweep, err := service.SweepFederationIncidentResponses(ctx, overdueAt, SecureCellLifecycleRequest{
		ActorDID: "did:aethelred:incident-response-sweeper",
		Reason:   "automated bilateral response escalation sweep",
		Metadata: map[string]string{"ticket": "FED-RESP-SWEEP-01"},
	})
	if err != nil {
		t.Fatalf("SweepFederationIncidentResponses failed: %v", err)
	}
	if responseSweep.ResponsesScanned == 0 || responseSweep.ResponsesEscalated == 0 {
		t.Fatalf("expected response sweep to scan and escalate at least one response, got %+v", responseSweep)
	}

	sweep, err := service.SweepFederationIncidents(ctx, time.Now().UTC(), SecureCellLifecycleRequest{
		ActorDID: "did:aethelred:automation-sweeper",
		Reason:   "automated reciprocal federation incident sweep",
		Metadata: map[string]string{"ticket": "FED-INC-SWEEP-01"},
	})
	if err != nil {
		t.Fatalf("SweepFederationIncidents failed: %v", err)
	}
	if sweep.ContractsSuspended != 1 || sweep.SessionsQuarantined != 1 || sweep.ArtifactsContained < 2 {
		t.Fatalf("expected incident sweep to suspend contract, quarantine session, and contain artifacts, got %+v", sweep)
	}

	final, err := service.GetCell(ctx, created.CellID)
	if err != nil {
		t.Fatalf("GetCell failed: %v", err)
	}
	_, finalContract := findSecureCellFederationContract(final.FederationContracts, contractID)
	if finalContract == nil || finalContract.Status != SecureCellFederationContractStatusSuspended {
		t.Fatalf("expected contract %q to be suspended after incident sweep, got %+v", contractID, final.FederationContracts)
	}
	finalSession, ok := mustSecureCellSession(t, final, session.ID)
	if !ok || finalSession.Status != SecureCellSessionStatusQuarantined {
		t.Fatalf("expected session %q to be quarantined after incident sweep, got %+v", session.ID, final.Sessions)
	}
	finalOutput, ok := mustSecureCellSharedOutput(t, final, sharedOutput.ID)
	if !ok || finalOutput.ContainmentStatus != SecureCellArtifactContainmentStatusContained || finalOutput.ContainmentSourceType != "federation_incident" || finalOutput.ContainmentSourceID != incidentID {
		t.Fatalf("expected shared output containment from federation incident %q, got %+v", incidentID, finalOutput)
	}
	var finalExchange SecureCellSessionExchange
	for _, item := range final.SessionExchanges {
		if item.ID == sessionExchange.ID {
			finalExchange = item
			break
		}
	}
	if finalExchange.ID == "" || finalExchange.ContainmentStatus != SecureCellArtifactContainmentStatusContained || finalExchange.ContainmentSourceType != "federation_incident" || finalExchange.ContainmentSourceID != incidentID {
		t.Fatalf("expected session exchange containment from federation incident %q, got %+v", incidentID, finalExchange)
	}

	actions, err := service.ListFederationIncidentActions(ctx, SecureCellFederationIncidentActionFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		IncidentID:     incidentID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentActions failed: %v", err)
	}
	if len(actions) == 0 {
		t.Fatalf("expected incident action records after sweep, got %+v", actions)
	}

	responseActions, err := service.ListFederationIncidentResponseActions(ctx, SecureCellFederationIncidentResponseActionFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ResponseID:     counterpartyResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponseActions failed: %v", err)
	}
	if len(responseActions) < 3 {
		t.Fatalf("expected response acknowledgement, remediation, and verification actions, got %+v", responseActions)
	}

	trustPack, err := service.BuildFederationOrganizationTrustPack(ctx, created.CellID, orgID, SecureCellFederationOrganizationTrustPackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationOrganizationTrustPack failed: %v", err)
	}
	if len(trustPack.Incidents) != 1 || trustPack.Incidents[0].IncidentID != incidentID {
		t.Fatalf("expected trust pack to include local incident summary, got %+v", trustPack.Incidents)
	}
	if len(trustPack.CounterpartyIncidents) != 1 || trustPack.CounterpartyIncidents[0].BulletinID != bulletin.ID {
		t.Fatalf("expected trust pack to include imported counterparty incident summary, got %+v", trustPack.CounterpartyIncidents)
	}
	if len(trustPack.CounterpartyIncidentReports) != 1 || trustPack.CounterpartyIncidentReports[0].ReportID != reportID || trustPack.CounterpartyIncidentReports[0].ReconciliationStatus != SecureCellFederationIncidentReportReconciliationStatusAligned {
		t.Fatalf("expected trust pack to include aligned imported counterparty incident report summary, got %+v", trustPack.CounterpartyIncidentReports)
	}
	if len(trustPack.IncidentResponses) < 2 || len(trustPack.IncidentRemediations) != 1 {
		t.Fatalf("expected trust pack to include incident response and remediation summaries, got responses=%+v remediations=%+v", trustPack.IncidentResponses, trustPack.IncidentRemediations)
	}
	if len(trustPack.IncidentReports) != 1 || trustPack.IncidentReports[0].ReportID != reportID || trustPack.IncidentReports[0].Status != SecureCellFederationIncidentReportStatusAcknowledged {
		t.Fatalf("expected trust pack to include acknowledged incident report summary, got %+v", trustPack.IncidentReports)
	}
	if len(trustPack.IncidentReportReconciliations) != 1 || trustPack.IncidentReportReconciliations[0].LocalReportID != reportID || trustPack.IncidentReportReconciliations[0].Status != SecureCellFederationIncidentReportReconciliationStatusAligned {
		t.Fatalf("expected trust pack to include aligned incident report reconciliation summary, got %+v", trustPack.IncidentReportReconciliations)
	}
	if len(trustPack.IncidentVerifications) != 1 || trustPack.IncidentVerifications[0].ResponseID != counterpartyResponseID {
		t.Fatalf("expected trust pack to include incident verification summary, got %+v", trustPack.IncidentVerifications)
	}
	if !controlLedgerHasControl(verified.ControlLedger, "CELL-FED-06") {
		t.Fatalf("expected control ledger to include federation incident command fabric control, got %+v", verified.ControlLedger.Controls)
	}

	comparisonKey := reconciliations[0].ComparisonKey
	acknowledgedReconciliation, err := service.AcknowledgeFederationIncidentReportReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentReportReconciliationAcknowledgeRequest{
		ActorDID: owner.AgentID(),
		Reason:   "reviewed and accepted reciprocal report alignment",
		Metadata: map[string]string{"ticket": "FED-REPORT-RECON-ACK-01"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeFederationIncidentReportReconciliation failed: %v", err)
	}

	disputedReconciliation, err := service.DisputeFederationIncidentReportReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentReportReconciliationDisputeRequest{
		ActorDID:    owner.AgentID(),
		Reason:      "capture bilateral filing review challenge for auditor traceability",
		Divergences: []string{"counterparty report requires enhanced bilateral review notes"},
		Metadata:    map[string]string{"ticket": "FED-REPORT-RECON-DISPUTE-01"},
	})
	if err != nil {
		t.Fatalf("DisputeFederationIncidentReportReconciliation failed: %v", err)
	}

	resolvedReconciliation, err := service.ResolveFederationIncidentReportReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentReportReconciliationResolveRequest{
		ActorDID: owner.AgentID(),
		Reason:   "bilateral report review completed and dispute closed",
		Metadata: map[string]string{"ticket": "FED-REPORT-RECON-RESOLVE-01"},
	})
	if err != nil {
		t.Fatalf("ResolveFederationIncidentReportReconciliation failed: %v", err)
	}

	reconciliationActions, err := service.ListFederationIncidentReportReconciliationActions(ctx, SecureCellFederationIncidentReportReconciliationActionFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportReconciliationActions failed: %v", err)
	}
	if len(reconciliationActions) != 3 || reconciliationActions[0].Action != SecureCellFederationIncidentReportReconciliationActionResolve || reconciliationActions[0].ReviewStatus != SecureCellFederationIncidentReportReviewStatusResolved {
		t.Fatalf("expected three governed reconciliation actions ending in resolve, got %+v", reconciliationActions)
	}

	reconciliationBundle, err := service.BuildFederationIncidentReportReconciliationBundle(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentReportReconciliationBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentReportReconciliationBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentReportReconciliationBundle(reconciliationBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentReportReconciliationBundle failed: %v", err)
	}
	if reconciliationBundle.Reconciliation.ReviewStatus != SecureCellFederationIncidentReportReviewStatusResolved || len(reconciliationBundle.Actions) != 3 {
		t.Fatalf("expected resolved reconciliation bundle with three actions, got %+v", reconciliationBundle.Reconciliation)
	}

	reviewedTrustPack, err := service.BuildFederationOrganizationTrustPack(ctx, created.CellID, orgID, SecureCellFederationOrganizationTrustPackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationOrganizationTrustPack after reconciliation review failed: %v", err)
	}
	if len(reviewedTrustPack.IncidentReportReconciliations) != 1 || reviewedTrustPack.IncidentReportReconciliations[0].ReviewStatus != SecureCellFederationIncidentReportReviewStatusResolved || reviewedTrustPack.IncidentReportReconciliations[0].ReviewActionCount != 3 {
		t.Fatalf("expected trust pack reconciliation review state to be resolved with three actions, got %+v", reviewedTrustPack.IncidentReportReconciliations)
	}
	if !controlLedgerHasControl(resolvedReconciliation.ControlLedger, "CELL-FED-08") {
		t.Fatalf("expected control ledger to include bilateral report reconciliation control, got %+v", resolvedReconciliation.ControlLedger.Controls)
	}
	if len(acknowledgedReconciliation.Transitions) == 0 || len(disputedReconciliation.Transitions) == 0 || len(resolvedReconciliation.Transitions) == 0 {
		t.Fatalf("expected reconciliation lifecycle mutations to append transitions")
	}

	if _, err := service.AcknowledgeFederationIncidentResponse(ctx, created.CellID, localResponseID, SecureCellFederationIncidentResponseAcknowledgeRequest{
		ActorDID: participantB.AgentID(),
		Reason:   "counterparty acknowledged local incident response",
		Metadata: map[string]string{"ticket": "FED-LOCAL-ACK-01"},
	}); err != nil {
		t.Fatalf("AcknowledgeFederationIncidentResponse local failed: %v", err)
	}
	localRemediated, err := service.AttestFederationIncidentRemediation(ctx, created.CellID, localResponseID, SecureCellFederationIncidentRemediationAttestationRequest{
		ActorDID:       participantB.AgentID(),
		AttestingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:        "Counterparty completed coordinated remediation",
		Description:    "The counterparty rotated scoped credentials, confirmed containment, and provided bilateral remediation evidence.",
		EvidenceIDs:    []string{verified.ControlLedger.Bundle.ID},
		Reason:         "submit counterparty remediation evidence",
		Metadata:       map[string]string{"ticket": "FED-LOCAL-REMEDIATE-01"},
	})
	if err != nil {
		t.Fatalf("AttestFederationIncidentRemediation local failed: %v", err)
	}
	if _, err := service.ResolveFederationIncident(ctx, created.CellID, orgID, incidentID, SecureCellFederationIncidentResolveRequest{
		ActorDID: owner.AgentID(),
		Reason:   "local incident resolved after bilateral remediation",
		Metadata: map[string]string{"ticket": "FED-LOCAL-RESOLVE-01"},
	}); err != nil {
		t.Fatalf("ResolveFederationIncident failed: %v", err)
	}
	localClosedResult, err := service.VerifyFederationIncidentRemediation(ctx, created.CellID, localResponseID, SecureCellFederationIncidentRemediationVerificationRequest{
		ActorDID:       owner.AgentID(),
		ReviewingParty: SecureCellFederationIncidentResponsePartyLocalOrg,
		Decision:       SecureCellFederationIncidentRemediationVerificationDecisionAccepted,
		Summary:        "Local organization verified counterparty remediation",
		Description:    "The local organization reviewed the counterparty remediation evidence and accepted closure readiness.",
		EvidenceIDs:    []string{localRemediated.ControlLedger.Bundle.ID},
		Reason:         "close bilateral local incident response",
		Metadata:       map[string]string{"ticket": "FED-LOCAL-VERIFY-01"},
	})
	if err != nil {
		t.Fatalf("VerifyFederationIncidentRemediation local failed: %v", err)
	}
	localClosedResponse, err := service.GetFederationIncidentResponse(ctx, created.CellID, localResponseID)
	if err != nil {
		t.Fatalf("GetFederationIncidentResponse local after close failed: %v", err)
	}
	if localClosedResponse.Status != SecureCellFederationIncidentResponseStatusClosed || localClosedResponse.VerifiedBy != owner.AgentID() || localClosedResponse.ClosedBy != owner.AgentID() || localClosedResponse.ClosedAt == nil {
		t.Fatalf("expected resolved local response to close after accepted verification, got %+v", localClosedResponse)
	}
	_, err = service.AttestFederationIncidentClosure(ctx, created.CellID, localResponseID, SecureCellFederationIncidentClosureAttestationRequest{
		ActorDID:       participantB.AgentID(),
		AttestingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:        "Counterparty attested coordinated closure",
		Description:    "The counterparty confirmed the local response is jointly ready for closure.",
		EvidenceIDs:    []string{localClosedResult.ControlLedger.Bundle.ID},
		Reason:         "record bilateral closure acknowledgement",
		Metadata:       map[string]string{"ticket": "FED-LOCAL-CLOSE-ATTEST-01"},
	})
	if err != nil {
		t.Fatalf("AttestFederationIncidentClosure failed: %v", err)
	}
	localClosedResponse, err = service.GetFederationIncidentResponse(ctx, created.CellID, localResponseID)
	if err != nil {
		t.Fatalf("GetFederationIncidentResponse local after closure attestation failed: %v", err)
	}
	if len(localClosedResponse.ClosureAttestations) != 1 || localClosedResponse.ClosureAttestations[0].SubmittedBy != participantB.AgentID() {
		t.Fatalf("expected one closure attestation recorded on local response, got %+v", localClosedResponse.ClosureAttestations)
	}
	closures, err := service.ListFederationIncidentClosureAttestations(ctx, SecureCellFederationIncidentClosureAttestationFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ResponseID:     localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentClosureAttestations failed: %v", err)
	}
	if len(closures) != 1 || closures[0].ResponseID != localResponseID {
		t.Fatalf("expected one closure attestation summary, got %+v", closures)
	}
	closedBundle, err := service.BuildFederationIncidentResponseBundle(ctx, created.CellID, localResponseID, SecureCellFederationIncidentResponseBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentResponseBundle before dispute failed: %v", err)
	}
	if err := VerifyFederationIncidentResponseBundle(closedBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentResponseBundle before dispute failed: %v", err)
	}
	if closedBundle.ResponseSummary.ClosureAttestationCount != 1 || len(closedBundle.Response.ClosureAttestations) != 1 {
		t.Fatalf("expected closure attestation to appear in response bundle, got %+v", closedBundle.ResponseSummary)
	}
	disputed, err := service.DisputeFederationIncidentResponse(ctx, created.CellID, localResponseID, SecureCellFederationIncidentResponseDisputeRequest{
		ActorDID:              participantB.AgentID(),
		DisputingParty:        SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		RelatedVerificationID: localClosedResponse.RemediationVerifications[0].ID,
		RelatedClosureID:      localClosedResponse.ClosureAttestations[0].ID,
		Summary:               "Counterparty reopened local incident response for follow-up validation",
		Description:           "The counterparty disputed final closure readiness and reopened the response pending additional validation.",
		EvidenceIDs:           []string{localClosedResponse.ClosureAttestations[0].ID},
		Reason:                "reopen local response after closure challenge",
		Metadata:              map[string]string{"ticket": "FED-LOCAL-DISPUTE-01"},
	})
	if err != nil {
		t.Fatalf("DisputeFederationIncidentResponse failed: %v", err)
	}
	disputedResponse, err := service.GetFederationIncidentResponse(ctx, created.CellID, localResponseID)
	if err != nil {
		t.Fatalf("GetFederationIncidentResponse local after dispute failed: %v", err)
	}
	if disputedResponse.Status != SecureCellFederationIncidentResponseStatusRemediating || disputedResponse.VerifiedAt != nil || disputedResponse.ClosedAt != nil || len(disputedResponse.Disputes) != 1 {
		t.Fatalf("expected disputed local response to reopen with one dispute, got %+v", disputedResponse)
	}
	disputes, err := service.ListFederationIncidentDisputes(ctx, SecureCellFederationIncidentDisputeFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ResponseID:     localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDisputes failed: %v", err)
	}
	if len(disputes) != 1 || disputes[0].ResponseID != localResponseID || !disputes[0].Reopened {
		t.Fatalf("expected one reopening dispute summary, got %+v", disputes)
	}
	reopenedBundle, err := service.BuildFederationIncidentResponseBundle(ctx, created.CellID, localResponseID, SecureCellFederationIncidentResponseBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentResponseBundle after dispute failed: %v", err)
	}
	if err := VerifyFederationIncidentResponseBundle(reopenedBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentResponseBundle after dispute failed: %v", err)
	}
	if reopenedBundle.ResponseSummary.DisputeCount != 1 || len(reopenedBundle.Response.Disputes) != 1 || reopenedBundle.ResponseSummary.Status != SecureCellFederationIncidentResponseStatusRemediating {
		t.Fatalf("expected dispute to appear in reopened response bundle, got %+v", reopenedBundle.ResponseSummary)
	}
	if !controlLedgerHasControl(localClosedResult.ControlLedger, "CELL-FED-06") {
		t.Fatalf("expected closed local response control ledger to retain federation incident command fabric control, got %+v", localClosedResult.ControlLedger.Controls)
	}
	if !controlLedgerHasControl(disputed.ControlLedger, "CELL-FED-06") {
		t.Fatalf("expected disputed local response control ledger to retain federation incident command fabric control, got %+v", disputed.ControlLedger.Controls)
	}
}

func TestService_FederatedExchangeContractsRestrictSessionScope(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federated Scope Cell",
		Purpose:       "contract-scoped exchange enforcement",
		Resource:      "cell:federated-scope",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	scopedSessionResult, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Scoped Session",
		Purpose:         "allowed federated room",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "scoped room opened",
	})
	if err != nil {
		t.Fatalf("StartSession scoped failed: %v", err)
	}
	scopedSession, ok := mustSecureCellSession(t, scopedSessionResult, scopedSessionResult.Sessions[0].ID)
	if !ok {
		t.Fatalf("expected scoped session, got %+v", scopedSessionResult.Sessions)
	}

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{scopedSession.ID},
		DataClasses:      []string{"decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		Reason:           "scoped counterparty invite",
		Metadata:         map[string]string{"ticket": "SC-FED-CONTRACT-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invited.FederationInvitations[len(invited.FederationInvitations)-1].ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "joined scoped counterparty room",
		Metadata: map[string]string{"ticket": "SC-FED-CONTRACT-02"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	if len(accepted.FederationContracts) != 1 {
		t.Fatalf("expected one active contract after accept, got %+v", accepted.FederationContracts)
	}

	if _, err := service.AddSessionMember(ctx, created.CellID, SecureCellSessionMemberTransitionRequest{
		ParticipantDID: participantB.AgentID(),
		ActorDID:       owner.AgentID(),
		Reason:         "counterparty admitted to scoped room",
	}, scopedSession.ID); err != nil {
		t.Fatalf("AddSessionMember scoped failed: %v", err)
	}

	allowedShare, err := service.ShareOutput(ctx, created.CellID, SecureCellSessionShareRequest{
		ActorDID:       participantB.AgentID(),
		SessionID:      scopedSession.ID,
		Name:           "Scoped Memo",
		ArtifactType:   "memo",
		Classification: "decisioning",
		Summary:        "allowed counterparty share",
		SharedWith:     []string{participantA.AgentID()},
		Reason:         "share inside scoped contract room",
		Metadata:       map[string]string{"ticket": "SC-FED-CONTRACT-03"},
	})
	if err != nil {
		t.Fatalf("ShareOutput scoped failed: %v", err)
	}
	if len(allowedShare.SharedOutputs) != 1 || len(allowedShare.SharedOutputs[0].FederationContractIDs) != 1 {
		t.Fatalf("expected shared output bound to federation contract, got %+v", allowedShare.SharedOutputs)
	}

	unscopedSessionResult, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Unscoped Session",
		Purpose:         "room outside contract scope",
		ParticipantDIDs: []string{participantA.AgentID(), participantB.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "unscoped room opened",
	})
	if err != nil {
		t.Fatalf("StartSession unscoped failed: %v", err)
	}
	unscopedSession, ok := mustSecureCellSession(t, unscopedSessionResult, unscopedSessionResult.Sessions[len(unscopedSessionResult.Sessions)-1].ID)
	if !ok {
		t.Fatalf("expected unscoped session, got %+v", unscopedSessionResult.Sessions)
	}

	_, err = service.ShareOutput(ctx, created.CellID, SecureCellSessionShareRequest{
		ActorDID:       participantB.AgentID(),
		SessionID:      unscopedSession.ID,
		Name:           "Blocked Memo",
		ArtifactType:   "memo",
		Classification: "decisioning",
		Summary:        "blocked counterparty share",
		SharedWith:     []string{participantA.AgentID()},
		Reason:         "share outside scoped contract room",
	})
	if !errors.Is(err, ErrFederationExchangePolicyDenied) {
		t.Fatalf("expected ErrFederationExchangePolicyDenied, got %v", err)
	}
}

func TestService_FederationContractRenewalAndRevocationLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Contract Renewal Cell",
		Purpose:       "renew and revoke federated contracts with replayable diffs",
		Resource:      "cell:federation-renewal",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	firstSessionResult, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Initial Federation Room",
		Purpose:         "initial federated scope",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "initial room opened",
	})
	if err != nil {
		t.Fatalf("StartSession first failed: %v", err)
	}
	firstSession := firstSessionResult.Sessions[len(firstSessionResult.Sessions)-1]

	secondSessionResult, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Renewed Federation Room",
		Purpose:         "renewed federated scope",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "renewed room opened",
	})
	if err != nil {
		t.Fatalf("StartSession second failed: %v", err)
	}
	secondSession := secondSessionResult.Sessions[len(secondSessionResult.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{firstSession.ID, secondSession.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{secureCellFederationContractActionShareOutput, secureCellFederationContractActionSessionExchange},
		Reason:           "bilateral invite created",
		Metadata:         map[string]string{"ticket": "SC-FED-RENEW-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID:           invitation.ID,
		ActorDID:               participantB.AgentID(),
		Participant:            SecureCellParticipant{Identity: participantB, Role: "bank_b_reviewer"},
		OfferedSessionScopeIDs: []string{firstSession.ID},
		OfferedDataClasses:     []string{"decisioning"},
		OfferedActions:         []string{secureCellFederationContractActionShareOutput},
		Reason:                 "counterparty narrowed invite",
		Metadata:               map[string]string{"ticket": "SC-FED-RENEW-02"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	if len(accepted.FederationContracts) != 1 {
		t.Fatalf("expected one active contract after accept, got %+v", accepted.FederationContracts)
	}
	initialContract := accepted.FederationContracts[0]
	if initialContract.Revision != 1 || len(initialContract.NegotiationDiffs) == 0 {
		t.Fatalf("expected first revision with negotiation diffs, got %+v", initialContract)
	}
	if got := strings.Join(initialContract.AllowedActions, ","); got != secureCellFederationContractActionShareOutput {
		t.Fatalf("expected narrowed allowed actions, got %q", got)
	}
	if len(initialContract.SessionScopeIDs) != 1 || initialContract.SessionScopeIDs[0] != firstSession.ID {
		t.Fatalf("expected initial scope to be narrowed to first session, got %+v", initialContract.SessionScopeIDs)
	}

	if _, err := service.AddSessionMember(ctx, created.CellID, SecureCellSessionMemberTransitionRequest{
		ParticipantDID: participantB.AgentID(),
		ActorDID:       owner.AgentID(),
		Reason:         "counterparty admitted to initial room",
	}, firstSession.ID); err != nil {
		t.Fatalf("AddSessionMember first failed: %v", err)
	}
	if _, err := service.AddSessionMember(ctx, created.CellID, SecureCellSessionMemberTransitionRequest{
		ParticipantDID: participantB.AgentID(),
		ActorDID:       owner.AgentID(),
		Reason:         "counterparty admitted to renewed room",
	}, secondSession.ID); err != nil {
		t.Fatalf("AddSessionMember second failed: %v", err)
	}

	if _, err := service.ShareOutput(ctx, created.CellID, SecureCellSessionShareRequest{
		ActorDID:       participantB.AgentID(),
		SessionID:      firstSession.ID,
		Name:           "Initial Scoped Memo",
		ArtifactType:   "memo",
		Classification: "decisioning",
		Summary:        "allowed under initial contract",
		SharedWith:     []string{participantA.AgentID()},
		Reason:         "share under initial contract",
	}); err != nil {
		t.Fatalf("ShareOutput initial failed: %v", err)
	}

	renewed, err := service.RenewFederationContract(ctx, created.CellID, initialContract.ID, SecureCellFederationContractRenewRequest{
		ActorDID:               owner.AgentID(),
		SessionScopeIDs:        []string{firstSession.ID, secondSession.ID},
		DataClasses:            []string{"confidential", "decisioning"},
		AllowedActions:         []string{secureCellFederationContractActionShareOutput, secureCellFederationContractActionSessionExchange},
		OfferedSessionScopeIDs: []string{secondSession.ID},
		OfferedDataClasses:     []string{"decisioning"},
		OfferedActions:         []string{secureCellFederationContractActionSessionExchange},
		Resource:               "secure-cell:federation-contract:renewed",
		Reason:                 "counterparty requested renewed scope",
		Metadata:               map[string]string{"ticket": "SC-FED-RENEW-03"},
	})
	if err != nil {
		t.Fatalf("RenewFederationContract failed: %v", err)
	}
	if len(renewed.FederationContracts) != 2 {
		t.Fatalf("expected historical and renewed contracts, got %+v", renewed.FederationContracts)
	}
	var revokedContract, activeContract *SecureCellFederationContract
	for idx := range renewed.FederationContracts {
		contract := &renewed.FederationContracts[idx]
		switch contract.Status {
		case SecureCellFederationContractStatusRevoked:
			revokedContract = contract
		case SecureCellFederationContractStatusActive:
			activeContract = contract
		}
	}
	if revokedContract == nil || activeContract == nil {
		t.Fatalf("expected one revoked and one active contract after renewal, got %+v", renewed.FederationContracts)
	}
	if revokedContract.ID != initialContract.ID || revokedContract.ReplacedByContractID != activeContract.ID {
		t.Fatalf("expected initial contract to be superseded, got revoked=%+v active=%+v", revokedContract, activeContract)
	}
	if activeContract.Revision != 2 || activeContract.SupersedesContractID != initialContract.ID {
		t.Fatalf("expected revision 2 contract tied to initial contract, got %+v", activeContract)
	}
	if len(activeContract.SessionScopeIDs) != 1 || activeContract.SessionScopeIDs[0] != secondSession.ID {
		t.Fatalf("expected renewed contract to target second session, got %+v", activeContract.SessionScopeIDs)
	}
	if got := strings.Join(activeContract.AllowedActions, ","); got != secureCellFederationContractActionSessionExchange {
		t.Fatalf("expected renewed contract to narrow to session_exchange, got %q", got)
	}
	if len(activeContract.NegotiationDiffs) == 0 {
		t.Fatalf("expected renewed contract to carry negotiation diffs, got %+v", activeContract)
	}
	if got := renewed.Transitions[len(renewed.Transitions)-1].Action; got != "secure_cell.federation_contract_renewed" {
		t.Fatalf("expected final renewal transition, got %q", got)
	}

	if _, err := service.ShareOutput(ctx, created.CellID, SecureCellSessionShareRequest{
		ActorDID:       participantB.AgentID(),
		SessionID:      firstSession.ID,
		Name:           "Blocked Renewed Memo",
		ArtifactType:   "memo",
		Classification: "decisioning",
		Summary:        "blocked under renewed contract",
		SharedWith:     []string{participantA.AgentID()},
		Reason:         "share outside renewed scope",
	}); !errors.Is(err, ErrFederationExchangePolicyDenied) {
		t.Fatalf("expected ErrFederationExchangePolicyDenied after renewal, got %v", err)
	}

	if _, err := service.RecordExchange(ctx, created.CellID, SecureCellSessionExchangeRequest{
		ActorDID:       participantB.AgentID(),
		SessionID:      secondSession.ID,
		Name:           "Renewed Session Exchange",
		ExchangeType:   "note",
		Classification: "decisioning",
		Summary:        "allowed under renewed contract",
		Recipients:     []string{participantA.AgentID()},
		Reason:         "exchange inside renewed scope",
	}); err != nil {
		t.Fatalf("RecordExchange renewed failed: %v", err)
	}

	suspended, err := service.SuspendFederationContract(ctx, created.CellID, activeContract.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "temporary cross-org containment",
		Metadata: map[string]string{"ticket": "SC-FED-RENEW-03A"},
	})
	if err != nil {
		t.Fatalf("SuspendFederationContract failed: %v", err)
	}
	suspendedContracts := secureCellFederationContractsByStatus(suspended.FederationContracts, SecureCellFederationContractStatusSuspended)
	if len(suspendedContracts) != 1 || suspendedContracts[0].ID != activeContract.ID {
		t.Fatalf("expected renewed contract to be suspended, got %+v", suspended.FederationContracts)
	}
	if suspendedContracts[0].SuspendedAt == nil || strings.TrimSpace(suspendedContracts[0].SuspendedBy) != owner.AgentID() {
		t.Fatalf("expected suspension provenance on contract, got %+v", suspendedContracts[0])
	}
	if got := suspended.Transitions[len(suspended.Transitions)-1].Action; got != "secure_cell.federation_contract_suspended" {
		t.Fatalf("expected suspension transition, got %q", got)
	}

	if _, err := service.RecordExchange(ctx, created.CellID, SecureCellSessionExchangeRequest{
		ActorDID:       participantB.AgentID(),
		SessionID:      secondSession.ID,
		Name:           "Blocked Suspended Exchange",
		ExchangeType:   "note",
		Classification: "decisioning",
		Summary:        "blocked while contract is suspended",
		Recipients:     []string{participantA.AgentID()},
		Reason:         "exchange under suspended contract",
	}); !errors.Is(err, ErrFederationContractSuspended) {
		t.Fatalf("expected ErrFederationContractSuspended while suspended, got %v", err)
	}

	resumed, err := service.ResumeFederationContract(ctx, created.CellID, activeContract.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "containment lifted after review",
		Metadata: map[string]string{"ticket": "SC-FED-RENEW-03B"},
	})
	if err != nil {
		t.Fatalf("ResumeFederationContract failed: %v", err)
	}
	activeContractsAfterResume := secureCellFederationContractsByStatus(resumed.FederationContracts, SecureCellFederationContractStatusActive)
	if len(activeContractsAfterResume) != 1 || activeContractsAfterResume[0].ID != activeContract.ID {
		t.Fatalf("expected suspended contract to return active after resume, got %+v", resumed.FederationContracts)
	}
	if activeContractsAfterResume[0].ResumedAt == nil || strings.TrimSpace(activeContractsAfterResume[0].ResumedBy) != owner.AgentID() {
		t.Fatalf("expected resume provenance on contract, got %+v", activeContractsAfterResume[0])
	}
	if got := resumed.Transitions[len(resumed.Transitions)-1].Action; got != "secure_cell.federation_contract_resumed" {
		t.Fatalf("expected resume transition, got %q", got)
	}

	if _, err := service.RecordExchange(ctx, created.CellID, SecureCellSessionExchangeRequest{
		ActorDID:       participantB.AgentID(),
		SessionID:      secondSession.ID,
		Name:           "Resumed Session Exchange",
		ExchangeType:   "note",
		Classification: "decisioning",
		Summary:        "allowed again after contract resume",
		Recipients:     []string{participantA.AgentID()},
		Reason:         "exchange after contract resume",
	}); err != nil {
		t.Fatalf("RecordExchange after resume failed: %v", err)
	}

	revoked, err := service.RevokeFederationContract(ctx, created.CellID, activeContract.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "counterparty trust suspended",
		Metadata: map[string]string{"ticket": "SC-FED-RENEW-04"},
	})
	if err != nil {
		t.Fatalf("RevokeFederationContract failed: %v", err)
	}
	if got := revoked.Transitions[len(revoked.Transitions)-1].Action; got != "secure_cell.federation_contract_revoked" {
		t.Fatalf("expected final revoke transition, got %q", got)
	}
	activeContracts := secureCellFederationContractsByStatus(revoked.FederationContracts, SecureCellFederationContractStatusActive)
	if len(activeContracts) != 0 {
		t.Fatalf("expected no active contracts after revoke, got %+v", activeContracts)
	}

	if _, err := service.RecordExchange(ctx, created.CellID, SecureCellSessionExchangeRequest{
		ActorDID:       participantB.AgentID(),
		SessionID:      secondSession.ID,
		Name:           "Blocked Post-Revoke Exchange",
		ExchangeType:   "note",
		Classification: "decisioning",
		Summary:        "blocked after contract revoke",
		Recipients:     []string{participantA.AgentID()},
		Reason:         "exchange after contract revoke",
	}); !errors.Is(err, ErrFederationContractRequired) {
		t.Fatalf("expected ErrFederationContractRequired after revoke, got %v", err)
	}
}

func TestService_FederationCounterproposalApprovalLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Counterproposal Cell",
		Purpose:       "govern bilateral negotiation before cross-org onboarding",
		Resource:      "cell:federation-counterproposal",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	firstSessionResult, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Primary Federation Room",
		Purpose:         "broad owner-authored scope",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "initial room opened",
	})
	if err != nil {
		t.Fatalf("StartSession first failed: %v", err)
	}
	firstSession := firstSessionResult.Sessions[len(firstSessionResult.Sessions)-1]

	secondSessionResult, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Counterparty Narrowed Room",
		Purpose:         "narrower negotiated scope",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "negotiation room opened",
	})
	if err != nil {
		t.Fatalf("StartSession second failed: %v", err)
	}
	secondSession := secondSessionResult.Sessions[len(secondSessionResult.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{firstSession.ID, secondSession.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{secureCellFederationContractActionShareOutput, secureCellFederationContractActionSessionExchange},
		Reason:           "owner-authored invitation created",
		Metadata:         map[string]string{"ticket": "SC-FED-NEG-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	counterproposed, err := service.SubmitFederationCounterproposal(ctx, created.CellID, invitation.ID, SecureCellFederationCounterproposalRequest{
		ActorDID:               participantB.AgentID(),
		OfferedSessionScopeIDs: []string{secondSession.ID},
		OfferedDataClasses:     []string{"decisioning"},
		OfferedActions:         []string{secureCellFederationContractActionSessionExchange},
		Resource:               "secure-cell:federation-counterproposal:bank-b",
		Reason:                 "counterparty narrows exposure before joining",
		Metadata:               map[string]string{"ticket": "SC-FED-NEG-02"},
	})
	if err != nil {
		t.Fatalf("SubmitFederationCounterproposal failed: %v", err)
	}
	if len(counterproposed.FederationCounterproposals) != 1 {
		t.Fatalf("expected one counterproposal, got %+v", counterproposed.FederationCounterproposals)
	}
	proposal := counterproposed.FederationCounterproposals[0]
	if proposal.Status != SecureCellFederationCounterproposalStatusPending {
		t.Fatalf("expected pending counterproposal, got %+v", proposal)
	}
	if got := counterproposed.Transitions[len(counterproposed.Transitions)-1].Action; got != "secure_cell.federation_counterproposed" {
		t.Fatalf("expected counterproposal transition, got %q", got)
	}

	approved, err := service.ApproveFederationCounterproposal(ctx, created.CellID, proposal.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "owner approved counterparty narrowing",
		Metadata: map[string]string{"ticket": "SC-FED-NEG-03"},
	})
	if err != nil {
		t.Fatalf("ApproveFederationCounterproposal failed: %v", err)
	}
	approvedProposals := secureCellFederationCounterproposalsByStatus(approved.FederationCounterproposals, SecureCellFederationCounterproposalStatusApproved)
	if len(approvedProposals) != 1 || approvedProposals[0].ID != proposal.ID {
		t.Fatalf("expected approved counterproposal after approval, got %+v", approved.FederationCounterproposals)
	}
	_, approvedInvitation := findSecureCellFederationInvitation(approved.FederationInvitations, invitation.ID)
	if approvedInvitation == nil || strings.TrimSpace(approvedInvitation.ApprovedCounterproposalID) != proposal.ID {
		t.Fatalf("expected approved counterproposal to be linked onto invitation, got %+v", approvedInvitation)
	}
	if got := approved.Transitions[len(approved.Transitions)-1].Action; got != "secure_cell.federation_counterproposal_approved" {
		t.Fatalf("expected approval transition, got %q", got)
	}

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant:  SecureCellParticipant{Identity: participantB, Role: "bank_b_reviewer"},
		Reason:       "counterparty joins under approved narrowed terms",
		Metadata:     map[string]string{"ticket": "SC-FED-NEG-04"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	if len(accepted.FederationContracts) != 1 {
		t.Fatalf("expected one active contract after accept, got %+v", accepted.FederationContracts)
	}
	contract := accepted.FederationContracts[0]
	if len(contract.SessionScopeIDs) != 1 || contract.SessionScopeIDs[0] != secondSession.ID {
		t.Fatalf("expected approved counterproposal scope to bind contract, got %+v", contract.SessionScopeIDs)
	}
	if got := strings.Join(contract.AllowedActions, ","); got != secureCellFederationContractActionSessionExchange {
		t.Fatalf("expected approved counterproposal action set on contract, got %q", got)
	}
	if len(contract.NegotiationDiffs) == 0 {
		t.Fatalf("expected approved counterproposal diffs to persist into contract, got %+v", contract)
	}
	_, acceptedInvitation := findSecureCellFederationInvitation(accepted.FederationInvitations, invitation.ID)
	if acceptedInvitation == nil || acceptedInvitation.Status != SecureCellFederationInvitationStatusAccepted || strings.TrimSpace(acceptedInvitation.ApprovedCounterproposalID) != proposal.ID {
		t.Fatalf("expected accepted invitation to retain approved counterproposal linkage, got %+v", acceptedInvitation)
	}
	if len(secureCellFederationCounterproposalsByStatus(accepted.FederationCounterproposals, SecureCellFederationCounterproposalStatusApproved)) != 1 {
		t.Fatalf("expected approved counterproposal to remain in result, got %+v", accepted.FederationCounterproposals)
	}
}

func TestService_FederationCounterproposalCommitteeThresholdAndEscalation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Committee Cell",
		Purpose:       "prove committee thresholds and escalation before cross-org onboarding",
		Resource:      "cell:federation-committee",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	sessionResult, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Federation Review Room",
		Purpose:         "committee-based federation review",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "review room opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	sessionID := sessionResult.Sessions[len(sessionResult.Sessions)-1].ID

	escalationDueAt := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	resolutionDueAt := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:                            owner.AgentID(),
		SponsorOfRecord:                     secureCellFederationSponsor(participantB),
		OrganizationName:                    secureCellFederationOrganizationName(participantB),
		Jurisdiction:                        "UK",
		ExpectedDID:                         participantB.AgentID(),
		Role:                                "bank_b_reviewer",
		SessionScopeIDs:                     []string{sessionID},
		DataClasses:                         []string{"confidential"},
		ComputeZones:                        []string{"uae-enclave"},
		AllowedActions:                      []string{secureCellFederationContractActionSessionExchange},
		CounterproposalGovernanceTemplate:   "finance_review",
		CounterproposalApprovalThreshold:    2,
		CounterproposalEligibleApproverDIDs: []string{owner.AgentID()},
		CounterproposalEscalationLadder: []SecureCellFederationEscalationTier{
			{
				TierID:    "tier_1",
				TargetDID: participantA.AgentID(),
				DueAt:     &escalationDueAt,
				Reason:    "secondary reviewer deadline reached",
			},
		},
		CounterproposalResolutionDueAt: &resolutionDueAt,
		Reason:                         "owner-authored invitation created",
		Metadata:                       map[string]string{"ticket": "SC-FED-COMMITTEE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	counterproposed, err := service.SubmitFederationCounterproposal(ctx, created.CellID, invitation.ID, SecureCellFederationCounterproposalRequest{
		ActorDID:               participantB.AgentID(),
		OfferedSessionScopeIDs: []string{sessionID},
		OfferedDataClasses:     []string{"confidential"},
		OfferedActions:         []string{secureCellFederationContractActionSessionExchange},
		Resource:               "secure-cell:federation-counterproposal:committee",
		Reason:                 "counterparty proposes narrow committee-reviewed terms",
		Metadata:               map[string]string{"ticket": "SC-FED-COMMITTEE-02"},
	})
	if err != nil {
		t.Fatalf("SubmitFederationCounterproposal failed: %v", err)
	}
	proposal := counterproposed.FederationCounterproposals[0]
	if proposal.ApprovalThreshold != 2 || len(proposal.EligibleApproverDIDs) != 1 || proposal.EligibleApproverDIDs[0] != owner.AgentID() {
		t.Fatalf("expected committee governance to persist on proposal, got %+v", proposal)
	}

	voted, err := service.ApproveFederationCounterproposal(ctx, created.CellID, proposal.ID, SecureCellLifecycleRequest{
		ActorDID: owner.AgentID(),
		Reason:   "owner casts first committee vote",
		Metadata: map[string]string{"ticket": "SC-FED-COMMITTEE-03"},
	})
	if err != nil {
		t.Fatalf("ApproveFederationCounterproposal owner vote failed: %v", err)
	}
	afterOwnerVote, ok := mustSecureCellFederationCounterproposal(t, voted, proposal.ID)
	if !ok {
		t.Fatalf("expected counterproposal %q after owner vote", proposal.ID)
	}
	if afterOwnerVote.Status != SecureCellFederationCounterproposalStatusPending || len(afterOwnerVote.ApprovalVotes) != 1 {
		t.Fatalf("expected pending proposal with one vote, got %+v", afterOwnerVote)
	}
	if got := voted.Transitions[len(voted.Transitions)-1].Action; got != "secure_cell.federation_counterproposal_vote_recorded" {
		t.Fatalf("expected vote-recorded transition, got %q", got)
	}

	before := time.Now().UTC()
	overdue, err := service.ListOverdueFederationCounterproposals(ctx, SecureCellOverdueFederationCounterproposalFilter{
		CellID: created.CellID,
		Before: &before,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationCounterproposals failed: %v", err)
	}
	if len(overdue) != 1 {
		t.Fatalf("expected one overdue counterproposal, got %+v", overdue)
	}
	if overdue[0].CounterproposalID != proposal.ID || overdue[0].AutomationAction != "escalate" || overdue[0].TierID != "tier_1" || overdue[0].TargetDID != participantA.AgentID() {
		t.Fatalf("expected overdue escalation projection, got %+v", overdue[0])
	}

	report, err := service.SweepFederationGovernance(ctx, before, SecureCellLifecycleRequest{
		ActorDID: "did:aethelred:automation-sweeper",
		Reason:   "automated federation governance sweep",
		Metadata: map[string]string{"ticket": "SC-FED-COMMITTEE-SWEEP"},
	})
	if err != nil {
		t.Fatalf("SweepFederationGovernance failed: %v", err)
	}
	if report.CounterproposalsEscalated != 1 || report.CounterproposalsRejected != 0 {
		t.Fatalf("expected one escalation and zero rejections, got %+v", report)
	}

	escalated, ok := mustSecureCellFederationCounterproposal(t, mustSecureCellResult(t, service, created.CellID), proposal.ID)
	if !ok {
		t.Fatalf("expected escalated counterproposal %q", proposal.ID)
	}
	if !containsStringFold(escalated.EligibleApproverDIDs, participantA.AgentID()) || !containsStringFold(escalated.EscalatedTierIDs, "tier_1") {
		t.Fatalf("expected escalation tier to expand eligible approvers, got %+v", escalated)
	}

	actions, err := service.ListFederationAutomationActions(ctx, SecureCellFederationAutomationActionFilter{
		CellID: created.CellID,
	})
	if err != nil {
		t.Fatalf("ListFederationAutomationActions failed: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected one federation automation action, got %+v", actions)
	}
	if actions[0].Action != "secure_cell.federation_counterproposal_escalated" || actions[0].TierID != "tier_1" || actions[0].TargetDID != participantA.AgentID() || actions[0].Trigger != "tier_1" {
		t.Fatalf("expected escalation automation action metadata, got %+v", actions[0])
	}

	approved, err := service.ApproveFederationCounterproposal(ctx, created.CellID, proposal.ID, SecureCellLifecycleRequest{
		ActorDID: participantA.AgentID(),
		Reason:   "escalated reviewer casts second committee vote",
		Metadata: map[string]string{"ticket": "SC-FED-COMMITTEE-04"},
	})
	if err != nil {
		t.Fatalf("ApproveFederationCounterproposal escalated reviewer failed: %v", err)
	}
	finalProposal, ok := mustSecureCellFederationCounterproposal(t, approved, proposal.ID)
	if !ok {
		t.Fatalf("expected approved counterproposal %q", proposal.ID)
	}
	if finalProposal.Status != SecureCellFederationCounterproposalStatusApproved || len(finalProposal.ApprovalVotes) != 2 || strings.TrimSpace(finalProposal.ApprovedBy) != participantA.AgentID() {
		t.Fatalf("expected approved committee counterproposal, got %+v", finalProposal)
	}
	if got := approved.Transitions[len(approved.Transitions)-1].Action; got != "secure_cell.federation_counterproposal_approved" {
		t.Fatalf("expected approval transition after escalated vote, got %q", got)
	}
}

func TestService_FederationCounterproposalOverdueRejectSuspendsContracts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)
	participantC := mustSecureCellIdentity(t, "participant-c", []string{"UK"})

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Suspension Cell",
		Purpose:       "prove overdue counterproposals suspend live federation contracts",
		Resource:      "cell:federation-suspension",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	sessionResult, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Federation Contract Room",
		Purpose:         "contract-bearing collaboration",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "contract room opened",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	sessionID := sessionResult.Sessions[len(sessionResult.Sessions)-1].ID

	acceptedInvite, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{sessionID},
		DataClasses:      []string{"confidential"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{secureCellFederationContractActionSessionExchange},
		Reason:           "initial contract-bearing invitation",
		Metadata:         map[string]string{"ticket": "SC-FED-SUSPEND-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation accepted path failed: %v", err)
	}
	firstInvitation := acceptedInvite.FederationInvitations[len(acceptedInvite.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: firstInvitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant:  SecureCellParticipant{Identity: participantB, Role: "bank_b_reviewer"},
		Reason:       "counterparty joins under accepted terms",
		Metadata:     map[string]string{"ticket": "SC-FED-SUSPEND-02"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	activeContracts := activeFederationContractsForOrganization(accepted.FederationContracts, secureCellFederationOrganizationID(secureCellFederationSponsor(participantB)))
	if len(activeContracts) != 1 {
		t.Fatalf("expected one active contract for organization, got %+v", accepted.FederationContracts)
	}
	activeContractID := activeContracts[0].ID

	resolutionDueAt := time.Now().UTC().Add(-15 * time.Minute).Truncate(time.Second)
	overdueInvite, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:                            owner.AgentID(),
		SponsorOfRecord:                     secureCellFederationSponsor(participantB),
		OrganizationName:                    secureCellFederationOrganizationName(participantB),
		Jurisdiction:                        "UK",
		ExpectedDID:                         participantC.AgentID(),
		Role:                                "bank_b_delegate",
		SessionScopeIDs:                     []string{sessionID},
		DataClasses:                         []string{"confidential"},
		ComputeZones:                        []string{"uae-enclave"},
		AllowedActions:                      []string{secureCellFederationContractActionSessionExchange},
		CounterproposalApprovalThreshold:    1,
		CounterproposalEligibleApproverDIDs: []string{owner.AgentID()},
		CounterproposalResolutionDueAt:      &resolutionDueAt,
		CounterproposalAutoSuspendOnOverdue: true,
		Reason:                              "follow-on negotiated invitation for same organization",
		Metadata:                            map[string]string{"ticket": "SC-FED-SUSPEND-03"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation overdue path failed: %v", err)
	}
	secondInvitation := overdueInvite.FederationInvitations[len(overdueInvite.FederationInvitations)-1]

	counterproposed, err := service.SubmitFederationCounterproposal(ctx, created.CellID, secondInvitation.ID, SecureCellFederationCounterproposalRequest{
		ActorDID:               participantC.AgentID(),
		OfferedSessionScopeIDs: []string{sessionID},
		OfferedDataClasses:     []string{"confidential"},
		OfferedActions:         []string{secureCellFederationContractActionSessionExchange},
		Resource:               "secure-cell:federation-counterproposal:overdue",
		Reason:                 "counterparty does not close review in time",
		Metadata:               map[string]string{"ticket": "SC-FED-SUSPEND-04"},
	})
	if err != nil {
		t.Fatalf("SubmitFederationCounterproposal overdue path failed: %v", err)
	}
	proposal := counterproposed.FederationCounterproposals[len(counterproposed.FederationCounterproposals)-1]

	before := time.Now().UTC()
	overdue, err := service.ListOverdueFederationCounterproposals(ctx, SecureCellOverdueFederationCounterproposalFilter{
		CellID: created.CellID,
		Before: &before,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationCounterproposals failed: %v", err)
	}
	if len(overdue) != 1 || overdue[0].CounterproposalID != proposal.ID || overdue[0].AutomationAction != "reject_and_suspend" {
		t.Fatalf("expected reject-and-suspend overdue projection, got %+v", overdue)
	}

	report, err := service.SweepFederationGovernance(ctx, before, SecureCellLifecycleRequest{
		ActorDID: "did:aethelred:automation-sweeper",
		Reason:   "automated federation governance sweep",
		Metadata: map[string]string{"ticket": "SC-FED-SUSPEND-SWEEP"},
	})
	if err != nil {
		t.Fatalf("SweepFederationGovernance failed: %v", err)
	}
	if report.CounterproposalsRejected != 1 || report.ContractsSuspended != 1 {
		t.Fatalf("expected one rejection and one suspension, got %+v", report)
	}

	afterSweep := mustSecureCellResult(t, service, created.CellID)
	finalProposal, ok := mustSecureCellFederationCounterproposal(t, afterSweep, proposal.ID)
	if !ok {
		t.Fatalf("expected rejected counterproposal %q", proposal.ID)
	}
	if finalProposal.Status != SecureCellFederationCounterproposalStatusRejected || strings.TrimSpace(finalProposal.RejectedBy) != owner.AgentID() {
		t.Fatalf("expected rejected counterproposal after sweep, got %+v", finalProposal)
	}

	var suspendedContract *SecureCellFederationContract
	for idx := range afterSweep.FederationContracts {
		contract := &afterSweep.FederationContracts[idx]
		if strings.TrimSpace(contract.ID) == activeContractID {
			suspendedContract = contract
			break
		}
	}
	if suspendedContract == nil || suspendedContract.Status != SecureCellFederationContractStatusSuspended {
		t.Fatalf("expected active contract %q to be suspended, got %+v", activeContractID, suspendedContract)
	}

	remaining, err := service.ListOverdueFederationCounterproposals(ctx, SecureCellOverdueFederationCounterproposalFilter{
		CellID: created.CellID,
		Before: &before,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationCounterproposals after sweep failed: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected overdue federation queue to clear after sweep, got %+v", remaining)
	}

	actions, err := service.ListFederationAutomationActions(ctx, SecureCellFederationAutomationActionFilter{
		CellID: created.CellID,
	})
	if err != nil {
		t.Fatalf("ListFederationAutomationActions failed: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("expected two automation actions, got %+v", actions)
	}
	actionMap := make(map[string]SecureCellFederationAutomationActionRecord, len(actions))
	for _, action := range actions {
		actionMap[action.Action] = action
	}
	suspendAction, ok := actionMap["secure_cell.federation_contract_suspended"]
	if !ok || suspendAction.ContractID != activeContractID || suspendAction.ContractStatusBefore != SecureCellFederationContractStatusActive || suspendAction.ContractStatusAfter != SecureCellFederationContractStatusSuspended {
		t.Fatalf("expected suspended contract automation action metadata, got %+v", suspendAction)
	}
	rejectAction, ok := actionMap["secure_cell.federation_counterproposal_rejected"]
	if !ok || rejectAction.CounterproposalID != proposal.ID || rejectAction.CounterproposalStatusBefore != SecureCellFederationCounterproposalStatusPending || rejectAction.CounterproposalStatusAfter != SecureCellFederationCounterproposalStatusRejected || rejectAction.Trigger != "resolution_due" {
		t.Fatalf("expected rejected counterproposal automation action metadata, got %+v", rejectAction)
	}
}

func TestService_SweepFederationIncidentReportReconciliationsAutoDisputesAndSuspendsContracts(t *testing.T) {
	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Report Reconciliation Cell",
		Purpose:       "prove bilateral filing drift escalates into governed containment",
		Resource:      "cell:federation-report-reconciliation-automation",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer_a"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	sessionResult, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Federation Incident Room",
		Purpose:         "regulated incident collaboration",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "open federation incident room",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := sessionResult.Sessions[len(sessionResult.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{secureCellFederationContractActionShareOutput, secureCellFederationContractActionSessionExchange},
		Reason:           "owner-authored federation invitation",
		Metadata:         map[string]string{"ticket": "FED-REPORT-AUTO-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "counterparty joins secure cell",
		Metadata: map[string]string{"ticket": "FED-REPORT-AUTO-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	if len(accepted.FederationContracts) != 1 {
		t.Fatalf("expected one active federation contract, got %+v", accepted.FederationContracts)
	}
	contractID := accepted.FederationContracts[0].ID
	orgID := secureCellFederationOrganizationID(secureCellFederationSponsor(participantB))

	published, err := service.PublishFederationIncident(ctx, created.CellID, orgID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityCritical,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Counterparty filing posture has drifted",
		Description:              "This incident sets up bilateral filing reconciliation automation.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: true,
		Reason:                   "publish bilateral filing drift incident",
		Metadata:                 map[string]string{"ticket": "FED-REPORT-AUTO-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local incident response, got %+v", responses)
	}

	reportDueAt := time.Now().UTC().Add(2 * time.Hour)
	planned, err := service.CreateFederationIncidentReport(ctx, created.CellID, localResponseID, SecureCellFederationIncidentReportPlanRequest{
		ActorDID:         participantB.AgentID(),
		Regulator:        "uk-ico",
		Jurisdiction:     "UK",
		Framework:        "uk-gdpr",
		ReportType:       "breach_notification",
		Summary:          "Counterparty planned regulator filing",
		Description:      "This report will be used to prove automated reconciliation governance.",
		RequiredSections: []string{"scope", "impact", "containment"},
		EvidenceIDs:      []string{incidentID},
		DueAt:            &reportDueAt,
		Reason:           "plan regulator-facing report",
		Metadata:         map[string]string{"ticket": "FED-REPORT-AUTO-PLAN-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationIncidentReport failed: %v", err)
	}

	reportItems, err := service.ListFederationIncidentReports(ctx, SecureCellFederationIncidentReportFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ResponseID:     localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReports failed: %v", err)
	}
	if len(reportItems) != 1 {
		t.Fatalf("expected one federation incident report, got %+v", reportItems)
	}
	reportID := reportItems[0].ReportID

	submitted, err := service.SubmitFederationIncidentReport(ctx, created.CellID, reportID, SecureCellFederationIncidentReportSubmitRequest{
		ActorDID:            participantB.AgentID(),
		SubmissionReference: "ico-2026-automation-local",
		Summary:             "Counterparty submitted regulator filing",
		Description:         "The counterparty submitted the local report before reciprocal bundle intake.",
		EvidenceIDs:         []string{planned.ControlLedger.Bundle.ID},
		Reason:              "submit regulator filing",
		Metadata:            map[string]string{"ticket": "FED-REPORT-AUTO-SUBMIT-01"},
	})
	if err != nil {
		t.Fatalf("SubmitFederationIncidentReport failed: %v", err)
	}

	acknowledged, err := service.AcknowledgeFederationIncidentReport(ctx, created.CellID, reportID, SecureCellFederationIncidentReportAcknowledgeRequest{
		ActorDID:                 owner.AgentID(),
		AcknowledgingParty:       SecureCellFederationIncidentResponsePartyLocalOrg,
		AcknowledgementReference: "ico-2026-automation-ack",
		Reason:                   "acknowledge filing receipt",
		Metadata:                 map[string]string{"ticket": "FED-REPORT-AUTO-ACK-01"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeFederationIncidentReport failed: %v", err)
	}

	reportBundle, err := service.BuildFederationIncidentReportBundle(ctx, created.CellID, reportID, SecureCellFederationIncidentReportBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentReportBundle failed: %v", err)
	}
	reportBundle.Report.SubmissionReference = "ico-2026-automation-counterparty-drift"
	reportBundle.ReportSummary.SubmissionReference = reportBundle.Report.SubmissionReference

	intakeResult, err := service.IngestFederationIncidentReportBundle(ctx, created.CellID, orgID, SecureCellFederationIncidentReportBundleIntakeRequest{
		ActorDID: owner.AgentID(),
		Bundle:   reportBundle,
		Reason:   "ingest reciprocal bundle with drifted submission reference",
		Metadata: map[string]string{"ticket": "FED-REPORT-AUTO-INTAKE-01"},
	})
	if err != nil {
		t.Fatalf("IngestFederationIncidentReportBundle failed: %v", err)
	}
	if len(intakeResult.FederationCounterpartyIncidentReports) != 1 || intakeResult.FederationCounterpartyIncidentReports[0].Status != SecureCellFederationCounterpartyIncidentReportStatusInvalid {
		t.Fatalf("expected one invalid imported counterparty report, got %+v", intakeResult.FederationCounterpartyIncidentReports)
	}

	reconciliations, err := service.ListFederationIncidentReportReconciliations(ctx, SecureCellFederationIncidentReportReconciliationFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		IncidentID:     incidentID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportReconciliations failed: %v", err)
	}
	if len(reconciliations) != 1 || reconciliations[0].Status != SecureCellFederationIncidentReportReconciliationStatusCounterpartyInvalid {
		t.Fatalf("expected one invalid bilateral reconciliation, got %+v", reconciliations)
	}
	comparisonKey := reconciliations[0].ComparisonKey

	if reconciliations[0].CounterpartyReceivedAt == nil {
		t.Fatalf("expected counterparty received timestamp on reconciliation, got %+v", reconciliations[0])
	}
	reviewOverdueAt := reconciliations[0].CounterpartyReceivedAt.UTC().Add(secureCellFederationIncidentReportReconciliationReviewSLA + time.Hour)
	overdue, err := service.ListOverdueFederationIncidentReportReconciliations(ctx, SecureCellOverdueFederationIncidentReportReconciliationFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ComparisonKey:  comparisonKey,
		Before:         &reviewOverdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentReportReconciliations failed: %v", err)
	}
	if len(overdue) != 1 || overdue[0].AutomationAction != "auto_dispute" || overdue[0].ReviewStatus != SecureCellFederationIncidentReportReviewStatusUnreviewed {
		t.Fatalf("expected one overdue reconciliation queued for automated dispute, got %+v", overdue)
	}

	sweepActor := "did:aethelred:automation-sweeper"
	reviewSweep, err := service.SweepFederationIncidentReportReconciliations(ctx, reviewOverdueAt, SecureCellLifecycleRequest{
		ActorDID: sweepActor,
		Reason:   "automated report reconciliation sweep",
		Metadata: map[string]string{"ticket": "FED-REPORT-AUTO-SWEEP-REVIEW-01"},
	})
	if err != nil {
		t.Fatalf("SweepFederationIncidentReportReconciliations review failed: %v", err)
	}
	if reviewSweep.ReconciliationsAutoDisputed != 1 {
		t.Fatalf("expected one automated dispute, got %+v", reviewSweep)
	}

	reconciliations, err = service.ListFederationIncidentReportReconciliations(ctx, SecureCellFederationIncidentReportReconciliationFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ComparisonKey:  comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportReconciliations after auto-dispute failed: %v", err)
	}
	if len(reconciliations) != 1 || reconciliations[0].ReviewStatus != SecureCellFederationIncidentReportReviewStatusDisputed {
		t.Fatalf("expected reconciliation review state to be disputed after automated sweep, got %+v", reconciliations)
	}

	automationActions, err := service.ListFederationIncidentReportReconciliationAutomationActions(ctx, SecureCellFederationIncidentReportReconciliationAutomationActionFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportReconciliationAutomationActions failed: %v", err)
	}
	if len(automationActions) != 1 || automationActions[0].Action != "secure_cell.federation_incident_report_reconciliation_disputed" || automationActions[0].AutomatedActor != sweepActor {
		t.Fatalf("expected one automated dispute action, got %+v", automationActions)
	}

	if reconciliations[0].LastReviewedAt == nil {
		t.Fatalf("expected last reviewed timestamp after automated dispute, got %+v", reconciliations[0])
	}
	resolutionOverdueAt := reconciliations[0].LastReviewedAt.UTC().Add(secureCellFederationIncidentReportReconciliationResolutionSLA + time.Hour)
	overdue, err = service.ListOverdueFederationIncidentReportReconciliations(ctx, SecureCellOverdueFederationIncidentReportReconciliationFilter{
		CellID:         created.CellID,
		OrganizationID: orgID,
		ComparisonKey:  comparisonKey,
		Before:         &resolutionOverdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentReportReconciliations resolution failed: %v", err)
	}
	if len(overdue) != 1 || overdue[0].AutomationAction != "suspend_contracts" || overdue[0].ReviewStatus != SecureCellFederationIncidentReportReviewStatusDisputed {
		t.Fatalf("expected one overdue reconciliation queued for contract suspension, got %+v", overdue)
	}

	resolutionSweep, err := service.SweepFederationIncidentReportReconciliations(ctx, resolutionOverdueAt, SecureCellLifecycleRequest{
		ActorDID: sweepActor,
		Reason:   "automated report reconciliation containment sweep",
		Metadata: map[string]string{"ticket": "FED-REPORT-AUTO-SWEEP-RESOLUTION-01"},
	})
	if err != nil {
		t.Fatalf("SweepFederationIncidentReportReconciliations resolution failed: %v", err)
	}
	if resolutionSweep.ContractsSuspended != 1 {
		t.Fatalf("expected one suspended contract after unresolved dispute, got %+v", resolutionSweep)
	}

	afterSweep := mustSecureCellResult(t, service, created.CellID)
	if len(afterSweep.FederationContracts) != 1 || afterSweep.FederationContracts[0].Status != SecureCellFederationContractStatusSuspended {
		t.Fatalf("expected federation contract suspension after unresolved reconciliation dispute, got %+v", afterSweep.FederationContracts)
	}

	automationActions, err = service.ListFederationIncidentReportReconciliationAutomationActions(ctx, SecureCellFederationIncidentReportReconciliationAutomationActionFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportReconciliationAutomationActions after suspension failed: %v", err)
	}
	if len(automationActions) != 2 {
		t.Fatalf("expected automated dispute and contract suspension actions, got %+v", automationActions)
	}
	if automationActions[0].Action != "secure_cell.federation_contract_suspended" || automationActions[0].ContractID != contractID {
		t.Fatalf("expected latest automation action to be contract suspension for %q, got %+v", contractID, automationActions[0])
	}
	if automationActions[1].Action != "secure_cell.federation_incident_report_reconciliation_disputed" {
		t.Fatalf("expected earlier automation action to be automated dispute, got %+v", automationActions[1])
	}

	if len(submitted.Transitions) == 0 || len(acknowledged.Transitions) == 0 {
		t.Fatalf("expected report submission and acknowledgement lifecycle transitions, got submitted=%+v acknowledged=%+v", submitted.Transitions, acknowledged.Transitions)
	}
}

func newTestSecureCellService(t *testing.T) (*Service, evidence.ControlLedgerStore, *agent.AgentIdentity, *agent.AgentIdentity, *agent.AgentIdentity) {
	t.Helper()
	return newTestSecureCellServiceWithWorkflowStoreAndPublisher(t, nil, nil)
}

func newTestSecureCellServiceWithPublisher(t *testing.T, publisher SecureCellEventPublisher) (*Service, evidence.ControlLedgerStore, *agent.AgentIdentity, *agent.AgentIdentity, *agent.AgentIdentity) {
	t.Helper()
	return newTestSecureCellServiceWithWorkflowStoreAndPublisher(t, nil, publisher)
}

func newTestSecureCellServiceWithWorkflowStore(t *testing.T, workflowStore SecureCellStore, publisher SecureCellEventPublisher) (*Service, evidence.ControlLedgerStore, *agent.AgentIdentity, *agent.AgentIdentity, *agent.AgentIdentity) {
	t.Helper()
	return newTestSecureCellServiceWithWorkflowStoreAndPublisher(t, workflowStore, publisher)
}

func newTestSecureCellServiceWithWorkflowStoreAndPublisher(t *testing.T, workflowStore SecureCellStore, publisher SecureCellEventPublisher) (*Service, evidence.ControlLedgerStore, *agent.AgentIdentity, *agent.AgentIdentity, *agent.AgentIdentity) {
	t.Helper()

	policySignerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate policy signer key: %v", err)
	}
	packageSigningKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	store := evidence.NewInMemoryControlLedgerStore()
	sealer := &mockSecureCellSealer{}

	service, err := NewService(ServiceConfig{
		PolicySignerKey:      policySignerKey,
		PolicySigner:         "did:aethelred:secure-cells-policy",
		CredentialIssuerKey:  policySignerKey,
		CredentialIssuer:     "did:aethelred:secure-cells-issuer",
		Sealer:               sealer,
		ConfidentialAttestor: &mockSecureCellConfidentialAttestor{signingKey: policySignerKey},
		ConfidentialPolicy: confidential.Policy{
			TrustedPlatforms:         []string{"aws-nitro"},
			TrustedValidatorKeys:     map[string]*ecdsa.PublicKey{"did:aethelred:secure-cells-policy": &policySignerKey.PublicKey},
			AllowedEnclaveIDs:        []string{"secure-cells-enclave-test"},
			RequireQuoteBinding:      true,
			MinimumValidAttestations: 1,
		},
		LedgerStore:             store,
		WorkflowStore:           workflowStore,
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

func mustSecureCellDecision(t *testing.T, result *SecureCellResult, decisionID string) (SecureCellThreadDecision, bool) {
	t.Helper()
	if result == nil {
		t.Fatal("secure cell result is required")
	}
	for _, decision := range result.Decisions {
		if decision.ID == decisionID {
			return decision, true
		}
	}
	return SecureCellThreadDecision{}, false
}

func mustSecureCellResult(t *testing.T, service *Service, cellID string) *SecureCellResult {
	t.Helper()
	result, err := service.GetCell(context.Background(), cellID)
	if err != nil {
		t.Fatalf("GetCell failed for %q: %v", cellID, err)
	}
	return result
}

func mustSecureCellFederationCounterproposal(t *testing.T, result *SecureCellResult, counterproposalID string) (SecureCellFederationCounterproposal, bool) {
	t.Helper()
	if result == nil {
		t.Fatal("secure cell result is required")
	}
	for _, proposal := range result.FederationCounterproposals {
		if proposal.ID == counterproposalID {
			return proposal, true
		}
	}
	return SecureCellFederationCounterproposal{}, false
}

func TestService_FederationIncidentDirectiveFlow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Directive Cell",
		Purpose:       "govern bilateral incident work orders",
		Resource:      "cell:federation-directive",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Directive Coordination Room",
		Purpose:         "coordinate bilateral incident directives",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "open directive coordination session",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-SESSION-01"},
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[len(started.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite counterparty directive reviewer",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "counterparty joins directive room",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	if len(accepted.FederationContracts) != 1 {
		t.Fatalf("expected one federation contract, got %+v", accepted.FederationContracts)
	}
	organizationID := accepted.FederationContracts[0].OrganizationID
	contractID := accepted.FederationContracts[0].ID

	published, err := service.PublishFederationIncident(ctx, created.CellID, organizationID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityCritical,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Counterparty evidence request required",
		Description:              "The local organization requires a governed counterparty evidence package for the incident response.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: false,
		Reason:                   "publish directive-driving incident",
		Metadata:                 map[string]string{"ticket": "FED-DIRECTIVE-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local response, got %+v", responses)
	}

	dueAt := time.Now().UTC().Add(2 * time.Hour)
	if _, err := service.CreateFederationIncidentDirective(ctx, created.CellID, localResponseID, SecureCellFederationIncidentDirectiveCreateRequest{
		ActorDID:      owner.AgentID(),
		DirectiveType: "counterparty_evidence_request",
		Title:         "Provide counterparty evidence package",
		Summary:       "Counterparty must provide an evidence package for bilateral incident review.",
		Description:   "Provide the scoped evidence package, timeline, and remediation artifacts for the bilateral incident response.",
		Priority:      SecureCellFederationIncidentDirectivePriorityHigh,
		AssigneeParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		ReviewerParty: SecureCellFederationIncidentResponsePartyLocalOrg,
		AssigneeDID:   participantB.AgentID(),
		ReviewerDID:   owner.AgentID(),
		EvidenceIDs:   []string{incidentID},
		DueAt:         &dueAt,
		Reason:        "issue bilateral evidence work order",
		Metadata:      map[string]string{"ticket": "FED-DIRECTIVE-ISSUE-01"},
	}); err != nil {
		t.Fatalf("CreateFederationIncidentDirective failed: %v", err)
	}

	directives, err := service.ListFederationIncidentDirectives(ctx, SecureCellFederationIncidentDirectiveFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		ResponseID:     localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectives failed: %v", err)
	}
	if len(directives) != 1 || directives[0].Status != SecureCellFederationIncidentDirectiveStatusIssued {
		t.Fatalf("expected one issued directive, got %+v", directives)
	}
	directiveID := directives[0].DirectiveID

	overdueAt := dueAt.Add(time.Hour)
	overdue, err := service.ListOverdueFederationIncidentDirectives(ctx, SecureCellOverdueFederationIncidentDirectiveFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		ResponseID:     localResponseID,
		Before:         &overdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentDirectives failed: %v", err)
	}
	if len(overdue) != 1 || overdue[0].DirectiveID != directiveID || overdue[0].PendingAction != "acknowledge" {
		t.Fatalf("expected one overdue issued directive awaiting acknowledgement, got %+v", overdue)
	}

	if _, err := service.AcknowledgeFederationIncidentDirective(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveAcknowledgeRequest{
		ActorDID:           participantB.AgentID(),
		AcknowledgingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Reason:             "counterparty accepted bilateral work order",
		Metadata:           map[string]string{"ticket": "FED-DIRECTIVE-ACK-01"},
	}); err != nil {
		t.Fatalf("AcknowledgeFederationIncidentDirective failed: %v", err)
	}

	if _, err := service.CompleteFederationIncidentDirective(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveCompleteRequest{
		ActorDID:              participantB.AgentID(),
		CompletingParty:       SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		CompletionSummary:     "Counterparty uploaded evidence package",
		CompletionDescription: "The counterparty uploaded the requested evidence package and remediation timeline.",
		EvidenceIDs:           []string{incidentID},
		Reason:                "complete bilateral work order",
		Metadata:              map[string]string{"ticket": "FED-DIRECTIVE-COMPLETE-01"},
	}); err != nil {
		t.Fatalf("CompleteFederationIncidentDirective failed: %v", err)
	}

	if _, err := service.VerifyFederationIncidentDirective(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveVerifyRequest{
		ActorDID:                owner.AgentID(),
		ReviewingParty:          SecureCellFederationIncidentResponsePartyLocalOrg,
		Decision:                SecureCellFederationIncidentDirectiveVerificationDecisionRejected,
		VerificationSummary:     "Evidence package needs correction",
		VerificationDescription: "The local organization rejected the first package because one scoped timeline artifact was missing.",
		EvidenceIDs:             []string{incidentID},
		Reason:                  "reject incomplete work order delivery",
		Metadata:                map[string]string{"ticket": "FED-DIRECTIVE-VERIFY-01"},
	}); err != nil {
		t.Fatalf("VerifyFederationIncidentDirective reject failed: %v", err)
	}

	rejectedDirective, err := service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective after rejection failed: %v", err)
	}
	if rejectedDirective.Status != SecureCellFederationIncidentDirectiveStatusAcknowledged || rejectedDirective.VerificationDecision != SecureCellFederationIncidentDirectiveVerificationDecisionRejected {
		t.Fatalf("expected directive to reopen in acknowledged state after rejected verification, got %+v", rejectedDirective)
	}

	if _, err := service.CompleteFederationIncidentDirective(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveCompleteRequest{
		ActorDID:              participantB.AgentID(),
		CompletingParty:       SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		CompletionSummary:     "Counterparty uploaded corrected evidence package",
		CompletionDescription: "The counterparty uploaded the corrected evidence package with the missing timeline artifact.",
		EvidenceIDs:           []string{incidentID, directiveID},
		Reason:                "complete corrected bilateral work order",
		Metadata:              map[string]string{"ticket": "FED-DIRECTIVE-COMPLETE-02"},
	}); err != nil {
		t.Fatalf("CompleteFederationIncidentDirective second completion failed: %v", err)
	}

	if _, err := service.VerifyFederationIncidentDirective(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveVerifyRequest{
		ActorDID:                owner.AgentID(),
		ReviewingParty:          SecureCellFederationIncidentResponsePartyLocalOrg,
		Decision:                SecureCellFederationIncidentDirectiveVerificationDecisionAccepted,
		VerificationSummary:     "Corrected evidence package accepted",
		VerificationDescription: "The local organization accepted the corrected evidence package and closed the work order.",
		EvidenceIDs:             []string{incidentID, directiveID},
		Reason:                  "accept corrected work order delivery",
		Metadata:                map[string]string{"ticket": "FED-DIRECTIVE-VERIFY-02"},
	}); err != nil {
		t.Fatalf("VerifyFederationIncidentDirective accept failed: %v", err)
	}

	finalDirective, err := service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective final failed: %v", err)
	}
	if finalDirective.Status != SecureCellFederationIncidentDirectiveStatusVerified || finalDirective.VerificationDecision != SecureCellFederationIncidentDirectiveVerificationDecisionAccepted {
		t.Fatalf("expected verified directive after accepted review, got %+v", finalDirective)
	}

	directiveBundle, err := service.BuildFederationIncidentDirectiveBundle(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveBundle(directiveBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveBundle failed: %v", err)
	}
	if directiveBundle.DirectiveSummary.DirectiveID != directiveID || directiveBundle.DirectiveSummary.Status != SecureCellFederationIncidentDirectiveStatusVerified || directiveBundle.ResponseBundleHash == "" || directiveBundle.Signature == nil {
		t.Fatalf("expected signed directive bundle linked to response bundle, got %+v", directiveBundle)
	}

	directiveActions, err := service.ListFederationIncidentDirectiveActions(ctx, SecureCellFederationIncidentDirectiveActionFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		ResponseID:     localResponseID,
		DirectiveID:    directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveActions failed: %v", err)
	}
	if len(directiveActions) != 6 {
		t.Fatalf("expected six directive actions, got %+v", directiveActions)
	}
	actionSet := map[string]bool{}
	for _, item := range directiveActions {
		actionSet[item.Action] = true
	}
	for _, want := range []string{
		"secure_cell.federation_incident_directive_issued",
		"secure_cell.federation_incident_directive_acknowledged",
		"secure_cell.federation_incident_directive_completed",
		"secure_cell.federation_incident_directive_verified",
	} {
		if !actionSet[want] {
			t.Fatalf("expected directive action %q in %+v", want, directiveActions)
		}
	}

	responseDetail, err := service.GetFederationIncidentResponse(ctx, created.CellID, localResponseID)
	if err != nil {
		t.Fatalf("GetFederationIncidentResponse failed: %v", err)
	}
	if len(responseDetail.IncidentDirectives) != 1 || responseDetail.IncidentDirectives[0].ID != directiveID || responseDetail.IncidentDirectives[0].Status != SecureCellFederationIncidentDirectiveStatusVerified {
		t.Fatalf("expected one verified directive on response detail, got %+v", responseDetail.IncidentDirectives)
	}

	responseSummaries, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		ResponseID:     localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses final failed: %v", err)
	}
	if len(responseSummaries) != 1 || responseSummaries[0].DirectiveCount != 1 || responseSummaries[0].PendingDirectiveCount != 0 || responseSummaries[0].OverdueDirectiveCount != 0 || responseSummaries[0].NextDirectiveDueAt != nil {
		t.Fatalf("expected response summary to show one completed directive with no pending or overdue work, got %+v", responseSummaries)
	}

	finalResult := mustSecureCellResult(t, service, created.CellID)
	if finalResult.ControlLedger == nil || !controlLedgerHasControl(finalResult.ControlLedger, "CELL-FED-12") {
		t.Fatalf("expected directive governance control in control ledger, got %+v", finalResult.ControlLedger)
	}
}

func TestService_FederationIncidentDirectiveAutomationAndCasePack(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Directive Automation Cell",
		Purpose:       "govern overdue bilateral directives",
		Resource:      "cell:federation-directive-automation",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "local_reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Directive Automation Room",
		Purpose:         "coordinate automated cross-org incident directives",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"confidential", "decisioning"},
		Reason:          "open directive automation room",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[len(started.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  participantB.Liability.SponsorOfRecord,
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_responder",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite counterparty responder",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-AUTO-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_responder",
		},
		Reason:   "counterparty joins automation room",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-AUTO-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	if len(accepted.FederationContracts) != 1 {
		t.Fatalf("expected one federation contract, got %+v", accepted.FederationContracts)
	}
	organizationID := accepted.FederationContracts[0].OrganizationID
	contractID := accepted.FederationContracts[0].ID

	published, err := service.PublishFederationIncident(ctx, created.CellID, organizationID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityCritical,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Counterparty evidence package overdue",
		Description:              "The counterparty has not yet acknowledged the evidence request directive.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: false,
		Reason:                   "publish directive automation incident",
		Metadata:                 map[string]string{"ticket": "FED-DIRECTIVE-AUTO-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local response, got %+v", responses)
	}

	dueAt := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := service.CreateFederationIncidentDirective(ctx, created.CellID, localResponseID, SecureCellFederationIncidentDirectiveCreateRequest{
		ActorDID:      owner.AgentID(),
		DirectiveType: "counterparty_evidence_request",
		Title:         "Provide counterparty evidence package",
		Summary:       "Counterparty must acknowledge and deliver the evidence package.",
		Description:   "Provide the scoped evidence package and remediation artifacts for the bilateral incident response.",
		Priority:      SecureCellFederationIncidentDirectivePriorityCritical,
		AssigneeParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		ReviewerParty: SecureCellFederationIncidentResponsePartyLocalOrg,
		AssigneeDID:   participantB.AgentID(),
		ReviewerDID:   owner.AgentID(),
		EvidenceIDs:   []string{incidentID},
		DueAt:         &dueAt,
		Reason:        "issue overdue bilateral work order",
		Metadata:      map[string]string{"ticket": "FED-DIRECTIVE-AUTO-ISSUE-01"},
	}); err != nil {
		t.Fatalf("CreateFederationIncidentDirective failed: %v", err)
	}

	directives, err := service.ListFederationIncidentDirectives(ctx, SecureCellFederationIncidentDirectiveFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		ResponseID:     localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectives failed: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected one directive, got %+v", directives)
	}
	directiveID := directives[0].DirectiveID

	sweep, err := service.SweepFederationIncidentDirectives(ctx, time.Now().UTC(), SecureCellLifecycleRequest{
		ActorDID: "secure-cell-runtime",
		Reason:   "automated directive supervision",
		Metadata: map[string]string{"automation_mode": "federation_incident_directive"},
	})
	if err != nil {
		t.Fatalf("SweepFederationIncidentDirectives failed: %v", err)
	}
	if sweep == nil || sweep.CellsMutated != 1 {
		t.Fatalf("expected one mutated cell from directive sweep, got %+v", sweep)
	}

	actions, err := service.ListFederationIncidentDirectiveAutomationActions(ctx, SecureCellFederationIncidentDirectiveAutomationActionFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		ResponseID:     localResponseID,
		DirectiveID:    directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveAutomationActions failed: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected one directive automation action, got %+v", actions)
	}
	action := actions[0]
	if action.DirectiveID != directiveID || action.PendingAction != "acknowledge" || action.DirectiveStatus != SecureCellFederationIncidentDirectiveStatusIssued {
		t.Fatalf("expected issued directive automation record awaiting acknowledgement, got %+v", action)
	}
	if action.Action != "secure_cell.federation_incident_response_escalated" && action.Action != "secure_cell.federation_contract_suspended" {
		t.Fatalf("expected directive automation to escalate response or suspend contracts, got %+v", action)
	}

	casePack, err := service.BuildFederationIncidentCasePack(ctx, created.CellID, localResponseID, SecureCellFederationIncidentCasePackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentCasePack failed: %v", err)
	}
	if err := VerifyFederationIncidentCasePack(casePack); err != nil {
		t.Fatalf("VerifyFederationIncidentCasePack failed: %v", err)
	}
	if len(casePack.DirectiveBundles) != 1 || casePack.DirectiveBundles[0] == nil || casePack.DirectiveBundles[0].DirectiveSummary.DirectiveID != directiveID {
		t.Fatalf("expected one directive bundle in case pack, got %+v", casePack.DirectiveBundles)
	}
	if len(casePack.DirectiveAutomationActions) != 1 || casePack.DirectiveAutomationActions[0].DirectiveID != directiveID {
		t.Fatalf("expected directive automation actions in case pack, got %+v", casePack.DirectiveAutomationActions)
	}
}

func TestService_FederationIncidentDirectiveExtensionGovernance(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Directive Extension Cell",
		Purpose:       "govern bilateral directive deadline exceptions",
		Resource:      "cell:federation-directive-extension",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Directive Exception Room",
		Purpose:         "coordinate bilateral directive exceptions",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "open directive exception session",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-EXT-SESSION-01"},
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[len(started.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite counterparty directive participant",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "counterparty joins directive exception room",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	organizationID := accepted.FederationContracts[0].OrganizationID
	contractID := accepted.FederationContracts[0].ID

	published, err := service.PublishFederationIncident(ctx, created.CellID, organizationID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityHigh,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Counterparty work order requires deadline exception handling",
		Description:              "The local organization opened a bilateral incident directive and wants governed deadline exception handling.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: false,
		Reason:                   "publish directive extension incident",
		Metadata:                 map[string]string{"ticket": "FED-DIRECTIVE-EXT-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local response, got %+v", responses)
	}

	dueAt := time.Now().UTC().Add(2 * time.Hour)
	if _, err := service.CreateFederationIncidentDirective(ctx, created.CellID, localResponseID, SecureCellFederationIncidentDirectiveCreateRequest{
		ActorDID:      owner.AgentID(),
		DirectiveType: "counterparty_evidence_request",
		Title:         "Provide counterparty evidence package",
		Summary:       "Counterparty must provide an evidence package for bilateral incident review.",
		Description:   "Provide the scoped evidence package, timeline, and remediation artifacts for the bilateral incident response.",
		Priority:      SecureCellFederationIncidentDirectivePriorityHigh,
		AssigneeParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		ReviewerParty: SecureCellFederationIncidentResponsePartyLocalOrg,
		AssigneeDID:   participantB.AgentID(),
		ReviewerDID:   owner.AgentID(),
		EvidenceIDs:   []string{incidentID},
		DueAt:         &dueAt,
		Reason:        "issue bilateral evidence work order",
		Metadata:      map[string]string{"ticket": "FED-DIRECTIVE-EXT-ISSUE-01"},
	}); err != nil {
		t.Fatalf("CreateFederationIncidentDirective failed: %v", err)
	}

	directives, err := service.ListFederationIncidentDirectives(ctx, SecureCellFederationIncidentDirectiveFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		ResponseID:     localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectives failed: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected one directive, got %+v", directives)
	}
	directiveID := directives[0].DirectiveID

	proposedDueAt := dueAt.Add(4 * time.Hour)
	if _, err := service.RequestFederationIncidentDirectiveExtension(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveExtensionRequest{
		ActorDID:        participantB.AgentID(),
		RequestingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:         "Counterparty needs longer evidence collection window",
		Description:     "The counterparty needs additional time to gather the full evidence package for the bilateral review.",
		EvidenceIDs:     []string{incidentID},
		ProposedDueAt:   &proposedDueAt,
		Reason:          "request governed deadline extension",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-EXT-REQUEST-01"},
	}); err != nil {
		t.Fatalf("RequestFederationIncidentDirectiveExtension failed: %v", err)
	}

	extensions, err := service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		ResponseID:  localResponseID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions failed: %v", err)
	}
	if len(extensions) != 1 || extensions[0].Status != SecureCellFederationIncidentDirectiveExtensionStatusPendingReview {
		t.Fatalf("expected one pending extension, got %+v", extensions)
	}
	firstExtensionID := extensions[0].ExtensionID

	if _, err := service.ApproveFederationIncidentDirectiveExtension(ctx, created.CellID, firstExtensionID, SecureCellFederationIncidentDirectiveExtensionApproveRequest{
		ActorDID:            owner.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local reviewer approved deadline extension",
		DecisionDescription: "The local organization approved the requested extension because the evidence scope is still being collected.",
		EvidenceIDs:         []string{incidentID, directiveID},
		Reason:              "approve governed deadline extension",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPROVE-01"},
	}); err != nil {
		t.Fatalf("ApproveFederationIncidentDirectiveExtension failed: %v", err)
	}

	rejectedProposedDueAt := proposedDueAt.Add(3 * time.Hour)
	if _, err := service.RequestFederationIncidentDirectiveExtension(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveExtensionRequest{
		ActorDID:        participantB.AgentID(),
		RequestingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:         "Counterparty asks for a second extension",
		Description:     "The counterparty asked for another exception window after the first deadline reset.",
		EvidenceIDs:     []string{incidentID, directiveID},
		ProposedDueAt:   &rejectedProposedDueAt,
		Reason:          "request second governed deadline extension",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-EXT-REQUEST-02"},
	}); err != nil {
		t.Fatalf("RequestFederationIncidentDirectiveExtension second failed: %v", err)
	}

	extensions, err = service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		ResponseID:  localResponseID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions second failed: %v", err)
	}
	if len(extensions) != 2 {
		t.Fatalf("expected two extension records, got %+v", extensions)
	}
	secondExtensionID := extensions[0].ExtensionID
	if secondExtensionID == firstExtensionID {
		secondExtensionID = extensions[1].ExtensionID
	}

	if _, err := service.RejectFederationIncidentDirectiveExtension(ctx, created.CellID, secondExtensionID, SecureCellFederationIncidentDirectiveExtensionRejectRequest{
		ActorDID:            owner.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Second extension denied",
		DecisionDescription: "The local organization denied the second request because the approved exception window was sufficient.",
		EvidenceIDs:         []string{directiveID},
		Reason:              "reject second governed deadline extension",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-REJECT-01"},
	}); err != nil {
		t.Fatalf("RejectFederationIncidentDirectiveExtension failed: %v", err)
	}

	directive, err := service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective failed: %v", err)
	}
	if directive.DueAt == nil || !directive.DueAt.UTC().Equal(proposedDueAt.UTC()) {
		t.Fatalf("expected directive due_at to be reset to approved extension, got %+v", directive.DueAt)
	}
	if len(directive.Extensions) != 2 {
		t.Fatalf("expected two extension records on directive detail, got %+v", directive.Extensions)
	}

	directives, err = service.ListFederationIncidentDirectives(ctx, SecureCellFederationIncidentDirectiveFilter{
		CellID:      created.CellID,
		ResponseID:  localResponseID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectives final failed: %v", err)
	}
	if len(directives) != 1 || directives[0].ExtensionCount != 2 || directives[0].PendingExtensionCount != 0 || directives[0].LastExtensionStatus != SecureCellFederationIncidentDirectiveExtensionStatusRejected {
		t.Fatalf("expected directive summary to reflect extension posture, got %+v", directives)
	}

	extensions, err = service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		ResponseID:  localResponseID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions final failed: %v", err)
	}
	if len(extensions) != 2 {
		t.Fatalf("expected two final extension summaries, got %+v", extensions)
	}
	statuses := map[SecureCellFederationIncidentDirectiveExtensionStatus]int{}
	for _, item := range extensions {
		statuses[item.Status]++
	}
	if statuses[SecureCellFederationIncidentDirectiveExtensionStatusApproved] != 1 || statuses[SecureCellFederationIncidentDirectiveExtensionStatusRejected] != 1 {
		t.Fatalf("expected one approved and one rejected extension, got %+v", extensions)
	}

	actions, err := service.ListFederationIncidentDirectiveActions(ctx, SecureCellFederationIncidentDirectiveActionFilter{
		CellID:      created.CellID,
		ResponseID:  localResponseID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveActions failed: %v", err)
	}
	actionSet := map[string]bool{}
	for _, item := range actions {
		actionSet[item.Action] = true
	}
	for _, want := range []string{
		"secure_cell.federation_incident_directive_issued",
		"secure_cell.federation_incident_directive_extension_requested",
		"secure_cell.federation_incident_directive_extension_approved",
		"secure_cell.federation_incident_directive_extension_rejected",
	} {
		if !actionSet[want] {
			t.Fatalf("expected directive action %q in %+v", want, actions)
		}
	}

	bundle, err := service.BuildFederationIncidentDirectiveBundle(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveBundle(bundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveBundle failed: %v", err)
	}
	if bundle.DirectiveSummary.ExtensionCount != 2 || bundle.DirectiveSummary.LastExtensionStatus != SecureCellFederationIncidentDirectiveExtensionStatusRejected || len(bundle.Directive.Extensions) != 2 {
		t.Fatalf("expected directive bundle to carry extension posture, got %+v", bundle)
	}

	finalResult := mustSecureCellResult(t, service, created.CellID)
	if finalResult.ControlLedger == nil || !controlLedgerHasControl(finalResult.ControlLedger, "CELL-FED-13") {
		t.Fatalf("expected directive extension governance control in control ledger, got %+v", finalResult.ControlLedger)
	}
}

func TestService_FederationIncidentDirectiveExtensionCommitteeDelegation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Directive Extension Committee Cell",
		Purpose:       "govern bilateral directive deadline exceptions with committee review",
		Resource:      "cell:federation-directive-extension-committee",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Directive Exception Committee Room",
		Purpose:         "coordinate bilateral directive exception committee review",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "open directive exception committee session",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-SESSION-01"},
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[len(started.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite counterparty directive committee participant",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "counterparty joins directive exception committee room",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	organizationID := accepted.FederationContracts[0].OrganizationID
	contractID := accepted.FederationContracts[0].ID

	published, err := service.PublishFederationIncident(ctx, created.CellID, organizationID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityHigh,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Directive extension committee incident",
		Description:              "The local organization opened a bilateral incident directive and wants committee-based extension governance.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: false,
		Reason:                   "publish directive extension committee incident",
		Metadata:                 map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local response, got %+v", responses)
	}

	dueAt := time.Now().UTC().Add(2 * time.Hour)
	if _, err := service.CreateFederationIncidentDirective(ctx, created.CellID, localResponseID, SecureCellFederationIncidentDirectiveCreateRequest{
		ActorDID:      owner.AgentID(),
		DirectiveType: "counterparty_evidence_request",
		Title:         "Provide counterparty evidence package",
		Summary:       "Counterparty must provide an evidence package for bilateral incident review.",
		Description:   "Provide the scoped evidence package, timeline, and remediation artifacts for the bilateral incident response.",
		Priority:      SecureCellFederationIncidentDirectivePriorityHigh,
		AssigneeParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		ReviewerParty: SecureCellFederationIncidentResponsePartyLocalOrg,
		AssigneeDID:   participantB.AgentID(),
		ReviewerDID:   owner.AgentID(),
		EvidenceIDs:   []string{incidentID},
		DueAt:         &dueAt,
		Reason:        "issue bilateral evidence work order",
		Metadata:      map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-ISSUE-01"},
	}); err != nil {
		t.Fatalf("CreateFederationIncidentDirective failed: %v", err)
	}

	directives, err := service.ListFederationIncidentDirectives(ctx, SecureCellFederationIncidentDirectiveFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		ResponseID:     localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectives failed: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected one directive, got %+v", directives)
	}
	directiveID := directives[0].DirectiveID

	firstProposedDueAt := dueAt.Add(4 * time.Hour)
	if _, err := service.RequestFederationIncidentDirectiveExtension(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveExtensionRequest{
		ActorDID:                   participantB.AgentID(),
		RequestingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                    "Counterparty needs longer evidence collection window",
		Description:                "The counterparty needs additional time to gather the full evidence package for bilateral review.",
		EvidenceIDs:                []string{incidentID},
		ProposedDueAt:              &firstProposedDueAt,
		ReviewApprovalThreshold:    2,
		EligibleReviewerDIDs:       []string{owner.AgentID()},
		DisputeResolutionThreshold: 2,
		EligibleResolverDIDs:       []string{owner.AgentID(), participantA.AgentID()},
		Reason:                     "request committee reviewed directive extension",
		Metadata:                   map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-REQUEST-01"},
	}); err != nil {
		t.Fatalf("RequestFederationIncidentDirectiveExtension failed: %v", err)
	}

	extensions, err := service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions failed: %v", err)
	}
	if len(extensions) != 1 {
		t.Fatalf("expected one extension summary, got %+v", extensions)
	}
	firstExtensionID := extensions[0].ExtensionID
	if extensions[0].ReviewApprovalThreshold != 2 || extensions[0].EligibleReviewerCount != 1 {
		t.Fatalf("expected committee review posture on extension summary, got %+v", extensions[0])
	}

	if _, err := service.DelegateFederationIncidentDirectiveExtensionReview(ctx, created.CellID, firstExtensionID, SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
		ActorDID:  owner.AgentID(),
		TargetDID: participantA.AgentID(),
		Reason:    "delegate local committee review",
		Metadata:  map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-DELEGATE-REVIEW-01"},
	}); err != nil {
		t.Fatalf("DelegateFederationIncidentDirectiveExtensionReview failed: %v", err)
	}

	if _, err := service.ApproveFederationIncidentDirectiveExtension(ctx, created.CellID, firstExtensionID, SecureCellFederationIncidentDirectiveExtensionApproveRequest{
		ActorDID:            owner.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local committee vote one approved extension",
		DecisionDescription: "The first committee reviewer approved the exception but the threshold is not met yet.",
		EvidenceIDs:         []string{incidentID, directiveID},
		Reason:              "record first committee approval vote",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-APPROVE-01"},
	}); err != nil {
		t.Fatalf("ApproveFederationIncidentDirectiveExtension first vote failed: %v", err)
	}

	directive, err := service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective failed: %v", err)
	}
	if len(directive.Extensions) != 1 {
		t.Fatalf("expected one extension on directive, got %+v", directive.Extensions)
	}
	firstExtension := directive.Extensions[0]
	if firstExtension.Status != SecureCellFederationIncidentDirectiveExtensionStatusPendingReview || len(firstExtension.ReviewVotes) != 1 || len(firstExtension.ReviewDelegations) != 1 {
		t.Fatalf("expected pending review committee state after first vote, got %+v", firstExtension)
	}

	if _, err := service.ApproveFederationIncidentDirectiveExtension(ctx, created.CellID, firstExtensionID, SecureCellFederationIncidentDirectiveExtensionApproveRequest{
		ActorDID:            participantA.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local committee approved extension",
		DecisionDescription: "The delegated local reviewer completed the threshold and approved the extension.",
		EvidenceIDs:         []string{incidentID, directiveID},
		Reason:              "record second committee approval vote",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-APPROVE-02"},
	}); err != nil {
		t.Fatalf("ApproveFederationIncidentDirectiveExtension second vote failed: %v", err)
	}

	directive, err = service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective after approval failed: %v", err)
	}
	firstExtension = directive.Extensions[0]
	if firstExtension.Status != SecureCellFederationIncidentDirectiveExtensionStatusApproved || firstExtension.ReviewedBy != participantA.AgentID() || directive.DueAt == nil || !directive.DueAt.UTC().Equal(firstProposedDueAt.UTC()) {
		t.Fatalf("expected approved extension after second committee vote, got directive=%+v extension=%+v", directive, firstExtension)
	}

	secondProposedDueAt := firstProposedDueAt.Add(2 * time.Hour)
	if _, err := service.RequestFederationIncidentDirectiveExtension(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveExtensionRequest{
		ActorDID:                   participantB.AgentID(),
		RequestingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                    "Counterparty asks for another exception window",
		Description:                "The counterparty asked for another governed exception window after the first reset.",
		EvidenceIDs:                []string{incidentID, directiveID},
		ProposedDueAt:              &secondProposedDueAt,
		ReviewApprovalThreshold:    2,
		EligibleReviewerDIDs:       []string{owner.AgentID()},
		DisputeResolutionThreshold: 2,
		EligibleResolverDIDs:       []string{owner.AgentID()},
		Reason:                     "request second committee reviewed directive extension",
		Metadata:                   map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-REQUEST-02"},
	}); err != nil {
		t.Fatalf("RequestFederationIncidentDirectiveExtension second failed: %v", err)
	}

	extensions, err = service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions second failed: %v", err)
	}
	var secondExtensionID string
	for _, item := range extensions {
		if item.ExtensionID != firstExtensionID {
			secondExtensionID = item.ExtensionID
			break
		}
	}
	if secondExtensionID == "" {
		t.Fatalf("expected second extension id, got %+v", extensions)
	}

	if _, err := service.DelegateFederationIncidentDirectiveExtensionReview(ctx, created.CellID, secondExtensionID, SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
		ActorDID:  owner.AgentID(),
		TargetDID: participantA.AgentID(),
		Reason:    "delegate second local committee review",
		Metadata:  map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-DELEGATE-REVIEW-02"},
	}); err != nil {
		t.Fatalf("DelegateFederationIncidentDirectiveExtensionReview second failed: %v", err)
	}

	if _, err := service.RejectFederationIncidentDirectiveExtension(ctx, created.CellID, secondExtensionID, SecureCellFederationIncidentDirectiveExtensionRejectRequest{
		ActorDID:            owner.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local committee vote one rejected extension",
		DecisionDescription: "The first local reviewer rejected the second exception but the threshold is not met yet.",
		EvidenceIDs:         []string{directiveID},
		Reason:              "record first committee rejection vote",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-REJECT-01"},
	}); err != nil {
		t.Fatalf("RejectFederationIncidentDirectiveExtension first vote failed: %v", err)
	}

	if _, err := service.RejectFederationIncidentDirectiveExtension(ctx, created.CellID, secondExtensionID, SecureCellFederationIncidentDirectiveExtensionRejectRequest{
		ActorDID:            participantA.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local committee rejected extension",
		DecisionDescription: "The delegated local reviewer completed the threshold and rejected the second extension.",
		EvidenceIDs:         []string{directiveID},
		Reason:              "record second committee rejection vote",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-REJECT-02"},
	}); err != nil {
		t.Fatalf("RejectFederationIncidentDirectiveExtension second vote failed: %v", err)
	}

	directive, err = service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective after rejection failed: %v", err)
	}
	secondExtension := directive.Extensions[1]
	if secondExtension.Status != SecureCellFederationIncidentDirectiveExtensionStatusRejected || secondExtension.ReviewedBy != participantA.AgentID() || directive.DueAt == nil || !directive.DueAt.UTC().Equal(firstProposedDueAt.UTC()) {
		t.Fatalf("expected rejected second extension without due_at reset, got directive=%+v extension=%+v", directive, secondExtension)
	}

	if _, err := service.DisputeFederationIncidentDirectiveExtension(ctx, created.CellID, secondExtensionID, SecureCellFederationIncidentDirectiveExtensionDisputeRequest{
		ActorDID:         participantB.AgentID(),
		ChallengingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:          "Counterparty challenges rejected extension",
		Description:      "The counterparty challenged the rejected exception and requested local dispute resolution.",
		EvidenceIDs:      []string{directiveID},
		Reason:           "open committee dispute resolution",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-DISPUTE-01"},
	}); err != nil {
		t.Fatalf("DisputeFederationIncidentDirectiveExtension failed: %v", err)
	}

	disputes, err := service.ListFederationIncidentDirectiveExtensionDisputes(ctx, SecureCellFederationIncidentDirectiveExtensionDisputeFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		ExtensionID: secondExtensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionDisputes failed: %v", err)
	}
	if len(disputes) != 1 || disputes[0].ResolutionThreshold != 2 || disputes[0].EligibleResolverCount != 1 {
		t.Fatalf("expected committee dispute posture, got %+v", disputes)
	}
	disputeID := disputes[0].DisputeID

	if _, err := service.DelegateFederationIncidentDirectiveExtensionDisputeResolution(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
		ActorDID:  owner.AgentID(),
		TargetDID: participantA.AgentID(),
		Reason:    "delegate local dispute resolution review",
		Metadata:  map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-DELEGATE-RESOLVE-01"},
	}); err != nil {
		t.Fatalf("DelegateFederationIncidentDirectiveExtensionDisputeResolution failed: %v", err)
	}

	if _, err := service.ResolveFederationIncidentDirectiveExtensionDispute(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionDisputeResolveRequest{
		ActorDID:              owner.AgentID(),
		RespondingParty:       SecureCellFederationIncidentResponsePartyLocalOrg,
		Resolution:            SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold,
		ResolutionSummary:     "Local committee vote one upheld rejection",
		ResolutionDescription: "The first local resolver upheld the rejection but the dispute threshold is not met yet.",
		EvidenceIDs:           []string{disputeID},
		Reason:                "record first dispute resolution vote",
		Metadata:              map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-RESOLVE-01"},
	}); err != nil {
		t.Fatalf("ResolveFederationIncidentDirectiveExtensionDispute first vote failed: %v", err)
	}

	directive, err = service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective after first dispute vote failed: %v", err)
	}
	secondExtension = directive.Extensions[1]
	if secondExtension.Status != SecureCellFederationIncidentDirectiveExtensionStatusDisputed || len(secondExtension.Disputes) != 1 || len(secondExtension.Disputes[0].ResolutionVotes) != 1 || secondExtension.Disputes[0].Status != SecureCellFederationIncidentDirectiveExtensionDisputeStatusPendingResolution {
		t.Fatalf("expected disputed extension with one resolution vote, got %+v", secondExtension)
	}

	if _, err := service.ResolveFederationIncidentDirectiveExtensionDispute(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionDisputeResolveRequest{
		ActorDID:              participantA.AgentID(),
		RespondingParty:       SecureCellFederationIncidentResponsePartyLocalOrg,
		Resolution:            SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold,
		ResolutionSummary:     "Local committee upheld rejection",
		ResolutionDescription: "The delegated local resolver completed the threshold and upheld the rejection.",
		EvidenceIDs:           []string{disputeID},
		Reason:                "record second dispute resolution vote",
		Metadata:              map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-RESOLVE-02"},
	}); err != nil {
		t.Fatalf("ResolveFederationIncidentDirectiveExtensionDispute second vote failed: %v", err)
	}

	directive, err = service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective final failed: %v", err)
	}
	secondExtension = directive.Extensions[1]
	if secondExtension.Status != SecureCellFederationIncidentDirectiveExtensionStatusRejected || secondExtension.Disputes[0].Status != SecureCellFederationIncidentDirectiveExtensionDisputeStatusUpheld || secondExtension.Disputes[0].ResolvedBy != participantA.AgentID() || directive.DueAt == nil || !directive.DueAt.UTC().Equal(firstProposedDueAt.UTC()) {
		t.Fatalf("expected upheld dispute after second committee resolver vote, got directive=%+v extension=%+v", directive, secondExtension)
	}

	extensions, err = service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions final failed: %v", err)
	}
	var committeeSummary SecureCellFederationIncidentDirectiveExtensionSummary
	for _, item := range extensions {
		if item.ExtensionID == firstExtensionID {
			committeeSummary = item
			break
		}
	}
	if committeeSummary.ExtensionID == "" || committeeSummary.ApproveVoteCount != 2 || committeeSummary.ReviewDelegationCount != 1 || !committeeSummary.ReviewThresholdSatisfied {
		t.Fatalf("expected extension summary with committee counts, got %+v", committeeSummary)
	}

	disputes, err = service.ListFederationIncidentDirectiveExtensionDisputes(ctx, SecureCellFederationIncidentDirectiveExtensionDisputeFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		ExtensionID: secondExtensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionDisputes final failed: %v", err)
	}
	if len(disputes) != 1 || disputes[0].UpholdVoteCount != 2 || disputes[0].ResolutionDelegationCount != 1 || !disputes[0].ResolutionThresholdSatisfied {
		t.Fatalf("expected dispute summary with committee counts, got %+v", disputes)
	}

	actions, err := service.ListFederationIncidentDirectiveActions(ctx, SecureCellFederationIncidentDirectiveActionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveActions failed: %v", err)
	}
	actionSet := map[string]bool{}
	for _, item := range actions {
		actionSet[item.Action] = true
	}
	for _, want := range []string{
		"secure_cell.federation_incident_directive_extension_review_delegated",
		"secure_cell.federation_incident_directive_extension_review_vote_recorded",
		"secure_cell.federation_incident_directive_extension_dispute_resolution_delegated",
		"secure_cell.federation_incident_directive_extension_dispute_resolution_vote_recorded",
	} {
		if !actionSet[want] {
			t.Fatalf("expected directive committee action %q in %+v", want, actions)
		}
	}
}

func TestService_FederationIncidentDirectiveExtensionDisputeAutomationAndCasePack(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Directive Extension Dispute Cell",
		Purpose:       "govern disputed directive deadline exceptions with timed automation",
		Resource:      "cell:federation-directive-extension-dispute",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Directive Exception Dispute Room",
		Purpose:         "coordinate disputed bilateral directive exceptions",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "open directive extension dispute room",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-EXT-DISPUTE-SESSION-01"},
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[len(started.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite counterparty dispute participant",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-DISPUTE-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "counterparty joins directive dispute room",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-DISPUTE-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	organizationID := accepted.FederationContracts[0].OrganizationID
	contractID := accepted.FederationContracts[0].ID

	published, err := service.PublishFederationIncident(ctx, created.CellID, organizationID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityHigh,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Directive exception dispute incident",
		Description:              "The local organization wants governed extension dispute handling plus timed automation.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: false,
		Reason:                   "publish directive dispute incident",
		Metadata:                 map[string]string{"ticket": "FED-DIRECTIVE-EXT-DISPUTE-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local response, got %+v", responses)
	}

	currentDueAt := time.Now().UTC().Add(2 * time.Hour)
	if _, err := service.CreateFederationIncidentDirective(ctx, created.CellID, localResponseID, SecureCellFederationIncidentDirectiveCreateRequest{
		ActorDID:      owner.AgentID(),
		DirectiveType: "counterparty_evidence_request",
		Title:         "Provide bilateral evidence package",
		Summary:       "Counterparty must provide the evidence package for coordinated review.",
		Description:   "Provide the scoped evidence package, timeline, and remediation artifacts for the bilateral review.",
		Priority:      SecureCellFederationIncidentDirectivePriorityHigh,
		AssigneeParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		ReviewerParty: SecureCellFederationIncidentResponsePartyLocalOrg,
		AssigneeDID:   participantB.AgentID(),
		ReviewerDID:   owner.AgentID(),
		EvidenceIDs:   []string{incidentID},
		DueAt:         &currentDueAt,
		Reason:        "issue directive with governed exception workflow",
		Metadata:      map[string]string{"ticket": "FED-DIRECTIVE-EXT-DISPUTE-ISSUE-01"},
	}); err != nil {
		t.Fatalf("CreateFederationIncidentDirective failed: %v", err)
	}

	directives, err := service.ListFederationIncidentDirectives(ctx, SecureCellFederationIncidentDirectiveFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		ResponseID:     localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectives failed: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected one directive, got %+v", directives)
	}
	directiveID := directives[0].DirectiveID

	proposedDueAt := currentDueAt.Add(4 * time.Hour)
	if _, err := service.RequestFederationIncidentDirectiveExtension(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveExtensionRequest{
		ActorDID:        participantB.AgentID(),
		RequestingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:         "Counterparty needs longer evidence collection window",
		Description:     "The counterparty needs additional time to gather the full bilateral evidence package.",
		EvidenceIDs:     []string{incidentID},
		ProposedDueAt:   &proposedDueAt,
		Reason:          "request governed directive extension",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-EXT-DISPUTE-REQUEST-01"},
	}); err != nil {
		t.Fatalf("RequestFederationIncidentDirectiveExtension failed: %v", err)
	}

	extensions, err := service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		ResponseID:  localResponseID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions failed: %v", err)
	}
	if len(extensions) != 1 || extensions[0].Status != SecureCellFederationIncidentDirectiveExtensionStatusPendingReview {
		t.Fatalf("expected one pending extension, got %+v", extensions)
	}
	extensionID := extensions[0].ExtensionID
	reviewOverdueAt := extensions[0].CreatedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionReviewSLA + time.Hour)

	overdueExtensions, err := service.ListOverdueFederationIncidentDirectiveExtensions(ctx, SecureCellOverdueFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		ResponseID:  localResponseID,
		DirectiveID: directiveID,
		Before:      &reviewOverdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentDirectiveExtensions review failed: %v", err)
	}
	if len(overdueExtensions) != 1 || overdueExtensions[0].ExtensionID != extensionID || overdueExtensions[0].PendingAction != "review" {
		t.Fatalf("expected one overdue review item, got %+v", overdueExtensions)
	}

	sweepActor := "did:aethelred:directive-extension-sweeper"
	if _, err := service.SweepFederationIncidentDirectiveExtensions(ctx, reviewOverdueAt, SecureCellLifecycleRequest{
		ActorDID: sweepActor,
		Reason:   "automated directive extension review sweep",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-DISPUTE-SWEEP-REVIEW-01"},
	}); err != nil {
		t.Fatalf("SweepFederationIncidentDirectiveExtensions review failed: %v", err)
	}

	automationActions, err := service.ListFederationIncidentDirectiveExtensionAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAutomationActionFilter{
		CellID:      created.CellID,
		ResponseID:  localResponseID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAutomationActions review failed: %v", err)
	}
	if len(automationActions) == 0 || automationActions[0].ExtensionID != extensionID || automationActions[0].PendingAction != "review" {
		t.Fatalf("expected extension review automation action, got %+v", automationActions)
	}
	if automationActions[0].Action != "secure_cell.federation_incident_response_escalated" && automationActions[0].Action != "secure_cell.federation_contract_suspended" {
		t.Fatalf("expected review automation to escalate response or suspend contracts, got %+v", automationActions[0])
	}

	if _, err := service.ApproveFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionApproveRequest{
		ActorDID:            owner.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local reviewer approved the directive extension",
		DecisionDescription: "The local organization approved the requested extension because evidence collection is still underway.",
		EvidenceIDs:         []string{directiveID},
		Reason:              "approve governed directive extension",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-DISPUTE-APPROVE-01"},
	}); err != nil {
		t.Fatalf("ApproveFederationIncidentDirectiveExtension failed: %v", err)
	}

	directive, err := service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective after approve failed: %v", err)
	}
	if directive.DueAt == nil || !directive.DueAt.UTC().Equal(proposedDueAt.UTC()) {
		t.Fatalf("expected directive due_at to match approved extension, got %+v", directive.DueAt)
	}

	if _, err := service.DisputeFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionDisputeRequest{
		ActorDID:    owner.AgentID(),
		Summary:     "Local reviewer challenges the approved extension",
		Description: "The local organization re-opened the approved extension because the original deadline should remain fail-closed pending re-review.",
		EvidenceIDs: []string{directiveID},
		Reason:      "dispute approved directive extension",
		Metadata:    map[string]string{"ticket": "FED-DIRECTIVE-EXT-DISPUTE-OPEN-01"},
	}); err != nil {
		t.Fatalf("DisputeFederationIncidentDirectiveExtension failed: %v", err)
	}

	directive, err = service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective after dispute failed: %v", err)
	}
	if directive.DueAt == nil || !directive.DueAt.UTC().Equal(currentDueAt.UTC()) {
		t.Fatalf("expected directive due_at to revert fail-closed during dispute, got %+v", directive.DueAt)
	}

	disputes, err := service.ListFederationIncidentDirectiveExtensionDisputes(ctx, SecureCellFederationIncidentDirectiveExtensionDisputeFilter{
		CellID:      created.CellID,
		ResponseID:  localResponseID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionDisputes failed: %v", err)
	}
	if len(disputes) != 1 || disputes[0].Status != SecureCellFederationIncidentDirectiveExtensionDisputeStatusPendingResolution {
		t.Fatalf("expected one pending dispute, got %+v", disputes)
	}
	disputeID := disputes[0].DisputeID
	resolutionOverdueAt := disputes[0].CreatedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionResolutionSLA + time.Hour)

	overdueExtensions, err = service.ListOverdueFederationIncidentDirectiveExtensions(ctx, SecureCellOverdueFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		ResponseID:  localResponseID,
		DirectiveID: directiveID,
		Before:      &resolutionOverdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentDirectiveExtensions dispute failed: %v", err)
	}
	if len(overdueExtensions) != 1 || overdueExtensions[0].PendingAction != "resolve_dispute" || overdueExtensions[0].PendingDisputeID != disputeID {
		t.Fatalf("expected one overdue dispute-resolution item, got %+v", overdueExtensions)
	}

	if _, err := service.SweepFederationIncidentDirectiveExtensions(ctx, resolutionOverdueAt, SecureCellLifecycleRequest{
		ActorDID: sweepActor,
		Reason:   "automated directive extension dispute sweep",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-DISPUTE-SWEEP-RESOLVE-01"},
	}); err != nil {
		t.Fatalf("SweepFederationIncidentDirectiveExtensions dispute failed: %v", err)
	}

	automationActions, err = service.ListFederationIncidentDirectiveExtensionAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAutomationActionFilter{
		CellID:      created.CellID,
		ResponseID:  localResponseID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAutomationActions dispute failed: %v", err)
	}
	if len(automationActions) < 2 {
		t.Fatalf("expected review and dispute automation actions, got %+v", automationActions)
	}
	var sawDisputeAutomation bool
	for _, item := range automationActions {
		if item.PendingAction == "resolve_dispute" && item.ExtensionID == extensionID {
			sawDisputeAutomation = true
			if item.Action != "secure_cell.federation_incident_response_escalated" && item.Action != "secure_cell.federation_contract_suspended" {
				t.Fatalf("expected dispute automation to escalate response or suspend contracts, got %+v", item)
			}
		}
	}
	if !sawDisputeAutomation {
		t.Fatalf("expected one dispute-resolution automation record, got %+v", automationActions)
	}

	if _, err := service.ResolveFederationIncidentDirectiveExtensionDispute(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionDisputeResolveRequest{
		ActorDID:              participantB.AgentID(),
		Resolution:            SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold,
		ResolutionSummary:     "Counterparty upheld the original approved extension",
		ResolutionDescription: "The counterparty completed the governed dispute loop and upheld the approved extension window.",
		EvidenceIDs:           []string{disputeID},
		Reason:                "resolve directive extension dispute",
		Metadata:              map[string]string{"ticket": "FED-DIRECTIVE-EXT-DISPUTE-RESOLVE-01"},
	}); err != nil {
		t.Fatalf("ResolveFederationIncidentDirectiveExtensionDispute failed: %v", err)
	}

	directive, err = service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective after resolve failed: %v", err)
	}
	if directive.DueAt == nil || !directive.DueAt.UTC().Equal(proposedDueAt.UTC()) {
		t.Fatalf("expected directive due_at to restore approved extension after resolution, got %+v", directive.DueAt)
	}

	bundle, err := service.BuildFederationIncidentDirectiveBundle(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveBundle(bundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveBundle failed: %v", err)
	}
	if len(bundle.ExtensionDisputes) != 1 || bundle.ExtensionDisputes[0].DisputeID != disputeID {
		t.Fatalf("expected directive bundle dispute evidence, got %+v", bundle.ExtensionDisputes)
	}
	if len(bundle.ExtensionAutomationActions) < 2 {
		t.Fatalf("expected directive bundle automation history, got %+v", bundle.ExtensionAutomationActions)
	}

	casePack, err := service.BuildFederationIncidentCasePack(ctx, created.CellID, localResponseID, SecureCellFederationIncidentCasePackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentCasePack failed: %v", err)
	}
	if err := VerifyFederationIncidentCasePack(casePack); err != nil {
		t.Fatalf("VerifyFederationIncidentCasePack failed: %v", err)
	}
	if len(casePack.DirectiveExtensionDisputes) != 1 || casePack.DirectiveExtensionDisputes[0].DisputeID != disputeID {
		t.Fatalf("expected case pack dispute evidence, got %+v", casePack.DirectiveExtensionDisputes)
	}
	if len(casePack.DirectiveExtensionAutomationActions) < 2 {
		t.Fatalf("expected case pack extension automation history, got %+v", casePack.DirectiveExtensionAutomationActions)
	}

	finalResult := mustSecureCellResult(t, service, created.CellID)
	if finalResult.ControlLedger == nil || !controlLedgerHasControl(finalResult.ControlLedger, "CELL-FED-14") {
		t.Fatalf("expected directive extension dispute automation control in control ledger, got %+v", finalResult.ControlLedger)
	}
}

func TestService_FederationIncidentReportAmendmentFlow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Report Amendment Cell",
		Purpose:       "governed incident report amendment handling",
		Resource:      "cell:federation-report-amendment",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Regulator Coordination Room",
		Purpose:         "prepare bilateral regulator coordination steps",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "regulator coordination opened",
		Metadata:        map[string]string{"ticket": "FED-REPORT-AMEND-SESSION-01"},
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[len(started.Sessions)-1]

	sponsorOfRecord := secureCellFederationSponsor(participantB)
	organizationName := secureCellFederationOrganizationName(participantB)

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  sponsorOfRecord,
		OrganizationName: organizationName,
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite counterparty regulator reviewer",
		Metadata:         map[string]string{"ticket": "FED-REPORT-AMEND-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "counterparty joins regulator room",
		Metadata: map[string]string{"ticket": "FED-REPORT-AMEND-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	if len(accepted.FederationContracts) != 1 {
		t.Fatalf("expected one federation contract, got %+v", accepted.FederationContracts)
	}
	organizationID := accepted.FederationContracts[0].OrganizationID
	contractID := accepted.FederationContracts[0].ID

	published, err := service.PublishFederationIncident(ctx, created.CellID, organizationID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityCritical,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Local filing posture drift detected",
		Description:              "The local organization needs to coordinate an updated regulator notification with the counterparty.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: false,
		Reason:                   "publish local filing drift incident",
		Metadata:                 map[string]string{"ticket": "FED-REPORT-AMEND-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local response, got %+v", responses)
	}

	dueAt := time.Now().UTC().Add(2 * time.Hour)
	if _, err := service.CreateFederationIncidentReport(ctx, created.CellID, localResponseID, SecureCellFederationIncidentReportPlanRequest{
		ActorDID:         owner.AgentID(),
		ReportingParty:   SecureCellFederationIncidentResponsePartyLocalOrg,
		Regulator:        "uk-ico",
		Jurisdiction:     "UK",
		Framework:        "uk-gdpr",
		ReportType:       "breach_notification",
		Summary:          "Local regulator notification",
		Description:      "The local organization prepared an initial regulator notification.",
		RequiredSections: []string{"scope", "impact", "containment"},
		EvidenceIDs:      []string{incidentID},
		DueAt:            &dueAt,
		Reason:           "plan local regulator notification",
		Metadata:         map[string]string{"ticket": "FED-REPORT-AMEND-PLAN-01"},
	}); err != nil {
		t.Fatalf("CreateFederationIncidentReport failed: %v", err)
	}

	reports, err := service.ListFederationIncidentReports(ctx, SecureCellFederationIncidentReportFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		ResponseID:     localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReports failed: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected one federation incident report, got %+v", reports)
	}
	reportID := reports[0].ReportID

	submitted, err := service.SubmitFederationIncidentReport(ctx, created.CellID, reportID, SecureCellFederationIncidentReportSubmitRequest{
		ActorDID:            owner.AgentID(),
		SubmissionReference: "ico-2026-local-0001",
		Summary:             "Local submitted regulator notification",
		Description:         "The local organization submitted the initial regulator notification package.",
		EvidenceIDs:         []string{incidentID},
		Reason:              "submit local regulator notification",
		Metadata:            map[string]string{"ticket": "FED-REPORT-AMEND-SUBMIT-01"},
	})
	if err != nil {
		t.Fatalf("SubmitFederationIncidentReport failed: %v", err)
	}

	acknowledged, err := service.AcknowledgeFederationIncidentReport(ctx, created.CellID, reportID, SecureCellFederationIncidentReportAcknowledgeRequest{
		ActorDID:                 participantB.AgentID(),
		AcknowledgingParty:       SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		AcknowledgementReference: "counterparty-ack-0001",
		Reason:                   "counterparty acknowledged local filing",
		Metadata:                 map[string]string{"ticket": "FED-REPORT-AMEND-ACK-01"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeFederationIncidentReport failed: %v", err)
	}

	amended, err := service.AmendFederationIncidentReport(ctx, created.CellID, reportID, SecureCellFederationIncidentReportAmendRequest{
		ActorDID:        owner.AgentID(),
		Summary:         "Local amended regulator notification",
		Description:     "The local organization amended the filing with narrowed impact and updated evidence.",
		ChangedSections: []string{"scope", "impact"},
		EvidenceIDs:     []string{acknowledged.ControlLedger.Bundle.ID},
		Reason:          "amend local regulator notification",
		Metadata:        map[string]string{"ticket": "FED-REPORT-AMEND-01"},
	})
	if err != nil {
		t.Fatalf("AmendFederationIncidentReport failed: %v", err)
	}

	amendments, err := service.ListFederationIncidentReportAmendments(ctx, SecureCellFederationIncidentReportAmendmentFilter{
		CellID:   created.CellID,
		ReportID: reportID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportAmendments failed: %v", err)
	}
	if len(amendments) != 1 || amendments[0].Status != SecureCellFederationIncidentReportAmendmentStatusPendingSubmission || amendments[0].Sequence != 1 {
		t.Fatalf("expected one pending amendment, got %+v", amendments)
	}
	amendmentID := amendments[0].AmendmentID

	amendSubmitted, err := service.SubmitFederationIncidentReportAmendment(ctx, created.CellID, amendmentID, SecureCellFederationIncidentReportAmendmentSubmitRequest{
		ActorDID:            owner.AgentID(),
		SubmissionReference: "ico-2026-local-amend-0001",
		Summary:             "Local submitted regulator amendment",
		Description:         "The local organization submitted the regulator amendment package.",
		EvidenceIDs:         []string{submitted.ControlLedger.Bundle.ID},
		Reason:              "submit local regulator amendment",
		Metadata:            map[string]string{"ticket": "FED-REPORT-AMEND-SUBMIT-02"},
	})
	if err != nil {
		t.Fatalf("SubmitFederationIncidentReportAmendment failed: %v", err)
	}

	amendAcknowledged, err := service.AcknowledgeFederationIncidentReportAmendment(ctx, created.CellID, amendmentID, SecureCellFederationIncidentReportAmendmentAcknowledgeRequest{
		ActorDID:                 participantB.AgentID(),
		AcknowledgingParty:       SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		AcknowledgementReference: "counterparty-amend-ack-0001",
		Reason:                   "counterparty acknowledged regulator amendment",
		Metadata:                 map[string]string{"ticket": "FED-REPORT-AMEND-ACK-02"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeFederationIncidentReportAmendment failed: %v", err)
	}

	amendments, err = service.ListFederationIncidentReportAmendments(ctx, SecureCellFederationIncidentReportAmendmentFilter{
		CellID:   created.CellID,
		ReportID: reportID,
		Status:   SecureCellFederationIncidentReportAmendmentStatusAcknowledged,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportAmendments after acknowledgement failed: %v", err)
	}
	if len(amendments) != 1 || amendments[0].AmendmentID != amendmentID || amendments[0].AcknowledgedBy != participantB.AgentID() {
		t.Fatalf("expected one acknowledged amendment, got %+v", amendments)
	}

	responseWithReport, err := service.GetFederationIncidentResponse(ctx, created.CellID, localResponseID)
	if err != nil {
		t.Fatalf("GetFederationIncidentResponse failed: %v", err)
	}
	if len(responseWithReport.IncidentReports) != 1 || len(responseWithReport.IncidentReports[0].Amendments) != 1 || responseWithReport.IncidentReports[0].Amendments[0].Status != SecureCellFederationIncidentReportAmendmentStatusAcknowledged {
		t.Fatalf("expected acknowledged amendment on local report, got %+v", responseWithReport.IncidentReports)
	}

	amendmentBundle, err := service.BuildFederationIncidentReportAmendmentBundle(ctx, created.CellID, amendmentID, SecureCellFederationIncidentReportAmendmentBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentReportAmendmentBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentReportAmendmentBundle(amendmentBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentReportAmendmentBundle failed: %v", err)
	}
	if amendmentBundle.ReportSummary.ReportID != reportID || amendmentBundle.AmendmentSummary.AmendmentID != amendmentID || amendmentBundle.AmendmentSummary.Status != SecureCellFederationIncidentReportAmendmentStatusAcknowledged {
		t.Fatalf("expected acknowledged amendment bundle projection, got %+v", amendmentBundle.AmendmentSummary)
	}
	if amendmentBundle.ReportBundleHash == "" || amendmentBundle.Signature == nil {
		t.Fatalf("expected signed amendment bundle with report linkage, got %+v", amendmentBundle)
	}
	if len(amended.Transitions) == 0 || len(amendSubmitted.Transitions) == 0 || len(amendAcknowledged.Transitions) == 0 {
		t.Fatalf("expected amendment lifecycle mutations to append transitions")
	}

	intakeResult, err := service.IngestFederationIncidentReportAmendmentBundle(ctx, created.CellID, organizationID, SecureCellFederationIncidentReportAmendmentBundleIntakeRequest{
		ActorDID: owner.AgentID(),
		Bundle:   amendmentBundle,
		Reason:   "ingest reciprocal incident report amendment bundle",
		Metadata: map[string]string{"ticket": "FED-REPORT-AMEND-INTAKE-01"},
	})
	if err != nil {
		t.Fatalf("IngestFederationIncidentReportAmendmentBundle failed: %v", err)
	}
	if len(intakeResult.FederationCounterpartyIncidentReportAmendments) != 1 || intakeResult.FederationCounterpartyIncidentReportAmendments[0].Status != SecureCellFederationCounterpartyIncidentReportAmendmentStatusVerified || intakeResult.FederationCounterpartyIncidentReportAmendments[0].Bundle.Amendment.ID != amendmentID {
		t.Fatalf("expected one verified counterparty incident report amendment snapshot, got %+v", intakeResult.FederationCounterpartyIncidentReportAmendments)
	}

	counterpartyAmendments, err := service.ListFederationCounterpartyIncidentReportAmendments(ctx, SecureCellFederationCounterpartyIncidentReportAmendmentFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		Status:         SecureCellFederationCounterpartyIncidentReportAmendmentStatusVerified,
	})
	if err != nil {
		t.Fatalf("ListFederationCounterpartyIncidentReportAmendments failed: %v", err)
	}
	if len(counterpartyAmendments) != 1 || counterpartyAmendments[0].AmendmentID != amendmentID || counterpartyAmendments[0].ReportID != reportID || counterpartyAmendments[0].ReconciliationStatus != SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned {
		t.Fatalf("expected one aligned verified counterparty amendment summary, got %+v", counterpartyAmendments)
	}

	amendmentReconciliations, err := service.ListFederationIncidentReportAmendmentReconciliations(ctx, SecureCellFederationIncidentReportAmendmentReconciliationFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		IncidentID:     incidentID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportAmendmentReconciliations failed: %v", err)
	}
	if len(amendmentReconciliations) != 1 || amendmentReconciliations[0].LocalAmendmentID != amendmentID || amendmentReconciliations[0].LocalReportID != reportID || amendmentReconciliations[0].Status != SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned {
		t.Fatalf("expected one aligned incident report amendment reconciliation summary, got %+v", amendmentReconciliations)
	}

	trustPack, err := service.BuildFederationOrganizationTrustPack(ctx, created.CellID, organizationID, SecureCellFederationOrganizationTrustPackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationOrganizationTrustPack failed: %v", err)
	}
	if len(trustPack.CounterpartyIncidentReportAmendments) != 1 || trustPack.CounterpartyIncidentReportAmendments[0].AmendmentID != amendmentID || trustPack.CounterpartyIncidentReportAmendments[0].ReconciliationStatus != SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned {
		t.Fatalf("expected trust pack to include aligned imported incident report amendment summary, got %+v", trustPack.CounterpartyIncidentReportAmendments)
	}
	if len(trustPack.IncidentReportAmendments) != 1 || trustPack.IncidentReportAmendments[0].AmendmentID != amendmentID || trustPack.IncidentReportAmendments[0].Status != SecureCellFederationIncidentReportAmendmentStatusAcknowledged {
		t.Fatalf("expected trust pack to include acknowledged local incident report amendment summary, got %+v", trustPack.IncidentReportAmendments)
	}
	if len(trustPack.IncidentReportAmendmentReconciliations) != 1 || trustPack.IncidentReportAmendmentReconciliations[0].LocalAmendmentID != amendmentID || trustPack.IncidentReportAmendmentReconciliations[0].Status != SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned {
		t.Fatalf("expected trust pack to include aligned incident report amendment reconciliation summary, got %+v", trustPack.IncidentReportAmendmentReconciliations)
	}
	if !controlLedgerHasControl(intakeResult.ControlLedger, "CELL-FED-09") {
		t.Fatalf("expected control ledger to include reciprocal incident report amendment control, got %+v", intakeResult.ControlLedger.Controls)
	}

	comparisonKey := amendmentReconciliations[0].ComparisonKey
	acknowledgedReconciliation, err := service.AcknowledgeFederationIncidentReportAmendmentReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentReportAmendmentReconciliationAcknowledgeRequest{
		ActorDID: owner.AgentID(),
		Reason:   "reviewed and accepted reciprocal amendment alignment",
		Metadata: map[string]string{"ticket": "FED-REPORT-AMEND-RECON-ACK-01"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeFederationIncidentReportAmendmentReconciliation failed: %v", err)
	}

	disputedReconciliation, err := service.DisputeFederationIncidentReportAmendmentReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentReportAmendmentReconciliationDisputeRequest{
		ActorDID:    owner.AgentID(),
		Reason:      "capture bilateral amendment review challenge for auditor traceability",
		Divergences: []string{"counterparty amendment requires enhanced bilateral correction notes"},
		Metadata:    map[string]string{"ticket": "FED-REPORT-AMEND-RECON-DISPUTE-01"},
	})
	if err != nil {
		t.Fatalf("DisputeFederationIncidentReportAmendmentReconciliation failed: %v", err)
	}

	reconciliationsAfterDispute, err := service.ListFederationIncidentReportAmendmentReconciliations(ctx, SecureCellFederationIncidentReportAmendmentReconciliationFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportAmendmentReconciliations after dispute failed: %v", err)
	}
	if len(reconciliationsAfterDispute) != 1 || reconciliationsAfterDispute[0].LastReviewedAt == nil {
		t.Fatalf("expected one disputed amendment reconciliation with review timestamp, got %+v", reconciliationsAfterDispute)
	}
	ackOverdueAt := reconciliationsAfterDispute[0].LastReviewedAt.UTC().Add(secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAckSLA + time.Hour)
	overdueAmendmentReconciliations, err := service.ListOverdueFederationIncidentReportAmendmentReconciliations(ctx, SecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter{
		CellID:            created.CellID,
		OrganizationID:    organizationID,
		ComparisonKey:     comparisonKey,
		ReviewStatus:      SecureCellFederationIncidentReportReviewStatusDisputed,
		AttestationStatus: SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested,
		Before:            &ackOverdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentReportAmendmentReconciliations failed: %v", err)
	}
	if len(overdueAmendmentReconciliations) != 1 || overdueAmendmentReconciliations[0].AutomationAction != "escalate_counterparty" {
		t.Fatalf("expected one overdue amendment reconciliation queued for escalation, got %+v", overdueAmendmentReconciliations)
	}

	sweepActor := "did:aethelred:automation-sweeper"
	amendmentSweep, err := service.SweepFederationIncidentReportAmendmentReconciliations(ctx, ackOverdueAt, SecureCellLifecycleRequest{
		ActorDID: sweepActor,
		Reason:   "automated amendment reconciliation escalation sweep",
		Metadata: map[string]string{"ticket": "FED-REPORT-AMEND-RECON-SWEEP-01"},
	})
	if err != nil {
		t.Fatalf("SweepFederationIncidentReportAmendmentReconciliations failed: %v", err)
	}
	if amendmentSweep.ReconciliationsEscalated != 1 {
		t.Fatalf("expected one escalated amendment reconciliation, got %+v", amendmentSweep)
	}

	automationActions, err := service.ListFederationIncidentReportAmendmentReconciliationAutomationActions(ctx, SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportAmendmentReconciliationAutomationActions failed: %v", err)
	}
	if len(automationActions) != 1 || automationActions[0].Action != "secure_cell.federation_incident_report_amendment_reconciliation_escalated" || automationActions[0].AutomatedActor != sweepActor {
		t.Fatalf("expected one automated escalation action, got %+v", automationActions)
	}

	acknowledgedCounterpartyReconciliation, err := service.AcknowledgeFederationIncidentReportAmendmentReconciliationDispute(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAcknowledgeRequest{
		ActorDID:              participantB.AgentID(),
		CounterpartyReference: "counterparty-amendment-dispute-ack-0001",
		Reason:                "counterparty acknowledged bilateral amendment dispute",
		Metadata:              map[string]string{"ticket": "FED-REPORT-AMEND-RECON-ATT-ACK-01"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeFederationIncidentReportAmendmentReconciliationDispute failed: %v", err)
	}

	correctedReconciliation, err := service.AttestFederationIncidentReportAmendmentReconciliationCorrection(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentReportAmendmentReconciliationCorrectionAttestationRequest{
		ActorDID:               participantB.AgentID(),
		CounterpartySnapshotID: amendmentReconciliations[0].CounterpartySnapshotID,
		CounterpartyReference:  "counterparty-amendment-correction-0001",
		Reason:                 "counterparty attested corrected amendment package",
		Metadata:               map[string]string{"ticket": "FED-REPORT-AMEND-RECON-ATT-CORRECT-01"},
	})
	if err != nil {
		t.Fatalf("AttestFederationIncidentReportAmendmentReconciliationCorrection failed: %v", err)
	}

	resolvedCounterpartyReconciliation, err := service.AttestFederationIncidentReportAmendmentReconciliationResolution(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentReportAmendmentReconciliationResolutionAttestationRequest{
		ActorDID:              participantB.AgentID(),
		CounterpartyReference: "counterparty-amendment-resolution-0001",
		Reason:                "counterparty attested bilateral amendment dispute resolution",
		Metadata:              map[string]string{"ticket": "FED-REPORT-AMEND-RECON-ATT-RESOLVE-01"},
	})
	if err != nil {
		t.Fatalf("AttestFederationIncidentReportAmendmentReconciliationResolution failed: %v", err)
	}

	attestations, err := service.ListFederationIncidentReportAmendmentReconciliationCounterpartyAttestations(ctx, SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportAmendmentReconciliationCounterpartyAttestations failed: %v", err)
	}
	if len(attestations) != 3 || attestations[0].AttestationStatus != SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved || attestations[0].Attestation != SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationResolve {
		t.Fatalf("expected three amendment reconciliation counterparty attestations ending in resolution, got %+v", attestations)
	}

	resolvedReconciliation, err := service.ResolveFederationIncidentReportAmendmentReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentReportAmendmentReconciliationResolveRequest{
		ActorDID: owner.AgentID(),
		Reason:   "bilateral amendment review completed and dispute closed",
		Metadata: map[string]string{"ticket": "FED-REPORT-AMEND-RECON-RESOLVE-01"},
	})
	if err != nil {
		t.Fatalf("ResolveFederationIncidentReportAmendmentReconciliation failed: %v", err)
	}

	reconciliationActions, err := service.ListFederationIncidentReportAmendmentReconciliationActions(ctx, SecureCellFederationIncidentReportAmendmentReconciliationActionFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentReportAmendmentReconciliationActions failed: %v", err)
	}
	if len(reconciliationActions) != 3 || reconciliationActions[0].Action != SecureCellFederationIncidentReportAmendmentReconciliationActionResolve || reconciliationActions[0].ReviewStatus != SecureCellFederationIncidentReportReviewStatusResolved {
		t.Fatalf("expected three governed amendment reconciliation actions ending in resolve, got %+v", reconciliationActions)
	}

	reconciliationBundle, err := service.BuildFederationIncidentReportAmendmentReconciliationBundle(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentReportAmendmentReconciliationBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentReportAmendmentReconciliationBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentReportAmendmentReconciliationBundle(reconciliationBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentReportAmendmentReconciliationBundle failed: %v", err)
	}
	if reconciliationBundle.Reconciliation.ReviewStatus != SecureCellFederationIncidentReportReviewStatusResolved || len(reconciliationBundle.Actions) != 3 || len(reconciliationBundle.Attestations) != 3 {
		t.Fatalf("expected resolved amendment reconciliation bundle with three actions, got %+v", reconciliationBundle.Reconciliation)
	}

	reviewedTrustPack, err := service.BuildFederationOrganizationTrustPack(ctx, created.CellID, organizationID, SecureCellFederationOrganizationTrustPackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationOrganizationTrustPack after amendment reconciliation review failed: %v", err)
	}
	if len(reviewedTrustPack.IncidentReportAmendmentReconciliations) != 1 || reviewedTrustPack.IncidentReportAmendmentReconciliations[0].ReviewStatus != SecureCellFederationIncidentReportReviewStatusResolved || reviewedTrustPack.IncidentReportAmendmentReconciliations[0].ReviewActionCount != 3 || reviewedTrustPack.IncidentReportAmendmentReconciliations[0].CounterpartyAttestationStatus != SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved || reviewedTrustPack.IncidentReportAmendmentReconciliations[0].CounterpartyAttestationCount != 3 {
		t.Fatalf("expected trust pack amendment reconciliation review state to be resolved with three actions, got %+v", reviewedTrustPack.IncidentReportAmendmentReconciliations)
	}

	casePack, err := service.BuildFederationIncidentCasePack(ctx, created.CellID, localResponseID, SecureCellFederationIncidentCasePackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentCasePack failed: %v", err)
	}
	if err := VerifyFederationIncidentCasePack(casePack); err != nil {
		t.Fatalf("VerifyFederationIncidentCasePack failed: %v", err)
	}
	if casePack.ResponseSummary.ResponseID != localResponseID || len(casePack.ReportBundles) != 1 || len(casePack.AmendmentBundles) != 1 || len(casePack.AmendmentReconciliationBundles) != 1 || len(casePack.AmendmentReconciliationAttestations) != 3 || len(casePack.ResponseActions) == 0 {
		t.Fatalf("expected signed incident case pack with bundled filing governance artifacts, got %+v", casePack)
	}
	if len(casePack.ReportReconciliationAutomationActions) != 0 || len(casePack.AmendmentReconciliationAutomationActions) != 1 {
		t.Fatalf("expected case pack to include amendment automation trail and no report automation actions, got report=%+v amendment=%+v", casePack.ReportReconciliationAutomationActions, casePack.AmendmentReconciliationAutomationActions)
	}
	if !controlLedgerHasControl(resolvedReconciliation.ControlLedger, "CELL-FED-10") {
		t.Fatalf("expected control ledger to include bilateral amendment reconciliation control, got %+v", resolvedReconciliation.ControlLedger.Controls)
	}
	if !controlLedgerHasControl(resolvedReconciliation.ControlLedger, "CELL-FED-11") {
		t.Fatalf("expected control ledger to include bilateral amendment dispute coordination control, got %+v", resolvedReconciliation.ControlLedger.Controls)
	}
	if len(acknowledgedReconciliation.Transitions) == 0 || len(disputedReconciliation.Transitions) == 0 || len(acknowledgedCounterpartyReconciliation.Transitions) == 0 || len(correctedReconciliation.Transitions) == 0 || len(resolvedCounterpartyReconciliation.Transitions) == 0 || len(resolvedReconciliation.Transitions) == 0 {
		t.Fatalf("expected amendment reconciliation lifecycle mutations to append transitions")
	}
}

func TestService_FederationIncidentDirectiveExtensionCommitteeAutomation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Directive Extension Committee Automation Cell",
		Purpose:       "governed committee automation over directive exceptions",
		Resource:      "cell:federation-directive-extension-committee-automation",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Committee Automation Room",
		Purpose:         "coordinate directive exception automation",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "open committee automation session",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-AUTO-SESSION-01"},
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[len(started.Sessions)-1]

	sponsorOfRecord := secureCellFederationSponsor(participantB)
	organizationName := secureCellFederationOrganizationName(participantB)
	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  sponsorOfRecord,
		OrganizationName: organizationName,
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite counterparty committee participant",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-AUTO-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "counterparty joins committee automation room",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-AUTO-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	organizationID := accepted.FederationContracts[0].OrganizationID
	contractID := accepted.FederationContracts[0].ID

	published, err := service.PublishFederationIncident(ctx, created.CellID, organizationID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityHigh,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Committee automation incident",
		Description:              "The local organization wants committee-aware directive exception automation.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: false,
		Reason:                   "publish committee automation incident",
		Metadata:                 map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-AUTO-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local response, got %+v", responses)
	}

	dueAt := time.Now().UTC().Add(2 * time.Hour)
	if _, err := service.CreateFederationIncidentDirective(ctx, created.CellID, localResponseID, SecureCellFederationIncidentDirectiveCreateRequest{
		ActorDID:      owner.AgentID(),
		DirectiveType: "counterparty_evidence_request",
		Title:         "Provide counterparty evidence package",
		Summary:       "Counterparty must provide an evidence package for bilateral incident review.",
		Description:   "Provide the scoped evidence package, timeline, and remediation artifacts for the bilateral incident response.",
		Priority:      SecureCellFederationIncidentDirectivePriorityHigh,
		AssigneeParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		ReviewerParty: SecureCellFederationIncidentResponsePartyLocalOrg,
		AssigneeDID:   participantB.AgentID(),
		ReviewerDID:   owner.AgentID(),
		EvidenceIDs:   []string{incidentID},
		DueAt:         &dueAt,
		Reason:        "issue bilateral evidence work order",
		Metadata:      map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-AUTO-ISSUE-01"},
	}); err != nil {
		t.Fatalf("CreateFederationIncidentDirective failed: %v", err)
	}

	directives, err := service.ListFederationIncidentDirectives(ctx, SecureCellFederationIncidentDirectiveFilter{
		CellID:     created.CellID,
		ResponseID: localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectives failed: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected one directive, got %+v", directives)
	}
	directiveID := directives[0].DirectiveID

	proposedDueAt := dueAt.Add(4 * time.Hour)
	if _, err := service.RequestFederationIncidentDirectiveExtension(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveExtensionRequest{
		ActorDID:                   participantB.AgentID(),
		RequestingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                    "Counterparty needs longer evidence collection window",
		Description:                "The counterparty needs additional time to gather the full evidence package for bilateral review.",
		EvidenceIDs:                []string{incidentID},
		ProposedDueAt:              &proposedDueAt,
		ReviewApprovalThreshold:    2,
		EligibleReviewerDIDs:       []string{owner.AgentID()},
		DisputeResolutionThreshold: 2,
		EligibleResolverDIDs:       []string{owner.AgentID()},
		Reason:                     "request committee reviewed directive extension",
		Metadata:                   map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-AUTO-REQUEST-01"},
	}); err != nil {
		t.Fatalf("RequestFederationIncidentDirectiveExtension failed: %v", err)
	}

	extensions, err := service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions failed: %v", err)
	}
	if len(extensions) != 1 {
		t.Fatalf("expected one extension, got %+v", extensions)
	}
	extensionID := extensions[0].ExtensionID
	reviewOverdueAt := extensions[0].CreatedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionReviewSLA + time.Hour)

	overdueExtensions, err := service.ListOverdueFederationIncidentDirectiveExtensions(ctx, SecureCellOverdueFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		Before:      &reviewOverdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentDirectiveExtensions review failed: %v", err)
	}
	if len(overdueExtensions) != 1 || overdueExtensions[0].AutomationAction != "delegate_review_committee" || overdueExtensions[0].CommitteeThreshold != 2 || overdueExtensions[0].CommitteeMemberCount != 1 || overdueExtensions[0].CommitteeMissingQuorumCount != 2 {
		t.Fatalf("expected committee-aware overdue review posture, got %+v", overdueExtensions)
	}

	if _, err := service.SweepFederationIncidentDirectiveExtensions(ctx, reviewOverdueAt, SecureCellLifecycleRequest{
		ActorDID: "did:aethelred:directive-extension-committee-sweeper",
		Reason:   "automated directive extension committee review sweep",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-AUTO-SWEEP-REVIEW-01"},
	}); err != nil {
		t.Fatalf("SweepFederationIncidentDirectiveExtensions review failed: %v", err)
	}

	automationActions, err := service.ListFederationIncidentDirectiveExtensionAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAutomationActionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAutomationActions review failed: %v", err)
	}
	if len(automationActions) == 0 || automationActions[0].Action != "secure_cell.federation_incident_directive_extension_review_delegated" || automationActions[0].CommitteeThreshold != 2 || automationActions[0].CommitteeMissingQuorumCount != 2 || automationActions[0].TargetDID == "" {
		t.Fatalf("expected automated committee review delegation, got %+v", automationActions)
	}

	directive, err := service.GetFederationIncidentDirective(ctx, created.CellID, directiveID)
	if err != nil {
		t.Fatalf("GetFederationIncidentDirective after review sweep failed: %v", err)
	}
	if len(directive.Extensions) != 1 || len(directive.Extensions[0].ReviewDelegations) != 1 || directive.Extensions[0].ReviewDelegations[0].ToActorDID == "" {
		t.Fatalf("expected delegated review committee member after sweep, got %+v", directive.Extensions)
	}
	delegatedReviewDID := directive.Extensions[0].ReviewDelegations[0].ToActorDID

	if _, err := service.ApproveFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionApproveRequest{
		ActorDID:            owner.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local committee vote one approved extension",
		DecisionDescription: "The first committee reviewer approved the exception but the threshold is not met yet.",
		EvidenceIDs:         []string{directiveID},
		Reason:              "record first committee approval vote",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-AUTO-APPROVE-01"},
	}); err != nil {
		t.Fatalf("ApproveFederationIncidentDirectiveExtension first vote failed: %v", err)
	}
	if _, err := service.ApproveFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionApproveRequest{
		ActorDID:            delegatedReviewDID,
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local committee approved extension",
		DecisionDescription: "The delegated reviewer completed the threshold and approved the extension.",
		EvidenceIDs:         []string{directiveID},
		Reason:              "record second committee approval vote",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-AUTO-APPROVE-02"},
	}); err != nil {
		t.Fatalf("ApproveFederationIncidentDirectiveExtension second vote failed: %v", err)
	}

	if _, err := service.DisputeFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionDisputeRequest{
		ActorDID:         participantB.AgentID(),
		ChallengingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:          "Counterparty challenges approved extension",
		Description:      "The counterparty challenged the approved exception and requested local dispute resolution.",
		EvidenceIDs:      []string{directiveID},
		Reason:           "open committee dispute resolution",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-AUTO-DISPUTE-01"},
	}); err != nil {
		t.Fatalf("DisputeFederationIncidentDirectiveExtension failed: %v", err)
	}

	disputes, err := service.ListFederationIncidentDirectiveExtensionDisputes(ctx, SecureCellFederationIncidentDirectiveExtensionDisputeFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionDisputes failed: %v", err)
	}
	if len(disputes) != 1 {
		t.Fatalf("expected one dispute, got %+v", disputes)
	}
	disputeID := disputes[0].DisputeID
	resolutionOverdueAt := disputes[0].CreatedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionResolutionSLA + time.Hour)

	overdueExtensions, err = service.ListOverdueFederationIncidentDirectiveExtensions(ctx, SecureCellOverdueFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		Before:      &resolutionOverdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentDirectiveExtensions dispute failed: %v", err)
	}
	if len(overdueExtensions) != 1 || overdueExtensions[0].AutomationAction != "delegate_resolution_committee" || overdueExtensions[0].PendingDisputeID != disputeID || overdueExtensions[0].CommitteeThreshold != 2 || overdueExtensions[0].CommitteeMemberCount != 1 || overdueExtensions[0].CommitteeMissingQuorumCount != 2 {
		t.Fatalf("expected committee-aware overdue dispute posture, got %+v", overdueExtensions)
	}

	if _, err := service.SweepFederationIncidentDirectiveExtensions(ctx, resolutionOverdueAt, SecureCellLifecycleRequest{
		ActorDID: "did:aethelred:directive-extension-committee-sweeper",
		Reason:   "automated directive extension committee dispute sweep",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-COMMITTEE-AUTO-SWEEP-DISPUTE-01"},
	}); err != nil {
		t.Fatalf("SweepFederationIncidentDirectiveExtensions dispute failed: %v", err)
	}

	automationActions, err = service.ListFederationIncidentDirectiveExtensionAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAutomationActionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAutomationActions dispute failed: %v", err)
	}
	var sawResolutionDelegation bool
	for _, item := range automationActions {
		if item.Action == "secure_cell.federation_incident_directive_extension_dispute_resolution_delegated" {
			sawResolutionDelegation = item.TargetDID != "" && item.CommitteeThreshold == 2 && item.CommitteeMissingQuorumCount == 2
			break
		}
	}
	if !sawResolutionDelegation {
		t.Fatalf("expected automated committee dispute-resolution delegation, got %+v", automationActions)
	}

	bundle, err := service.BuildFederationIncidentDirectiveBundle(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveBundle(bundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveBundle failed: %v", err)
	}
	if len(bundle.ExtensionSummaries) != 1 || bundle.ExtensionSummaries[0].ReviewCommitteeMemberCount < 2 || bundle.ExtensionSummaries[0].ReviewRecordedVoteCount != 2 {
		t.Fatalf("expected directive bundle committee summary projection, got %+v", bundle.ExtensionSummaries)
	}
	if len(bundle.ExtensionAutomationActions) < 2 {
		t.Fatalf("expected directive bundle automation history, got %+v", bundle.ExtensionAutomationActions)
	}

	casePack, err := service.BuildFederationIncidentCasePack(ctx, created.CellID, localResponseID, SecureCellFederationIncidentCasePackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentCasePack failed: %v", err)
	}
	if err := VerifyFederationIncidentCasePack(casePack); err != nil {
		t.Fatalf("VerifyFederationIncidentCasePack failed: %v", err)
	}
	if len(casePack.DirectiveExtensionSummaries) != 1 || casePack.DirectiveExtensionSummaries[0].ReviewCommitteeMemberCount < 2 || len(casePack.DirectiveExtensionAutomationActions) < 2 {
		t.Fatalf("expected case pack committee projections and automation history, got summaries=%+v actions=%+v", casePack.DirectiveExtensionSummaries, casePack.DirectiveExtensionAutomationActions)
	}
}

func TestService_FederationIncidentDirectiveExtensionAppealGovernance(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Directive Extension Appeal Cell",
		Purpose:       "govern bilateral directive extension appeal reviews",
		Resource:      "cell:federation-directive-extension-appeal",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Appeal Governance Room",
		Purpose:         "coordinate bilateral directive exception appeals",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "open appeal governance session",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-SESSION-01"},
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[len(started.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite counterparty appeal participant",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "counterparty joins appeal governance room",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	organizationID := accepted.FederationContracts[0].OrganizationID
	contractID := accepted.FederationContracts[0].ID

	published, err := service.PublishFederationIncident(ctx, created.CellID, organizationID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityHigh,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Appeal governance incident",
		Description:              "The local organization wants bilateral appeal-board governance for directive deadline exceptions.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: false,
		Reason:                   "publish appeal governance incident",
		Metadata:                 map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local response, got %+v", responses)
	}

	dueAt := time.Now().UTC().Add(2 * time.Hour)
	if _, err := service.CreateFederationIncidentDirective(ctx, created.CellID, localResponseID, SecureCellFederationIncidentDirectiveCreateRequest{
		ActorDID:      owner.AgentID(),
		DirectiveType: "counterparty_evidence_request",
		Title:         "Provide counterparty evidence package",
		Summary:       "Counterparty must provide an evidence package for bilateral incident review.",
		Description:   "Provide the scoped evidence package, timeline, and remediation artifacts for the bilateral incident response.",
		Priority:      SecureCellFederationIncidentDirectivePriorityHigh,
		AssigneeParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		ReviewerParty: SecureCellFederationIncidentResponsePartyLocalOrg,
		AssigneeDID:   participantB.AgentID(),
		ReviewerDID:   owner.AgentID(),
		EvidenceIDs:   []string{incidentID},
		DueAt:         &dueAt,
		Reason:        "issue bilateral evidence work order",
		Metadata:      map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-ISSUE-01"},
	}); err != nil {
		t.Fatalf("CreateFederationIncidentDirective failed: %v", err)
	}

	directives, err := service.ListFederationIncidentDirectives(ctx, SecureCellFederationIncidentDirectiveFilter{
		CellID:     created.CellID,
		ResponseID: localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectives failed: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected one directive, got %+v", directives)
	}
	directiveID := directives[0].DirectiveID

	proposedDueAt := dueAt.Add(4 * time.Hour)
	if _, err := service.RequestFederationIncidentDirectiveExtension(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveExtensionRequest{
		ActorDID:                   participantB.AgentID(),
		RequestingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                    "Counterparty needs longer evidence collection window",
		Description:                "The counterparty needs additional time to gather the full evidence package for bilateral review.",
		EvidenceIDs:                []string{incidentID},
		ProposedDueAt:              &proposedDueAt,
		ReviewApprovalThreshold:    1,
		EligibleReviewerDIDs:       []string{owner.AgentID()},
		DisputeResolutionThreshold: 1,
		EligibleResolverDIDs:       []string{owner.AgentID()},
		Reason:                     "request directive extension before appeal",
		Metadata:                   map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-REQUEST-01"},
	}); err != nil {
		t.Fatalf("RequestFederationIncidentDirectiveExtension failed: %v", err)
	}

	extensions, err := service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions failed: %v", err)
	}
	if len(extensions) != 1 {
		t.Fatalf("expected one extension, got %+v", extensions)
	}
	extensionID := extensions[0].ExtensionID

	if _, err := service.RejectFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionRejectRequest{
		ActorDID:            owner.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local org rejected the extension",
		DecisionDescription: "The local organization rejected the exception request.",
		EvidenceIDs:         []string{directiveID},
		Reason:              "reject directive extension before dispute",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-REJECT-01"},
	}); err != nil {
		t.Fatalf("RejectFederationIncidentDirectiveExtension failed: %v", err)
	}

	if _, err := service.DisputeFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionDisputeRequest{
		ActorDID:         participantB.AgentID(),
		ChallengingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:          "Counterparty disputes rejected extension",
		Description:      "The counterparty reopened the rejected extension for bilateral review.",
		EvidenceIDs:      []string{directiveID},
		Reason:           "open directive extension dispute before appeal",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-DISPUTE-01"},
	}); err != nil {
		t.Fatalf("DisputeFederationIncidentDirectiveExtension failed: %v", err)
	}

	disputes, err := service.ListFederationIncidentDirectiveExtensionDisputes(ctx, SecureCellFederationIncidentDirectiveExtensionDisputeFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionDisputes failed: %v", err)
	}
	if len(disputes) != 1 {
		t.Fatalf("expected one dispute, got %+v", disputes)
	}
	disputeID := disputes[0].DisputeID

	if _, err := service.ResolveFederationIncidentDirectiveExtensionDispute(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionDisputeResolveRequest{
		ActorDID:              owner.AgentID(),
		RespondingParty:       SecureCellFederationIncidentResponsePartyLocalOrg,
		Resolution:            SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold,
		ResolutionSummary:     "Local org upheld the rejection",
		ResolutionDescription: "The local organization upheld the rejection during dispute resolution.",
		EvidenceIDs:           []string{directiveID},
		Reason:                "resolve dispute before appeal",
		Metadata:              map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RESOLVE-01"},
	}); err != nil {
		t.Fatalf("ResolveFederationIncidentDirectiveExtensionDispute failed: %v", err)
	}

	if _, err := service.AppealFederationIncidentDirectiveExtensionDispute(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionAppealRequest{
		ActorDID:                  participantB.AgentID(),
		AppealingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                   "Counterparty appeals upheld rejection",
		Description:               "The counterparty escalated the upheld rejection to the bilateral appeal board.",
		EvidenceIDs:               []string{directiveID},
		BoardReviewThreshold:      2,
		EligibleBoardReviewerDIDs: []string{owner.AgentID()},
		Reason:                    "open directive extension appeal board review",
		Metadata:                  map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-OPEN-01"},
	}); err != nil {
		t.Fatalf("AppealFederationIncidentDirectiveExtensionDispute failed: %v", err)
	}

	appeals, err := service.ListFederationIncidentDirectiveExtensionAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
		DisputeID:   disputeID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppeals failed: %v", err)
	}
	if len(appeals) != 1 || appeals[0].Status != SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview || appeals[0].BoardReviewThreshold != 2 {
		t.Fatalf("expected one pending appeal with threshold 2, got %+v", appeals)
	}
	appealID := appeals[0].AppealID

	if _, err := service.RuleFederationIncidentDirectiveExtensionAppeal(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealRulingRequest{
		ActorDID:          owner.AgentID(),
		BoardParty:        SecureCellFederationIncidentResponsePartyLocalOrg,
		Ruling:            SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify,
		RulingSummary:     "Local board vote one ratified rejection",
		RulingDescription: "The first local board reviewer ratified the rejection but the threshold is not met yet.",
		EvidenceIDs:       []string{directiveID},
		Reason:            "record first appeal board vote",
		Metadata:          map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RULE-01"},
	}); err != nil {
		t.Fatalf("RuleFederationIncidentDirectiveExtensionAppeal first vote failed: %v", err)
	}

	if _, err := service.DelegateFederationIncidentDirectiveExtensionAppealReview(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
		ActorDID:  owner.AgentID(),
		TargetDID: participantA.AgentID(),
		Reason:    "delegate second appeal board review",
		Metadata:  map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-DELEGATE-01"},
	}); err != nil {
		t.Fatalf("DelegateFederationIncidentDirectiveExtensionAppealReview failed: %v", err)
	}

	if _, err := service.RuleFederationIncidentDirectiveExtensionAppeal(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealRulingRequest{
		ActorDID:          participantA.AgentID(),
		BoardParty:        SecureCellFederationIncidentResponsePartyLocalOrg,
		Ruling:            SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify,
		RulingSummary:     "Local board ratified rejection",
		RulingDescription: "The delegated reviewer completed the appeal-board threshold and ratified the rejection.",
		EvidenceIDs:       []string{directiveID},
		Reason:            "record second appeal board vote",
		Metadata:          map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RULE-02"},
	}); err != nil {
		t.Fatalf("RuleFederationIncidentDirectiveExtensionAppeal second vote failed: %v", err)
	}

	if _, err := service.AcknowledgeFederationIncidentDirectiveExtensionAppealEnforcement(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest{
		ActorDID:           participantB.AgentID(),
		AcknowledgingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:            "Counterparty acknowledged final appeal ruling",
		Description:        "The counterparty accepted the ratified rejection for enforcement.",
		EvidenceIDs:        []string{directiveID},
		Reason:             "acknowledge final appeal ruling",
		Metadata:           map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-ACK-01"},
	}); err != nil {
		t.Fatalf("AcknowledgeFederationIncidentDirectiveExtensionAppealEnforcement failed: %v", err)
	}

	appeals, err = service.ListFederationIncidentDirectiveExtensionAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealFilter{
		CellID:   created.CellID,
		AppealID: appealID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppeals final failed: %v", err)
	}
	if len(appeals) != 1 || appeals[0].Status != SecureCellFederationIncidentDirectiveExtensionAppealStatusEnforcementAcknowledged || appeals[0].RatifyVoteCount != 2 || appeals[0].BoardDelegationCount != 1 {
		t.Fatalf("expected acknowledged appeal with ratify quorum and delegation, got %+v", appeals)
	}

	appealBundle, err := service.BuildFederationIncidentDirectiveExtensionAppealBundle(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveExtensionAppealBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveExtensionAppealBundle(appealBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveExtensionAppealBundle failed: %v", err)
	}
	if appealBundle.AppealSummary.AppealID != appealID || appealBundle.AppealSummary.EnforcementAcknowledgedBy != participantB.AgentID() {
		t.Fatalf("expected verified appeal bundle projection, got %+v", appealBundle.AppealSummary)
	}

	directiveBundle, err := service.BuildFederationIncidentDirectiveBundle(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveBundle(directiveBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveBundle failed: %v", err)
	}
	if len(directiveBundle.ExtensionAppeals) != 1 || directiveBundle.ExtensionAppeals[0].AppealID != appealID {
		t.Fatalf("expected directive bundle appeal projection, got %+v", directiveBundle.ExtensionAppeals)
	}

	casePack, err := service.BuildFederationIncidentCasePack(ctx, created.CellID, localResponseID, SecureCellFederationIncidentCasePackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentCasePack failed: %v", err)
	}
	if err := VerifyFederationIncidentCasePack(casePack); err != nil {
		t.Fatalf("VerifyFederationIncidentCasePack failed: %v", err)
	}
	if len(casePack.DirectiveExtensionAppealBundles) != 1 || casePack.DirectiveExtensionAppealBundles[0].AppealSummary.AppealID != appealID {
		t.Fatalf("expected case pack appeal bundle projection, got %+v", casePack.DirectiveExtensionAppealBundles)
	}
}

func TestService_FederationIncidentDirectiveExtensionAppealRecusalAndRehearing(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Directive Extension Appeal Recusal Cell",
		Purpose:       "govern bilateral directive extension appeal recusals and rehearings",
		Resource:      "cell:federation-directive-extension-appeal-recusal",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Appeal Recusal Room",
		Purpose:         "coordinate bilateral directive exception recusals and rehearings",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "open appeal recusal session",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-SESSION-01"},
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[len(started.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite counterparty recusal participant",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "counterparty joins recusal room",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	organizationID := accepted.FederationContracts[0].OrganizationID
	contractID := accepted.FederationContracts[0].ID

	published, err := service.PublishFederationIncident(ctx, created.CellID, organizationID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityHigh,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Appeal recusal incident",
		Description:              "The local organization wants governed board recusals and rehearings for directive exceptions.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: false,
		Reason:                   "publish appeal recusal incident",
		Metadata:                 map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local response, got %+v", responses)
	}

	dueAt := time.Now().UTC().Add(2 * time.Hour)
	if _, err := service.CreateFederationIncidentDirective(ctx, created.CellID, localResponseID, SecureCellFederationIncidentDirectiveCreateRequest{
		ActorDID:      owner.AgentID(),
		DirectiveType: "counterparty_evidence_request",
		Title:         "Provide counterparty evidence package",
		Summary:       "Counterparty must provide an evidence package for bilateral incident review.",
		Description:   "Provide the scoped evidence package, timeline, and remediation artifacts for the bilateral incident response.",
		Priority:      SecureCellFederationIncidentDirectivePriorityHigh,
		AssigneeParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		ReviewerParty: SecureCellFederationIncidentResponsePartyLocalOrg,
		AssigneeDID:   participantB.AgentID(),
		ReviewerDID:   owner.AgentID(),
		EvidenceIDs:   []string{incidentID},
		DueAt:         &dueAt,
		Reason:        "issue bilateral evidence work order",
		Metadata:      map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-ISSUE-01"},
	}); err != nil {
		t.Fatalf("CreateFederationIncidentDirective failed: %v", err)
	}

	directives, err := service.ListFederationIncidentDirectives(ctx, SecureCellFederationIncidentDirectiveFilter{
		CellID:     created.CellID,
		ResponseID: localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectives failed: %v", err)
	}
	directiveID := directives[0].DirectiveID

	proposedDueAt := dueAt.Add(4 * time.Hour)
	if _, err := service.RequestFederationIncidentDirectiveExtension(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveExtensionRequest{
		ActorDID:                   participantB.AgentID(),
		RequestingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                    "Counterparty needs longer evidence collection window",
		Description:                "The counterparty needs additional time to gather the full evidence package for bilateral review.",
		EvidenceIDs:                []string{incidentID},
		ProposedDueAt:              &proposedDueAt,
		ReviewApprovalThreshold:    1,
		EligibleReviewerDIDs:       []string{owner.AgentID()},
		DisputeResolutionThreshold: 1,
		EligibleResolverDIDs:       []string{owner.AgentID()},
		Reason:                     "request directive extension before recusal",
		Metadata:                   map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-REQUEST-01"},
	}); err != nil {
		t.Fatalf("RequestFederationIncidentDirectiveExtension failed: %v", err)
	}

	extensions, err := service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions failed: %v", err)
	}
	extensionID := extensions[0].ExtensionID

	if _, err := service.RejectFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionRejectRequest{
		ActorDID:            owner.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local org rejected the extension",
		DecisionDescription: "The local organization rejected the exception request.",
		EvidenceIDs:         []string{directiveID},
		Reason:              "reject directive extension before recusal",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-REJECT-01"},
	}); err != nil {
		t.Fatalf("RejectFederationIncidentDirectiveExtension failed: %v", err)
	}

	if _, err := service.DisputeFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionDisputeRequest{
		ActorDID:         participantB.AgentID(),
		ChallengingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:          "Counterparty disputes rejected extension",
		Description:      "The counterparty reopened the rejected extension for bilateral review.",
		EvidenceIDs:      []string{directiveID},
		Reason:           "open directive extension dispute before recusal",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-DISPUTE-01"},
	}); err != nil {
		t.Fatalf("DisputeFederationIncidentDirectiveExtension failed: %v", err)
	}

	disputes, err := service.ListFederationIncidentDirectiveExtensionDisputes(ctx, SecureCellFederationIncidentDirectiveExtensionDisputeFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionDisputes failed: %v", err)
	}
	disputeID := disputes[0].DisputeID

	if _, err := service.ResolveFederationIncidentDirectiveExtensionDispute(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionDisputeResolveRequest{
		ActorDID:              owner.AgentID(),
		RespondingParty:       SecureCellFederationIncidentResponsePartyLocalOrg,
		Resolution:            SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold,
		ResolutionSummary:     "Local org upheld the rejection",
		ResolutionDescription: "The local organization upheld the rejection during dispute resolution.",
		EvidenceIDs:           []string{directiveID},
		Reason:                "resolve dispute before recusal",
		Metadata:              map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-RESOLVE-01"},
	}); err != nil {
		t.Fatalf("ResolveFederationIncidentDirectiveExtensionDispute failed: %v", err)
	}

	if _, err := service.AppealFederationIncidentDirectiveExtensionDispute(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionAppealRequest{
		ActorDID:                  participantB.AgentID(),
		AppealingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                   "Counterparty appeals upheld rejection",
		Description:               "The counterparty escalated the upheld rejection to the bilateral appeal board.",
		EvidenceIDs:               []string{directiveID},
		BoardReviewThreshold:      1,
		EligibleBoardReviewerDIDs: []string{owner.AgentID(), participantA.AgentID()},
		Reason:                    "open directive extension appeal board review",
		Metadata:                  map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-OPEN-01"},
	}); err != nil {
		t.Fatalf("AppealFederationIncidentDirectiveExtensionDispute failed: %v", err)
	}

	appeals, err := service.ListFederationIncidentDirectiveExtensionAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealFilter{
		CellID:    created.CellID,
		DisputeID: disputeID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppeals failed: %v", err)
	}
	appealID := appeals[0].AppealID

	if _, err := service.RecuseFederationIncidentDirectiveExtensionAppealReview(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealRecuseRequest{
		ActorDID:    owner.AgentID(),
		BoardParty:  SecureCellFederationIncidentResponsePartyLocalOrg,
		Summary:     "Owner recused from appeal board review",
		Description: "The owner declared a reviewer conflict and stepped off the bilateral appeal board.",
		EvidenceIDs: []string{directiveID},
		Reason:      "recuse conflicted appeal reviewer",
		Metadata:    map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-ACT-01"},
	}); err != nil {
		t.Fatalf("RecuseFederationIncidentDirectiveExtensionAppealReview failed: %v", err)
	}

	recusals, err := service.ListFederationIncidentDirectiveExtensionAppealRecusals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealRecusalFilter{
		CellID:   created.CellID,
		AppealID: appealID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealRecusals failed: %v", err)
	}
	if len(recusals) != 1 || recusals[0].ActorDID != owner.AgentID() {
		t.Fatalf("expected one owner recusal, got %+v", recusals)
	}

	appeals, err = service.ListFederationIncidentDirectiveExtensionAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealFilter{
		CellID:   created.CellID,
		AppealID: appealID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppeals after recusal failed: %v", err)
	}
	if len(appeals) != 1 || appeals[0].BoardRecusalCount != 1 || appeals[0].BoardCommitteeMemberCount != 1 || appeals[0].AppealGeneration != 1 {
		t.Fatalf("expected recusal-aware appeal posture, got %+v", appeals)
	}

	if _, err := service.RuleFederationIncidentDirectiveExtensionAppeal(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealRulingRequest{
		ActorDID:          participantA.AgentID(),
		BoardParty:        SecureCellFederationIncidentResponsePartyLocalOrg,
		Ruling:            SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify,
		RulingSummary:     "Local board ratified rejection after recusal",
		RulingDescription: "The alternate local board reviewer ratified the rejection after the conflicted reviewer recused.",
		EvidenceIDs:       []string{directiveID},
		Reason:            "rule appeal after recusal",
		Metadata:          map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-RULE-01"},
	}); err != nil {
		t.Fatalf("RuleFederationIncidentDirectiveExtensionAppeal failed: %v", err)
	}

	if _, err := service.AcknowledgeFederationIncidentDirectiveExtensionAppealEnforcement(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest{
		ActorDID:           participantB.AgentID(),
		AcknowledgingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:            "Counterparty acknowledged final appeal ruling",
		Description:        "The counterparty accepted the ratified rejection for enforcement.",
		EvidenceIDs:        []string{directiveID},
		Reason:             "acknowledge final appeal ruling",
		Metadata:           map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-ACK-01"},
	}); err != nil {
		t.Fatalf("AcknowledgeFederationIncidentDirectiveExtensionAppealEnforcement failed: %v", err)
	}

	if _, err := service.RehearFederationIncidentDirectiveExtensionAppeal(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealRehearingRequest{
		ActorDID:                  participantB.AgentID(),
		AppealingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                   "Counterparty requested rehearing of ratified rejection",
		Description:               "The counterparty challenged the ratified ruling and requested a fresh board rehearing.",
		EvidenceIDs:               []string{directiveID},
		BoardReviewThreshold:      1,
		EligibleBoardReviewerDIDs: []string{owner.AgentID()},
		Reason:                    "request appeal rehearing after acknowledgement",
		Metadata:                  map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECUSE-REHEAR-01"},
	}); err != nil {
		t.Fatalf("RehearFederationIncidentDirectiveExtensionAppeal failed: %v", err)
	}

	rehearings, err := service.ListFederationIncidentDirectiveExtensionAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealFilter{
		CellID:         created.CellID,
		ParentAppealID: appealID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppeals rehearings failed: %v", err)
	}
	if len(rehearings) != 1 || rehearings[0].ParentAppealID != appealID || rehearings[0].AppealGeneration != 2 || rehearings[0].Status != SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview {
		t.Fatalf("expected one pending rehearing, got %+v", rehearings)
	}

	originalBundle, err := service.BuildFederationIncidentDirectiveExtensionAppealBundle(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveExtensionAppealBundle original failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveExtensionAppealBundle(originalBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveExtensionAppealBundle original failed: %v", err)
	}
	if len(originalBundle.Appeal.BoardRecusals) != 1 {
		t.Fatalf("expected original appeal bundle to preserve recusal, got %+v", originalBundle.Appeal.BoardRecusals)
	}

	ingested, err := service.IngestFederationIncidentDirectiveExtensionAppealBundle(ctx, created.CellID, organizationID, SecureCellFederationIncidentDirectiveExtensionAppealBundleIntakeRequest{
		ActorDID: owner.AgentID(),
		Bundle:   originalBundle,
		Reason:   "ingest reciprocal directive extension appeal bundle",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-BUNDLE-INTAKE-01"},
	})
	if err != nil {
		t.Fatalf("IngestFederationIncidentDirectiveExtensionAppealBundle failed: %v", err)
	}

	counterpartyAppeals, err := service.ListFederationCounterpartyIncidentDirectiveExtensionAppeals(ctx, SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		AppealID:       appealID,
	})
	if err != nil {
		t.Fatalf("ListFederationCounterpartyIncidentDirectiveExtensionAppeals failed: %v", err)
	}
	if len(counterpartyAppeals) != 1 || counterpartyAppeals[0].Status != SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusVerified || counterpartyAppeals[0].ReconciliationStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAligned {
		t.Fatalf("expected one verified aligned counterparty appeal snapshot, got %+v", counterpartyAppeals)
	}

	appealReconciliations, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliations(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		AppealID:       appealID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliations failed: %v", err)
	}
	if len(appealReconciliations) != 1 || appealReconciliations[0].Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAligned {
		t.Fatalf("expected one aligned appeal reconciliation, got %+v", appealReconciliations)
	}
	foundReciprocalControl := false
	for _, control := range ingested.ControlLedger.Controls {
		if control.ControlID == "CELL-FED-18" {
			foundReciprocalControl = true
			break
		}
	}
	if !foundReciprocalControl {
		t.Fatalf("expected ingested control ledger to include CELL-FED-18, got %+v", ingested.ControlLedger.Controls)
	}

	comparisonKey := appealReconciliations[0].ComparisonKey
	acknowledgedReconciliation, err := service.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeRequest{
		ActorDID: owner.AgentID(),
		Reason:   "reviewed and accepted reciprocal appeal alignment",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-ACK-01"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliation failed: %v", err)
	}
	if !controlLedgerHasControl(acknowledgedReconciliation.ControlLedger, "CELL-FED-19") {
		t.Fatalf("expected acknowledged reconciliation control ledger to include CELL-FED-19, got %+v", acknowledgedReconciliation.ControlLedger.Controls)
	}

	disputedReconciliation, err := service.DisputeFederationIncidentDirectiveExtensionAppealReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest{
		ActorDID:    owner.AgentID(),
		Reason:      "capture bilateral appeal review challenge for auditor traceability",
		Divergences: []string{"counterparty appeal requires additional bilateral review notes"},
		Metadata:    map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-DISPUTE-01"},
	})
	if err != nil {
		t.Fatalf("DisputeFederationIncidentDirectiveExtensionAppealReconciliation failed: %v", err)
	}

	reconciliationsAfterDispute, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliations(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliations after dispute failed: %v", err)
	}
	if len(reconciliationsAfterDispute) != 1 || reconciliationsAfterDispute[0].LastReviewedAt == nil {
		t.Fatalf("expected one disputed appeal reconciliation with review timestamp, got %+v", reconciliationsAfterDispute)
	}

	challengedReconciliation, err := service.ChallengeFederationIncidentDirectiveExtensionAppealReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest{
		ActorDID:                  owner.AgentID(),
		ChallengingParty:          SecureCellFederationIncidentResponsePartyLocalOrg,
		Summary:                   "Local org escalated reconciliation to bilateral challenge board",
		Description:               "The local organization requested a formal board review over the disputed appeal reconciliation posture.",
		EvidenceIDs:               []string{directiveID, comparisonKey},
		BoardReviewThreshold:      1,
		EligibleBoardReviewerDIDs: []string{participantB.AgentID()},
		Reason:                    "open bilateral appeal reconciliation challenge board review",
		Metadata:                  map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-01"},
	})
	if err != nil {
		t.Fatalf("ChallengeFederationIncidentDirectiveExtensionAppealReconciliation failed: %v", err)
	}

	ruledChallengeReconciliation, err := service.RuleFederationIncidentDirectiveExtensionAppealReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest{
		ActorDID:          participantB.AgentID(),
		BoardParty:        SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Ruling:            SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify,
		RulingSummary:     "Counterparty board ratified disputed reconciliation",
		RulingDescription: "The counterparty board ratified the disputed reconciliation posture after formal bilateral challenge review.",
		EvidenceIDs:       []string{directiveID, comparisonKey},
		Reason:            "record bilateral appeal reconciliation challenge board ruling",
		Metadata:          map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-RULE-01"},
	})
	if err != nil {
		t.Fatalf("RuleFederationIncidentDirectiveExtensionAppealReconciliation failed: %v", err)
	}

	challenges, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
		Status:        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusRatified,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges failed: %v", err)
	}
	if len(challenges) != 1 || challenges[0].ChallengeStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusRatified || challenges[0].BoardRecordedVoteCount != 1 || challenges[0].RatifyVoteCount != 1 {
		t.Fatalf("expected one ratified appeal reconciliation challenge, got %+v", challenges)
	}

	challengeActions, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeActions failed: %v", err)
	}
	if len(challengeActions) != 2 || challengeActions[0].Action != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRuled {
		t.Fatalf("expected two appeal reconciliation challenge actions ending in rule, got %+v", challengeActions)
	}

	if !controlLedgerHasControl(challengedReconciliation.ControlLedger, "CELL-FED-22") || !controlLedgerHasControl(ruledChallengeReconciliation.ControlLedger, "CELL-FED-22") {
		t.Fatalf("expected challenge-board control ledger coverage on challenge lifecycle, challenged=%+v ruled=%+v", challengedReconciliation.ControlLedger.Controls, ruledChallengeReconciliation.ControlLedger.Controls)
	}
	ackOverdueAt := reconciliationsAfterDispute[0].LastReviewedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAckSLA + time.Hour)
	overdueAppealReconciliations, err := service.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliations(ctx, SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationFilter{
		CellID:            created.CellID,
		OrganizationID:    organizationID,
		ComparisonKey:     comparisonKey,
		ReviewStatus:      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed,
		AttestationStatus: SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested,
		Before:            &ackOverdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentDirectiveExtensionAppealReconciliations failed: %v", err)
	}
	if len(overdueAppealReconciliations) != 1 || overdueAppealReconciliations[0].AutomationAction != "escalate_counterparty" || overdueAppealReconciliations[0].AttestationStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested {
		t.Fatalf("expected one overdue appeal reconciliation queued for escalation, got %+v", overdueAppealReconciliations)
	}

	sweepActor := "did:aethelred:appeal-reconciliation-sweeper"
	reconciliationSweep, err := service.SweepFederationIncidentDirectiveExtensionAppealReconciliations(ctx, ackOverdueAt, SecureCellLifecycleRequest{
		ActorDID: sweepActor,
		Reason:   "automated appeal reconciliation escalation sweep",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-SWEEP-01"},
	})
	if err != nil {
		t.Fatalf("SweepFederationIncidentDirectiveExtensionAppealReconciliations failed: %v", err)
	}
	if reconciliationSweep.ReconciliationsEscalated != 1 {
		t.Fatalf("expected one escalated appeal reconciliation, got %+v", reconciliationSweep)
	}

	automationActions, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliationAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationAutomationActions failed: %v", err)
	}
	if len(automationActions) != 1 || automationActions[0].Action != "secure_cell.federation_incident_directive_extension_appeal_reconciliation_escalated" || automationActions[0].AutomatedActor != sweepActor {
		t.Fatalf("expected one automated appeal reconciliation escalation action, got %+v", automationActions)
	}

	acknowledgedCounterpartyReconciliation, err := service.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationDispute(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeRequest{
		ActorDID:              participantB.AgentID(),
		CounterpartyReference: "counterparty-appeal-dispute-ack-0001",
		Reason:                "counterparty acknowledged bilateral appeal dispute",
		Metadata:              map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-ATT-ACK-01"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationDispute failed: %v", err)
	}

	correctedReconciliation, err := service.AttestFederationIncidentDirectiveExtensionAppealReconciliationCorrection(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestationRequest{
		ActorDID:               participantB.AgentID(),
		CounterpartySnapshotID: appealReconciliations[0].CounterpartySnapshotID,
		CounterpartyReference:  "counterparty-appeal-correction-0001",
		Reason:                 "counterparty attested corrected appeal posture",
		Metadata:               map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-ATT-CORRECT-01"},
	})
	if err != nil {
		t.Fatalf("AttestFederationIncidentDirectiveExtensionAppealReconciliationCorrection failed: %v", err)
	}

	resolvedCounterpartyReconciliation, err := service.AttestFederationIncidentDirectiveExtensionAppealReconciliationResolution(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestationRequest{
		ActorDID:              participantB.AgentID(),
		CounterpartyReference: "counterparty-appeal-resolution-0001",
		Reason:                "counterparty attested bilateral appeal dispute resolution",
		Metadata:              map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-ATT-RESOLVE-01"},
	})
	if err != nil {
		t.Fatalf("AttestFederationIncidentDirectiveExtensionAppealReconciliationResolution failed: %v", err)
	}

	attestations, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestations(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestations failed: %v", err)
	}
	if len(attestations) != 3 || attestations[0].AttestationStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusResolved || attestations[0].Attestation != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationResolve {
		t.Fatalf("expected three appeal reconciliation counterparty attestations ending in resolution, got %+v", attestations)
	}

	resolvedReconciliation, err := service.ResolveFederationIncidentDirectiveExtensionAppealReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolveRequest{
		ActorDID: owner.AgentID(),
		Reason:   "bilateral appeal review completed and dispute closed",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-RESOLVE-01"},
	})
	if err != nil {
		t.Fatalf("ResolveFederationIncidentDirectiveExtensionAppealReconciliation failed: %v", err)
	}

	reviewedAppealReconciliations, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliations(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
		ReviewStatus:  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusResolved,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliations after review failed: %v", err)
	}
	if len(reviewedAppealReconciliations) != 1 || reviewedAppealReconciliations[0].ReviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusResolved || reviewedAppealReconciliations[0].ReviewActionCount != 3 || reviewedAppealReconciliations[0].AttestationStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusResolved || reviewedAppealReconciliations[0].CounterpartyAttestationCount != 3 {
		t.Fatalf("expected one resolved appeal reconciliation with three actions, got %+v", reviewedAppealReconciliations)
	}

	reconciliationActions, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationActions failed: %v", err)
	}
	if len(reconciliationActions) != 3 || reconciliationActions[0].Action != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionResolve || reconciliationActions[0].ReviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusResolved {
		t.Fatalf("expected three governed appeal reconciliation actions ending in resolve, got %+v", reconciliationActions)
	}

	reconciliationBundle, err := service.BuildFederationIncidentDirectiveExtensionAppealReconciliationBundle(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveExtensionAppealReconciliationBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveExtensionAppealReconciliationBundle(reconciliationBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveExtensionAppealReconciliationBundle failed: %v", err)
	}
	if reconciliationBundle.Reconciliation.ReviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusResolved || len(reconciliationBundle.Actions) != 3 || len(reconciliationBundle.Attestations) != 3 || len(reconciliationBundle.Challenges) != 1 || len(reconciliationBundle.ChallengeActions) != 2 || len(reconciliationBundle.AutomationActions) != 1 {
		t.Fatalf("expected resolved appeal reconciliation bundle with three actions, got %+v", reconciliationBundle.Reconciliation)
	}
	if reconciliationBundle.AutomationActions[0].Action != "secure_cell.federation_incident_directive_extension_appeal_reconciliation_escalated" {
		t.Fatalf("expected reconciliation bundle automation trail to include escalation, got %+v", reconciliationBundle.AutomationActions)
	}

	casePack, err := service.BuildFederationIncidentCasePack(ctx, created.CellID, localResponseID, SecureCellFederationIncidentCasePackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentCasePack failed: %v", err)
	}
	if len(casePack.DirectiveExtensionAppealReconciliationAutomationActions) == 0 {
		t.Fatalf("expected case pack to include appeal reconciliation automation actions, got %+v", casePack.DirectiveExtensionAppealReconciliationAutomationActions)
	}
	if len(casePack.DirectiveExtensionAppealReconciliationChallenges) != 1 || len(casePack.DirectiveExtensionAppealReconciliationChallengeActions) != 2 {
		t.Fatalf("expected case pack to include appeal reconciliation challenge governance, got summaries=%+v actions=%+v", casePack.DirectiveExtensionAppealReconciliationChallenges, casePack.DirectiveExtensionAppealReconciliationChallengeActions)
	}
	foundReconciliationBundle := false
	for _, bundle := range casePack.DirectiveExtensionAppealReconciliationBundles {
		if bundle != nil && bundle.Reconciliation.ComparisonKey == comparisonKey {
			foundReconciliationBundle = true
			break
		}
	}
	if !foundReconciliationBundle {
		t.Fatalf("expected case pack to include reconciliation bundle for %s, got %+v", comparisonKey, casePack.DirectiveExtensionAppealReconciliationBundles)
	}

	if !controlLedgerHasControl(disputedReconciliation.ControlLedger, "CELL-FED-19") || !controlLedgerHasControl(resolvedReconciliation.ControlLedger, "CELL-FED-19") {
		t.Fatalf("expected disputed and resolved reconciliation control ledgers to include CELL-FED-19, disputed=%+v resolved=%+v", disputedReconciliation.ControlLedger.Controls, resolvedReconciliation.ControlLedger.Controls)
	}
	if !controlLedgerHasControl(resolvedReconciliation.ControlLedger, "CELL-FED-20") {
		t.Fatalf("expected resolved reconciliation control ledger to include CELL-FED-20, got %+v", resolvedReconciliation.ControlLedger.Controls)
	}
	if !controlLedgerHasControl(resolvedReconciliation.ControlLedger, "CELL-FED-21") {
		t.Fatalf("expected resolved reconciliation control ledger to include CELL-FED-21, got %+v", resolvedReconciliation.ControlLedger.Controls)
	}
	if !controlLedgerHasControl(resolvedReconciliation.ControlLedger, "CELL-FED-22") {
		t.Fatalf("expected resolved reconciliation control ledger to include CELL-FED-22, got %+v", resolvedReconciliation.ControlLedger.Controls)
	}
	if len(acknowledgedCounterpartyReconciliation.Transitions) == 0 || len(correctedReconciliation.Transitions) == 0 || len(resolvedCounterpartyReconciliation.Transitions) == 0 {
		t.Fatalf("expected appeal reconciliation counterparty attestation lifecycle mutations to append transitions")
	}

	rehearingID := rehearings[0].AppealID
	rehearingBundle, err := service.BuildFederationIncidentDirectiveExtensionAppealBundle(ctx, created.CellID, rehearingID, SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveExtensionAppealBundle rehearing failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveExtensionAppealBundle(rehearingBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveExtensionAppealBundle rehearing failed: %v", err)
	}
	if rehearingBundle.AppealSummary.ParentAppealID != appealID || rehearingBundle.AppealSummary.AppealGeneration != 2 {
		t.Fatalf("expected rehearing bundle lineage, got %+v", rehearingBundle.AppealSummary)
	}
	foundControl := false
	for _, control := range rehearingBundle.Controls {
		if control.ControlID == "CELL-FED-17" {
			foundControl = true
			break
		}
	}
	if !foundControl {
		t.Fatalf("expected rehearing bundle controls to include CELL-FED-17, got %+v", rehearingBundle.Controls)
	}
}

func TestService_FederationIncidentDirectiveExtensionAppealAutomation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Directive Extension Appeal Automation Cell",
		Purpose:       "govern bilateral directive extension appeal automation",
		Resource:      "cell:federation-directive-extension-appeal-automation",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Appeal Automation Room",
		Purpose:         "coordinate automated bilateral directive exception appeals",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "open appeal automation session",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-SESSION-01"},
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[len(started.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite counterparty appeal participant",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "counterparty joins appeal automation room",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	organizationID := accepted.FederationContracts[0].OrganizationID
	contractID := accepted.FederationContracts[0].ID

	published, err := service.PublishFederationIncident(ctx, created.CellID, organizationID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityHigh,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Appeal automation incident",
		Description:              "The local organization wants timed appeal-board supervision for directive deadline exceptions.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: false,
		Reason:                   "publish appeal automation incident",
		Metadata:                 map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local response, got %+v", responses)
	}

	dueAt := time.Now().UTC().Add(2 * time.Hour)
	if _, err := service.CreateFederationIncidentDirective(ctx, created.CellID, localResponseID, SecureCellFederationIncidentDirectiveCreateRequest{
		ActorDID:      owner.AgentID(),
		DirectiveType: "counterparty_evidence_request",
		Title:         "Provide counterparty evidence package",
		Summary:       "Counterparty must provide an evidence package for bilateral incident review.",
		Description:   "Provide the scoped evidence package, timeline, and remediation artifacts for the bilateral incident response.",
		Priority:      SecureCellFederationIncidentDirectivePriorityHigh,
		AssigneeParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		ReviewerParty: SecureCellFederationIncidentResponsePartyLocalOrg,
		AssigneeDID:   participantB.AgentID(),
		ReviewerDID:   owner.AgentID(),
		EvidenceIDs:   []string{incidentID},
		DueAt:         &dueAt,
		Reason:        "issue bilateral evidence work order",
		Metadata:      map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-ISSUE-01"},
	}); err != nil {
		t.Fatalf("CreateFederationIncidentDirective failed: %v", err)
	}

	directives, err := service.ListFederationIncidentDirectives(ctx, SecureCellFederationIncidentDirectiveFilter{
		CellID:     created.CellID,
		ResponseID: localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectives failed: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected one directive, got %+v", directives)
	}
	directiveID := directives[0].DirectiveID

	proposedDueAt := dueAt.Add(4 * time.Hour)
	if _, err := service.RequestFederationIncidentDirectiveExtension(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveExtensionRequest{
		ActorDID:                   participantB.AgentID(),
		RequestingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                    "Counterparty needs longer evidence collection window",
		Description:                "The counterparty needs additional time to gather the full evidence package for bilateral review.",
		EvidenceIDs:                []string{incidentID},
		ProposedDueAt:              &proposedDueAt,
		ReviewApprovalThreshold:    1,
		EligibleReviewerDIDs:       []string{owner.AgentID()},
		DisputeResolutionThreshold: 1,
		EligibleResolverDIDs:       []string{owner.AgentID()},
		Reason:                     "request directive extension before appeal automation",
		Metadata:                   map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-REQUEST-01"},
	}); err != nil {
		t.Fatalf("RequestFederationIncidentDirectiveExtension failed: %v", err)
	}

	extensions, err := service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions failed: %v", err)
	}
	if len(extensions) != 1 {
		t.Fatalf("expected one extension, got %+v", extensions)
	}
	extensionID := extensions[0].ExtensionID

	if _, err := service.RejectFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionRejectRequest{
		ActorDID:            owner.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local org rejected the extension",
		DecisionDescription: "The local organization rejected the exception request.",
		EvidenceIDs:         []string{directiveID},
		Reason:              "reject directive extension before dispute",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-REJECT-01"},
	}); err != nil {
		t.Fatalf("RejectFederationIncidentDirectiveExtension failed: %v", err)
	}

	if _, err := service.DisputeFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionDisputeRequest{
		ActorDID:         participantB.AgentID(),
		ChallengingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:          "Counterparty disputes rejected extension",
		Description:      "The counterparty reopened the rejected extension for bilateral review.",
		EvidenceIDs:      []string{directiveID},
		Reason:           "open directive extension dispute before appeal automation",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-DISPUTE-01"},
	}); err != nil {
		t.Fatalf("DisputeFederationIncidentDirectiveExtension failed: %v", err)
	}

	disputes, err := service.ListFederationIncidentDirectiveExtensionDisputes(ctx, SecureCellFederationIncidentDirectiveExtensionDisputeFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionDisputes failed: %v", err)
	}
	if len(disputes) != 1 {
		t.Fatalf("expected one dispute, got %+v", disputes)
	}
	disputeID := disputes[0].DisputeID

	if _, err := service.ResolveFederationIncidentDirectiveExtensionDispute(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionDisputeResolveRequest{
		ActorDID:              owner.AgentID(),
		RespondingParty:       SecureCellFederationIncidentResponsePartyLocalOrg,
		Resolution:            SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold,
		ResolutionSummary:     "Local org upheld the rejection",
		ResolutionDescription: "The local organization upheld the rejection during dispute resolution.",
		EvidenceIDs:           []string{directiveID},
		Reason:                "resolve dispute before appeal automation",
		Metadata:              map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-RESOLVE-01"},
	}); err != nil {
		t.Fatalf("ResolveFederationIncidentDirectiveExtensionDispute failed: %v", err)
	}

	if _, err := service.AppealFederationIncidentDirectiveExtensionDispute(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionAppealRequest{
		ActorDID:                  participantB.AgentID(),
		AppealingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                   "Counterparty appeals upheld rejection",
		Description:               "The counterparty escalated the upheld rejection to the bilateral appeal board.",
		EvidenceIDs:               []string{directiveID},
		BoardReviewThreshold:      2,
		EligibleBoardReviewerDIDs: []string{owner.AgentID()},
		Reason:                    "open directive extension appeal board review",
		Metadata:                  map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-OPEN-01"},
	}); err != nil {
		t.Fatalf("AppealFederationIncidentDirectiveExtensionDispute failed: %v", err)
	}

	appeals, err := service.ListFederationIncidentDirectiveExtensionAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
		DisputeID:   disputeID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppeals failed: %v", err)
	}
	if len(appeals) != 1 || appeals[0].Status != SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview || appeals[0].BoardReviewThreshold != 2 {
		t.Fatalf("expected one pending appeal, got %+v", appeals)
	}
	appealID := appeals[0].AppealID

	if _, err := service.RuleFederationIncidentDirectiveExtensionAppeal(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealRulingRequest{
		ActorDID:          owner.AgentID(),
		BoardParty:        SecureCellFederationIncidentResponsePartyLocalOrg,
		Ruling:            SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify,
		RulingSummary:     "Local board vote one ratified rejection",
		RulingDescription: "The first local board reviewer ratified the rejection but the threshold is not met yet.",
		EvidenceIDs:       []string{directiveID},
		Reason:            "record first appeal board vote",
		Metadata:          map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-RULE-01"},
	}); err != nil {
		t.Fatalf("RuleFederationIncidentDirectiveExtensionAppeal first vote failed: %v", err)
	}

	appeals, err = service.ListFederationIncidentDirectiveExtensionAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealFilter{
		CellID:   created.CellID,
		AppealID: appealID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppeals review posture failed: %v", err)
	}
	if len(appeals) != 1 || appeals[0].RatifyVoteCount != 1 || appeals[0].BoardRecordedVoteCount != 1 || appeals[0].BoardMissingQuorumCount != 1 {
		t.Fatalf("expected one recorded vote with one missing quorum seat, got %+v", appeals)
	}

	reviewOverdueAt := appeals[0].CreatedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionAppealBoardReviewSLA + time.Hour)
	overdueAppeals, err := service.ListOverdueFederationIncidentDirectiveExtensionAppeals(ctx, SecureCellOverdueFederationIncidentDirectiveExtensionAppealFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		AppealID:    appealID,
		Before:      &reviewOverdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentDirectiveExtensionAppeals review failed: %v", err)
	}
	if len(overdueAppeals) != 1 || overdueAppeals[0].AutomationAction != "delegate_review_committee" || overdueAppeals[0].BoardReviewThreshold != 2 || overdueAppeals[0].BoardCommitteeMemberCount != 1 || overdueAppeals[0].BoardMissingQuorumCount != 1 {
		t.Fatalf("expected committee-aware overdue appeal posture, got %+v", overdueAppeals)
	}

	sweepActor := "did:aethelred:directive-extension-appeal-sweeper"
	if _, err := service.SweepFederationIncidentDirectiveExtensionAppeals(ctx, reviewOverdueAt, SecureCellLifecycleRequest{
		ActorDID: sweepActor,
		Reason:   "automated directive extension appeal review sweep",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-SWEEP-REVIEW-01"},
	}); err != nil {
		t.Fatalf("SweepFederationIncidentDirectiveExtensionAppeals review failed: %v", err)
	}

	automationActions, err := service.ListFederationIncidentDirectiveExtensionAppealAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		AppealID:    appealID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealAutomationActions review failed: %v", err)
	}
	if len(automationActions) == 0 || automationActions[0].Action != "secure_cell.federation_incident_directive_extension_appeal_review_delegated" || automationActions[0].TargetDID == "" || automationActions[0].BoardReviewThreshold != 2 || automationActions[0].BoardMissingQuorumCount != 1 {
		t.Fatalf("expected automated appeal-board delegation, got %+v", automationActions)
	}
	delegatedReviewDID := automationActions[0].TargetDID

	directiveBundle, err := service.BuildFederationIncidentDirectiveBundle(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveBundle after review sweep failed: %v", err)
	}
	if len(directiveBundle.ExtensionAppealAutomationActions) != 1 || directiveBundle.ExtensionAppealAutomationActions[0].AppealID != appealID {
		t.Fatalf("expected directive bundle appeal automation projection, got %+v", directiveBundle.ExtensionAppealAutomationActions)
	}
	appealBundle, err := service.BuildFederationIncidentDirectiveExtensionAppealBundle(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveExtensionAppealBundle after review sweep failed: %v", err)
	}
	if len(appealBundle.AutomationActions) != 1 || appealBundle.AutomationActions[0].Action != "secure_cell.federation_incident_directive_extension_appeal_review_delegated" {
		t.Fatalf("expected appeal bundle automation projection, got %+v", appealBundle.AutomationActions)
	}

	if _, err := service.RuleFederationIncidentDirectiveExtensionAppeal(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealRulingRequest{
		ActorDID:          delegatedReviewDID,
		BoardParty:        SecureCellFederationIncidentResponsePartyLocalOrg,
		Ruling:            SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify,
		RulingSummary:     "Local board ratified rejection",
		RulingDescription: "The delegated reviewer completed the appeal-board threshold and ratified the rejection.",
		EvidenceIDs:       []string{directiveID},
		Reason:            "record second appeal board vote",
		Metadata:          map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-RULE-02"},
	}); err != nil {
		t.Fatalf("RuleFederationIncidentDirectiveExtensionAppeal second vote failed: %v", err)
	}

	appeals, err = service.ListFederationIncidentDirectiveExtensionAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealFilter{
		CellID:   created.CellID,
		AppealID: appealID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppeals final review failed: %v", err)
	}
	if len(appeals) != 1 || appeals[0].Status != SecureCellFederationIncidentDirectiveExtensionAppealStatusRatified || appeals[0].BoardDelegationCount != 1 {
		t.Fatalf("expected ratified appeal awaiting acknowledgement, got %+v", appeals)
	}

	ackOverdueAt := appeals[0].RuledAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionAppealAcknowledgementSLA + time.Hour)
	overdueAppeals, err = service.ListOverdueFederationIncidentDirectiveExtensionAppeals(ctx, SecureCellOverdueFederationIncidentDirectiveExtensionAppealFilter{
		CellID:   created.CellID,
		AppealID: appealID,
		Before:   &ackOverdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentDirectiveExtensionAppeals acknowledgement failed: %v", err)
	}
	if len(overdueAppeals) != 1 || overdueAppeals[0].PendingAction != "acknowledge_enforcement" {
		t.Fatalf("expected overdue enforcement acknowledgement posture, got %+v", overdueAppeals)
	}

	if _, err := service.SweepFederationIncidentDirectiveExtensionAppeals(ctx, ackOverdueAt, SecureCellLifecycleRequest{
		ActorDID: sweepActor,
		Reason:   "automated directive extension appeal enforcement sweep",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-AUTO-SWEEP-ACK-01"},
	}); err != nil {
		t.Fatalf("SweepFederationIncidentDirectiveExtensionAppeals acknowledgement failed: %v", err)
	}

	automationActions, err = service.ListFederationIncidentDirectiveExtensionAppealAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		AppealID:    appealID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealAutomationActions acknowledgement failed: %v", err)
	}
	if len(automationActions) < 2 {
		t.Fatalf("expected review and acknowledgement automation actions, got %+v", automationActions)
	}
	var sawAckAutomation bool
	for _, item := range automationActions {
		if item.PendingAction == "acknowledge_enforcement" && item.AppealID == appealID {
			sawAckAutomation = true
			if item.Action != "secure_cell.federation_incident_response_escalated" && item.Action != "secure_cell.federation_contract_suspended" {
				t.Fatalf("expected acknowledgement automation to escalate response or suspend contracts, got %+v", item)
			}
		}
	}
	if !sawAckAutomation {
		t.Fatalf("expected one acknowledgement automation action, got %+v", automationActions)
	}

	appealBundle, err = service.BuildFederationIncidentDirectiveExtensionAppealBundle(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveExtensionAppealBundle final failed: %v", err)
	}
	if len(appealBundle.AutomationActions) < 2 {
		t.Fatalf("expected appeal bundle to retain automation trail, got %+v", appealBundle.AutomationActions)
	}
	casePack, err := service.BuildFederationIncidentCasePack(ctx, created.CellID, localResponseID, SecureCellFederationIncidentCasePackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentCasePack final failed: %v", err)
	}
	if len(casePack.DirectiveExtensionAppealAutomationActions) < 2 {
		t.Fatalf("expected case pack to include appeal automation trail, got %+v", casePack.DirectiveExtensionAppealAutomationActions)
	}
}

func TestService_FederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service, _, owner, participantA, participantB := newTestSecureCellService(t)

	created, err := service.CreateCell(ctx, SecureCellRequest{
		OwnerIdentity: owner,
		Name:          "Federation Appeal Reconciliation Challenge Automation Cell",
		Purpose:       "govern timed bilateral appeal reconciliation challenge boards",
		Resource:      "cell:federation-appeal-reconciliation-challenge-automation",
		Jurisdiction:  "UAE",
		Participants: []SecureCellParticipant{
			{Identity: participantA, Role: "reviewer"},
		},
		Policy: SecureCellPolicy{
			DataClasses:                []string{"confidential", "decisioning"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("CreateCell failed: %v", err)
	}

	started, err := service.StartSession(ctx, created.CellID, SecureCellSessionStartRequest{
		ActorDID:        owner.AgentID(),
		Name:            "Appeal Reconciliation Challenge Automation Room",
		Purpose:         "coordinate automated bilateral reconciliation challenge reviews",
		ParticipantDIDs: []string{participantA.AgentID()},
		DataClasses:     []string{"decisioning"},
		Reason:          "open appeal reconciliation challenge automation session",
		Metadata:        map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-SESSION-01"},
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	session := started.Sessions[len(started.Sessions)-1]

	invited, err := service.CreateFederationInvitation(ctx, created.CellID, SecureCellFederationInviteRequest{
		ActorDID:         owner.AgentID(),
		SponsorOfRecord:  secureCellFederationSponsor(participantB),
		OrganizationName: secureCellFederationOrganizationName(participantB),
		Jurisdiction:     "UK",
		ExpectedDID:      participantB.AgentID(),
		Role:             "bank_b_reviewer",
		SessionScopeIDs:  []string{session.ID},
		DataClasses:      []string{"confidential", "decisioning"},
		ComputeZones:     []string{"uae-enclave"},
		AllowedActions:   []string{"share_output", "session_exchange"},
		Reason:           "invite counterparty reconciliation participant",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-INVITE-01"},
	})
	if err != nil {
		t.Fatalf("CreateFederationInvitation failed: %v", err)
	}
	invitation := invited.FederationInvitations[len(invited.FederationInvitations)-1]

	accepted, err := service.AcceptFederationInvitation(ctx, created.CellID, SecureCellFederationAcceptRequest{
		InvitationID: invitation.ID,
		ActorDID:     participantB.AgentID(),
		Participant: SecureCellParticipant{
			Identity: participantB,
			Role:     "bank_b_reviewer",
		},
		Reason:   "counterparty joins reconciliation room",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-ACCEPT-01"},
	})
	if err != nil {
		t.Fatalf("AcceptFederationInvitation failed: %v", err)
	}
	organizationID := accepted.FederationContracts[0].OrganizationID
	contractID := accepted.FederationContracts[0].ID

	published, err := service.PublishFederationIncident(ctx, created.CellID, organizationID, SecureCellFederationIncidentPublishRequest{
		ActorDID:                 owner.AgentID(),
		Severity:                 SecureCellFederationIncidentSeverityHigh,
		Category:                 SecureCellFederationIncidentCategoryUnauthorizedExchange,
		Summary:                  "Appeal reconciliation challenge automation incident",
		Description:              "The local organization wants timed supervision for bilateral appeal reconciliation challenge boards.",
		ContractIDs:              []string{contractID},
		SessionIDs:               []string{session.ID},
		AutoContainmentRequested: false,
		Reason:                   "publish appeal reconciliation challenge automation incident",
		Metadata:                 map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-INC-01"},
	})
	if err != nil {
		t.Fatalf("PublishFederationIncident failed: %v", err)
	}
	incidentID := published.FederationIncidents[0].ID

	responses, err := service.ListFederationIncidentResponses(ctx, SecureCellFederationIncidentResponseFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentResponses failed: %v", err)
	}
	var localResponseID string
	for _, item := range responses {
		if item.SourceType == SecureCellFederationIncidentResponseSourceLocalIncident {
			localResponseID = item.ResponseID
			break
		}
	}
	if localResponseID == "" {
		t.Fatalf("expected local response, got %+v", responses)
	}

	dueAt := time.Now().UTC().Add(2 * time.Hour)
	if _, err := service.CreateFederationIncidentDirective(ctx, created.CellID, localResponseID, SecureCellFederationIncidentDirectiveCreateRequest{
		ActorDID:      owner.AgentID(),
		DirectiveType: "counterparty_evidence_request",
		Title:         "Provide counterparty evidence package",
		Summary:       "Counterparty must provide an evidence package for bilateral incident review.",
		Description:   "Provide the scoped evidence package, timeline, and remediation artifacts for bilateral incident review.",
		Priority:      SecureCellFederationIncidentDirectivePriorityHigh,
		AssigneeParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		ReviewerParty: SecureCellFederationIncidentResponsePartyLocalOrg,
		AssigneeDID:   participantB.AgentID(),
		ReviewerDID:   owner.AgentID(),
		EvidenceIDs:   []string{incidentID},
		DueAt:         &dueAt,
		Reason:        "issue bilateral evidence work order",
		Metadata:      map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-ISSUE-01"},
	}); err != nil {
		t.Fatalf("CreateFederationIncidentDirective failed: %v", err)
	}

	directives, err := service.ListFederationIncidentDirectives(ctx, SecureCellFederationIncidentDirectiveFilter{
		CellID:     created.CellID,
		ResponseID: localResponseID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectives failed: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected one directive, got %+v", directives)
	}
	directiveID := directives[0].DirectiveID

	proposedDueAt := dueAt.Add(4 * time.Hour)
	if _, err := service.RequestFederationIncidentDirectiveExtension(ctx, created.CellID, directiveID, SecureCellFederationIncidentDirectiveExtensionRequest{
		ActorDID:                   participantB.AgentID(),
		RequestingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                    "Counterparty needs longer evidence collection window",
		Description:                "The counterparty needs additional time to gather the full evidence package for bilateral review.",
		EvidenceIDs:                []string{incidentID},
		ProposedDueAt:              &proposedDueAt,
		ReviewApprovalThreshold:    1,
		EligibleReviewerDIDs:       []string{owner.AgentID()},
		DisputeResolutionThreshold: 1,
		EligibleResolverDIDs:       []string{owner.AgentID()},
		Reason:                     "request directive extension before reconciliation challenge automation",
		Metadata:                   map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-REQUEST-01"},
	}); err != nil {
		t.Fatalf("RequestFederationIncidentDirectiveExtension failed: %v", err)
	}

	extensions, err := service.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensions failed: %v", err)
	}
	if len(extensions) != 1 {
		t.Fatalf("expected one extension, got %+v", extensions)
	}
	extensionID := extensions[0].ExtensionID

	if _, err := service.RejectFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionRejectRequest{
		ActorDID:            owner.AgentID(),
		ReviewingParty:      SecureCellFederationIncidentResponsePartyLocalOrg,
		DecisionSummary:     "Local org rejected the extension",
		DecisionDescription: "The local organization rejected the extension request.",
		EvidenceIDs:         []string{directiveID},
		Reason:              "reject directive extension before dispute",
		Metadata:            map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-REJECT-01"},
	}); err != nil {
		t.Fatalf("RejectFederationIncidentDirectiveExtension failed: %v", err)
	}

	if _, err := service.DisputeFederationIncidentDirectiveExtension(ctx, created.CellID, extensionID, SecureCellFederationIncidentDirectiveExtensionDisputeRequest{
		ActorDID:         participantB.AgentID(),
		ChallengingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:          "Counterparty disputes rejected extension",
		Description:      "The counterparty reopened the rejected extension for bilateral review.",
		EvidenceIDs:      []string{directiveID},
		Reason:           "open directive extension dispute before reconciliation challenge automation",
		Metadata:         map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-DISPUTE-01"},
	}); err != nil {
		t.Fatalf("DisputeFederationIncidentDirectiveExtension failed: %v", err)
	}

	disputes, err := service.ListFederationIncidentDirectiveExtensionDisputes(ctx, SecureCellFederationIncidentDirectiveExtensionDisputeFilter{
		CellID:      created.CellID,
		DirectiveID: directiveID,
		ExtensionID: extensionID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionDisputes failed: %v", err)
	}
	if len(disputes) != 1 {
		t.Fatalf("expected one dispute, got %+v", disputes)
	}
	disputeID := disputes[0].DisputeID

	if _, err := service.ResolveFederationIncidentDirectiveExtensionDispute(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionDisputeResolveRequest{
		ActorDID:              owner.AgentID(),
		RespondingParty:       SecureCellFederationIncidentResponsePartyLocalOrg,
		Resolution:            SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold,
		ResolutionSummary:     "Local org upheld the rejection",
		ResolutionDescription: "The local organization upheld the rejection during dispute resolution.",
		EvidenceIDs:           []string{directiveID},
		Reason:                "resolve dispute before reconciliation challenge automation",
		Metadata:              map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-RESOLVE-01"},
	}); err != nil {
		t.Fatalf("ResolveFederationIncidentDirectiveExtensionDispute failed: %v", err)
	}

	if _, err := service.AppealFederationIncidentDirectiveExtensionDispute(ctx, created.CellID, disputeID, SecureCellFederationIncidentDirectiveExtensionAppealRequest{
		ActorDID:                  participantB.AgentID(),
		AppealingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                   "Counterparty appeals upheld rejection",
		Description:               "The counterparty escalated the upheld rejection to the bilateral appeal board.",
		EvidenceIDs:               []string{directiveID},
		BoardReviewThreshold:      1,
		EligibleBoardReviewerDIDs: []string{owner.AgentID()},
		Reason:                    "open directive extension appeal board review",
		Metadata:                  map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-OPEN-01"},
	}); err != nil {
		t.Fatalf("AppealFederationIncidentDirectiveExtensionDispute failed: %v", err)
	}

	appeals, err := service.ListFederationIncidentDirectiveExtensionAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealFilter{
		CellID:    created.CellID,
		DisputeID: disputeID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppeals failed: %v", err)
	}
	if len(appeals) != 1 {
		t.Fatalf("expected one appeal, got %+v", appeals)
	}
	appealID := appeals[0].AppealID

	if _, err := service.RuleFederationIncidentDirectiveExtensionAppeal(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealRulingRequest{
		ActorDID:          owner.AgentID(),
		BoardParty:        SecureCellFederationIncidentResponsePartyLocalOrg,
		Ruling:            SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify,
		RulingSummary:     "Local board ratified rejection",
		RulingDescription: "The local board ratified the rejection for reciprocal bundle issuance.",
		EvidenceIDs:       []string{directiveID},
		Reason:            "record appeal board ruling before reciprocal intake",
		Metadata:          map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-RULE-01"},
	}); err != nil {
		t.Fatalf("RuleFederationIncidentDirectiveExtensionAppeal failed: %v", err)
	}

	if _, err := service.AcknowledgeFederationIncidentDirectiveExtensionAppealEnforcement(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest{
		ActorDID:           participantB.AgentID(),
		AcknowledgingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:            "Counterparty acknowledged final appeal ruling",
		Description:        "The counterparty accepted the ratified rejection for reciprocal bundle issuance.",
		EvidenceIDs:        []string{directiveID},
		Reason:             "acknowledge final appeal ruling before reciprocal intake",
		Metadata:           map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-ACK-01"},
	}); err != nil {
		t.Fatalf("AcknowledgeFederationIncidentDirectiveExtensionAppealEnforcement failed: %v", err)
	}

	originalBundle, err := service.BuildFederationIncidentDirectiveExtensionAppealBundle(ctx, created.CellID, appealID, SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveExtensionAppealBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveExtensionAppealBundle(originalBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveExtensionAppealBundle failed: %v", err)
	}

	if _, err := service.IngestFederationIncidentDirectiveExtensionAppealBundle(ctx, created.CellID, organizationID, SecureCellFederationIncidentDirectiveExtensionAppealBundleIntakeRequest{
		ActorDID: owner.AgentID(),
		Bundle:   originalBundle,
		Reason:   "ingest reciprocal directive extension appeal bundle",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-INTAKE-01"},
	}); err != nil {
		t.Fatalf("IngestFederationIncidentDirectiveExtensionAppealBundle failed: %v", err)
	}

	appealReconciliations, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliations(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter{
		CellID:         created.CellID,
		OrganizationID: organizationID,
		AppealID:       appealID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliations failed: %v", err)
	}
	if len(appealReconciliations) != 1 || appealReconciliations[0].Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAligned {
		t.Fatalf("expected one aligned appeal reconciliation, got %+v", appealReconciliations)
	}
	comparisonKey := appealReconciliations[0].ComparisonKey

	if _, err := service.DisputeFederationIncidentDirectiveExtensionAppealReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest{
		ActorDID:    owner.AgentID(),
		Reason:      "capture bilateral appeal review challenge for timed supervision",
		Divergences: []string{"counterparty appeal requires formal board review"},
		Metadata:    map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-DISPUTE-RECON-01"},
	}); err != nil {
		t.Fatalf("DisputeFederationIncidentDirectiveExtensionAppealReconciliation failed: %v", err)
	}

	if _, err := service.ChallengeFederationIncidentDirectiveExtensionAppealReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest{
		ActorDID:                  participantB.AgentID(),
		ChallengingParty:          SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                   "Counterparty escalated reconciliation to bilateral challenge board",
		Description:               "The counterparty requested a formal local board review over the disputed appeal reconciliation posture.",
		EvidenceIDs:               []string{directiveID, comparisonKey},
		BoardReviewThreshold:      2,
		EligibleBoardReviewerDIDs: []string{owner.AgentID()},
		Reason:                    "open bilateral appeal reconciliation challenge board review",
		Metadata:                  map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-OPEN-01"},
	}); err != nil {
		t.Fatalf("ChallengeFederationIncidentDirectiveExtensionAppealReconciliation failed: %v", err)
	}

	challenges, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges failed: %v", err)
	}
	if len(challenges) != 1 || challenges[0].ChallengeStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview || challenges[0].BoardReviewThreshold != 2 {
		t.Fatalf("expected one pending appeal reconciliation challenge, got %+v", challenges)
	}
	challengeID := challenges[0].ChallengeID

	if _, err := service.RuleFederationIncidentDirectiveExtensionAppealReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest{
		ActorDID:          owner.AgentID(),
		BoardParty:        SecureCellFederationIncidentResponsePartyLocalOrg,
		Ruling:            SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify,
		RulingSummary:     "Local board vote one ratified disputed reconciliation",
		RulingDescription: "The first local board reviewer ratified the disputed reconciliation posture but the threshold is not met yet.",
		EvidenceIDs:       []string{directiveID, comparisonKey},
		Reason:            "record first appeal reconciliation challenge board vote",
		Metadata:          map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-VOTE-01"},
	}); err != nil {
		t.Fatalf("RuleFederationIncidentDirectiveExtensionAppealReconciliation first vote failed: %v", err)
	}

	challenges, err = service.ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter{
		CellID:        created.CellID,
		ChallengeID:   challengeID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges review posture failed: %v", err)
	}
	if len(challenges) != 1 || challenges[0].BoardRecordedVoteCount != 1 || challenges[0].RatifyVoteCount != 1 || challenges[0].BoardCommitteeMemberCount != 1 || challenges[0].BoardMissingQuorumCount != 1 {
		t.Fatalf("expected one recorded challenge vote with one missing quorum seat, got %+v", challenges)
	}

	reviewOverdueAt := challenges[0].CreatedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeBoardReviewSLA + time.Hour)
	overdueChallenges, err := service.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenges(ctx, SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
		ChallengeID:   challengeID,
		Before:        &reviewOverdueAt,
	})
	if err != nil {
		t.Fatalf("ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenges failed: %v", err)
	}
	if len(overdueChallenges) != 1 || overdueChallenges[0].AutomationAction != "delegate_review_committee" || overdueChallenges[0].BoardReviewThreshold != 2 || overdueChallenges[0].BoardCommitteeMemberCount != 1 || overdueChallenges[0].BoardMissingQuorumCount != 1 {
		t.Fatalf("expected committee-aware overdue appeal reconciliation challenge posture, got %+v", overdueChallenges)
	}

	sweepActor := "did:aethelred:appeal-reconciliation-challenge-sweeper"
	sweep, err := service.SweepFederationIncidentDirectiveExtensionAppealReconciliationChallenges(ctx, reviewOverdueAt, SecureCellLifecycleRequest{
		ActorDID: sweepActor,
		Reason:   "automated appeal reconciliation challenge review sweep",
		Metadata: map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-SWEEP-01"},
	})
	if err != nil {
		t.Fatalf("SweepFederationIncidentDirectiveExtensionAppealReconciliationChallenges failed: %v", err)
	}
	if sweep.CommitteesExpanded != 1 {
		t.Fatalf("expected one committee expansion, got %+v", sweep)
	}

	automationActions, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionFilter{
		CellID:        created.CellID,
		ComparisonKey: comparisonKey,
		ChallengeID:   challengeID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActions failed: %v", err)
	}
	if len(automationActions) != 1 || automationActions[0].Action != "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_review_delegated" || automationActions[0].TargetDID == "" || automationActions[0].AutomatedActor != sweepActor || automationActions[0].BoardDelegationCount != 1 {
		t.Fatalf("expected one automated reconciliation challenge review delegation, got %+v", automationActions)
	}
	delegatedReviewDID := automationActions[0].TargetDID

	reconciliationBundle, err := service.BuildFederationIncidentDirectiveExtensionAppealReconciliationBundle(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveExtensionAppealReconciliationBundle failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveExtensionAppealReconciliationBundle(reconciliationBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveExtensionAppealReconciliationBundle failed: %v", err)
	}
	if len(reconciliationBundle.ChallengeAutomationActions) != 1 || reconciliationBundle.ChallengeAutomationActions[0].Action != "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_review_delegated" {
		t.Fatalf("expected reconciliation bundle automation trail, got %+v", reconciliationBundle.ChallengeAutomationActions)
	}

	casePack, err := service.BuildFederationIncidentCasePack(ctx, created.CellID, localResponseID, SecureCellFederationIncidentCasePackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentCasePack failed: %v", err)
	}
	if len(casePack.DirectiveExtensionAppealReconciliationChallengeAutomationActions) != 1 || casePack.DirectiveExtensionAppealReconciliationChallengeAutomationActions[0].Action != "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_review_delegated" {
		t.Fatalf("expected case pack reconciliation challenge automation trail, got %+v", casePack.DirectiveExtensionAppealReconciliationChallengeAutomationActions)
	}

	ruledChallengeReconciliation, err := service.RuleFederationIncidentDirectiveExtensionAppealReconciliation(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest{
		ActorDID:          delegatedReviewDID,
		BoardParty:        SecureCellFederationIncidentResponsePartyLocalOrg,
		Ruling:            SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify,
		RulingSummary:     "Local board ratified disputed reconciliation",
		RulingDescription: "The delegated reviewer completed the challenge-board threshold and ratified the disputed reconciliation posture.",
		EvidenceIDs:       []string{directiveID, comparisonKey},
		Reason:            "record second appeal reconciliation challenge board vote",
		Metadata:          map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-AUTO-VOTE-02"},
	})
	if err != nil {
		t.Fatalf("RuleFederationIncidentDirectiveExtensionAppealReconciliation second vote failed: %v", err)
	}

	challenges, err = service.ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter{
		CellID:      created.CellID,
		ChallengeID: challengeID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges final failed: %v", err)
	}
	if len(challenges) != 1 || challenges[0].ChallengeStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusRatified || challenges[0].BoardDelegationCount != 1 || challenges[0].RatifyVoteCount != 2 || challenges[0].BoardRecordedVoteCount != 2 {
		t.Fatalf("expected ratified reconciliation challenge after delegated review, got %+v", challenges)
	}
	if !controlLedgerHasControl(ruledChallengeReconciliation.ControlLedger, "CELL-FED-23") {
		t.Fatalf("expected reconciled challenge control ledger to include CELL-FED-23, got %+v", ruledChallengeReconciliation.ControlLedger.Controls)
	}

	if _, err := service.AppealFederationIncidentDirectiveExtensionAppealReconciliationChallenge(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRequest{
		ActorDID:                  participantB.AgentID(),
		AppealingParty:            SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:                   "Counterparty appealed the reconciliation challenge ruling",
		Description:               "The counterparty requested one more governed review over the ratified reconciliation challenge ruling.",
		EvidenceIDs:               []string{directiveID, comparisonKey, challengeID},
		BoardReviewThreshold:      1,
		EligibleBoardReviewerDIDs: []string{owner.AgentID()},
		Reason:                    "open reconciliation challenge appeal board",
		Metadata:                  map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-APPEAL-OPEN-01"},
	}); err != nil {
		t.Fatalf("AppealFederationIncidentDirectiveExtensionAppealReconciliationChallenge failed: %v", err)
	}

	challengeAppeals, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter{
		CellID:        created.CellID,
		AppealID:      appealID,
		ComparisonKey: comparisonKey,
		ChallengeID:   challengeID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals failed: %v", err)
	}
	if len(challengeAppeals) != 1 || challengeAppeals[0].AppealID != appealID || challengeAppeals[0].ChallengeAppealStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview {
		t.Fatalf("expected one pending reconciliation challenge appeal filtered by parent appeal, got %+v", challengeAppeals)
	}
	challengeAppealID := challengeAppeals[0].ChallengeAppealID

	ruledChallengeAppeal, err := service.RuleFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(ctx, created.CellID, challengeAppealID, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRulingRequest{
		ActorDID:          owner.AgentID(),
		BoardParty:        SecureCellFederationIncidentResponsePartyLocalOrg,
		Ruling:            SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify,
		RulingSummary:     "Local board ratified the challenge appeal ruling",
		RulingDescription: "The local board ratified the reconciliation challenge appeal and kept the bilateral ruling in force.",
		EvidenceIDs:       []string{directiveID, comparisonKey, challengeAppealID},
		Reason:            "rule reconciliation challenge appeal board",
		Metadata:          map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-APPEAL-RULE-01"},
	})
	if err != nil {
		t.Fatalf("RuleFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal failed: %v", err)
	}

	challengeAppeals, err = service.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter{
		CellID:        created.CellID,
		AppealID:      appealID,
		ComparisonKey: comparisonKey,
		ChallengeID:   challengeID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals after rule failed: %v", err)
	}
	if len(challengeAppeals) != 1 || challengeAppeals[0].ChallengeAppealID != challengeAppealID || challengeAppeals[0].ChallengeAppealStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusRatified {
		t.Fatalf("expected one ratified reconciliation challenge appeal after ruling, got %+v", challengeAppeals)
	}

	acknowledgedChallengeAppeal, err := service.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealEnforcement(ctx, created.CellID, challengeAppealID, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeRequest{
		ActorDID:           participantB.AgentID(),
		AcknowledgingParty: SecureCellFederationIncidentResponsePartyCounterpartyOrg,
		Summary:            "Counterparty acknowledged challenge appeal enforcement",
		Description:        "The counterparty accepted enforcement of the ratified reconciliation challenge appeal ruling.",
		EvidenceIDs:        []string{directiveID, comparisonKey, challengeAppealID},
		Reason:             "acknowledge reconciliation challenge appeal enforcement",
		Metadata:           map[string]string{"ticket": "FED-DIRECTIVE-EXT-APPEAL-RECON-CHALLENGE-APPEAL-ACK-01"},
	})
	if err != nil {
		t.Fatalf("AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealEnforcement failed: %v", err)
	}

	challengeAppeals, err = service.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter{
		CellID:        created.CellID,
		AppealID:      appealID,
		ComparisonKey: comparisonKey,
		ChallengeID:   challengeID,
		Status:        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusEnforcementAcknowledged,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals final failed: %v", err)
	}
	if len(challengeAppeals) != 1 || challengeAppeals[0].ChallengeAppealID != challengeAppealID || challengeAppeals[0].EnforcementAcknowledgedBy != participantB.AgentID() || challengeAppeals[0].RatifyVoteCount != 1 {
		t.Fatalf("expected one acknowledged reconciliation challenge appeal, got %+v", challengeAppeals)
	}

	challengeAppealActions, err := service.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter{
		CellID:        created.CellID,
		AppealID:      appealID,
		ComparisonKey: comparisonKey,
		ChallengeID:   challengeID,
	})
	if err != nil {
		t.Fatalf("ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActions failed: %v", err)
	}
	if len(challengeAppealActions) != 3 || challengeAppealActions[0].Action != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionEnforcementAcknowledged || challengeAppealActions[2].Action != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionAppealed {
		t.Fatalf("expected challenge appeal action trail with three records, got %+v", challengeAppealActions)
	}

	reconciliationBundle, err = service.BuildFederationIncidentDirectiveExtensionAppealReconciliationBundle(ctx, created.CellID, comparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentDirectiveExtensionAppealReconciliationBundle after challenge appeal failed: %v", err)
	}
	if err := VerifyFederationIncidentDirectiveExtensionAppealReconciliationBundle(reconciliationBundle); err != nil {
		t.Fatalf("VerifyFederationIncidentDirectiveExtensionAppealReconciliationBundle after challenge appeal failed: %v", err)
	}
	if len(reconciliationBundle.ChallengeAppeals) != 1 || len(reconciliationBundle.ChallengeAppealActions) != 3 || reconciliationBundle.ChallengeAppeals[0].ChallengeAppealID != challengeAppealID {
		t.Fatalf("expected reconciliation bundle to include challenge appeal artifacts, got %+v", reconciliationBundle)
	}

	casePack, err = service.BuildFederationIncidentCasePack(ctx, created.CellID, localResponseID, SecureCellFederationIncidentCasePackOptions{})
	if err != nil {
		t.Fatalf("BuildFederationIncidentCasePack after challenge appeal failed: %v", err)
	}
	if len(casePack.DirectiveExtensionAppealReconciliationChallengeAppeals) != 1 || len(casePack.DirectiveExtensionAppealReconciliationChallengeAppealActions) != 3 || casePack.DirectiveExtensionAppealReconciliationChallengeAppeals[0].ChallengeAppealID != challengeAppealID {
		t.Fatalf("expected case pack to include challenge appeal artifacts, got %+v", casePack)
	}
	if !controlLedgerHasControl(ruledChallengeAppeal.ControlLedger, "CELL-FED-24") {
		t.Fatalf("expected ruled challenge appeal control ledger to include CELL-FED-24, got %+v", ruledChallengeAppeal.ControlLedger.Controls)
	}
	if !controlLedgerHasControl(acknowledgedChallengeAppeal.ControlLedger, "CELL-FED-24") {
		t.Fatalf("expected acknowledged challenge appeal control ledger to include CELL-FED-24, got %+v", acknowledgedChallengeAppeal.ControlLedger.Controls)
	}
}

func containsStringFold(items []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), want) {
			return true
		}
	}
	return false
}

func mustSecureCellSharedOutput(t *testing.T, result *SecureCellResult, outputID string) (SecureCellSharedOutput, bool) {
	t.Helper()
	if result == nil {
		t.Fatal("secure cell result is required")
	}
	for _, output := range result.SharedOutputs {
		if output.ID == outputID {
			return output, true
		}
	}
	return SecureCellSharedOutput{}, false
}

func mustSecureCellDecisionOutcome(t *testing.T, result *SecureCellResult, decisionID string) (SecureCellThreadDecisionOutcome, bool) {
	t.Helper()
	if result == nil {
		t.Fatal("secure cell result is required")
	}
	for _, outcome := range result.DecisionOutcomes {
		if outcome.DecisionID == decisionID {
			return outcome, true
		}
	}
	return SecureCellThreadDecisionOutcome{}, false
}
