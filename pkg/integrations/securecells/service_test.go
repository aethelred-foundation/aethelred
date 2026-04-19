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
