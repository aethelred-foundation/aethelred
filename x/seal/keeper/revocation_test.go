package keeper

import (
	"context"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/x/seal/types"
)

func TestRevocationRegisterAuthority(t *testing.T) {
	rm := NewRevocationManager(log.NewNopLogger(), nil, DefaultRevocationConfig())

	if err := rm.RegisterAuthority(RevocationAuthority{}); err == nil {
		t.Fatalf("expected error for missing address")
	}

	auth := RevocationAuthority{Address: "addr1", Level: AuthorityLevelAdmin}
	if err := rm.RegisterAuthority(auth); err != nil {
		t.Fatalf("expected register success, got %v", err)
	}
	if !rm.authorities["addr1"].Active {
		t.Fatalf("expected authority active")
	}
}

func TestRevocationRequestAuthorization(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := newSDKContext()
	rm := NewRevocationManager(log.NewNopLogger(), &k, DefaultRevocationConfig())

	seal := newSealForTest(1)
	_ = k.SetSeal(context.Background(), seal)

	req := &RevocationRequest{SealID: seal.Id, Requester: "other", Reason: RevocationReasonUserRequest}
	if _, err := rm.RequestRevocation(ctx, req); err == nil {
		t.Fatalf("expected unauthorized error")
	}

	req.Requester = seal.RequestedBy
	resp, err := rm.RequestRevocation(ctx, req)
	if err != nil {
		t.Fatalf("expected request success, got %v", err)
	}
	if resp.Status != RevocationStatusPending {
		t.Fatalf("expected pending status")
	}
}

func TestRevocationRequesterAuthorityRecordsInitialApproval(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := newSDKContext()
	rm := NewRevocationManager(log.NewNopLogger(), &k, DefaultRevocationConfig())

	auth := RevocationAuthority{Address: testAccAddress(9), Level: AuthorityLevelAdmin}
	_ = rm.RegisterAuthority(auth)

	seal := newSealForTest(2)
	_ = k.SetSeal(context.Background(), seal)

	req := &RevocationRequest{SealID: seal.Id, Requester: auth.Address, Reason: RevocationReasonLegalOrder}
	resp, err := rm.RequestRevocation(ctx, req)
	if err != nil {
		t.Fatalf("expected request success, got %v", err)
	}
	if resp.Status != RevocationStatusPending {
		t.Fatalf("expected pending status until a second authority approval is recorded")
	}

	stored, err := rm.GetRequest(resp.RequestID)
	if err != nil {
		t.Fatalf("expected stored request, got %v", err)
	}
	if len(stored.Approvals) != 1 {
		t.Fatalf("expected requester approval to be recorded")
	}
	if stored.ProcessedAt != nil {
		t.Fatalf("expected request to remain unprocessed before quorum is met")
	}
}

func TestRevocationValidateRequest(t *testing.T) {
	rm := NewRevocationManager(log.NewNopLogger(), nil, DefaultRevocationConfig())
	longReason := strings.Repeat("x", rm.config.MaxRevocationReason+1)
	if err := rm.validateRevocationRequest(context.Background(), &RevocationRequest{ReasonDetails: longReason}); err == nil {
		t.Fatalf("expected error for long reason")
	}
}

func TestRevocationRevokeSeal(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := newSDKContext()
	rm := NewRevocationManager(log.NewNopLogger(), &k, DefaultRevocationConfig())

	seal := newSealForTest(3)
	_ = k.SetSeal(context.Background(), seal)

	if _, err := rm.RevokeSeal(ctx, seal.Id, "other", RevocationReasonFraud, "details"); err == nil {
		t.Fatalf("expected unauthorized error")
	}

	admin := RevocationAuthority{Address: testAccAddress(10), Level: AuthorityLevelAdmin}
	_ = rm.RegisterAuthority(admin)
	if _, err := rm.RevokeSeal(ctx, seal.Id, admin.Address, RevocationReasonFraud, "details"); err == nil {
		t.Fatalf("expected direct authority revoke to be rejected")
	}

	_, err := rm.RevokeSeal(ctx, seal.Id, seal.RequestedBy, RevocationReasonFraud, "details")
	if err != nil {
		t.Fatalf("expected revocation success, got %v", err)
	}

	if _, err := rm.RevokeSeal(ctx, seal.Id, seal.RequestedBy, RevocationReasonFraud, "details"); err == nil {
		t.Fatalf("expected already revoked error")
	}
}

func TestRevocationApproveAndExecuteStoredRequest(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := newSDKContext()
	cfg := DefaultRevocationConfig()
	cfg.MinDisputePeriod = 0
	cfg.RequiredAuthorityThreshold = 2
	rm := NewRevocationManager(log.NewNopLogger(), &k, cfg)

	adminA := RevocationAuthority{Address: testAccAddress(11), Level: AuthorityLevelAdmin}
	adminB := RevocationAuthority{Address: testAccAddress(12), Level: AuthorityLevelAdmin}
	_ = rm.RegisterAuthority(adminA)
	_ = rm.RegisterAuthority(adminB)

	seal := newSealForTest(30)
	_ = k.SetSeal(context.Background(), seal)

	req, err := rm.RequestRevocation(ctx, &RevocationRequest{
		SealID:    seal.Id,
		Requester: adminA.Address,
		Reason:    RevocationReasonLegalOrder,
	})
	if err != nil {
		t.Fatalf("expected request success, got %v", err)
	}
	if req.Status != RevocationStatusPending {
		t.Fatalf("expected pending status before threshold is met")
	}

	if _, err := rm.ExecuteRevocation(ctx, req.RequestID); err == nil {
		t.Fatalf("expected execute to fail before approval threshold is met")
	}

	if err := rm.ApproveRevocation(ctx, req.RequestID, adminB.Address, "co-signed"); err != nil {
		t.Fatalf("expected approval success, got %v", err)
	}

	stored, err := rm.GetRequest(req.RequestID)
	if err != nil {
		t.Fatalf("expected stored request, got %v", err)
	}
	if stored.Status != RevocationStatusApproved {
		t.Fatalf("expected approved status after threshold is met")
	}

	result, err := rm.ExecuteRevocation(ctx, req.RequestID)
	if err != nil {
		t.Fatalf("expected execute success, got %v", err)
	}
	if !result.Success {
		t.Fatalf("expected successful revocation result")
	}

	updatedSeal, err := k.GetSeal(context.Background(), seal.Id)
	if err != nil {
		t.Fatalf("expected updated seal, got %v", err)
	}
	if updatedSeal.Status != types.SealStatusRevoked {
		t.Fatalf("expected seal to be revoked")
	}
}

func TestRevocationEmergencyAndBatch(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := newSDKContext()
	rm := NewRevocationManager(log.NewNopLogger(), &k, DefaultRevocationConfig())

	seal := newSealForTest(4)
	_ = k.SetSeal(context.Background(), seal)

	if _, err := rm.EmergencyRevoke(ctx, seal.Id, "other", RevocationReasonLegalOrder, "justification"); err == nil {
		t.Fatalf("expected unauthorized emergency revoke")
	}

	auth := RevocationAuthority{Address: testAccAddress(10), Level: AuthorityLevelEmergency}
	_ = rm.RegisterAuthority(auth)

	if _, err := rm.EmergencyRevoke(ctx, seal.Id, auth.Address, RevocationReasonLegalOrder, ""); err == nil {
		t.Fatalf("expected missing emergency justification to fail")
	}

	if _, err := rm.EmergencyRevoke(ctx, seal.Id, auth.Address, RevocationReasonLegalOrder, "justification"); err != nil {
		t.Fatalf("expected emergency revoke success, got %v", err)
	}

	seal2 := newSealForTest(5)
	_ = k.SetSeal(context.Background(), seal2)

	results, err := rm.BatchRevoke(ctx, []string{seal2.Id, "missing"}, auth.Address, RevocationReasonOther, "details")
	if err != nil {
		t.Fatalf("unexpected batch revoke error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results")
	}
	if results[1].Success {
		t.Fatalf("expected failure for missing seal")
	}
}

func TestRevocationDisputeFlow(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := newSDKContext()
	cfg := DefaultRevocationConfig()
	cfg.MinDisputePeriod = time.Hour
	rm := NewRevocationManager(log.NewNopLogger(), &k, cfg)

	auth := RevocationAuthority{Address: "resolver", Level: AuthorityLevelAdmin}
	_ = rm.RegisterAuthority(auth)

	seal := newSealForTest(40)
	_ = k.SetSeal(context.Background(), seal)

	req, err := rm.RequestRevocation(ctx, &RevocationRequest{
		SealID:    seal.Id,
		Requester: auth.Address,
		Reason:    RevocationReasonLegalOrder,
	})
	if err != nil {
		t.Fatalf("expected request success, got %v", err)
	}

	dispute, err := rm.FileDispute(ctx, req.RequestID, "user", "reason")
	if err != nil {
		t.Fatalf("expected dispute created, got %v", err)
	}

	stored, err := rm.GetRequest(req.RequestID)
	if err != nil {
		t.Fatalf("expected stored request")
	}
	if stored.Status != RevocationStatusDisputed {
		t.Fatalf("expected disputed request status")
	}

	if _, err := rm.GetDispute(dispute.DisputeID); err != nil {
		t.Fatalf("expected dispute lookup")
	}

	if _, err := rm.ExecuteRevocation(ctx, req.RequestID); err == nil {
		t.Fatalf("expected execution to fail while dispute is unresolved")
	}

	if err := rm.ResolveDispute(ctx, dispute.DisputeID, "resolver", true, "cancel"); err != nil {
		t.Fatalf("expected resolve success, got %v", err)
	}

	stored, err = rm.GetRequest(req.RequestID)
	if err != nil {
		t.Fatalf("expected stored request")
	}
	if stored.Status != RevocationStatusCancelled {
		t.Fatalf("expected cancelled request after upheld dispute")
	}
}

func TestRevocationDisputeResolutionRequiresAuthority(t *testing.T) {
	rm := NewRevocationManager(log.NewNopLogger(), nil, DefaultRevocationConfig())
	ctx := newSDKContext()
	rm.disputes["disp-1"] = &RevocationDispute{DisputeID: "disp-1", RequestID: "req-1", Status: DisputeStatusOpen}

	if err := rm.ResolveDispute(ctx, "disp-1", "resolver", true, "ok"); err == nil {
		t.Fatalf("expected unauthorized resolution")
	}
}

func TestGetRevocationReasons(t *testing.T) {
	reasons := GetRevocationReasons()
	if len(reasons) == 0 {
		t.Fatalf("expected reasons")
	}
	found := false
	for _, r := range reasons {
		if r == RevocationReasonFraud {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected fraud reason")
	}
}

func TestComplianceInfoDefaults(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := context.Background()
	seal := newSealForTest(6)
	seal.RegulatoryInfo = nil
	_ = k.SetSeal(ctx, seal)

	helper := NewSDKHelper(log.NewNopLogger(), &k, nil, nil)
	info, err := helper.GetComplianceInfo(ctx, seal.Id)
	if err != nil {
		t.Fatalf("expected compliance info, got %v", err)
	}
	if info.SealID != seal.Id {
		t.Fatalf("expected seal ID in compliance info")
	}
}

func TestVerifySealBasic(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	ctx := context.Background()
	seal := newSealForTest(7)
	_ = k.SetSeal(ctx, seal)

	ok, err := k.VerifySeal(ctx, seal.Id)
	if err != nil || !ok {
		t.Fatalf("expected verify seal true")
	}

	seal.Status = types.SealStatusPending
	_ = k.SetSeal(ctx, seal)
	ok, _ = k.VerifySeal(ctx, seal.Id)
	if ok {
		t.Fatalf("expected verify seal false for pending")
	}
}
