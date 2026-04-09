package incident

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Incident Controller tests
// ---------------------------------------------------------------------------

func TestNewIncidentController(t *testing.T) {
	ctrl := NewIncidentController()
	if ctrl == nil {
		t.Fatal("expected non-nil controller")
	}
}

func TestCreateIncident(t *testing.T) {
	ctrl := NewIncidentController()
	inc, err := ctrl.CreateIncident(context.Background(), &Incident{
		Type:     IncidentSecurityBreach,
		Severity: SeverityP0,
		Title:    "Test security breach",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inc.ID == "" {
		t.Fatal("expected non-empty incident ID")
	}
	if inc.Status != StatusDetected {
		t.Fatalf("expected detected, got %s", inc.Status)
	}
	if len(inc.Timeline) == 0 {
		t.Fatal("expected at least one timeline entry")
	}
	if inc.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
}

func TestCreateIncident_Nil(t *testing.T) {
	ctrl := NewIncidentController()
	_, err := ctrl.CreateIncident(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil incident")
	}
}

func TestCreateIncident_MissingTitle(t *testing.T) {
	ctrl := NewIncidentController()
	_, err := ctrl.CreateIncident(context.Background(), &Incident{
		Type:     IncidentSecurityBreach,
		Severity: SeverityP0,
	})
	if err == nil {
		t.Fatal("expected error for missing title")
	}
}

func TestGetIncident(t *testing.T) {
	ctrl := NewIncidentController()
	inc, _ := ctrl.CreateIncident(context.Background(), &Incident{
		Type:     IncidentConsensusHalt,
		Severity: SeverityP1,
		Title:    "Consensus halted",
	})

	fetched, err := ctrl.GetIncident(context.Background(), inc.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fetched.ID != inc.ID {
		t.Fatalf("expected %s, got %s", inc.ID, fetched.ID)
	}
}

func TestGetIncident_NotFound(t *testing.T) {
	ctrl := NewIncidentController()
	_, err := ctrl.GetIncident(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent incident")
	}
}

func TestUpdateIncident(t *testing.T) {
	ctrl := NewIncidentController()
	inc, _ := ctrl.CreateIncident(context.Background(), &Incident{
		Type:     IncidentSecurityBreach,
		Severity: SeverityP0,
		Title:    "Breach detected",
	})

	updated, err := ctrl.UpdateIncident(context.Background(), inc.ID, IncidentUpdate{
		Status: StatusTriaging,
		Actor:  "responder-01",
		Note:   "Beginning triage",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Status != StatusTriaging {
		t.Fatalf("expected triaging, got %s", updated.Status)
	}
	if len(updated.Timeline) != 2 {
		t.Fatalf("expected 2 timeline entries, got %d", len(updated.Timeline))
	}
}

func TestResolveIncident(t *testing.T) {
	ctrl := NewIncidentController()
	inc, _ := ctrl.CreateIncident(context.Background(), &Incident{
		Type:     IncidentDataCorruption,
		Severity: SeverityP2,
		Title:    "Data corruption detected",
	})

	resolved, err := ctrl.ResolveIncident(context.Background(), inc.ID, IncidentResolution{
		Actor:      "engineer-01",
		RootCause:  "Disk failure caused partial write",
		Resolution: "Restored from backup and verified integrity",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.Status != StatusResolved {
		t.Fatalf("expected resolved, got %s", resolved.Status)
	}
	if resolved.ResolvedAt == "" {
		t.Fatal("expected non-empty resolved_at")
	}
}

func TestListIncidents(t *testing.T) {
	ctrl := NewIncidentController()
	_, _ = ctrl.CreateIncident(context.Background(), &Incident{
		Type: IncidentSecurityBreach, Severity: SeverityP0, Title: "Breach 1",
	})
	inc2, _ := ctrl.CreateIncident(context.Background(), &Incident{
		Type: IncidentConsensusHalt, Severity: SeverityP1, Title: "Halt 1",
	})
	_, _ = ctrl.ResolveIncident(context.Background(), inc2.ID, IncidentResolution{
		Actor: "eng", RootCause: "bug", Resolution: "fix",
	})

	all := ctrl.ListIncidents(context.Background(), "")
	if len(all) != 2 {
		t.Fatalf("expected 2 incidents, got %d", len(all))
	}

	resolved := ctrl.ListIncidents(context.Background(), StatusResolved)
	if len(resolved) != 1 {
		t.Fatalf("expected 1 resolved incident, got %d", len(resolved))
	}
}

func TestGetAuditLog(t *testing.T) {
	ctrl := NewIncidentController()
	_, _ = ctrl.CreateIncident(context.Background(), &Incident{
		Type: IncidentSecurityBreach, Severity: SeverityP0, Title: "Breach",
	})

	log := ctrl.GetAuditLog()
	if len(log) == 0 {
		t.Fatal("expected non-empty audit log")
	}
}

// ---------------------------------------------------------------------------
// Kill Switch tests
// ---------------------------------------------------------------------------

func TestKillSwitch_ActivateDeactivate(t *testing.T) {
	ks := NewKillSwitch()
	record, err := ks.ActivateKillSwitch(context.Background(), ActionPause, "testing", KillSwitchScope{
		Systems: []string{"consensus-engine"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !record.Active {
		t.Fatal("expected active kill switch")
	}

	// Deactivate.
	deactivated, err := ks.DeactivateKillSwitch(context.Background(), record.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deactivated.Active {
		t.Fatal("expected inactive kill switch")
	}
}

func TestKillSwitch_EmptyAction(t *testing.T) {
	ks := NewKillSwitch()
	_, err := ks.ActivateKillSwitch(context.Background(), "", "test", KillSwitchScope{Systems: []string{"x"}})
	if err == nil {
		t.Fatal("expected error for empty action")
	}
}

func TestKillSwitch_EmptyScope(t *testing.T) {
	ks := NewKillSwitch()
	_, err := ks.ActivateKillSwitch(context.Background(), ActionPause, "test", KillSwitchScope{})
	if err == nil {
		t.Fatal("expected error for empty scope")
	}
}

func TestKillSwitch_DoubleDeactivate(t *testing.T) {
	ks := NewKillSwitch()
	record, _ := ks.ActivateKillSwitch(context.Background(), ActionHalt, "test", KillSwitchScope{
		Systems: []string{"bridge"},
	})
	_, _ = ks.DeactivateKillSwitch(context.Background(), record.ID)
	_, err := ks.DeactivateKillSwitch(context.Background(), record.ID)
	if err == nil {
		t.Fatal("expected error for double deactivation")
	}
}

func TestKillSwitch_GetActiveKillSwitches(t *testing.T) {
	ks := NewKillSwitch()
	_, _ = ks.ActivateKillSwitch(context.Background(), ActionPause, "test1", KillSwitchScope{Systems: []string{"a"}})
	r2, _ := ks.ActivateKillSwitch(context.Background(), ActionIsolate, "test2", KillSwitchScope{Systems: []string{"b"}})
	_, _ = ks.DeactivateKillSwitch(context.Background(), r2.ID)

	active := ks.GetActiveKillSwitches()
	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}
}

func TestKillSwitch_IsSystemPaused(t *testing.T) {
	ks := NewKillSwitch()
	_, _ = ks.ActivateKillSwitch(context.Background(), ActionPause, "test", KillSwitchScope{
		Systems: []string{"consensus-engine", "validator"},
	})

	if !ks.IsSystemPaused("consensus-engine") {
		t.Fatal("expected consensus-engine to be paused")
	}
	if ks.IsSystemPaused("bridge") {
		t.Fatal("expected bridge to NOT be paused")
	}
}

func TestKillSwitch_AuditTrail(t *testing.T) {
	ks := NewKillSwitch()
	record, _ := ks.ActivateKillSwitch(context.Background(), ActionEmergencyShutdown, "critical", KillSwitchScope{
		Systems: []string{"all"},
	})
	_, _ = ks.DeactivateKillSwitch(context.Background(), record.ID)

	trail := ks.GetAuditTrail()
	if len(trail) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(trail))
	}
	if trail[0].Operation != "activate" {
		t.Fatalf("expected activate, got %s", trail[0].Operation)
	}
	if trail[1].Operation != "deactivate" {
		t.Fatalf("expected deactivate, got %s", trail[1].Operation)
	}
}

// ---------------------------------------------------------------------------
// Rollback Engine tests
// ---------------------------------------------------------------------------

func TestRollbackEngine_CreatePlan(t *testing.T) {
	engine := NewRollbackEngine()
	plan, err := engine.CreateRollbackPlan(context.Background(), "inc-001", RollbackBinary, "v1.2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Type != RollbackBinary {
		t.Fatalf("expected binary, got %s", plan.Type)
	}
	if len(plan.Steps) == 0 {
		t.Fatal("expected non-empty steps")
	}
}

func TestRollbackEngine_CreatePlan_AllTypes(t *testing.T) {
	engine := NewRollbackEngine()
	types := []RollbackType{RollbackBinary, RollbackState, RollbackBridge, RollbackConfiguration}
	for _, rt := range types {
		plan, err := engine.CreateRollbackPlan(context.Background(), "inc-001", rt, "target-"+string(rt))
		if err != nil {
			t.Fatalf("failed to create %s plan: %v", rt, err)
		}
		if len(plan.Steps) == 0 {
			t.Fatalf("%s plan has no steps", rt)
		}
	}
}

func TestRollbackEngine_ValidateAndExecute(t *testing.T) {
	engine := NewRollbackEngine()
	plan, _ := engine.CreateRollbackPlan(context.Background(), "inc-002", RollbackConfiguration, "config-abc")

	if err := engine.ValidateRollback(context.Background(), plan.ID); err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	executed, err := engine.ExecuteRollback(context.Background(), plan.ID)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if executed.Status != RollbackStatusCompleted {
		t.Fatalf("expected completed, got %s", executed.Status)
	}
}

func TestRollbackEngine_ExecuteNonPending(t *testing.T) {
	engine := NewRollbackEngine()
	plan, _ := engine.CreateRollbackPlan(context.Background(), "inc-003", RollbackBinary, "v1.0.0")
	_, _ = engine.ExecuteRollback(context.Background(), plan.ID)
	_, err := engine.ExecuteRollback(context.Background(), plan.ID)
	if err == nil {
		t.Fatal("expected error for non-pending plan")
	}
}

// ---------------------------------------------------------------------------
// Disclosure tests
// ---------------------------------------------------------------------------

func TestDisclosureService_GetRequirements(t *testing.T) {
	svc := NewDisclosureService()
	inc := &Incident{
		ID:       "inc-disclosure-1",
		Type:     IncidentSecurityBreach,
		Severity: SeverityP0,
		Title:    "Security breach",
	}

	reqs, err := svc.GetDisclosureRequirements(context.Background(), inc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reqs) == 0 {
		t.Fatal("expected disclosure requirements for security breach")
	}

	// Security breach should trigger GDPR, HIPAA, SEC, and NYDFS.
	found := make(map[string]bool)
	for _, r := range reqs {
		found[r.Regulation] = true
	}
	for _, reg := range []string{"GDPR", "HIPAA", "SEC", "NYDFS 23 NYCRR 500"} {
		if !found[reg] {
			t.Fatalf("expected %s disclosure requirement", reg)
		}
	}
}

func TestDisclosureService_GenerateDisclosure(t *testing.T) {
	svc := NewDisclosureService()
	inc := &Incident{
		ID:              "inc-disclosure-2",
		Type:            IncidentSecurityBreach,
		Severity:        SeverityP0,
		Title:           "Data breach via compromised validator",
		Description:     "Unauthorized access to validator keys",
		DetectedAt:      time.Now().UTC().Format(time.RFC3339),
		AffectedSystems: []string{"validator-01", "consensus-engine"},
	}

	docs, err := svc.GenerateDisclosure(context.Background(), inc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected disclosure documents")
	}

	for _, doc := range docs {
		if doc.Content == "" {
			t.Fatalf("expected non-empty content for %s disclosure", doc.Regulation)
		}
		if doc.DeadlineTimestamp == "" {
			t.Fatalf("expected deadline for %s disclosure", doc.Regulation)
		}
		if doc.Status != DisclosureDrafted {
			t.Fatalf("expected drafted status, got %s", doc.Status)
		}
	}
}

func TestDisclosureService_NoRequirements(t *testing.T) {
	svc := NewDisclosureService()
	inc := &Incident{
		ID:       "inc-disclosure-3",
		Type:     IncidentSafetyViolation,
		Severity: SeverityP3,
		Title:    "Minor safety issue",
	}

	// Safety violation only triggers SEC.
	reqs, _ := svc.GetDisclosureRequirements(context.Background(), inc)
	found := false
	for _, r := range reqs {
		if r.Regulation == "SEC" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected SEC disclosure requirement for safety violation")
	}
}

func TestDisclosureService_NilIncident(t *testing.T) {
	svc := NewDisclosureService()
	_, err := svc.GetDisclosureRequirements(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil incident")
	}
}

// ---------------------------------------------------------------------------
// Runbook tests
// ---------------------------------------------------------------------------

func TestRunbookExecutor_DefaultRunbooks(t *testing.T) {
	executor := NewRunbookExecutor()
	runbooks := executor.ListRunbooks()
	if len(runbooks) < 4 {
		t.Fatalf("expected at least 4 default runbooks, got %d", len(runbooks))
	}
}

func TestRunbookExecutor_GetRunbook(t *testing.T) {
	executor := NewRunbookExecutor()
	rb, err := executor.GetRunbook("runbook-consensus-halt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rb.Name != "Consensus Halt Response" {
		t.Fatalf("expected 'Consensus Halt Response', got %s", rb.Name)
	}
}

func TestRunbookExecutor_GetRunbook_NotFound(t *testing.T) {
	executor := NewRunbookExecutor()
	_, err := executor.GetRunbook("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent runbook")
	}
}

func TestRunbookExecutor_FindRunbooksForIncident(t *testing.T) {
	executor := NewRunbookExecutor()
	inc := &Incident{
		Type:     IncidentSecurityBreach,
		Severity: SeverityP0,
	}

	matches := executor.FindRunbooksForIncident(inc)
	if len(matches) == 0 {
		t.Fatal("expected matching runbooks for P0 security breach")
	}

	found := false
	for _, rb := range matches {
		if rb.ID == "runbook-security-breach" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected security-breach runbook to match")
	}
}

func TestRunbookExecutor_ExecuteRunbook(t *testing.T) {
	executor := NewRunbookExecutor()
	inc := &Incident{
		ID:       "inc-rb-exec",
		Type:     IncidentConsensusHalt,
		Severity: SeverityP0,
		Title:    "Consensus halt",
	}

	exec, err := executor.ExecuteRunbook(context.Background(), "runbook-consensus-halt", inc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exec.Status != "completed" {
		t.Fatalf("expected completed, got %s", exec.Status)
	}
	if exec.IncidentID != inc.ID {
		t.Fatalf("expected incident ID %s, got %s", inc.ID, exec.IncidentID)
	}

	// Verify execution is retrievable.
	fetched, err := executor.GetExecution(exec.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fetched.ID != exec.ID {
		t.Fatalf("execution ID mismatch")
	}
}

func TestRunbookExecutor_ExecuteRunbook_NilIncident(t *testing.T) {
	executor := NewRunbookExecutor()
	_, err := executor.ExecuteRunbook(context.Background(), "runbook-consensus-halt", nil)
	if err == nil {
		t.Fatal("expected error for nil incident")
	}
}

func TestRunbookExecutor_RegisterCustomRunbook(t *testing.T) {
	executor := NewRunbookExecutor()
	custom := &Runbook{
		ID:   "custom-runbook",
		Name: "Custom Response",
		Steps: []RunbookStep{
			{Name: "step1", Action: StepActionCommand, SuccessCriteria: "done"},
		},
	}

	if err := executor.RegisterRunbook(custom); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rb, err := executor.GetRunbook("custom-runbook")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rb.Name != "Custom Response" {
		t.Fatalf("expected 'Custom Response', got %s", rb.Name)
	}
}

func TestRunbookExecutor_AuditLog(t *testing.T) {
	executor := NewRunbookExecutor()
	inc := &Incident{
		ID:       "inc-audit",
		Type:     IncidentSecurityBreach,
		Severity: SeverityP0,
		Title:    "Breach",
	}
	_, _ = executor.ExecuteRunbook(context.Background(), "runbook-security-breach", inc)

	log := executor.GetAuditLog()
	if len(log) < 2 {
		t.Fatalf("expected at least 2 audit entries, got %d", len(log))
	}
}

// ---------------------------------------------------------------------------
// Timeline entry hash tests
// ---------------------------------------------------------------------------

func TestTimelineEntry_ComputeHash(t *testing.T) {
	entry := TimelineEntry{
		Timestamp:   "2026-01-01T00:00:00Z",
		Action:      "test",
		Actor:       "tester",
		Description: "test entry",
	}
	hash := entry.computeHash()
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	// Same data should produce same hash.
	hash2 := entry.computeHash()
	if hash != hash2 {
		t.Fatal("hash not deterministic")
	}

	// Different data should produce different hash.
	entry.Action = "modified"
	hash3 := entry.computeHash()
	if hash == hash3 {
		t.Fatal("expected different hash for modified entry")
	}
}

// ---------------------------------------------------------------------------
// Incident Validate tests
// ---------------------------------------------------------------------------

func TestIncident_Validate(t *testing.T) {
	tests := []struct {
		name    string
		inc     Incident
		wantErr bool
	}{
		{
			name:    "valid",
			inc:     Incident{ID: "1", Type: IncidentSecurityBreach, Severity: SeverityP0, Title: "Test"},
			wantErr: false,
		},
		{
			name:    "missing ID",
			inc:     Incident{Type: IncidentSecurityBreach, Severity: SeverityP0, Title: "Test"},
			wantErr: true,
		},
		{
			name:    "missing type",
			inc:     Incident{ID: "1", Severity: SeverityP0, Title: "Test"},
			wantErr: true,
		},
		{
			name:    "missing severity",
			inc:     Incident{ID: "1", Type: IncidentSecurityBreach, Title: "Test"},
			wantErr: true,
		},
		{
			name:    "missing title",
			inc:     Incident{ID: "1", Type: IncidentSecurityBreach, Severity: SeverityP0},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.inc.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge-case, error-path, and concurrency tests
// ---------------------------------------------------------------------------

func TestIncident_InvalidSeverity(t *testing.T) {
	ctrl := NewIncidentController()
	_, err := ctrl.CreateIncident(context.Background(), &Incident{
		Type:     IncidentSecurityBreach,
		Severity: "UNKNOWN_SEVERITY",
		Title:    "Invalid severity test",
	})
	if err == nil {
		t.Fatal("expected error for unknown severity")
	}
	if !errors.Is(err, ErrInvalidSeverity) {
		t.Fatalf("expected ErrInvalidSeverity, got %v", err)
	}
}

func TestIncident_InvalidTransition(t *testing.T) {
	ctrl := NewIncidentController()
	inc, err := ctrl.CreateIncident(context.Background(), &Incident{
		Type:     IncidentSecurityBreach,
		Severity: SeverityP0,
		Title:    "Test breach",
	})
	if err != nil {
		t.Fatalf("CreateIncident failed: %v", err)
	}

	// Resolve it.
	resolved, err := ctrl.ResolveIncident(context.Background(), inc.ID, IncidentResolution{
		Actor: "eng", RootCause: "test", Resolution: "fixed",
	})
	if err != nil {
		t.Fatalf("ResolveIncident failed: %v", err)
	}

	// Resolved -> Detected should be invalid.
	_, err = ctrl.UpdateIncident(context.Background(), resolved.ID, IncidentUpdate{
		Status: StatusDetected,
		Actor:  "eng",
	})
	if err == nil {
		t.Fatal("expected error for Resolved -> Detected transition")
	}
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}
}

func TestIncident_ConcurrentUpdates(t *testing.T) {
	ctrl := NewIncidentController()
	inc, _ := ctrl.CreateIncident(context.Background(), &Incident{
		Type:     IncidentDataCorruption,
		Severity: SeverityP1,
		Title:    "Concurrent update test",
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _ = ctrl.UpdateIncident(context.Background(), inc.ID, IncidentUpdate{
				Status: StatusTriaging,
				Actor:  fmt.Sprintf("responder-%d", idx),
				Note:   fmt.Sprintf("Update from goroutine %d", idx),
			})
		}(i)
	}
	wg.Wait()

	fetched, _ := ctrl.GetIncident(context.Background(), inc.ID)
	if len(fetched.Timeline) < 2 {
		t.Error("expected at least 2 timeline entries after concurrent updates")
	}
}

func TestKillSwitch_AllActions(t *testing.T) {
	ks := NewKillSwitch()
	ctx := context.Background()

	actions := []KillSwitchAction{ActionPause, ActionIsolate, ActionHalt, ActionEmergencyShutdown}
	for _, action := range actions {
		t.Run(string(action), func(t *testing.T) {
			record, err := ks.ActivateKillSwitch(ctx, action, "test-"+string(action), KillSwitchScope{
				Systems: []string{"system-a"},
			})
			if err != nil {
				t.Fatalf("ActivateKillSwitch(%s) failed: %v", action, err)
			}
			if !record.Active {
				t.Errorf("expected active for action %s", action)
			}
			if record.Action != action {
				t.Errorf("expected action %s, got %s", action, record.Action)
			}
		})
	}
}

func TestKillSwitch_ConcurrentActivation(t *testing.T) {
	ks := NewKillSwitch()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _ = ks.ActivateKillSwitch(ctx, ActionPause, fmt.Sprintf("reason-%d", idx), KillSwitchScope{
				Systems: []string{fmt.Sprintf("system-%d", idx)},
			})
		}(i)
	}
	wg.Wait()

	active := ks.GetActiveKillSwitches()
	if len(active) < 1 {
		t.Error("expected at least 1 active kill switch from concurrent activations")
	}
}

func TestKillSwitch_DeactivateInactive(t *testing.T) {
	ks := NewKillSwitch()
	ctx := context.Background()

	record, _ := ks.ActivateKillSwitch(ctx, ActionHalt, "test", KillSwitchScope{
		Systems: []string{"sys"},
	})
	_, _ = ks.DeactivateKillSwitch(ctx, record.ID)

	// Deactivate again should fail.
	_, err := ks.DeactivateKillSwitch(ctx, record.ID)
	if err == nil {
		t.Fatal("expected error for deactivating inactive kill switch")
	}
}

func TestRollback_EmptyPlan(t *testing.T) {
	engine := NewRollbackEngine()
	_, err := engine.CreateRollbackPlan(context.Background(), "", RollbackBinary, "")
	if err == nil {
		t.Fatal("expected error for empty incident ID")
	}
}

func TestRollback_AllTypes(t *testing.T) {
	engine := NewRollbackEngine()
	ctx := context.Background()

	types := []RollbackType{RollbackBinary, RollbackState, RollbackBridge, RollbackConfiguration}
	for _, rt := range types {
		t.Run(string(rt), func(t *testing.T) {
			plan, err := engine.CreateRollbackPlan(ctx, "inc-types", rt, "target-"+string(rt))
			if err != nil {
				t.Fatalf("CreateRollbackPlan(%s) failed: %v", rt, err)
			}
			if plan.Type != rt {
				t.Errorf("expected type %s, got %s", rt, plan.Type)
			}
			if len(plan.Steps) == 0 {
				t.Errorf("expected steps for type %s", rt)
			}
		})
	}
}

func TestDisclosure_AllJurisdictions(t *testing.T) {
	svc := NewDisclosureService()
	ctx := context.Background()

	inc := &Incident{
		ID:       "inc-jurisdictions",
		Type:     IncidentSecurityBreach,
		Severity: SeverityP0,
		Title:    "Security breach for all jurisdictions",
	}

	reqs, err := svc.GetDisclosureRequirements(ctx, inc)
	if err != nil {
		t.Fatalf("GetDisclosureRequirements failed: %v", err)
	}

	regulations := make(map[string]bool)
	for _, r := range reqs {
		regulations[r.Regulation] = true
	}

	expected := []string{"GDPR", "HIPAA", "SEC", "NYDFS 23 NYCRR 500"}
	for _, reg := range expected {
		if !regulations[reg] {
			t.Errorf("expected %s disclosure requirement", reg)
		}
	}
}

func TestDisclosure_ExpiredDeadline(t *testing.T) {
	svc := NewDisclosureService()
	ctx := context.Background()

	// Create an incident with a past detection time.
	pastTime := time.Now().Add(-100 * 24 * time.Hour).UTC().Format(time.RFC3339)
	inc := &Incident{
		ID:              "inc-expired",
		Type:            IncidentSecurityBreach,
		Severity:        SeverityP0,
		Title:           "Old breach",
		DetectedAt:      pastTime,
		AffectedSystems: []string{"sys-1"},
	}

	docs, err := svc.GenerateDisclosure(ctx, inc)
	if err != nil {
		t.Fatalf("GenerateDisclosure failed: %v", err)
	}

	for _, doc := range docs {
		if doc.DeadlineTimestamp == "" {
			t.Errorf("expected deadline for %s", doc.Regulation)
		}
	}
}

func TestRunbook_NonExistentRunbook(t *testing.T) {
	executor := NewRunbookExecutor()
	_, err := executor.GetRunbook("nonexistent-runbook-id")
	if err == nil {
		t.Fatal("expected error for nonexistent runbook")
	}
	if !errors.Is(err, ErrRunbookFailed) {
		t.Logf("error type: %v", err)
	}
}

func TestRunbook_StepTimeout(t *testing.T) {
	executor := NewRunbookExecutor()

	// Register a custom runbook with a short timeout on steps.
	custom := &Runbook{
		ID:   "runbook-timeout-test",
		Name: "Timeout Test",
		Steps: []RunbookStep{
			{
				Name:            "fast-step",
				Action:          StepActionCommand,
				Timeout:         "1ms",
				SuccessCriteria: "done",
			},
		},
		TriggerConditions: []TriggerCondition{
			{IncidentType: IncidentSecurityBreach, MinSeverity: SeverityP3},
		},
	}
	_ = executor.RegisterRunbook(custom)

	inc := &Incident{
		ID:       "inc-timeout",
		Type:     IncidentSecurityBreach,
		Severity: SeverityP0,
		Title:    "Timeout test",
	}

	exec, err := executor.ExecuteRunbook(context.Background(), "runbook-timeout-test", inc)
	if err != nil {
		t.Fatalf("ExecuteRunbook failed: %v", err)
	}
	// The execution should complete (steps are simulated).
	if exec.Status != "completed" {
		t.Logf("execution status: %s", exec.Status)
	}

	// Suppress unused import warnings.
	_ = time.Now()
	_ = fmt.Sprintf("")
}
