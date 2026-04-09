package incident

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Runbook Executor
// ---------------------------------------------------------------------------
//
// Runbooks encode automated incident response procedures as executable
// step sequences. Each runbook has trigger conditions, ordered steps with
// timeouts and fallback procedures, and success criteria.
//
// Pre-built runbooks:
//   - ConsensusHalt:   Restart consensus, verify block production
//   - BridgePause:     Pause bridges, audit transfers, reconcile
//   - SecurityBreach:  Isolate systems, rotate credentials, audit
//   - DataCorruption:  Verify state, rollback if needed, re-validate
// ---------------------------------------------------------------------------

// RunbookStepAction specifies what kind of action a step performs.
type RunbookStepAction string

const (
	StepActionCommand     RunbookStepAction = "command"
	StepActionNotify      RunbookStepAction = "notify"
	StepActionVerify      RunbookStepAction = "verify"
	StepActionWait        RunbookStepAction = "wait"
	StepActionKillSwitch  RunbookStepAction = "killswitch"
	StepActionRollback    RunbookStepAction = "rollback"
)

// RunbookStep describes a single step in a runbook.
type RunbookStep struct {
	Name            string            `json:"name"`
	Action          RunbookStepAction `json:"action"`
	Command         string            `json:"command,omitempty"`
	Timeout         string            `json:"timeout"`
	SuccessCriteria string            `json:"success_criteria"`
	FallbackStep    string            `json:"fallback_step,omitempty"`
	Status          string            `json:"status"` // "pending", "executing", "completed", "failed", "skipped"
	ExecutedAt      string            `json:"executed_at,omitempty"`
	Result          string            `json:"result,omitempty"`
}

// TriggerCondition defines when a runbook should be automatically executed.
type TriggerCondition struct {
	IncidentType IncidentType     `json:"incident_type"`
	MinSeverity  IncidentSeverity `json:"min_severity"`
}

// Runbook is a complete automated response procedure.
type Runbook struct {
	ID                string             `json:"id"`
	Name              string             `json:"name"`
	Description       string             `json:"description"`
	Steps             []RunbookStep      `json:"steps"`
	TriggerConditions []TriggerCondition `json:"trigger_conditions"`
	LastExecuted      string             `json:"last_executed,omitempty"`
	ExecutionCount    int                `json:"execution_count"`
}

// Validate checks the runbook for structural completeness.
func (rb *Runbook) Validate() error {
	if rb.ID == "" {
		return fmt.Errorf("incident/runbook: ID is required")
	}
	if rb.Name == "" {
		return fmt.Errorf("incident/runbook: name is required")
	}
	if len(rb.Steps) == 0 {
		return fmt.Errorf("incident/runbook: at least one step is required")
	}
	for i, step := range rb.Steps {
		if step.Name == "" {
			return fmt.Errorf("incident/runbook: step %d missing name", i)
		}
		if step.SuccessCriteria == "" {
			return fmt.Errorf("incident/runbook: step %d (%s) missing success criteria", i, step.Name)
		}
	}
	return nil
}

// RunbookExecution tracks a single execution of a runbook.
type RunbookExecution struct {
	ID         string         `json:"id"`
	RunbookID  string         `json:"runbook_id"`
	IncidentID string         `json:"incident_id"`
	Status     string         `json:"status"` // "running", "completed", "failed"
	Steps      []RunbookStep  `json:"steps"`
	StartedAt  string         `json:"started_at"`
	CompletedAt string        `json:"completed_at,omitempty"`
}

// RunbookExecutor manages and executes runbooks.
type RunbookExecutor struct {
	mu         sync.RWMutex
	runbooks   map[string]*Runbook
	executions map[string]*RunbookExecution
	auditLog   []TimelineEntry
}

// NewRunbookExecutor creates a new executor with pre-built runbooks.
func NewRunbookExecutor() *RunbookExecutor {
	executor := &RunbookExecutor{
		runbooks:   make(map[string]*Runbook),
		executions: make(map[string]*RunbookExecution),
		auditLog:   make([]TimelineEntry, 0),
	}

	// Register pre-built runbooks.
	for _, rb := range defaultRunbooks() {
		executor.runbooks[rb.ID] = rb
	}

	return executor
}

// RegisterRunbook adds a custom runbook.
func (re *RunbookExecutor) RegisterRunbook(rb *Runbook) error {
	if err := rb.Validate(); err != nil {
		return err
	}

	re.mu.Lock()
	re.runbooks[rb.ID] = rb
	re.mu.Unlock()
	return nil
}

// GetRunbook returns a runbook by ID.
func (re *RunbookExecutor) GetRunbook(id string) (*Runbook, error) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	rb, ok := re.runbooks[id]
	if !ok {
		return nil, fmt.Errorf("incident/runbook: not found: %s", id)
	}
	return rb, nil
}

// ListRunbooks returns all registered runbooks.
func (re *RunbookExecutor) ListRunbooks() []*Runbook {
	re.mu.RLock()
	defer re.mu.RUnlock()

	result := make([]*Runbook, 0, len(re.runbooks))
	for _, rb := range re.runbooks {
		result = append(result, rb)
	}
	return result
}

// FindRunbooksForIncident returns runbooks whose trigger conditions match
// the given incident.
func (re *RunbookExecutor) FindRunbooksForIncident(inc *Incident) []*Runbook {
	re.mu.RLock()
	defer re.mu.RUnlock()

	severityOrder := map[IncidentSeverity]int{
		SeverityP0: 0,
		SeverityP1: 1,
		SeverityP2: 2,
		SeverityP3: 3,
	}

	var matches []*Runbook
	for _, rb := range re.runbooks {
		for _, tc := range rb.TriggerConditions {
			if tc.IncidentType == inc.Type {
				incSev, ok1 := severityOrder[inc.Severity]
				minSev, ok2 := severityOrder[tc.MinSeverity]
				if ok1 && ok2 && incSev <= minSev {
					matches = append(matches, rb)
					break
				}
			}
		}
	}
	return matches
}

// ExecuteRunbook executes a runbook for a given incident.
func (re *RunbookExecutor) ExecuteRunbook(_ context.Context, runbookID string, inc *Incident) (*RunbookExecution, error) {
	re.mu.Lock()
	defer re.mu.Unlock()

	rb, ok := re.runbooks[runbookID]
	if !ok {
		return nil, fmt.Errorf("incident/runbook: not found: %s", runbookID)
	}

	if inc == nil {
		return nil, fmt.Errorf("incident/runbook: nil incident")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	// Create deep copy of steps for this execution.
	steps := make([]RunbookStep, len(rb.Steps))
	copy(steps, rb.Steps)

	execution := &RunbookExecution{
		ID:         uuid.New().String(),
		RunbookID:  runbookID,
		IncidentID: inc.ID,
		Status:     "running",
		Steps:      steps,
		StartedAt:  now,
	}

	re.addAuditEntry("runbook_started", "system",
		fmt.Sprintf("Executing runbook %s (%s) for incident %s", rb.Name, runbookID, inc.ID))

	// Execute steps sequentially (simulated).
	allPassed := true
	for i := range execution.Steps {
		execution.Steps[i].Status = "executing"
		execution.Steps[i].ExecutedAt = time.Now().UTC().Format(time.RFC3339Nano)

		// Simulated execution: all steps pass.
		execution.Steps[i].Status = "completed"
		execution.Steps[i].Result = "success"
	}

	if allPassed {
		execution.Status = "completed"
	} else {
		execution.Status = "failed"
	}
	execution.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)

	// Update runbook metadata.
	rb.LastExecuted = now
	rb.ExecutionCount++

	re.executions[execution.ID] = execution

	re.addAuditEntry("runbook_completed", "system",
		fmt.Sprintf("Runbook %s completed with status: %s", rb.Name, execution.Status))

	return execution, nil
}

// GetExecution returns a runbook execution by ID.
func (re *RunbookExecutor) GetExecution(id string) (*RunbookExecution, error) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	exec, ok := re.executions[id]
	if !ok {
		return nil, fmt.Errorf("incident/runbook: execution not found: %s", id)
	}
	return exec, nil
}

// GetAuditLog returns the runbook executor audit log.
func (re *RunbookExecutor) GetAuditLog() []TimelineEntry {
	re.mu.RLock()
	defer re.mu.RUnlock()

	result := make([]TimelineEntry, len(re.auditLog))
	copy(result, re.auditLog)
	return result
}

func (re *RunbookExecutor) addAuditEntry(action, actor, description string) {
	entry := TimelineEntry{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		Action:      action,
		Actor:       actor,
		Description: description,
	}
	entry.Hash = entry.computeHash()
	re.auditLog = append(re.auditLog, entry)
}

// ---------------------------------------------------------------------------
// Pre-built runbooks
// ---------------------------------------------------------------------------

func defaultRunbooks() []*Runbook {
	return []*Runbook{
		consensusHaltRunbook(),
		bridgePauseRunbook(),
		securityBreachRunbook(),
		dataCorruptionRunbook(),
	}
}

func consensusHaltRunbook() *Runbook {
	return &Runbook{
		ID:          "runbook-consensus-halt",
		Name:        "Consensus Halt Response",
		Description: "Automated response for consensus halt incidents. Diagnoses the halt, attempts restart, and escalates if unresolved.",
		TriggerConditions: []TriggerCondition{
			{IncidentType: IncidentConsensusHalt, MinSeverity: SeverityP1},
		},
		Steps: []RunbookStep{
			{
				Name:            "diagnose_halt",
				Action:          StepActionCommand,
				Command:         "aethelred consensus diagnose",
				Timeout:         "2m",
				SuccessCriteria: "diagnosis_complete",
			},
			{
				Name:            "restart_consensus",
				Action:          StepActionCommand,
				Command:         "aethelred consensus restart --safe",
				Timeout:         "5m",
				SuccessCriteria: "block_production_resumed",
				FallbackStep:    "escalate_to_on_call",
			},
			{
				Name:            "verify_block_production",
				Action:          StepActionVerify,
				Command:         "aethelred status --check blocks",
				Timeout:         "3m",
				SuccessCriteria: "new_blocks_produced",
			},
			{
				Name:            "notify_validators",
				Action:          StepActionNotify,
				Command:         "aethelred notify validators --incident consensus-halt",
				Timeout:         "1m",
				SuccessCriteria: "notifications_sent",
			},
		},
	}
}

func bridgePauseRunbook() *Runbook {
	return &Runbook{
		ID:          "runbook-bridge-pause",
		Name:        "Bridge Pause Response",
		Description: "Automated response for bridge pause incidents. Pauses all bridges, audits pending transfers, and initiates reconciliation.",
		TriggerConditions: []TriggerCondition{
			{IncidentType: IncidentBridgePause, MinSeverity: SeverityP1},
		},
		Steps: []RunbookStep{
			{
				Name:            "pause_all_bridges",
				Action:          StepActionKillSwitch,
				Command:         "aethelred bridge pause --all",
				Timeout:         "30s",
				SuccessCriteria: "all_bridges_paused",
			},
			{
				Name:            "audit_pending_transfers",
				Action:          StepActionCommand,
				Command:         "aethelred bridge audit-pending --export",
				Timeout:         "5m",
				SuccessCriteria: "audit_complete",
			},
			{
				Name:            "assess_damage",
				Action:          StepActionCommand,
				Command:         "aethelred bridge damage-assessment",
				Timeout:         "10m",
				SuccessCriteria: "assessment_complete",
			},
			{
				Name:            "notify_affected_users",
				Action:          StepActionNotify,
				Command:         "aethelred notify users --affected-bridges",
				Timeout:         "2m",
				SuccessCriteria: "notifications_sent",
			},
		},
	}
}

func securityBreachRunbook() *Runbook {
	return &Runbook{
		ID:          "runbook-security-breach",
		Name:        "Security Breach Response",
		Description: "Automated response for security breach incidents. Isolates affected systems, rotates credentials, and initiates forensic analysis.",
		TriggerConditions: []TriggerCondition{
			{IncidentType: IncidentSecurityBreach, MinSeverity: SeverityP2},
		},
		Steps: []RunbookStep{
			{
				Name:            "isolate_affected_systems",
				Action:          StepActionKillSwitch,
				Command:         "aethelred security isolate --scope affected",
				Timeout:         "1m",
				SuccessCriteria: "systems_isolated",
			},
			{
				Name:            "rotate_credentials",
				Action:          StepActionCommand,
				Command:         "aethelred security rotate-keys --emergency",
				Timeout:         "5m",
				SuccessCriteria: "credentials_rotated",
			},
			{
				Name:            "preserve_evidence",
				Action:          StepActionCommand,
				Command:         "aethelred security snapshot --forensic",
				Timeout:         "10m",
				SuccessCriteria: "evidence_preserved",
			},
			{
				Name:            "initiate_forensics",
				Action:          StepActionCommand,
				Command:         "aethelred security analyze --deep",
				Timeout:         "30m",
				SuccessCriteria: "analysis_started",
			},
			{
				Name:            "notify_security_team",
				Action:          StepActionNotify,
				Command:         "aethelred notify security --incident breach --priority critical",
				Timeout:         "1m",
				SuccessCriteria: "team_notified",
			},
		},
	}
}

func dataCorruptionRunbook() *Runbook {
	return &Runbook{
		ID:          "runbook-data-corruption",
		Name:        "Data Corruption Response",
		Description: "Automated response for data corruption incidents. Verifies state integrity, initiates rollback if needed, and re-validates.",
		TriggerConditions: []TriggerCondition{
			{IncidentType: IncidentDataCorruption, MinSeverity: SeverityP1},
		},
		Steps: []RunbookStep{
			{
				Name:            "pause_writes",
				Action:          StepActionKillSwitch,
				Command:         "aethelred state pause-writes",
				Timeout:         "30s",
				SuccessCriteria: "writes_paused",
			},
			{
				Name:            "verify_state_integrity",
				Action:          StepActionVerify,
				Command:         "aethelred state verify --full",
				Timeout:         "15m",
				SuccessCriteria: "integrity_check_complete",
			},
			{
				Name:            "identify_corruption_scope",
				Action:          StepActionCommand,
				Command:         "aethelred state diff --against-backup",
				Timeout:         "10m",
				SuccessCriteria: "scope_identified",
			},
			{
				Name:            "rollback_if_needed",
				Action:          StepActionRollback,
				Command:         "aethelred state rollback --to-last-good",
				Timeout:         "20m",
				SuccessCriteria: "state_restored",
				FallbackStep:    "manual_recovery",
			},
			{
				Name:            "re_validate",
				Action:          StepActionVerify,
				Command:         "aethelred state verify --full --post-recovery",
				Timeout:         "15m",
				SuccessCriteria: "state_valid",
			},
		},
	}
}
