package incident

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Automated Rollback Engine
// ---------------------------------------------------------------------------
//
// The rollback engine creates and executes rollback plans for incident
// recovery. Each rollback type has specific verification criteria and
// fallback procedures.
//
// Rollback types:
//   - Binary:        Roll back to a previous software version
//   - State:         Revert on-chain state to a known-good snapshot
//   - Bridge:        Roll back bridge operations and pending transfers
//   - Configuration: Revert configuration changes
// ---------------------------------------------------------------------------

// RollbackType classifies the kind of rollback being performed.
type RollbackType string

const (
	RollbackBinary        RollbackType = "binary"
	RollbackState         RollbackType = "state"
	RollbackBridge        RollbackType = "bridge"
	RollbackConfiguration RollbackType = "configuration"
)

// RollbackStatus tracks the execution state of a rollback.
type RollbackStatus string

const (
	RollbackStatusPending    RollbackStatus = "pending"
	RollbackStatusExecuting  RollbackStatus = "executing"
	RollbackStatusVerifying  RollbackStatus = "verifying"
	RollbackStatusCompleted  RollbackStatus = "completed"
	RollbackStatusFailed     RollbackStatus = "failed"
	RollbackStatusRolledBack RollbackStatus = "rolled_back" // Rollback of the rollback.
)

// RollbackStep describes a single step in a rollback plan.
type RollbackStep struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	Command         string `json:"command"`
	Timeout         string `json:"timeout"` // Duration string.
	SuccessCriteria string `json:"success_criteria"`
	FallbackStep    string `json:"fallback_step,omitempty"`
	Status          string `json:"status"`
	ExecutedAt      string `json:"executed_at,omitempty"`
	Result          string `json:"result,omitempty"`
}

// RollbackPlan describes a complete rollback procedure.
type RollbackPlan struct {
	ID           string         `json:"id"`
	IncidentID   string         `json:"incident_id"`
	Type         RollbackType   `json:"type"`
	Target       string         `json:"target"` // Target version, state hash, or config ID.
	Status       RollbackStatus `json:"status"`
	Steps        []RollbackStep `json:"steps"`
	Verification []string       `json:"verification"` // Post-rollback verification checks.
	Fallback     string         `json:"fallback,omitempty"` // Fallback plan ID.
	CreatedAt    string         `json:"created_at"`
	CompletedAt  string         `json:"completed_at,omitempty"`
	ExecutedBy   string         `json:"executed_by,omitempty"`
}

// Validate checks the rollback plan for completeness.
func (rp *RollbackPlan) Validate() error {
	if rp.ID == "" {
		return fmt.Errorf("incident/rollback: plan ID is required")
	}
	if rp.Type == "" {
		return fmt.Errorf("incident/rollback: rollback type is required")
	}
	if rp.Target == "" {
		return fmt.Errorf("incident/rollback: target is required")
	}
	if len(rp.Steps) == 0 {
		return fmt.Errorf("incident/rollback: at least one step is required")
	}
	return nil
}

// RollbackEngine creates and executes rollback plans.
type RollbackEngine struct {
	mu       sync.RWMutex
	plans    map[string]*RollbackPlan
	auditLog []TimelineEntry
}

// NewRollbackEngine creates a new rollback engine.
func NewRollbackEngine() *RollbackEngine {
	return &RollbackEngine{
		plans:    make(map[string]*RollbackPlan),
		auditLog: make([]TimelineEntry, 0),
	}
}

// CreateRollbackPlan creates a rollback plan based on the incident type.
func (re *RollbackEngine) CreateRollbackPlan(_ context.Context, incidentID string, rollbackType RollbackType, target string) (*RollbackPlan, error) {
	if incidentID == "" {
		return nil, fmt.Errorf("incident/rollback: incident ID is required")
	}
	if target == "" {
		return nil, fmt.Errorf("incident/rollback: target is required")
	}

	plan := &RollbackPlan{
		ID:         uuid.New().String(),
		IncidentID: incidentID,
		Type:       rollbackType,
		Target:     target,
		Status:     RollbackStatusPending,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	// Generate type-specific steps.
	switch rollbackType {
	case RollbackBinary:
		plan.Steps = binaryRollbackSteps(target)
		plan.Verification = []string{
			"verify_binary_version",
			"health_check_endpoints",
			"consensus_participation_check",
		}
	case RollbackState:
		plan.Steps = stateRollbackSteps(target)
		plan.Verification = []string{
			"verify_state_hash",
			"block_production_check",
			"validator_set_check",
		}
	case RollbackBridge:
		plan.Steps = bridgeRollbackSteps(target)
		plan.Verification = []string{
			"verify_bridge_paused",
			"pending_transfer_audit",
			"balance_reconciliation",
		}
	case RollbackConfiguration:
		plan.Steps = configRollbackSteps(target)
		plan.Verification = []string{
			"verify_config_hash",
			"service_restart_check",
			"integration_test_suite",
		}
	default:
		return nil, fmt.Errorf("incident/rollback: unknown rollback type: %s", rollbackType)
	}

	re.mu.Lock()
	re.plans[plan.ID] = plan
	re.addAuditEntry("rollback_plan_created", "system",
		fmt.Sprintf("Created %s rollback plan for incident %s", rollbackType, incidentID))
	re.mu.Unlock()

	return plan, nil
}

// ValidateRollback verifies that a rollback plan is safe to execute.
func (re *RollbackEngine) ValidateRollback(_ context.Context, planID string) error {
	re.mu.RLock()
	plan, ok := re.plans[planID]
	re.mu.RUnlock()

	if !ok {
		return fmt.Errorf("incident/rollback: plan not found: %s", planID)
	}

	if err := plan.Validate(); err != nil {
		return err
	}

	if plan.Status != RollbackStatusPending {
		return fmt.Errorf("incident/rollback: plan is not pending (current status: %s)", plan.Status)
	}

	// Verify all steps have required fields.
	for i, step := range plan.Steps {
		if step.Name == "" {
			return fmt.Errorf("incident/rollback: step %d missing name", i)
		}
		if step.SuccessCriteria == "" {
			return fmt.Errorf("incident/rollback: step %d (%s) missing success criteria", i, step.Name)
		}
	}

	return nil
}

// ExecuteRollback executes a validated rollback plan.
func (re *RollbackEngine) ExecuteRollback(_ context.Context, planID string) (*RollbackPlan, error) {
	re.mu.Lock()
	defer re.mu.Unlock()

	plan, ok := re.plans[planID]
	if !ok {
		return nil, fmt.Errorf("incident/rollback: plan not found: %s", planID)
	}

	if plan.Status != RollbackStatusPending {
		return nil, fmt.Errorf("incident/rollback: plan must be pending to execute (current: %s)", plan.Status)
	}

	plan.Status = RollbackStatusExecuting
	plan.ExecutedBy = "system"
	now := time.Now().UTC().Format(time.RFC3339Nano)

	re.addAuditEntry("rollback_started", "system",
		fmt.Sprintf("Executing %s rollback plan %s", plan.Type, plan.ID))

	// Execute each step (simulated; real implementation would invoke actual commands).
	for i := range plan.Steps {
		plan.Steps[i].Status = "completed"
		plan.Steps[i].ExecutedAt = now
		plan.Steps[i].Result = "success"
	}

	// Run verification.
	plan.Status = RollbackStatusVerifying

	// All verifications pass (simulated).
	plan.Status = RollbackStatusCompleted
	plan.CompletedAt = time.Now().UTC().Format(time.RFC3339)

	re.addAuditEntry("rollback_completed", "system",
		fmt.Sprintf("Rollback plan %s completed for incident %s", plan.ID, plan.IncidentID))

	return plan, nil
}

// GetPlan returns a rollback plan by ID.
func (re *RollbackEngine) GetPlan(_ context.Context, planID string) (*RollbackPlan, error) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	plan, ok := re.plans[planID]
	if !ok {
		return nil, fmt.Errorf("incident/rollback: plan not found: %s", planID)
	}
	return plan, nil
}

// GetAuditLog returns the rollback engine audit log.
func (re *RollbackEngine) GetAuditLog() []TimelineEntry {
	re.mu.RLock()
	defer re.mu.RUnlock()

	result := make([]TimelineEntry, len(re.auditLog))
	copy(result, re.auditLog)
	return result
}

func (re *RollbackEngine) addAuditEntry(action, actor, description string) {
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
// Pre-built rollback step templates
// ---------------------------------------------------------------------------

func binaryRollbackSteps(targetVersion string) []RollbackStep {
	return []RollbackStep{
		{
			Name:            "stop_current_binary",
			Description:     "Gracefully stop the currently running binary",
			Command:         "systemctl stop aethelred",
			Timeout:         "30s",
			SuccessCriteria: "process_exited_cleanly",
		},
		{
			Name:            "backup_current_state",
			Description:     "Create backup of current application state",
			Command:         "aethelred snapshot create --label pre-rollback",
			Timeout:         "5m",
			SuccessCriteria: "snapshot_created_successfully",
		},
		{
			Name:            "deploy_target_version",
			Description:     fmt.Sprintf("Deploy target version %s", targetVersion),
			Command:         fmt.Sprintf("aethelred-deploy --version %s", targetVersion),
			Timeout:         "10m",
			SuccessCriteria: "binary_version_matches_target",
			FallbackStep:    "restore_from_backup",
		},
		{
			Name:            "start_service",
			Description:     "Start the rolled-back service",
			Command:         "systemctl start aethelred",
			Timeout:         "2m",
			SuccessCriteria: "service_healthy",
		},
		{
			Name:            "verify_consensus",
			Description:     "Verify the node rejoins consensus",
			Command:         "aethelred status --check consensus",
			Timeout:         "5m",
			SuccessCriteria: "consensus_participating",
		},
	}
}

func stateRollbackSteps(targetHash string) []RollbackStep {
	return []RollbackStep{
		{
			Name:            "pause_block_production",
			Description:     "Pause block production during state rollback",
			Command:         "aethelred consensus pause",
			Timeout:         "30s",
			SuccessCriteria: "block_production_paused",
		},
		{
			Name:            "export_current_state",
			Description:     "Export current state for forensic analysis",
			Command:         "aethelred export-state --output /backup/pre-rollback.json",
			Timeout:         "10m",
			SuccessCriteria: "state_exported",
		},
		{
			Name:            "restore_target_state",
			Description:     fmt.Sprintf("Restore state to hash %s", targetHash),
			Command:         fmt.Sprintf("aethelred unsafe-reset-all --restore %s", targetHash),
			Timeout:         "15m",
			SuccessCriteria: "state_hash_matches_target",
			FallbackStep:    "manual_state_recovery",
		},
		{
			Name:            "resume_block_production",
			Description:     "Resume block production after state rollback",
			Command:         "aethelred consensus resume",
			Timeout:         "1m",
			SuccessCriteria: "block_production_resumed",
		},
	}
}

func bridgeRollbackSteps(targetState string) []RollbackStep {
	return []RollbackStep{
		{
			Name:            "pause_bridge",
			Description:     "Pause all bridge operations",
			Command:         "aethelred bridge pause --all",
			Timeout:         "30s",
			SuccessCriteria: "all_bridges_paused",
		},
		{
			Name:            "audit_pending_transfers",
			Description:     "Audit all pending cross-chain transfers",
			Command:         "aethelred bridge audit-pending",
			Timeout:         "5m",
			SuccessCriteria: "pending_transfers_catalogued",
		},
		{
			Name:            "rollback_bridge_state",
			Description:     fmt.Sprintf("Rollback bridge state to %s", targetState),
			Command:         fmt.Sprintf("aethelred bridge rollback --target %s", targetState),
			Timeout:         "10m",
			SuccessCriteria: "bridge_state_restored",
			FallbackStep:    "manual_bridge_recovery",
		},
		{
			Name:            "reconcile_balances",
			Description:     "Reconcile cross-chain balances",
			Command:         "aethelred bridge reconcile",
			Timeout:         "15m",
			SuccessCriteria: "balances_reconciled",
		},
	}
}

func configRollbackSteps(targetConfig string) []RollbackStep {
	return []RollbackStep{
		{
			Name:            "backup_current_config",
			Description:     "Backup current configuration",
			Command:         "aethelred config export --output /backup/config-backup.yaml",
			Timeout:         "30s",
			SuccessCriteria: "config_exported",
		},
		{
			Name:            "restore_target_config",
			Description:     fmt.Sprintf("Restore configuration %s", targetConfig),
			Command:         fmt.Sprintf("aethelred config restore --id %s", targetConfig),
			Timeout:         "1m",
			SuccessCriteria: "config_hash_matches_target",
		},
		{
			Name:            "restart_affected_services",
			Description:     "Restart services affected by configuration change",
			Command:         "aethelred service restart --changed",
			Timeout:         "5m",
			SuccessCriteria: "all_services_healthy",
		},
	}
}
