package securecells

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
	"github.com/aethelred/aethelred/pkg/seal/sdk"
)

// SecureCellStatus tracks the lifecycle of a regulated collaboration cell.
type SecureCellStatus string

const (
	SecureCellStatusActive      SecureCellStatus = "active"
	SecureCellStatusPaused      SecureCellStatus = "paused"
	SecureCellStatusQuarantined SecureCellStatus = "quarantined"
	SecureCellStatusRevoked     SecureCellStatus = "revoked"
	SecureCellStatusTerminated  SecureCellStatus = "terminated"
	SecureCellStatusRejected    SecureCellStatus = "rejected"
)

// SecureCellParticipantStatus tracks one member's live collaboration posture.
type SecureCellParticipantStatus string

const (
	SecureCellParticipantStatusActive      SecureCellParticipantStatus = "active"
	SecureCellParticipantStatusQuarantined SecureCellParticipantStatus = "quarantined"
	SecureCellParticipantStatusRevoked     SecureCellParticipantStatus = "revoked"
)

const (
	secureCellTool                   = "secure_cells"
	secureCellCreateAction           = "secure_cells.create"
	secureCellActivateAction         = "secure_cells.activate"
	secureCellMemberAdmitAction      = "secure_cells.member.admit"
	secureCellMemberReleaseAction    = "secure_cells.member.release"
	secureCellMemberQuarantineAction = "secure_cells.member.quarantine"
	secureCellMemberRevokeAction     = "secure_cells.member.revoke"
	secureCellQuarantineExpireAction = "secure_cells.quarantine.expire"
	secureCellPauseAction            = "secure_cells.pause"
	secureCellResumeAction           = "secure_cells.resume"
	secureCellTerminateAction        = "secure_cells.terminate"
)

// SecureCellSealer creates execution seals for secure cells.
type SecureCellSealer interface {
	CreateSeal(ctx context.Context, req sdk.SealRequest) (*sdk.SealResponse, error)
}

// SecureCellPackageSigner signs a portable control-ledger package.
type SecureCellPackageSigner func(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error

// SecureCellPackageAnchorer anchors a portable package into external audit or governance state.
type SecureCellPackageAnchorer func(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error

// SecureCellPolicy describes the governed collaboration policy enforced inside
// the secure cell.
type SecureCellPolicy struct {
	AllowedActions             []string               `json:"allowed_actions,omitempty"`
	AllowedTools               []string               `json:"allowed_tools,omitempty"`
	DataClasses                []string               `json:"data_classes,omitempty"`
	ComputeZones               []string               `json:"compute_zones,omitempty"`
	RetentionPolicy            string                 `json:"retention_policy,omitempty"`
	RequiredCredentials        []agent.CredentialType `json:"required_credentials,omitempty"`
	RequireConfidentialCompute *bool                  `json:"require_confidential_compute,omitempty"`
	MaxParticipants            int                    `json:"max_participants,omitempty"`
}

// SecureCellParticipant identifies an invited collaboration participant.
type SecureCellParticipant struct {
	Identity *agent.AgentIdentity `json:"identity,omitempty"`
	Role     string               `json:"role"`
	Metadata map[string]string    `json:"metadata,omitempty"`
}

// SecureCellParticipantState is the projected participant state in the final
// secure-cell result.
type SecureCellParticipantState struct {
	ParticipantDID      string                      `json:"participant_did"`
	Role                string                      `json:"role"`
	Status              SecureCellParticipantStatus `json:"status"`
	NegotiationID       string                      `json:"negotiation_id,omitempty"`
	NegotiationStatus   string                      `json:"negotiation_status,omitempty"`
	CredentialID        string                      `json:"credential_id,omitempty"`
	AddedAt             time.Time                   `json:"added_at,omitempty"`
	UpdatedAt           time.Time                   `json:"updated_at,omitempty"`
	ReleasedAt          *time.Time                  `json:"released_at,omitempty"`
	QuarantineExpiresAt *time.Time                  `json:"quarantine_expires_at,omitempty"`
	Reason              string                      `json:"reason,omitempty"`
	Metadata            map[string]string           `json:"metadata,omitempty"`
}

// SecureCellRequest creates a new regulated collaboration cell.
type SecureCellRequest struct {
	OwnerIdentity *agent.AgentIdentity    `json:"owner_identity,omitempty"`
	Name          string                  `json:"name"`
	Purpose       string                  `json:"purpose"`
	Resource      string                  `json:"resource,omitempty"`
	Jurisdiction  string                  `json:"jurisdiction,omitempty"`
	Participants  []SecureCellParticipant `json:"participants,omitempty"`
	Policy        SecureCellPolicy        `json:"policy"`
	Metadata      map[string]string       `json:"metadata,omitempty"`
}

// SecureCellResult is the portable buyer-facing outcome for a secure cell.
type SecureCellResult struct {
	CellID            string                                 `json:"cell_id"`
	Name              string                                 `json:"name"`
	Purpose           string                                 `json:"purpose"`
	Status            SecureCellStatus                       `json:"status"`
	PausedFromStatus  SecureCellStatus                       `json:"paused_from_status,omitempty"`
	Policy            SecureCellPolicy                       `json:"policy"`
	Participants      []SecureCellParticipantState           `json:"participants,omitempty"`
	CreationReceipt   *policy.SignedPolicyReceipt            `json:"creation_receipt,omitempty"`
	ActivationReceipt *policy.SignedPolicyReceipt            `json:"activation_receipt,omitempty"`
	ReceiptChain      *policy.PolicyReceiptChain             `json:"receipt_chain,omitempty"`
	ExecutionSeal     *evidence.Seal                         `json:"execution_seal,omitempty"`
	ControlLedger     *evidence.ControlLedger                `json:"control_ledger,omitempty"`
	PortablePackage   *evidence.PortableControlLedgerPackage `json:"portable_package,omitempty"`
	Transitions       []SecureCellTransition                 `json:"transitions,omitempty"`
	RejectionReason   string                                 `json:"rejection_reason,omitempty"`
	TerminatedAt      *time.Time                             `json:"terminated_at,omitempty"`
	CreatedAt         time.Time                              `json:"created_at"`
	UpdatedAt         time.Time                              `json:"updated_at"`
}

// SecureCellTransition captures one evidence-bearing lifecycle mutation after
// the cell is provisioned.
type SecureCellTransition struct {
	ID                      string                      `json:"id"`
	Action                  string                      `json:"action"`
	Actor                   string                      `json:"actor"`
	TargetType              string                      `json:"target_type,omitempty"`
	TargetDID               string                      `json:"target_did,omitempty"`
	CellStatusBefore        SecureCellStatus            `json:"cell_status_before,omitempty"`
	CellStatusAfter         SecureCellStatus            `json:"cell_status_after,omitempty"`
	ParticipantStatusBefore SecureCellParticipantStatus `json:"participant_status_before,omitempty"`
	ParticipantStatusAfter  SecureCellParticipantStatus `json:"participant_status_after,omitempty"`
	NegotiationID           string                      `json:"negotiation_id,omitempty"`
	CredentialID            string                      `json:"credential_id,omitempty"`
	PolicyReceipt           *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	ExecutionSeal           *evidence.Seal              `json:"execution_seal,omitempty"`
	TraceLink               *evidence.TraceLink         `json:"trace_link,omitempty"`
	Reason                  string                      `json:"reason,omitempty"`
	Metadata                map[string]string           `json:"metadata,omitempty"`
	OccurredAt              time.Time                   `json:"occurred_at"`
}

// SecureCellAdmissionRequest admits a new member into a live secure cell.
type SecureCellAdmissionRequest struct {
	Participant SecureCellParticipant `json:"participant"`
	Reason      string                `json:"reason,omitempty"`
	Metadata    map[string]string     `json:"metadata,omitempty"`
}

// SecureCellMemberTransitionRequest mutates the live posture of an existing
// member.
type SecureCellMemberTransitionRequest struct {
	ParticipantDID      string            `json:"participant_did"`
	Reason              string            `json:"reason,omitempty"`
	QuarantineExpiresAt *time.Time        `json:"quarantine_expires_at,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

// SecureCellLifecycleRequest mutates the cell's own lifecycle posture.
type SecureCellLifecycleRequest struct {
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ServiceConfig configures Secure Cells v1.
type ServiceConfig struct {
	Negotiations            *agent.NegotiationManager
	PolicyEngine            *policy.PolicyEngine
	PolicySet               *policy.PolicySet
	PolicySignerKey         *ecdsa.PrivateKey
	PolicySigner            string
	CredentialIssuerKey     *ecdsa.PrivateKey
	CredentialIssuer        string
	Sealer                  SecureCellSealer
	LedgerStore             evidence.ControlLedgerStore
	Framework               string
	IncludeVerificationKeys bool
	PackageSigningKey       ed25519.PrivateKey
	PackageSigner           string
	PackageSignerFunc       SecureCellPackageSigner
	PackageAnchorer         SecureCellPackageAnchorer
	TrustAnchors            []evidence.PlatformTrustAnchor
}

type secureCellRun struct {
	request SecureCellRequest
	result  *SecureCellResult
}

// Service creates and serves secure cells.
type Service struct {
	config ServiceConfig

	mu   sync.RWMutex
	runs map[string]*secureCellRun
}

// NewService creates a new secure-cell service.
func NewService(config ServiceConfig) (*Service, error) {
	if config.Negotiations == nil {
		config.Negotiations = agent.NewNegotiationManager()
	}
	if config.PolicyEngine == nil {
		config.PolicyEngine = policy.NewPolicyEngine(policy.DefaultEngineConfig())
	}
	if config.PolicySignerKey == nil {
		return nil, fmt.Errorf("securecells/service: policy signer key is required")
	}
	if strings.TrimSpace(config.PolicySigner) == "" {
		return nil, fmt.Errorf("securecells/service: policy signer is required")
	}
	if config.CredentialIssuerKey == nil {
		config.CredentialIssuerKey = config.PolicySignerKey
	}
	if strings.TrimSpace(config.CredentialIssuer) == "" {
		config.CredentialIssuer = config.PolicySigner
	}
	if config.Sealer == nil {
		return nil, fmt.Errorf("securecells/service: sealer is required")
	}
	if config.LedgerStore == nil {
		config.LedgerStore = evidence.NewInMemoryControlLedgerStore()
	}
	if strings.TrimSpace(config.Framework) == "" {
		config.Framework = "Secure Cells v1"
	}
	if !config.IncludeVerificationKeys {
		config.IncludeVerificationKeys = true
	}
	if config.PolicySet == nil {
		config.PolicySet = newSecureCellPolicySet()
	}
	if err := config.PolicyEngine.RegisterPolicySet(config.PolicySet); err != nil {
		return nil, fmt.Errorf("securecells/service: register policy set: %w", err)
	}

	return &Service{
		config: config,
		runs:   make(map[string]*secureCellRun),
	}, nil
}

// CreateCell provisions a new secure collaboration cell.
func (s *Service) CreateCell(ctx context.Context, req SecureCellRequest) (*SecureCellResult, error) {
	normalized, err := s.normalizeRequest(req)
	if err != nil {
		return nil, err
	}

	createReceipt, err := s.evaluateStage(ctx, normalized, "create", "", nil)
	if err != nil {
		return nil, err
	}

	result := &SecureCellResult{
		CellID:          cellID(normalized),
		Name:            normalized.Name,
		Purpose:         normalized.Purpose,
		Status:          SecureCellStatusActive,
		Policy:          clonePolicy(normalized.Policy),
		CreationReceipt: cloneSignedPolicyReceipt(createReceipt),
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	run := &secureCellRun{request: normalized, result: result}

	if createReceipt.Decision != policy.Allow.String() {
		result.Status = SecureCellStatusRejected
		result.RejectionReason = "secure cell creation denied by policy"
		s.setRun(run)
		return cloneResult(result)
	}

	participantStates, negotiationSessionIDs, err := s.negotiateParticipants(ctx, normalized)
	if err != nil {
		result.Status = SecureCellStatusRejected
		result.RejectionReason = err.Error()
		s.setRun(run)
		return cloneResult(result)
	}
	result.Participants = participantStates

	activationReceipt, err := s.evaluateStage(ctx, normalized, "activate", createReceipt.ContentHash, nil)
	if err != nil {
		s.markNegotiationsFailed(ctx, negotiationSessionIDs, err.Error())
		return nil, err
	}
	if activationReceipt.Decision != policy.Allow.String() {
		result.Status = SecureCellStatusRejected
		result.RejectionReason = "secure cell activation denied by policy"
		result.ActivationReceipt = cloneSignedPolicyReceipt(activationReceipt)
		s.markNegotiationsFailed(ctx, negotiationSessionIDs, result.RejectionReason)
		s.setRun(run)
		return cloneResult(result)
	}
	createTransition := SecureCellTransition{
		ID:               transitionID(normalized, "created", ""),
		Action:           "secure_cell.created",
		Actor:            normalized.OwnerIdentity.AgentID(),
		TargetType:       "cell",
		CellStatusBefore: "",
		CellStatusAfter:  SecureCellStatusActive,
		PolicyReceipt:    cloneSignedPolicyReceipt(createReceipt),
		Metadata: map[string]string{
			"name":    normalized.Name,
			"purpose": normalized.Purpose,
		},
		OccurredAt: createReceipt.EvaluatedAt.UTC(),
	}
	result.Transitions = append(result.Transitions, createTransition)

	result.ActivationReceipt = cloneSignedPolicyReceipt(activationReceipt)
	if err := s.rebuildArtifacts(ctx, run, activationReceipt, SecureCellTransition{
		ID:               transitionID(normalized, "activated", ""),
		Action:           "secure_cell.activated",
		Actor:            normalized.OwnerIdentity.AgentID(),
		TargetType:       "cell",
		CellStatusBefore: SecureCellStatusActive,
		CellStatusAfter:  SecureCellStatusActive,
		PolicyReceipt:    cloneSignedPolicyReceipt(activationReceipt),
		Metadata: map[string]string{
			"participants_total": fmt.Sprintf("%d", len(participantStates)),
		},
		OccurredAt: activationReceipt.EvaluatedAt.UTC(),
	}); err != nil {
		s.markNegotiationsFailed(ctx, negotiationSessionIDs, err.Error())
		return nil, err
	}

	s.setRun(run)
	return cloneResult(result)
}

// GetCell returns a previously created secure cell.
func (s *Service) GetCell(_ context.Context, cellID string) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	return cloneResult(run.result)
}

func (s *Service) transitionMemberState(
	ctx context.Context,
	cellID string,
	mutation SecureCellMemberTransitionRequest,
	stage string,
	targetStatus SecureCellParticipantStatus,
	recordAction string,
	allowedCurrentStatuses ...SecureCellParticipantStatus,
) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive && run.result.Status != SecureCellStatusQuarantined {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not permit member lifecycle transitions while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}

	targetDID := strings.TrimSpace(mutation.ParticipantDID)
	if targetDID == "" {
		return nil, fmt.Errorf("securecells/service: participant DID is required")
	}
	idx, participant := findParticipantState(run.result.Participants, targetDID)
	if participant == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrParticipantNotFound, targetDID)
	}
	if participant.Status == targetStatus {
		return nil, fmt.Errorf("securecells/service: %w: participant %q is already %s", ErrParticipantExists, targetDID, targetStatus)
	}
	if participant.Status == SecureCellParticipantStatusRevoked {
		return nil, fmt.Errorf("securecells/service: %w: participant %q is already revoked", ErrCellImmutable, targetDID)
	}
	if !participantStatusAllowed(participant.Status, allowedCurrentStatuses...) {
		return nil, fmt.Errorf("securecells/service: %w: participant %q cannot transition from %s via %s", ErrCellImmutable, targetDID, participant.Status, stage)
	}

	transitionMetadata := cloneStringMap(mutation.Metadata)
	if mutation.QuarantineExpiresAt != nil {
		if transitionMetadata == nil {
			transitionMetadata = make(map[string]string)
		}
		transitionMetadata["quarantine_expires_at"] = mutation.QuarantineExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	receipt, err := s.evaluateStage(ctx, run.request, stage, lastReceiptHash(run.result), map[string]string{
		"target_participant_did":    targetDID,
		"target_role":               participant.Role,
		"cell_status_before":        string(run.result.Status),
		"participant_status_before": string(participant.Status),
		"participant_status_after":  string(targetStatus),
		"transition_reason":         strings.TrimSpace(mutation.Reason),
		"quarantine_expires_at":     strings.TrimSpace(safeTimeString(mutation.QuarantineExpiresAt)),
	})
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	statusBefore := participant.Status
	cellStatusBefore := run.result.Status
	updated := cloneParticipantState(*participant)
	updated.Status = targetStatus
	updated.UpdatedAt = time.Now().UTC()
	updated.Reason = strings.TrimSpace(mutation.Reason)
	updated.Metadata = cloneStringMap(mutation.Metadata)
	switch targetStatus {
	case SecureCellParticipantStatusQuarantined:
		updated.QuarantineExpiresAt = cloneTimePtr(mutation.QuarantineExpiresAt)
		updated.ReleasedAt = nil
	case SecureCellParticipantStatusActive:
		releasedAt := updated.UpdatedAt
		updated.ReleasedAt = &releasedAt
		updated.QuarantineExpiresAt = nil
	default:
		updated.QuarantineExpiresAt = nil
	}
	run.result.Participants[idx] = updated
	run.result.Status = recalculateCellStatus(run.result.Participants)
	run.result.UpdatedAt = updated.UpdatedAt

	transition := SecureCellTransition{
		ID:                      transitionID(run.request, strings.TrimPrefix(recordAction, "secure_cell."), targetDID),
		Action:                  recordAction,
		Actor:                   run.request.OwnerIdentity.AgentID(),
		TargetType:              "participant",
		TargetDID:               targetDID,
		CellStatusBefore:        cellStatusBefore,
		CellStatusAfter:         run.result.Status,
		ParticipantStatusBefore: statusBefore,
		ParticipantStatusAfter:  targetStatus,
		PolicyReceipt:           cloneSignedPolicyReceipt(receipt),
		Reason:                  strings.TrimSpace(mutation.Reason),
		Metadata:                transitionMetadata,
		OccurredAt:              receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) transitionCellState(
	ctx context.Context,
	cellID string,
	stage string,
	targetStatus SecureCellStatus,
	recordAction string,
	lifecycle SecureCellLifecycleRequest,
) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}

	statusBefore := run.result.Status
	statusAfter := targetStatus
	switch stage {
	case "pause_cell":
		if statusBefore != SecureCellStatusActive && statusBefore != SecureCellStatusQuarantined {
			return nil, fmt.Errorf("securecells/service: %w: secure cell %q cannot pause while %s", ErrCellImmutable, run.result.CellID, statusBefore)
		}
	case "resume_cell":
		if statusBefore != SecureCellStatusPaused {
			return nil, fmt.Errorf("securecells/service: %w: secure cell %q is not paused", ErrCellImmutable, run.result.CellID)
		}
		statusAfter = run.result.PausedFromStatus
		if statusAfter == "" {
			statusAfter = recalculateCellStatus(run.result.Participants)
		}
	case "terminate_cell":
		if statusBefore == SecureCellStatusTerminated {
			return nil, fmt.Errorf("securecells/service: %w: secure cell %q is already terminated", ErrCellImmutable, run.result.CellID)
		}
		statusAfter = SecureCellStatusTerminated
	}

	transitionMetadata := cloneStringMap(lifecycle.Metadata)
	if stage == "resume_cell" && run.result.PausedFromStatus != "" {
		if transitionMetadata == nil {
			transitionMetadata = make(map[string]string)
		}
		transitionMetadata["paused_from_status"] = string(run.result.PausedFromStatus)
	}
	receipt, err := s.evaluateStage(ctx, run.request, stage, lastReceiptHash(run.result), map[string]string{
		"cell_status_before": string(statusBefore),
		"cell_status_after":  string(statusAfter),
		"transition_reason":  strings.TrimSpace(lifecycle.Reason),
	})
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	updatedAt := time.Now().UTC()
	switch stage {
	case "pause_cell":
		run.result.PausedFromStatus = statusBefore
		run.result.Status = statusAfter
	case "resume_cell":
		run.result.Status = statusAfter
		run.result.PausedFromStatus = ""
	case "terminate_cell":
		run.result.Status = statusAfter
		run.result.TerminatedAt = &updatedAt
	}
	run.result.UpdatedAt = updatedAt

	transition := SecureCellTransition{
		ID:               transitionID(run.request, strings.TrimPrefix(recordAction, "secure_cell."), ""),
		Action:           recordAction,
		Actor:            run.request.OwnerIdentity.AgentID(),
		TargetType:       "cell",
		CellStatusBefore: statusBefore,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(lifecycle.Reason),
		Metadata:         transitionMetadata,
		OccurredAt:       receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) rebuildArtifacts(ctx context.Context, run *secureCellRun, latestReceipt *policy.SignedPolicyReceipt, transition SecureCellTransition) error {
	if run == nil || run.result == nil {
		return fmt.Errorf("securecells/service: nil secure cell run")
	}
	stage := transitionStageForAction(transition.Action)
	receiptChain, err := policy.BuildPolicyReceiptChain(ctx, orderedReceipts(run.result, transition.PolicyReceipt))
	if err != nil {
		return fmt.Errorf("securecells/service: build receipt chain: %w", err)
	}

	sealResp, err := s.config.Sealer.CreateSeal(ctx, s.buildSealRequest(run.request, run.result.Participants, receiptChain, latestReceipt, stage))
	if err != nil {
		return fmt.Errorf("securecells/service: create seal: %w", err)
	}
	executionSeal := s.buildExecutionSeal(cellID(run.request), latestReceipt, sealResp)
	traceLink, err := evidence.NewTraceLink(run.request.OwnerIdentity, latestReceipt, *executionSeal, transition.Action+" trace")
	if err != nil {
		return fmt.Errorf("securecells/service: create trace link: %w", err)
	}

	transition.ExecutionSeal = executionSeal
	transition.TraceLink = &traceLink
	run.result.Transitions = append(run.result.Transitions, transition)
	run.result.ReceiptChain = clonePolicyReceiptChain(receiptChain)
	run.result.ExecutionSeal = executionSeal

	if transition.Action == "secure_cell.created" {
		run.result.CreationReceipt = cloneSignedPolicyReceipt(transition.PolicyReceipt)
	}
	if transition.Action == "secure_cell.activated" {
		run.result.ActivationReceipt = cloneSignedPolicyReceipt(transition.PolicyReceipt)
	}

	ledger, err := s.buildControlLedger(run, receiptChain)
	if err != nil {
		return err
	}
	if err := s.config.LedgerStore.Save(ctx, ledger); err != nil {
		return fmt.Errorf("securecells/service: save control ledger: %w", err)
	}

	portablePkg, err := evidence.PackagePortableControlLedger(ledger, s.config.IncludeVerificationKeys)
	if err != nil {
		return fmt.Errorf("securecells/service: package control ledger: %w", err)
	}
	for _, anchor := range s.config.TrustAnchors {
		portablePkg.AddTrustAnchor(anchor)
	}
	if err := s.signAndAnchorPackage(ctx, portablePkg); err != nil {
		return err
	}
	if err := evidence.VerifyPortableControlLedgerPackage(portablePkg); err != nil {
		return fmt.Errorf("securecells/service: verify portable package: %w", err)
	}

	run.result.ControlLedger = ledger
	run.result.PortablePackage = portablePkg
	return nil
}

func ensureCellMutable(result *SecureCellResult) error {
	if result == nil {
		return fmt.Errorf("securecells/service: secure cell result is required")
	}
	switch result.Status {
	case SecureCellStatusRejected, SecureCellStatusRevoked, SecureCellStatusTerminated:
		return fmt.Errorf("securecells/service: %w: secure cell %q is not mutable while %s", ErrCellImmutable, result.CellID, result.Status)
	default:
		return nil
	}
}

// AdmitMember admits a new member into a live secure cell and regenerates the
// sealed evidence package.
func (s *Service) AdmitMember(ctx context.Context, cellID string, admission SecureCellAdmissionRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not admit members while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}
	if admission.Participant.Identity == nil {
		return nil, fmt.Errorf("securecells/service: participant identity is required")
	}
	if err := agent.VerifyIdentity(admission.Participant.Identity); err != nil {
		return nil, fmt.Errorf("securecells/service: invalid participant identity: %w", err)
	}
	if _, existing := findParticipantState(run.result.Participants, admission.Participant.Identity.AgentID()); existing != nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrParticipantExists, admission.Participant.Identity.AgentID())
	}

	nextParticipants := append(cloneParticipants(run.request.Participants), SecureCellParticipant{
		Identity: admission.Participant.Identity,
		Role:     firstNonEmpty(strings.TrimSpace(admission.Participant.Role), "participant"),
		Metadata: cloneStringMap(admission.Participant.Metadata),
	})
	if len(activeOrQuarantinedParticipants(run.result.Participants))+1 > run.request.Policy.MaxParticipants {
		return nil, fmt.Errorf("securecells/service: participant count would exceed max participants %d", run.request.Policy.MaxParticipants)
	}

	negotiatedStates, sessionIDs, err := s.negotiateParticipants(ctx, SecureCellRequest{
		OwnerIdentity: run.request.OwnerIdentity,
		Name:          run.request.Name,
		Purpose:       run.request.Purpose,
		Resource:      run.request.Resource,
		Jurisdiction:  run.request.Jurisdiction,
		Participants:  []SecureCellParticipant{nextParticipants[len(nextParticipants)-1]},
		Policy:        run.request.Policy,
		Metadata:      run.request.Metadata,
	})
	if err != nil {
		return nil, err
	}
	newState := negotiatedStates[0]
	newState.Status = SecureCellParticipantStatusActive
	newState.AddedAt = time.Now().UTC()
	newState.UpdatedAt = newState.AddedAt
	newState.Reason = strings.TrimSpace(admission.Reason)
	newState.Metadata = cloneStringMap(admission.Metadata)

	receipt, err := s.evaluateStage(ctx, run.request, "admit_member", lastReceiptHash(run.result), map[string]string{
		"target_participant_did":   admission.Participant.Identity.AgentID(),
		"target_role":              newState.Role,
		"cell_status_before":       string(run.result.Status),
		"participant_status_after": string(newState.Status),
		"transition_reason":        strings.TrimSpace(admission.Reason),
	})
	if err != nil {
		s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		s.markNegotiationsFailed(ctx, sessionIDs, "member admission denied by policy")
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	run.request.Participants = nextParticipants
	run.result.Participants = append(run.result.Participants, newState)
	run.result.Status = recalculateCellStatus(run.result.Participants)
	run.result.UpdatedAt = time.Now().UTC()
	transition := SecureCellTransition{
		ID:                      transitionID(run.request, "member_admitted", newState.ParticipantDID),
		Action:                  "secure_cell.member_admitted",
		Actor:                   run.request.OwnerIdentity.AgentID(),
		TargetType:              "participant",
		TargetDID:               newState.ParticipantDID,
		CellStatusBefore:        SecureCellStatusActive,
		CellStatusAfter:         run.result.Status,
		ParticipantStatusBefore: "",
		ParticipantStatusAfter:  newState.Status,
		NegotiationID:           newState.NegotiationID,
		CredentialID:            newState.CredentialID,
		PolicyReceipt:           cloneSignedPolicyReceipt(receipt),
		Reason:                  strings.TrimSpace(admission.Reason),
		Metadata:                cloneStringMap(admission.Metadata),
		OccurredAt:              receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// QuarantineMember quarantines an existing member and marks the cell as
// quarantined while containment is active.
func (s *Service) QuarantineMember(ctx context.Context, cellID string, mutation SecureCellMemberTransitionRequest) (*SecureCellResult, error) {
	return s.transitionMemberState(ctx, cellID, mutation, "quarantine_member", SecureCellParticipantStatusQuarantined, "secure_cell.member_quarantined", SecureCellParticipantStatusActive)
}

// ReleaseMember releases a quarantined member back to active collaboration.
func (s *Service) ReleaseMember(ctx context.Context, cellID string, mutation SecureCellMemberTransitionRequest) (*SecureCellResult, error) {
	return s.transitionMemberState(ctx, cellID, mutation, "release_member", SecureCellParticipantStatusActive, "secure_cell.member_released", SecureCellParticipantStatusQuarantined)
}

// RevokeMember revokes an existing member and regenerates the evidence package
// under the new membership posture.
func (s *Service) RevokeMember(ctx context.Context, cellID string, mutation SecureCellMemberTransitionRequest) (*SecureCellResult, error) {
	return s.transitionMemberState(ctx, cellID, mutation, "revoke_member", SecureCellParticipantStatusRevoked, "secure_cell.member_revoked", SecureCellParticipantStatusActive, SecureCellParticipantStatusQuarantined)
}

// ExpireQuarantinedMembers releases all quarantined members whose quarantine
// expiry has elapsed.
func (s *Service) ExpireQuarantinedMembers(ctx context.Context, cellID string, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var result *SecureCellResult
	for _, participant := range append([]SecureCellParticipantState(nil), run.result.Participants...) {
		if participant.Status != SecureCellParticipantStatusQuarantined || participant.QuarantineExpiresAt == nil || participant.QuarantineExpiresAt.After(at) {
			continue
		}
		result, err = s.transitionMemberState(ctx, cellID, SecureCellMemberTransitionRequest{
			ParticipantDID: participant.ParticipantDID,
			Reason:         firstNonEmpty(strings.TrimSpace(lifecycle.Reason), "quarantine expired"),
			Metadata:       mergeStringMaps(lifecycle.Metadata, map[string]string{"release_mode": "expiry"}),
		}, "expire_member", SecureCellParticipantStatusActive, "secure_cell.quarantine_expired", SecureCellParticipantStatusQuarantined)
		if err != nil {
			return nil, err
		}
	}
	if result != nil {
		return result, nil
	}
	return s.GetCell(ctx, cellID)
}

// PauseCell pauses collaboration activity while preserving the prior active or
// quarantined posture for later resume.
func (s *Service) PauseCell(ctx context.Context, cellID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionCellState(ctx, cellID, "pause_cell", SecureCellStatusPaused, "secure_cell.paused", lifecycle)
}

// ResumeCell resumes collaboration after an administrative pause.
func (s *Service) ResumeCell(ctx context.Context, cellID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionCellState(ctx, cellID, "resume_cell", SecureCellStatusActive, "secure_cell.resumed", lifecycle)
}

// TerminateCell permanently terminates a secure cell.
func (s *Service) TerminateCell(ctx context.Context, cellID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionCellState(ctx, cellID, "terminate_cell", SecureCellStatusTerminated, "secure_cell.terminated", lifecycle)
}

func (s *Service) negotiateParticipants(ctx context.Context, req SecureCellRequest) ([]SecureCellParticipantState, []string, error) {
	states := make([]SecureCellParticipantState, 0, len(req.Participants))
	sessionIDs := make([]string, 0, len(req.Participants))
	for _, participant := range req.Participants {
		requirements := &agent.NegotiationRequirements{
			RequiredCredentials:  req.Policy.RequiredCredentials,
			RequiredCapabilities: req.Policy.AllowedTools,
		}
		session, err := s.config.Negotiations.InitiateNegotiation(ctx, req.OwnerIdentity.AgentID(), participant.Identity.AgentID(), requirements)
		if err != nil {
			s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
			return nil, nil, fmt.Errorf("securecells/service: initiate negotiation: %w", err)
		}
		sessionIDs = append(sessionIDs, session.ID)
		if err := s.config.Negotiations.SetResponderRequirements(ctx, session.ID, requirements); err != nil {
			s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
			return nil, nil, fmt.Errorf("securecells/service: set responder requirements: %w", err)
		}

		credential, err := agent.IssueCredential(
			ctx,
			s.config.CredentialIssuerKey,
			s.config.CredentialIssuer,
			participant.Identity.AgentID(),
			agent.ComplianceCredential,
			s.cellClaims(req, participant),
			24*time.Hour,
		)
		if err != nil {
			s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
			return nil, nil, fmt.Errorf("securecells/service: issue participant credential: %w", err)
		}
		if err := agent.VerifyCredential(credential, &s.config.CredentialIssuerKey.PublicKey); err != nil {
			s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
			return nil, nil, fmt.Errorf("securecells/service: verify participant credential: %w", err)
		}
		if err := s.config.Negotiations.ExchangeCredentials(ctx, session.ID, []*agent.AgentCredential{credential}); err != nil {
			s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
			return nil, nil, fmt.Errorf("securecells/service: exchange credentials: %w", err)
		}

		authPolicy := &agent.AuthorizationPolicy{
			RequiredCredentials: req.Policy.RequiredCredentials,
			AllowedActions:      req.Policy.AllowedActions,
			DelegationRules: &agent.DelegationAuthRules{
				AllowDelegation:          false,
				MaxDepth:                 0,
				RequireChainVerification: true,
			},
		}
		if err := s.config.Negotiations.ProposePolicy(ctx, session.ID, req.OwnerIdentity.AgentID(), authPolicy); err != nil {
			s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
			return nil, nil, fmt.Errorf("securecells/service: propose policy: %w", err)
		}
		if err := s.config.Negotiations.AcceptPolicy(ctx, session.ID, participant.Identity.AgentID()); err != nil {
			s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
			return nil, nil, fmt.Errorf("securecells/service: accept policy: %w", err)
		}
		finalSession, err := s.config.Negotiations.GetNegotiationStatus(ctx, session.ID)
		if err != nil {
			s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
			return nil, nil, fmt.Errorf("securecells/service: get negotiation status: %w", err)
		}

		states = append(states, SecureCellParticipantState{
			ParticipantDID:    participant.Identity.AgentID(),
			Role:              participant.Role,
			Status:            SecureCellParticipantStatusActive,
			NegotiationID:     finalSession.ID,
			NegotiationStatus: finalSession.Status.String(),
			CredentialID:      credential.ID,
			AddedAt:           time.Now().UTC(),
			UpdatedAt:         time.Now().UTC(),
			Metadata:          cloneStringMap(participant.Metadata),
		})
	}
	return states, sessionIDs, nil
}

func (s *Service) markNegotiationsFailed(ctx context.Context, sessionIDs []string, reason string) {
	if s == nil || s.config.Negotiations == nil || len(sessionIDs) == 0 {
		return
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "secure cell provisioning failed"
	}
	for _, sessionID := range sessionIDs {
		if strings.TrimSpace(sessionID) == "" {
			continue
		}
		_ = s.config.Negotiations.FailNegotiation(ctx, sessionID, reason)
	}
}

func (s *Service) buildControlLedger(run *secureCellRun, receiptChain *policy.PolicyReceiptChain) (*evidence.ControlLedger, error) {
	if run == nil || run.result == nil {
		return nil, fmt.Errorf("securecells/service: nil secure cell run")
	}
	req := run.request
	participants := run.result.Participants
	ledger := evidence.NewControlLedger(s.config.Framework)
	ledger.Bundle.ID = cellID(req) + "-ledger"
	ledger.WithMetadata("workflow", "secure_cell")
	ledger.WithMetadata("cell_id", cellID(req))
	ledger.WithMetadata("jurisdiction", req.Jurisdiction)
	ledger.WithMetadata("purpose", req.Purpose)
	ledger.WithMetadata("cell_status", string(run.result.Status))
	ledger.WithMetadata("data_classes", strings.Join(req.Policy.DataClasses, ","))
	ledger.WithMetadata("compute_zones", strings.Join(req.Policy.ComputeZones, ","))
	ledger.WithMetadata("confidential_compute_required", fmt.Sprintf("%t", confidentialComputeRequired(req.Policy)))
	ledger.WithMetadata("retention_policy", req.Policy.RetentionPolicy)
	ledger.WithMetadata("participants_total", fmt.Sprintf("%d", len(participants)))
	ledger.WithMetadata("participants_active", fmt.Sprintf("%d", len(participantsByStatus(participants, SecureCellParticipantStatusActive))))
	ledger.WithMetadata("participants_quarantined", fmt.Sprintf("%d", len(participantsByStatus(participants, SecureCellParticipantStatusQuarantined))))
	ledger.WithMetadata("participants_revoked", fmt.Sprintf("%d", len(participantsByStatus(participants, SecureCellParticipantStatusRevoked))))
	if run.result.PausedFromStatus != "" {
		ledger.WithMetadata("paused_from_status", string(run.result.PausedFromStatus))
	}
	if run.result.TerminatedAt != nil {
		ledger.WithMetadata("terminated_at", run.result.TerminatedAt.UTC().Format(time.RFC3339Nano))
	}
	if receiptChain != nil {
		ledger.WithMetadata("receipt_chain_hash", receiptChain.ChainHash)
	}

	ownerPassport, err := evidence.NewAgentPassportEvidence(req.OwnerIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/service: create owner passport evidence: %w", err)
	}
	ledger.AddAgentPassport(ownerPassport)

	recordIDs := make([]string, 0, len(run.result.Transitions)+len(participants)+2)
	policyReceiptIDs := make([]string, 0, len(run.result.Transitions)+2)
	traceLinkIDs := make([]string, 0, len(run.result.Transitions)+1)
	sealIDs := make([]string, 0, len(run.result.Transitions)+1)
	negotiationRecordIDs := make([]string, 0, len(participants))
	lifecycleRecordIDs := make([]string, 0, len(run.result.Transitions))
	containmentRecordIDs := make([]string, 0, len(run.result.Transitions))
	admittedParticipants := make(map[string]struct{}, len(run.result.Transitions))

	for _, participant := range req.Participants {
		passport, err := evidence.NewAgentPassportEvidence(participant.Identity)
		if err != nil {
			return nil, fmt.Errorf("securecells/service: create participant passport evidence: %w", err)
		}
		ledger.AddAgentPassport(passport)
	}

	for idx, transition := range run.result.Transitions {
		recordID := firstNonEmpty(strings.TrimSpace(transition.ID), fmt.Sprintf("%s-transition-%02d", cellID(req), idx+1))
		recordIDs = append(recordIDs, recordID)
		lifecycleRecordIDs = append(lifecycleRecordIDs, recordID)
		data := cloneStringMap(transition.Metadata)
		if data == nil {
			data = make(map[string]string)
		}
		data["cell_status_before"] = string(transition.CellStatusBefore)
		data["cell_status_after"] = string(transition.CellStatusAfter)
		if transition.TargetType != "" {
			data["target_type"] = transition.TargetType
		}
		if transition.TargetDID != "" {
			data["target_did"] = transition.TargetDID
		}
		if transition.ParticipantStatusBefore != "" {
			data["participant_status_before"] = string(transition.ParticipantStatusBefore)
		}
		if transition.ParticipantStatusAfter != "" {
			data["participant_status_after"] = string(transition.ParticipantStatusAfter)
		}
		if transition.NegotiationID != "" {
			data["negotiation_id"] = transition.NegotiationID
		}
		if transition.CredentialID != "" {
			data["credential_id"] = transition.CredentialID
		}
		if transition.Reason != "" {
			data["reason"] = transition.Reason
		}
		if transition.PolicyReceipt != nil {
			data["policy_receipt_id"] = transition.PolicyReceipt.ID
			receiptEvidence, err := evidence.NewPolicyReceiptEvidence(transition.PolicyReceipt)
			if err != nil {
				return nil, fmt.Errorf("securecells/service: create transition receipt evidence: %w", err)
			}
			ledger.AddPolicyReceipt(receiptEvidence)
			policyReceiptIDs = append(policyReceiptIDs, transition.PolicyReceipt.ID)
		}
		if transition.ExecutionSeal != nil {
			ledger.AddSeal(*transition.ExecutionSeal)
			sealIDs = append(sealIDs, transition.ExecutionSeal.SealID)
		}
		if transition.TraceLink != nil {
			ledger.AddTraceLink(*transition.TraceLink)
			traceLinkIDs = append(traceLinkIDs, transition.TraceLink.ID)
		}
		ledger.AddRecord(evidence.Record{
			ID:        recordID,
			Type:      transitionRecordType(transition.Action),
			Action:    transition.Action,
			Actor:     transition.Actor,
			Timestamp: transition.OccurredAt.UTC().Format(time.RFC3339Nano),
			Data:      data,
		})
		if transition.Action == "secure_cell.member_admitted" && transition.TargetDID != "" {
			admittedParticipants[transition.TargetDID] = struct{}{}
			negotiationRecordID := recordID + "-negotiation"
			negotiationRecordIDs = append(negotiationRecordIDs, negotiationRecordID)
			ledger.AddRecord(evidence.Record{
				ID:        negotiationRecordID,
				Type:      "trust",
				Action:    "secure_cell.negotiation_agreed",
				Actor:     transition.Actor,
				Timestamp: transition.OccurredAt.UTC().Format(time.RFC3339Nano),
				Data: map[string]string{
					"participant_did":    transition.TargetDID,
					"negotiation_id":     transition.NegotiationID,
					"credential_id":      transition.CredentialID,
					"participant_status": string(transition.ParticipantStatusAfter),
				},
			})
		}
		if transition.Action == "secure_cell.member_quarantined" || transition.Action == "secure_cell.member_revoked" || transition.Action == "secure_cell.member_released" || transition.Action == "secure_cell.quarantine_expired" {
			containmentRecordIDs = append(containmentRecordIDs, recordID)
		}
	}

	for _, participant := range participants {
		if participant.ParticipantDID == "" {
			continue
		}
		if _, admitted := admittedParticipants[participant.ParticipantDID]; admitted {
			continue
		}
		if strings.TrimSpace(participant.NegotiationID) == "" && strings.TrimSpace(participant.CredentialID) == "" {
			continue
		}
		negotiationRecordID := fmt.Sprintf("%s-negotiation-%x", cellID(req), sha256.Sum256([]byte(participant.ParticipantDID)))
		negotiationRecordIDs = append(negotiationRecordIDs, negotiationRecordID)
		ledger.AddRecord(evidence.Record{
			ID:        negotiationRecordID,
			Type:      "trust",
			Action:    "secure_cell.negotiation_agreed",
			Actor:     req.OwnerIdentity.AgentID(),
			Timestamp: run.result.CreatedAt.UTC().Format(time.RFC3339Nano),
			Data: map[string]string{
				"participant_did":    participant.ParticipantDID,
				"negotiation_id":     participant.NegotiationID,
				"credential_id":      participant.CredentialID,
				"participant_status": string(participant.Status),
				"role":               participant.Role,
			},
		})
	}

	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "CELL-ID-01",
		ControlName: "Accountable Multi-Party Identity",
		Description: "Owner and participant passports are bound into the secure-cell evidence package across live membership changes.",
		Status:      evidence.ControlSatisfied,
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs: recordIDs,
		},
		Metadata: map[string]string{
			"participants_total": fmt.Sprintf("%d", len(participants)),
		},
	}); err != nil {
		return nil, err
	}
	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "CELL-NEG-01",
		ControlName: "Negotiated Collaboration Policy",
		Description: "Each admitted participant completed trust negotiation with an agreed collaboration policy and entry credential.",
		Status:      evidence.ControlSatisfied,
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs: negotiationRecordIDs,
		},
		Metadata: map[string]string{
			"participants_total": fmt.Sprintf("%d", len(participants)),
		},
	}); err != nil {
		return nil, err
	}
	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "CELL-POL-01",
		ControlName: "Policy-Gated Secure Cell Activation",
		Description: "Secure-cell creation and all subsequent lifecycle mutations emit signed policy receipts with traceable chain integrity.",
		Status:      evidence.ControlSatisfied,
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs:        recordIDs,
			PolicyReceiptIDs: policyReceiptIDs,
			TraceLinkIDs:     traceLinkIDs,
		},
		Metadata: map[string]string{
			"chain_hash": safeChainHash(receiptChain),
		},
	}); err != nil {
		return nil, err
	}
	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "CELL-CONF-01",
		ControlName: "Confidential Collaboration Envelope",
		Description: "The secure cell and all lifecycle mutations are sealed under confidential-compute and compute-zone policy.",
		Status:      evidence.ControlSatisfied,
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs:    recordIDs,
			SealIDs:      sealIDs,
			TraceLinkIDs: traceLinkIDs,
		},
		Metadata: map[string]string{
			"data_classes":  strings.Join(req.Policy.DataClasses, ","),
			"compute_zones": strings.Join(req.Policy.ComputeZones, ","),
		},
	}); err != nil {
		return nil, err
	}
	if len(lifecycleRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-LIFE-01",
			ControlName: "Evidence-Bearing Lifecycle History",
			Description: "All secure-cell membership mutations are captured as stateful, regulator-readable transitions.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs:        lifecycleRecordIDs,
				PolicyReceiptIDs: policyReceiptIDs,
				SealIDs:          sealIDs,
			},
			Metadata: map[string]string{
				"cell_status": string(run.result.Status),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(containmentRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-CONT-01",
			ControlName: "Programmable Containment And Revocation",
			Description: "Quarantine and revocation events are recorded as auditable collaboration-containment transitions.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: containmentRecordIDs,
			},
			Metadata: map[string]string{
				"quarantined_members": fmt.Sprintf("%d", len(participantsByStatus(participants, SecureCellParticipantStatusQuarantined))),
				"revoked_members":     fmt.Sprintf("%d", len(participantsByStatus(participants, SecureCellParticipantStatusRevoked))),
			},
		}); err != nil {
			return nil, err
		}
	}

	if err := ledger.Finalize(""); err != nil {
		return nil, fmt.Errorf("securecells/service: finalize control ledger: %w", err)
	}
	if err := ledger.Validate(); err != nil {
		return nil, fmt.Errorf("securecells/service: validate control ledger: %w", err)
	}
	return ledger, nil
}

func (s *Service) buildSealRequest(req SecureCellRequest, participants []SecureCellParticipantState, receiptChain *policy.PolicyReceiptChain, latestReceipt *policy.SignedPolicyReceipt, stage string) sdk.SealRequest {
	modelHash := sha256.Sum256([]byte("secure_cells/v1"))
	inputHash := sha256.Sum256(mustJSON(struct {
		CellID       string                       `json:"cell_id"`
		Name         string                       `json:"name"`
		Purpose      string                       `json:"purpose"`
		Participants []SecureCellParticipantState `json:"participants"`
		Policy       SecureCellPolicy             `json:"policy"`
	}{
		CellID:       cellID(req),
		Name:         req.Name,
		Purpose:      req.Purpose,
		Participants: participants,
		Policy:       req.Policy,
	}))
	outputHash := sha256.Sum256(mustJSON(struct {
		CellID           string `json:"cell_id"`
		LatestReceipt    string `json:"latest_receipt"`
		ReceiptChainHash string `json:"receipt_chain_hash"`
		Stage            string `json:"stage"`
	}{
		CellID:           cellID(req),
		LatestReceipt:    latestReceipt.ID,
		ReceiptChainHash: safeChainHash(receiptChain),
		Stage:            stage,
	}))
	return sdk.SealRequest{
		ModelHash:  modelHash[:],
		InputHash:  inputHash[:],
		OutputHash: outputHash[:],
		Purpose:    "secure_cell",
		Metadata: map[string]string{
			"workflow":                      "secure_cell",
			"cell_id":                       cellID(req),
			"purpose":                       req.Purpose,
			"resource":                      req.Resource,
			"jurisdiction":                  req.Jurisdiction,
			"confidential_compute_required": fmt.Sprintf("%t", confidentialComputeRequired(req.Policy)),
			"cell_stage":                    stage,
			"participants_total":            fmt.Sprintf("%d", len(participants)),
			"receipt_chain_hash":            safeChainHash(receiptChain),
			"data_classes":                  strings.Join(req.Policy.DataClasses, ","),
			"compute_zones":                 strings.Join(req.Policy.ComputeZones, ","),
		},
	}
}

func (s *Service) buildExecutionSeal(cellID string, activationReceipt *policy.SignedPolicyReceipt, sealResp *sdk.SealResponse) *evidence.Seal {
	timestamp := time.Now().UTC()
	if sealResp != nil && !sealResp.Timestamp.IsZero() {
		timestamp = sealResp.Timestamp.UTC()
	}
	return &evidence.Seal{
		SealID:         safeString(sealResp, func(in *sdk.SealResponse) string { return in.SealID }),
		JobID:          cellID,
		OutputHash:     activationReceipt.ContentHash,
		ValidatorCount: safeInt(sealResp, func(in *sdk.SealResponse) int { return len(in.ValidatorSet) }),
		BlockHeight:    safeInt64(sealResp, func(in *sdk.SealResponse) int64 { return in.BlockHeight }),
		Timestamp:      timestamp.Format(time.RFC3339Nano),
	}
}

func (s *Service) evaluateStage(ctx context.Context, req SecureCellRequest, stage string, previousReceiptHash string, extraMetadata map[string]string) (*policy.SignedPolicyReceipt, error) {
	evalReq := &policy.EvaluationRequest{
		Actor:    req.OwnerIdentity.AgentID(),
		Action:   actionForStage(stage),
		Resource: req.Resource,
		Context: map[string]string{
			"sector":       "regulated_autonomy",
			"jurisdiction": req.Jurisdiction,
		},
		Metadata: s.policyMetadata(req, stage, extraMetadata),
	}
	_, receipt, err := s.config.PolicyEngine.EvaluateAndSign(ctx, evalReq, s.config.PolicySignerKey, s.config.PolicySigner, previousReceiptHash)
	if err != nil {
		return nil, fmt.Errorf("securecells/service: evaluate %s stage: %w", stage, err)
	}
	if err := policy.VerifySignedPolicyReceipt(receipt, &s.config.PolicySignerKey.PublicKey); err != nil {
		return nil, fmt.Errorf("securecells/service: verify %s stage receipt: %w", stage, err)
	}
	return receipt, nil
}

func (s *Service) cellClaims(req SecureCellRequest, participant SecureCellParticipant) []agent.Claim {
	return []agent.Claim{
		{Name: "cell_id", Value: cellID(req), Source: "securecells", Verified: true},
		{Name: "role", Value: participant.Role, Source: "securecells", Verified: true},
		{Name: "jurisdiction", Value: req.Jurisdiction, Source: "securecells", Verified: true},
		{Name: "purpose", Value: req.Purpose, Source: "securecells", Verified: true},
		{Name: "data_classes", Value: strings.Join(req.Policy.DataClasses, ","), Source: "securecells", Verified: true},
		{Name: "compute_zones", Value: strings.Join(req.Policy.ComputeZones, ","), Source: "securecells", Verified: true},
	}
}

func (s *Service) policyMetadata(req SecureCellRequest, stage string, extraMetadata map[string]string) map[string]string {
	sponsorOfRecord := ""
	liabilityPresent := "false"
	if req.OwnerIdentity.Liability != nil {
		sponsorOfRecord = req.OwnerIdentity.Liability.SponsorOfRecord
		liabilityPresent = "true"
	}
	metadata := cloneStringMap(req.Metadata)
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["workflow"] = "secure_cell"
	metadata["cell_id"] = cellID(req)
	metadata["cell_stage"] = stage
	metadata["resource"] = req.Resource
	metadata["jurisdiction_allowed"] = fmt.Sprintf("%t", req.OwnerIdentity.HasJurisdiction(req.Jurisdiction))
	metadata["tool_allowed"] = fmt.Sprintf("%t", req.OwnerIdentity.AllowsTool(secureCellTool))
	metadata["capability_present"] = fmt.Sprintf("%t", req.OwnerIdentity.HasCapability(secureCellTool))
	metadata["sponsor_of_record_present"] = fmt.Sprintf("%t", strings.TrimSpace(sponsorOfRecord) != "")
	metadata["liability_profile_present"] = liabilityPresent
	metadata["participant_count"] = fmt.Sprintf("%d", len(req.Participants))
	metadata["max_participants"] = fmt.Sprintf("%d", req.Policy.MaxParticipants)
	metadata["confidential_compute"] = fmt.Sprintf("%t", confidentialComputeRequired(req.Policy))
	metadata["data_classes"] = strings.Join(req.Policy.DataClasses, ",")
	metadata["compute_zones"] = strings.Join(req.Policy.ComputeZones, ",")
	for key, value := range extraMetadata {
		if strings.TrimSpace(key) == "" {
			continue
		}
		metadata[key] = value
	}
	return metadata
}

func (s *Service) normalizeRequest(req SecureCellRequest) (SecureCellRequest, error) {
	if req.OwnerIdentity == nil {
		return SecureCellRequest{}, fmt.Errorf("securecells/service: owner identity is required")
	}
	if err := agent.VerifyIdentity(req.OwnerIdentity); err != nil {
		return SecureCellRequest{}, fmt.Errorf("securecells/service: invalid owner identity: %w", err)
	}
	if len(req.Participants) == 0 {
		return SecureCellRequest{}, fmt.Errorf("securecells/service: at least one participant is required")
	}
	normalized := req
	normalized.Metadata = cloneStringMap(req.Metadata)
	normalized.Participants = cloneParticipants(req.Participants)
	if strings.TrimSpace(normalized.Name) == "" {
		normalized.Name = "Secure Cell"
	}
	if strings.TrimSpace(normalized.Purpose) == "" {
		normalized.Purpose = "regulated collaboration"
	}
	if strings.TrimSpace(normalized.Resource) == "" {
		normalized.Resource = "cell:regulated-collaboration"
	}
	if strings.TrimSpace(normalized.Jurisdiction) == "" {
		if len(req.OwnerIdentity.JurisdictionTags) > 0 {
			normalized.Jurisdiction = req.OwnerIdentity.JurisdictionTags[0]
		} else {
			normalized.Jurisdiction = "global"
		}
	}
	normalized.Policy = clonePolicy(req.Policy)
	if len(normalized.Policy.AllowedActions) == 0 {
		normalized.Policy.AllowedActions = []string{"secure_cell.read", "secure_cell.write", "secure_cell.review"}
	}
	if len(normalized.Policy.AllowedTools) == 0 {
		normalized.Policy.AllowedTools = []string{secureCellTool}
	}
	if len(normalized.Policy.DataClasses) == 0 {
		normalized.Policy.DataClasses = []string{"confidential"}
	}
	if len(normalized.Policy.ComputeZones) == 0 {
		normalized.Policy.ComputeZones = []string{"regulated-enclave"}
	}
	if strings.TrimSpace(normalized.Policy.RetentionPolicy) == "" {
		normalized.Policy.RetentionPolicy = "evidence-365d"
	}
	if len(normalized.Policy.RequiredCredentials) == 0 {
		normalized.Policy.RequiredCredentials = []agent.CredentialType{agent.ComplianceCredential}
	}
	if normalized.Policy.MaxParticipants <= 0 {
		normalized.Policy.MaxParticipants = 12
	}
	if normalized.Policy.RequireConfidentialCompute == nil {
		normalized.Policy.RequireConfidentialCompute = boolPtr(true)
	}
	if len(normalized.Participants) > normalized.Policy.MaxParticipants {
		return SecureCellRequest{}, fmt.Errorf("securecells/service: participant count %d exceeds max participants %d", len(normalized.Participants), normalized.Policy.MaxParticipants)
	}
	seen := map[string]struct{}{
		req.OwnerIdentity.AgentID(): {},
	}
	for idx, participant := range normalized.Participants {
		if participant.Identity == nil {
			return SecureCellRequest{}, fmt.Errorf("securecells/service: participant %d identity is required", idx)
		}
		if err := agent.VerifyIdentity(participant.Identity); err != nil {
			return SecureCellRequest{}, fmt.Errorf("securecells/service: invalid participant identity: %w", err)
		}
		did := participant.Identity.AgentID()
		if _, ok := seen[did]; ok {
			return SecureCellRequest{}, fmt.Errorf("securecells/service: duplicate participant DID %q", did)
		}
		seen[did] = struct{}{}
		if strings.TrimSpace(participant.Role) == "" {
			normalized.Participants[idx].Role = "participant"
		}
		if normalized.Participants[idx].Metadata == nil {
			normalized.Participants[idx].Metadata = make(map[string]string)
		}
	}
	return normalized, nil
}

func (s *Service) signAndAnchorPackage(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error {
	if pkg == nil {
		return fmt.Errorf("securecells/service: nil portable package")
	}
	if s.config.PackageSignerFunc != nil {
		if err := s.config.PackageSignerFunc(ctx, pkg); err != nil {
			return fmt.Errorf("securecells/service: external package signing failed: %w", err)
		}
	} else if len(s.config.PackageSigningKey) == ed25519.PrivateKeySize {
		if err := pkg.SignEd25519(s.config.PackageSigningKey, s.config.PackageSigner); err != nil {
			return fmt.Errorf("securecells/service: package signing failed: %w", err)
		}
	}
	if s.config.PackageAnchorer != nil {
		if err := s.config.PackageAnchorer(ctx, pkg); err != nil {
			return fmt.Errorf("securecells/service: package anchoring failed: %w", err)
		}
	}
	return nil
}

func (s *Service) getRun(id string) (*secureCellRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	run, ok := s.runs[strings.TrimSpace(id)]
	if !ok {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrCellNotFound, id)
	}
	return run, nil
}

func (s *Service) setRun(run *secureCellRun) {
	if run == nil || run.result == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[run.result.CellID] = run
}

func lastReceiptHash(result *SecureCellResult) string {
	if result == nil {
		return ""
	}
	for i := len(result.Transitions) - 1; i >= 0; i-- {
		if result.Transitions[i].PolicyReceipt != nil {
			return result.Transitions[i].PolicyReceipt.ContentHash
		}
	}
	if result.ActivationReceipt != nil {
		return result.ActivationReceipt.ContentHash
	}
	if result.CreationReceipt != nil {
		return result.CreationReceipt.ContentHash
	}
	return ""
}

func orderedReceipts(result *SecureCellResult, extra *policy.SignedPolicyReceipt) []*policy.SignedPolicyReceipt {
	if result == nil {
		return nil
	}
	receipts := make([]*policy.SignedPolicyReceipt, 0, len(result.Transitions)+1)
	for _, transition := range result.Transitions {
		if transition.PolicyReceipt != nil {
			receipts = append(receipts, cloneSignedPolicyReceipt(transition.PolicyReceipt))
		}
	}
	if extra != nil {
		receipts = append(receipts, cloneSignedPolicyReceipt(extra))
	}
	return receipts
}

func findParticipantState(states []SecureCellParticipantState, did string) (int, *SecureCellParticipantState) {
	did = strings.TrimSpace(did)
	for idx := range states {
		if strings.TrimSpace(states[idx].ParticipantDID) == did {
			return idx, &states[idx]
		}
	}
	return -1, nil
}

func activeOrQuarantinedParticipants(states []SecureCellParticipantState) []SecureCellParticipantState {
	filtered := make([]SecureCellParticipantState, 0, len(states))
	for _, state := range states {
		if state.Status == SecureCellParticipantStatusActive || state.Status == SecureCellParticipantStatusQuarantined {
			filtered = append(filtered, state)
		}
	}
	return filtered
}

func participantsByStatus(states []SecureCellParticipantState, status SecureCellParticipantStatus) []SecureCellParticipantState {
	filtered := make([]SecureCellParticipantState, 0, len(states))
	for _, state := range states {
		if state.Status == status {
			filtered = append(filtered, state)
		}
	}
	return filtered
}

func recalculateCellStatus(states []SecureCellParticipantState) SecureCellStatus {
	if len(states) == 0 {
		return SecureCellStatusRevoked
	}
	hasActive := false
	hasQuarantined := false
	for _, state := range states {
		switch state.Status {
		case SecureCellParticipantStatusActive:
			hasActive = true
		case SecureCellParticipantStatusQuarantined:
			hasQuarantined = true
		}
	}
	switch {
	case hasQuarantined:
		return SecureCellStatusQuarantined
	case hasActive:
		return SecureCellStatusActive
	default:
		return SecureCellStatusRevoked
	}
}

func safeChainHash(chain *policy.PolicyReceiptChain) string {
	if chain == nil {
		return ""
	}
	return chain.ChainHash
}

func transitionRecordType(action string) string {
	switch action {
	case "secure_cell.activated", "secure_cell.created", "secure_cell.paused", "secure_cell.resumed", "secure_cell.terminated":
		return "governance"
	case "secure_cell.member_admitted":
		return "trust"
	case "secure_cell.member_quarantined", "secure_cell.member_revoked", "secure_cell.member_released", "secure_cell.quarantine_expired":
		return "containment"
	default:
		return "governance"
	}
}

func transitionStageForAction(action string) string {
	switch action {
	case "secure_cell.activated":
		return "activate"
	case "secure_cell.member_admitted":
		return "admit_member"
	case "secure_cell.member_released":
		return "release_member"
	case "secure_cell.member_quarantined":
		return "quarantine_member"
	case "secure_cell.member_revoked":
		return "revoke_member"
	case "secure_cell.quarantine_expired":
		return "expire_member"
	case "secure_cell.paused":
		return "pause_cell"
	case "secure_cell.resumed":
		return "resume_cell"
	case "secure_cell.terminated":
		return "terminate_cell"
	default:
		return "create"
	}
}

func transitionID(req SecureCellRequest, suffix string, targetDID string) string {
	targetDID = strings.TrimSpace(targetDID)
	if targetDID == "" {
		return fmt.Sprintf("%s-%s", cellID(req), suffix)
	}
	return fmt.Sprintf("%s-%s-%x", cellID(req), suffix, sha256.Sum256([]byte(targetDID)))
}

func cloneParticipantState(in SecureCellParticipantState) SecureCellParticipantState {
	out := in
	out.Metadata = cloneStringMap(in.Metadata)
	out.ReleasedAt = cloneTimePtr(in.ReleasedAt)
	out.QuarantineExpiresAt = cloneTimePtr(in.QuarantineExpiresAt)
	return out
}

func participantStatusAllowed(current SecureCellParticipantStatus, allowed ...SecureCellParticipantStatus) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, status := range allowed {
		if current == status {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func newSecureCellPolicySet() *policy.PolicySet {
	now := time.Now().UTC()
	return &policy.PolicySet{
		ID:          "secure-cells-v1",
		Name:        "Secure Cells v1",
		Description: "Identity-aware and confidential-compute-aware policy set for regulated collaboration cells",
		Priority:    520,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
		Scope: &policy.Scope{
			Sectors: []string{"regulated_autonomy"},
			Actions: []string{
				secureCellCreateAction,
				secureCellActivateAction,
				secureCellMemberAdmitAction,
				secureCellMemberReleaseAction,
				secureCellMemberQuarantineAction,
				secureCellMemberRevokeAction,
				secureCellQuarantineExpireAction,
				secureCellPauseAction,
				secureCellResumeAction,
				secureCellTerminateAction,
			},
		},
		Rules: []policy.Rule{
			policy.NewDenyRule("secure_cell_tool_guard", "agent passport does not authorize secure cells", []policy.Condition{
				{Field: "tool_allowed", Operator: policy.NotEquals, Value: "true"},
			}),
			policy.NewDenyRule("secure_cell_capability_guard", "agent capability missing for secure cells", []policy.Condition{
				{Field: "capability_present", Operator: policy.NotEquals, Value: "true"},
			}),
			policy.NewDenyRule("secure_cell_liability_guard", "liability profile is required", []policy.Condition{
				{Field: "liability_profile_present", Operator: policy.NotEquals, Value: "true"},
			}),
			policy.NewDenyRule("secure_cell_jurisdiction_guard", "jurisdiction is not allowed by passport", []policy.Condition{
				{Field: "jurisdiction_allowed", Operator: policy.NotEquals, Value: "true"},
			}),
			policy.NewDenyRule("secure_cell_sponsor_guard", "sponsor-of-record is required", []policy.Condition{
				{Field: "sponsor_of_record_present", Operator: policy.NotEquals, Value: "true"},
			}),
			policy.NewDenyRule("secure_cell_confidential_compute_guard", "confidential compute is required", []policy.Condition{
				{Field: "confidential_compute", Operator: policy.NotEquals, Value: "true"},
			}),
			policy.NewDenyRule("secure_cell_participant_guard", "secure cell requires at least one participant", []policy.Condition{
				{Field: "participant_count", Operator: policy.LessThanOrEqual, Value: "0"},
			}),
			policy.NewAllowRule("secure_cell_create_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "create"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
				{Field: "participant_count", Operator: policy.GreaterThan, Value: "0"},
			}),
			policy.NewAllowRule("secure_cell_activate_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "activate"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
				{Field: "participant_count", Operator: policy.GreaterThan, Value: "0"},
			}),
			policy.NewAllowRule("secure_cell_member_admit_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "admit_member"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
				{Field: "participant_count", Operator: policy.GreaterThan, Value: "0"},
			}),
			policy.NewAllowRule("secure_cell_member_quarantine_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "quarantine_member"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_member_release_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "release_member"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_member_revoke_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "revoke_member"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_quarantine_expire_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "expire_member"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_pause_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "pause_cell"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_resume_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "resume_cell"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_terminate_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "terminate_cell"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
		},
	}
}

func actionForStage(stage string) string {
	switch stage {
	case "activate":
		return secureCellActivateAction
	case "admit_member":
		return secureCellMemberAdmitAction
	case "release_member":
		return secureCellMemberReleaseAction
	case "quarantine_member":
		return secureCellMemberQuarantineAction
	case "revoke_member":
		return secureCellMemberRevokeAction
	case "expire_member":
		return secureCellQuarantineExpireAction
	case "pause_cell":
		return secureCellPauseAction
	case "resume_cell":
		return secureCellResumeAction
	case "terminate_cell":
		return secureCellTerminateAction
	default:
		return secureCellCreateAction
	}
}

func cellID(req SecureCellRequest) string {
	if trimmed := strings.TrimSpace(req.Metadata["cell_id"]); trimmed != "" {
		return trimmed
	}
	type participantFingerprint struct {
		DID  string `json:"did"`
		Role string `json:"role"`
	}
	fingerprint := struct {
		OwnerDID     string                   `json:"owner_did"`
		Name         string                   `json:"name"`
		Purpose      string                   `json:"purpose"`
		Resource     string                   `json:"resource"`
		Jurisdiction string                   `json:"jurisdiction"`
		Participants []participantFingerprint `json:"participants,omitempty"`
		Policy       SecureCellPolicy         `json:"policy"`
	}{
		OwnerDID:     req.OwnerIdentity.AgentID(),
		Name:         req.Name,
		Purpose:      req.Purpose,
		Resource:     req.Resource,
		Jurisdiction: req.Jurisdiction,
		Policy:       clonePolicy(req.Policy),
	}
	for _, participant := range req.Participants {
		did := ""
		if participant.Identity != nil {
			did = participant.Identity.AgentID()
		}
		fingerprint.Participants = append(fingerprint.Participants, participantFingerprint{
			DID:  did,
			Role: participant.Role,
		})
	}
	return fmt.Sprintf("cell-%x", sha256.Sum256(mustJSON(fingerprint)))
}

func clonePolicy(in SecureCellPolicy) SecureCellPolicy {
	return SecureCellPolicy{
		AllowedActions:             append([]string(nil), in.AllowedActions...),
		AllowedTools:               append([]string(nil), in.AllowedTools...),
		DataClasses:                append([]string(nil), in.DataClasses...),
		ComputeZones:               append([]string(nil), in.ComputeZones...),
		RetentionPolicy:            in.RetentionPolicy,
		RequiredCredentials:        append([]agent.CredentialType(nil), in.RequiredCredentials...),
		RequireConfidentialCompute: cloneBoolPtr(in.RequireConfidentialCompute),
		MaxParticipants:            in.MaxParticipants,
	}
}

func cloneParticipants(in []SecureCellParticipant) []SecureCellParticipant {
	if len(in) == 0 {
		return nil
	}
	out := make([]SecureCellParticipant, len(in))
	for i, participant := range in {
		out[i] = SecureCellParticipant{
			Identity: participant.Identity,
			Role:     participant.Role,
			Metadata: cloneStringMap(participant.Metadata),
		}
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mergeStringMaps(base, extra map[string]string) map[string]string {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := cloneStringMap(base)
	if out == nil {
		out = make(map[string]string, len(extra))
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func cloneBoolPtr(in *bool) *bool {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneTimePtr(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	out := in.UTC()
	return &out
}

func safeTimeString(in *time.Time) string {
	if in == nil {
		return ""
	}
	return in.UTC().Format(time.RFC3339Nano)
}

func boolPtr(v bool) *bool {
	return &v
}

func confidentialComputeRequired(policyConfig SecureCellPolicy) bool {
	if policyConfig.RequireConfidentialCompute == nil {
		return true
	}
	return *policyConfig.RequireConfidentialCompute
}

func cloneSignedPolicyReceipt(in *policy.SignedPolicyReceipt) *policy.SignedPolicyReceipt {
	if in == nil {
		return nil
	}
	data, _ := json.Marshal(in)
	var out policy.SignedPolicyReceipt
	_ = json.Unmarshal(data, &out)
	return &out
}

func clonePolicyReceiptChain(in *policy.PolicyReceiptChain) *policy.PolicyReceiptChain {
	if in == nil {
		return nil
	}
	data, _ := json.Marshal(in)
	var out policy.PolicyReceiptChain
	_ = json.Unmarshal(data, &out)
	return &out
}

func cloneResult(in *SecureCellResult) (*SecureCellResult, error) {
	if in == nil {
		return nil, nil
	}
	data, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	var out SecureCellResult
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func mustJSON(v any) []byte {
	data, _ := json.Marshal(v)
	return data
}

func safeString[T any](in *T, fn func(*T) string) string {
	if in == nil {
		return ""
	}
	return fn(in)
}

func safeInt[T any](in *T, fn func(*T) int) int {
	if in == nil {
		return 0
	}
	return fn(in)
}

func safeInt64[T any](in *T, fn func(*T) int64) int64 {
	if in == nil {
		return 0
	}
	return fn(in)
}

// EvidenceHash returns a stable hex hash for diagnostic or metadata use.
func EvidenceHash(v any) string {
	sum := sha256.Sum256(mustJSON(v))
	return hex.EncodeToString(sum[:])
}
