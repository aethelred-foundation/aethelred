package finance

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
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

// TreasuryReleaseSealer creates execution seals for treasury release workflows.
type TreasuryReleaseSealer interface {
	CreateSeal(ctx context.Context, req sdk.SealRequest) (*sdk.SealResponse, error)
}

// TreasuryReleasePackageSigner signs a portable control-ledger package.
type TreasuryReleasePackageSigner func(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error

// TreasuryReleasePackageAnchorer anchors a portable control-ledger package into
// an external governance or audit surface.
type TreasuryReleasePackageAnchorer func(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error

// TreasuryReleaseWorkflowStatus is the buyer-facing workflow state for a
// regulated treasury release.
type TreasuryReleaseWorkflowStatus string

const (
	ReleaseStatusPendingApproval TreasuryReleaseWorkflowStatus = "pending_approval"
	ReleaseStatusCompleted       TreasuryReleaseWorkflowStatus = "completed"
	ReleaseStatusRejected        TreasuryReleaseWorkflowStatus = "rejected"
)

const (
	treasuryReleaseRequestAction    = "payments.release.request"
	treasuryReleaseExecuteAction    = "payments.release.execute"
	treasuryReleaseSettlementAction = "payments.release.settle"
	treasuryReleaseTool             = "payments.release"
)

// TreasuryReleaseWorkflowConfig configures the finance-first attested release
// workflow that binds passport -> policy receipt -> seal -> control ledger.
type TreasuryReleaseWorkflowConfig struct {
	Controller      *TreasuryController
	Sanctions       *SanctionsService
	AuditTrail      *FinancialAuditTrail
	PolicyEngine    *policy.PolicyEngine
	PolicySet       *policy.PolicySet
	PolicySignerKey *ecdsa.PrivateKey
	PolicySigner    string
	Sealer          TreasuryReleaseSealer
	SettlementRail  TreasurySettlementRail
	LedgerStore     evidence.ControlLedgerStore

	Framework               string
	IncludeVerificationKeys bool
	TrustAnchors            []evidence.PlatformTrustAnchor

	PackageSigningKey ed25519.PrivateKey
	PackageSigner     string
	PackageSignerFunc TreasuryReleasePackageSigner
	PackageAnchorer   TreasuryReleasePackageAnchorer
}

// TreasuryReleaseRequest captures one treasury release request to be turned
// into a regulated, attested workflow.
type TreasuryReleaseRequest struct {
	Identity     *agent.AgentIdentity
	Operation    *TreasuryOperation
	Resource     string
	Jurisdiction string
	ReasonCode   string
	Tool         string
	Originator   ScreeningEntity
	Beneficiary  ScreeningEntity
	Metadata     map[string]string
}

// TreasuryReleaseApprovalRequest captures one approval mutation, including
// optional authenticated approver evidence carried from the edge into the
// workflow itself.
type TreasuryReleaseApprovalRequest struct {
	Approver      string
	Comment       string
	ActorIdentity *agent.AgentIdentity
	PolicyReceipt *policy.SignedPolicyReceipt
	Metadata      map[string]string
}

// TreasuryReleaseApprovalEvidence is the persisted evidence representation of
// one approval action inside the workflow state and final control ledger.
type TreasuryReleaseApprovalEvidence struct {
	Approver      string                      `json:"approver"`
	Comment       string                      `json:"comment,omitempty"`
	ActorIdentity *agent.AgentIdentity        `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
	AuthorizedAt  time.Time                   `json:"authorized_at"`
}

// TreasuryReleaseResult is the portable workflow result returned to callers.
type TreasuryReleaseResult struct {
	WorkflowID string                        `json:"workflow_id"`
	Status     TreasuryReleaseWorkflowStatus `json:"status"`

	Operation         *TreasuryOperation                     `json:"operation,omitempty"`
	ApprovalStatus    *ApprovalStatus                        `json:"approval_status,omitempty"`
	Screening         *ScreeningResult                       `json:"screening,omitempty"`
	RequestReceipt    *policy.SignedPolicyReceipt            `json:"request_receipt,omitempty"`
	ExecuteReceipt    *policy.SignedPolicyReceipt            `json:"execute_receipt,omitempty"`
	SettlementReceipt *policy.SignedPolicyReceipt            `json:"settlement_receipt,omitempty"`
	ReceiptChain      *policy.PolicyReceiptChain             `json:"receipt_chain,omitempty"`
	ApprovalEvidence  []TreasuryReleaseApprovalEvidence      `json:"approval_evidence,omitempty"`
	ExecutionSeal     *evidence.Seal                         `json:"execution_seal,omitempty"`
	Settlement        *evidence.ValueSettlementEvidence      `json:"settlement,omitempty"`
	ControlLedger     *evidence.ControlLedger                `json:"control_ledger,omitempty"`
	PortablePackage   *evidence.PortableControlLedgerPackage `json:"portable_package,omitempty"`
	SOXPackage        *SOXEvidencePackage                    `json:"sox_package,omitempty"`

	RejectionReason string    `json:"rejection_reason,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type treasuryReleaseRun struct {
	request TreasuryReleaseRequest
	result  *TreasuryReleaseResult
}

// TreasuryReleaseWorkflow packages the finance release flow into an
// enterprise-grade orchestrator instead of leaving the trust primitives
// disconnected.
type TreasuryReleaseWorkflow struct {
	config TreasuryReleaseWorkflowConfig

	mu   sync.RWMutex
	runs map[string]*treasuryReleaseRun
}

// NewTreasuryReleaseWorkflow creates a finance-first attested workflow product
// on top of the existing identity, policy, seal, and evidence layers.
func NewTreasuryReleaseWorkflow(config TreasuryReleaseWorkflowConfig) (*TreasuryReleaseWorkflow, error) {
	if config.Controller == nil {
		return nil, fmt.Errorf("finance/release_workflow: treasury controller is required")
	}
	if config.Sanctions == nil {
		return nil, fmt.Errorf("finance/release_workflow: sanctions service is required")
	}
	if config.PolicySignerKey == nil {
		return nil, fmt.Errorf("finance/release_workflow: policy signer key is required")
	}
	if strings.TrimSpace(config.PolicySigner) == "" {
		return nil, fmt.Errorf("finance/release_workflow: policy signer is required")
	}
	if config.Sealer == nil {
		return nil, fmt.Errorf("finance/release_workflow: sealer is required")
	}
	if config.SettlementRail == nil {
		config.SettlementRail = NewPolicyBoundSettlementRail(PolicyBoundSettlementConfig{})
	}
	if config.PolicyEngine == nil {
		config.PolicyEngine = policy.NewPolicyEngine(policy.DefaultEngineConfig())
	}
	if config.AuditTrail == nil {
		config.AuditTrail = NewFinancialAuditTrail()
	}
	if config.LedgerStore == nil {
		config.LedgerStore = evidence.NewInMemoryControlLedgerStore()
	}
	if strings.TrimSpace(config.Framework) == "" {
		config.Framework = "SOX Treasury Release"
	}
	if !config.IncludeVerificationKeys {
		config.IncludeVerificationKeys = true
	}
	if config.PolicySet == nil {
		config.PolicySet = newTreasuryReleaseWorkflowPolicySet()
	}
	if err := config.PolicyEngine.RegisterPolicySet(config.PolicySet); err != nil {
		return nil, fmt.Errorf("finance/release_workflow: register policy set: %w", err)
	}

	return &TreasuryReleaseWorkflow{
		config: config,
		runs:   make(map[string]*treasuryReleaseRun),
	}, nil
}

// InitiateRelease starts a regulated treasury release and returns either a
// pending-approval workflow or a fully sealed, packaged workflow when no extra
// approvals are required.
func (w *TreasuryReleaseWorkflow) InitiateRelease(ctx context.Context, req TreasuryReleaseRequest) (*TreasuryReleaseResult, error) {
	normalized, err := w.normalizeRequest(req)
	if err != nil {
		return nil, err
	}

	screening, err := w.config.Sanctions.ScreenTransaction(ctx, w.buildScreeningTransaction(normalized))
	if err != nil {
		return nil, fmt.Errorf("finance/release_workflow: sanctions screening failed: %w", err)
	}

	requestReceipt, err := w.evaluateStage(ctx, normalized, screening, "request", "requested", "", nil)
	if err != nil {
		return nil, err
	}

	result := &TreasuryReleaseResult{
		WorkflowID:     normalized.Operation.ID,
		Status:         ReleaseStatusPendingApproval,
		Operation:      cloneTreasuryOperation(normalized.Operation),
		Screening:      cloneScreeningResult(screening),
		RequestReceipt: cloneSignedPolicyReceipt(requestReceipt),
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	run := &treasuryReleaseRun{
		request: normalized,
		result:  result,
	}

	if err := w.recordScreeningEvent(ctx, normalized, screening); err != nil {
		return nil, err
	}

	if !screening.Clear || requestReceipt.Decision != policy.Allow.String() {
		reason := "treasury release request denied"
		if !screening.Clear {
			reason = "sanctions screening blocked the release"
		}
		result.Status = ReleaseStatusRejected
		result.RejectionReason = reason
		result.UpdatedAt = time.Now().UTC()
		w.setRun(run)
		_ = w.recordRejectionEvent(ctx, normalized, result, reason)

		if !screening.Clear {
			cloned, cloneErr := cloneTreasuryReleaseResult(result)
			if cloneErr != nil {
				return nil, cloneErr
			}
			return cloned, fmt.Errorf("%w: %s", ErrSanctionsMatch, screening.EntityName)
		}
		cloned, cloneErr := cloneTreasuryReleaseResult(result)
		if cloneErr != nil {
			return nil, cloneErr
		}
		return cloned, fmt.Errorf("%w: %s", ErrPolicyDenied, requestReceipt.Decision)
	}

	if err := w.config.Controller.InitiateOperation(ctx, normalized.Operation); err != nil {
		return nil, fmt.Errorf("finance/release_workflow: initiate treasury operation: %w", err)
	}

	operation, approvalStatus, err := w.refreshOperationState(ctx, normalized.Operation.ID)
	if err != nil {
		return nil, err
	}
	result.Operation = operation
	result.ApprovalStatus = approvalStatus
	result.UpdatedAt = time.Now().UTC()

	if err := w.recordInitiationEvent(ctx, normalized, result); err != nil {
		return nil, err
	}

	w.setRun(run)
	if operation.Status == StatusApproved {
		return w.finalizeRelease(ctx, run)
	}

	return cloneTreasuryReleaseResult(result)
}

// ApproveRelease records one approval and, when thresholds are met, converts
// the pending workflow into a sealed, packaged release.
func (w *TreasuryReleaseWorkflow) ApproveRelease(ctx context.Context, workflowID, approver, comment string) (*TreasuryReleaseResult, error) {
	return w.ApproveReleaseWithAuthorization(ctx, workflowID, TreasuryReleaseApprovalRequest{
		Approver: approver,
		Comment:  comment,
	})
}

// ApproveReleaseWithAuthorization records one approval and persists any
// authenticated approver evidence so the final control ledger can prove who
// approved the release, under what policy, and with which accountable
// identity.
func (w *TreasuryReleaseWorkflow) ApproveReleaseWithAuthorization(ctx context.Context, workflowID string, approval TreasuryReleaseApprovalRequest) (*TreasuryReleaseResult, error) {
	run, err := w.getRun(workflowID)
	if err != nil {
		return nil, err
	}
	if run.result.Status == ReleaseStatusRejected {
		return nil, fmt.Errorf("%w: %s", ErrReleaseRejected, workflowID)
	}
	if run.result.Status == ReleaseStatusCompleted {
		return cloneTreasuryReleaseResult(run.result)
	}

	normalizedApproval, err := normalizeTreasuryReleaseApprovalRequest(approval)
	if err != nil {
		return nil, err
	}

	if err := w.config.Controller.ApproveOperation(ctx, workflowID, normalizedApproval.Approver); err != nil {
		if strings.Contains(err.Error(), "initiator cannot approve") {
			return nil, fmt.Errorf("%w: %v", ErrSelfApproval, err)
		}
		return nil, err
	}

	operation, approvalStatus, err := w.refreshOperationState(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	run.result.Operation = operation
	run.result.ApprovalStatus = approvalStatus
	run.result.ApprovalEvidence = append(run.result.ApprovalEvidence, buildTreasuryReleaseApprovalEvidence(normalizedApproval))
	run.result.UpdatedAt = time.Now().UTC()

	if err := w.recordApprovalEvent(ctx, run.request, run.result, normalizedApproval); err != nil {
		return nil, err
	}

	if approvalStatus != nil && approvalStatus.FullyApproved && operation.Status == StatusApproved {
		return w.finalizeRelease(ctx, run)
	}

	run.result.Status = ReleaseStatusPendingApproval
	return cloneTreasuryReleaseResult(run.result)
}

// GetRelease returns the current workflow state.
func (w *TreasuryReleaseWorkflow) GetRelease(_ context.Context, workflowID string) (*TreasuryReleaseResult, error) {
	run, err := w.getRun(workflowID)
	if err != nil {
		return nil, err
	}
	return cloneTreasuryReleaseResult(run.result)
}

// PreviewSettlement returns a side-effect-free settlement admissibility quote
// for a treasury release request before the workflow is executed.
func (w *TreasuryReleaseWorkflow) PreviewSettlement(ctx context.Context, req TreasuryReleaseRequest) (*TreasurySettlementQuote, error) {
	normalized, err := w.normalizeRequest(req)
	if err != nil {
		return nil, err
	}
	return w.config.SettlementRail.Quote(ctx, TreasurySettlementRequest{
		WorkflowID:   normalized.Operation.ID,
		Operation:    normalized.Operation,
		Counterparty: normalized.Operation.Counterparty,
		Beneficiary:  normalized.Beneficiary.Name,
		Jurisdiction: normalized.Jurisdiction,
		ReasonCode:   normalized.ReasonCode,
		Metadata: map[string]string{
			"workflow":     "treasury_release",
			"resource":     normalized.Resource,
			"jurisdiction": normalized.Jurisdiction,
		},
	})
}

func (w *TreasuryReleaseWorkflow) finalizeRelease(ctx context.Context, run *treasuryReleaseRun) (*TreasuryReleaseResult, error) {
	operation, approvalStatus, err := w.refreshOperationState(ctx, run.request.Operation.ID)
	if err != nil {
		return nil, err
	}
	run.result.Operation = operation
	run.result.ApprovalStatus = approvalStatus

	if approvalStatus == nil || !approvalStatus.FullyApproved {
		return nil, fmt.Errorf("%w: workflow %s is not fully approved", ErrInsufficientApproval, run.request.Operation.ID)
	}

	executeReceipt, err := w.evaluateStage(ctx, run.request, run.result.Screening, "execute", "approved", run.result.RequestReceipt.ContentHash, approvalStatus)
	if err != nil {
		return nil, err
	}
	if executeReceipt.Decision != policy.Allow.String() {
		run.result.Status = ReleaseStatusRejected
		run.result.RejectionReason = "execution stage denied by policy"
		run.result.ExecuteReceipt = cloneSignedPolicyReceipt(executeReceipt)
		run.result.UpdatedAt = time.Now().UTC()
		_ = w.recordRejectionEvent(ctx, run.request, run.result, run.result.RejectionReason)
		cloned, cloneErr := cloneTreasuryReleaseResult(run.result)
		if cloneErr != nil {
			return nil, cloneErr
		}
		return cloned, fmt.Errorf("%w: %s", ErrPolicyDenied, executeReceipt.Decision)
	}

	executionReceiptChain, err := policy.BuildPolicyReceiptChain(ctx, []*policy.SignedPolicyReceipt{
		run.result.RequestReceipt,
		executeReceipt,
	})
	if err != nil {
		return nil, fmt.Errorf("finance/release_workflow: build policy receipt chain: %w", err)
	}

	sealResp, err := w.config.Sealer.CreateSeal(ctx, w.buildSealRequest(run.request, run.result, executeReceipt, executionReceiptChain))
	if err != nil {
		return nil, fmt.Errorf("finance/release_workflow: create seal: %w", err)
	}

	executionSeal := w.buildExecutionSeal(run.request.Operation.ID, executeReceipt, sealResp)
	settlementReceipt, err := w.evaluateStage(ctx, run.request, run.result.Screening, "settlement", "approved", executeReceipt.ContentHash, approvalStatus)
	if err != nil {
		return nil, err
	}
	if settlementReceipt.Decision != policy.Allow.String() {
		run.result.Status = ReleaseStatusRejected
		run.result.RejectionReason = "settlement stage denied by policy"
		run.result.ExecuteReceipt = cloneSignedPolicyReceipt(executeReceipt)
		run.result.SettlementReceipt = cloneSignedPolicyReceipt(settlementReceipt)
		run.result.UpdatedAt = time.Now().UTC()
		_ = w.recordRejectionEvent(ctx, run.request, run.result, run.result.RejectionReason)
		cloned, cloneErr := cloneTreasuryReleaseResult(run.result)
		if cloneErr != nil {
			return nil, cloneErr
		}
		return cloned, fmt.Errorf("%w: %s", ErrSettlementDenied, settlementReceipt.Decision)
	}

	settlement, err := w.config.SettlementRail.Settle(ctx, TreasurySettlementRequest{
		WorkflowID:      run.request.Operation.ID,
		Operation:       run.request.Operation,
		Counterparty:    run.request.Operation.Counterparty,
		Beneficiary:     run.request.Beneficiary.Name,
		Jurisdiction:    run.request.Jurisdiction,
		ReasonCode:      run.request.ReasonCode,
		PolicyReceipt:   settlementReceipt,
		ExecutionSealID: executionSeal.SealID,
		Metadata: map[string]string{
			"workflow":     "treasury_release",
			"resource":     run.request.Resource,
			"jurisdiction": run.request.Jurisdiction,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("finance/release_workflow: execute settlement: %w", err)
	}

	receiptChain, err := policy.BuildPolicyReceiptChain(ctx, []*policy.SignedPolicyReceipt{
		run.result.RequestReceipt,
		executeReceipt,
		settlementReceipt,
	})
	if err != nil {
		return nil, fmt.Errorf("finance/release_workflow: build final policy receipt chain: %w", err)
	}

	ledger, soxPackage, err := w.buildControlLedger(ctx, run.request, run.result, executeReceipt, settlementReceipt, settlement, receiptChain, executionSeal)
	if err != nil {
		return nil, err
	}

	if err := w.config.LedgerStore.Save(ctx, ledger); err != nil {
		return nil, fmt.Errorf("finance/release_workflow: save control ledger: %w", err)
	}

	portablePkg, err := evidence.PackagePortableControlLedger(ledger, w.config.IncludeVerificationKeys)
	if err != nil {
		return nil, fmt.Errorf("finance/release_workflow: package control ledger: %w", err)
	}
	for _, anchor := range w.config.TrustAnchors {
		portablePkg.AddTrustAnchor(anchor)
	}
	if err := w.signAndAnchorPackage(ctx, portablePkg); err != nil {
		return nil, err
	}
	if err := evidence.VerifyPortableControlLedgerPackage(portablePkg); err != nil {
		return nil, fmt.Errorf("finance/release_workflow: verify portable package: %w", err)
	}

	run.result.Status = ReleaseStatusCompleted
	run.result.ExecuteReceipt = cloneSignedPolicyReceipt(executeReceipt)
	run.result.SettlementReceipt = cloneSignedPolicyReceipt(settlementReceipt)
	run.result.ReceiptChain = clonePolicyReceiptChain(receiptChain)
	run.result.ExecutionSeal = executionSeal
	run.result.Settlement = cloneValueSettlement(settlement)
	run.result.ControlLedger = ledger
	run.result.PortablePackage = portablePkg
	run.result.SOXPackage = soxPackage
	run.result.UpdatedAt = time.Now().UTC()

	if err := w.recordSettlementEvent(ctx, run.request, run.result); err != nil {
		return nil, err
	}
	if err := w.recordCompletionEvent(ctx, run.request, run.result); err != nil {
		return nil, err
	}

	return cloneTreasuryReleaseResult(run.result)
}

func (w *TreasuryReleaseWorkflow) buildControlLedger(
	ctx context.Context,
	req TreasuryReleaseRequest,
	current *TreasuryReleaseResult,
	executeReceipt *policy.SignedPolicyReceipt,
	settlementReceipt *policy.SignedPolicyReceipt,
	settlement *evidence.ValueSettlementEvidence,
	receiptChain *policy.PolicyReceiptChain,
	executionSeal *evidence.Seal,
) (*evidence.ControlLedger, *SOXEvidencePackage, error) {
	ledger := evidence.NewControlLedger(w.config.Framework)
	ledger.Bundle.ID = req.Operation.ID + "-ledger"
	ledger.WithMetadata("workflow", "treasury_release")
	ledger.WithMetadata("resource", req.Resource)
	ledger.WithMetadata("jurisdiction", req.Jurisdiction)
	ledger.WithMetadata("counterparty", req.Operation.Counterparty)
	ledger.WithMetadata("receipt_chain_hash", receiptChain.ChainHash)
	ledger.WithMetadata("settlement_provider_id", settlement.Metadata["provider_id"])
	ledger.WithMetadata("settlement_corridor_id", settlement.Metadata["corridor_id"])

	passport, err := evidence.NewAgentPassportEvidence(req.Identity)
	if err != nil {
		return nil, nil, fmt.Errorf("finance/release_workflow: create passport evidence: %w", err)
	}
	requestReceiptEvidence, err := evidence.NewPolicyReceiptEvidence(current.RequestReceipt)
	if err != nil {
		return nil, nil, fmt.Errorf("finance/release_workflow: create request receipt evidence: %w", err)
	}
	executeReceiptEvidence, err := evidence.NewPolicyReceiptEvidence(executeReceipt)
	if err != nil {
		return nil, nil, fmt.Errorf("finance/release_workflow: create execute receipt evidence: %w", err)
	}
	settlementReceiptEvidence, err := evidence.NewPolicyReceiptEvidence(settlementReceipt)
	if err != nil {
		return nil, nil, fmt.Errorf("finance/release_workflow: create settlement receipt evidence: %w", err)
	}
	traceLink, err := evidence.NewTraceLink(req.Identity, executeReceipt, *executionSeal, "treasury release execution trace")
	if err != nil {
		return nil, nil, fmt.Errorf("finance/release_workflow: create trace link: %w", err)
	}

	screeningRecordID := req.Operation.ID + "-screening"
	requestRecordID := req.Operation.ID + "-request"
	approvalRecordID := req.Operation.ID + "-approval"
	policyRecordID := req.Operation.ID + "-policy"
	settlementRecordID := req.Operation.ID + "-settlement"
	sealRecordID := req.Operation.ID + "-seal"
	soxRecordID := req.Operation.ID + "-sox"
	approvalDetailRecordIDs := make([]string, 0, len(current.ApprovalEvidence))
	approvalAttestationIDs := make([]string, 0, len(current.ApprovalEvidence))
	approvalReceiptIDs := make([]string, 0, len(current.ApprovalEvidence))
	approvalTraceLinkIDs := make([]string, 0, len(current.ApprovalEvidence))
	authenticatedApprovals := 0

	ledger.AddRecord(evidence.Record{
		ID:        screeningRecordID,
		Type:      "audit",
		Action:    "finance.treasury.screened",
		Actor:     req.Identity.AgentID(),
		Timestamp: current.Screening.Timestamp.UTC().Format(time.RFC3339Nano),
		Data: map[string]string{
			"screening_seal_id": current.Screening.SealID,
			"risk_score":        fmt.Sprintf("%d", current.Screening.RiskScore),
			"sanctions_status":  screeningStatusValue(current.Screening),
			"transaction_id":    current.Screening.TransactionID,
		},
	})
	ledger.AddRecord(evidence.Record{
		ID:        requestRecordID,
		Type:      "governance",
		Action:    "finance.treasury.release_requested",
		Actor:     req.Identity.AgentID(),
		Timestamp: current.RequestReceipt.EvaluatedAt.UTC().Format(time.RFC3339Nano),
		Data: map[string]string{
			"policy_receipt_id": current.RequestReceipt.ID,
			"request_id":        current.RequestReceipt.RequestID,
			"amount":            fmt.Sprintf("%.2f", req.Operation.Amount),
			"currency":          req.Operation.Currency,
			"counterparty":      req.Operation.Counterparty,
			"resource":          req.Resource,
		},
	})
	ledger.AddRecord(evidence.Record{
		ID:        approvalRecordID,
		Type:      "audit",
		Action:    "finance.treasury.release_approved",
		Actor:     req.Identity.AgentID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Data: map[string]string{
			"approval_count":     fmt.Sprintf("%d", current.ApprovalStatus.CurrentApprovals),
			"required_approvals": fmt.Sprintf("%d", current.ApprovalStatus.RequiredApprovals),
			"workflow_status":    string(current.Operation.Status),
		},
	})
	ledger.AddRecord(evidence.Record{
		ID:        policyRecordID,
		Type:      "governance",
		Action:    "finance.treasury.execution_authorized",
		Actor:     req.Identity.AgentID(),
		Timestamp: executeReceipt.EvaluatedAt.UTC().Format(time.RFC3339Nano),
		Data: map[string]string{
			"policy_receipt_id":   executeReceipt.ID,
			"receipt_chain_id":    receiptChain.ID,
			"receipt_chain_hash":  receiptChain.ChainHash,
			"previous_receipt_id": current.RequestReceipt.ID,
		},
	})
	ledger.AddRecord(evidence.Record{
		ID:        settlementRecordID,
		Type:      "transaction",
		Action:    "finance.treasury.settlement_committed",
		Actor:     req.Identity.AgentID(),
		Timestamp: settlement.SettledAt,
		Data: map[string]string{
			"settlement_id":       settlement.SettlementID,
			"status":              settlement.Status,
			"tx_hash":             settlement.TxHash,
			"network":             settlement.Network,
			"provider_id":         settlement.Metadata["provider_id"],
			"corridor_id":         settlement.Metadata["corridor_id"],
			"policy_receipt_id":   settlementReceipt.ID,
			"policy_receipt_hash": settlementReceipt.ContentHash,
			"seal_id":             executionSeal.SealID,
		},
	})
	ledger.AddRecord(evidence.Record{
		ID:          sealRecordID,
		Type:        "verification",
		Action:      "finance.treasury.execution_sealed",
		Actor:       req.Identity.AgentID(),
		Timestamp:   executionSeal.Timestamp,
		BlockHeight: executionSeal.BlockHeight,
		Data: map[string]string{
			"seal_id":     executionSeal.SealID,
			"output_hash": executionSeal.OutputHash,
			"workflow_id": req.Operation.ID,
		},
	})

	ledger.AddAgentPassport(passport)
	ledger.AddPolicyReceipt(requestReceiptEvidence)
	ledger.AddPolicyReceipt(executeReceiptEvidence)
	ledger.AddPolicyReceipt(settlementReceiptEvidence)
	ledger.AddSeal(*executionSeal)
	if err := ledger.AddValueSettlement(*settlement); err != nil {
		return nil, nil, fmt.Errorf("finance/release_workflow: add value settlement evidence: %w", err)
	}
	ledger.AddTraceLink(traceLink)

	for idx, approvalEvidence := range current.ApprovalEvidence {
		approvalRecordID := fmt.Sprintf("%s-approval-%02d", req.Operation.ID, idx+1)
		recordActor := approvalEvidence.Approver
		recordTimestamp := approvalEvidence.AuthorizedAt.UTC()
		if approvalEntry, ok := findApprovalEntry(current.ApprovalStatus, approvalEvidence.Approver, idx); ok && !approvalEntry.Timestamp.IsZero() {
			recordTimestamp = approvalEntry.Timestamp.UTC()
		}
		if recordTimestamp.IsZero() {
			recordTimestamp = time.Now().UTC()
		}
		recordData := map[string]string{
			"approver": approvalEvidence.Approver,
		}
		if strings.TrimSpace(approvalEvidence.Comment) != "" {
			recordData["comment"] = strings.TrimSpace(approvalEvidence.Comment)
		}
		for key, value := range cloneStringMap(approvalEvidence.Metadata) {
			if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
				recordData[key] = value
			}
		}

		if approvalEvidence.ActorIdentity != nil {
			recordActor = approvalEvidence.ActorIdentity.AgentID()
			recordData["approver_did"] = approvalEvidence.ActorIdentity.AgentID()
			recordData["approver_issuer"] = approvalEvidence.ActorIdentity.Issuer
			passportEvidence, err := evidence.NewAgentPassportEvidence(approvalEvidence.ActorIdentity)
			if err != nil {
				return nil, nil, fmt.Errorf("finance/release_workflow: create approver passport evidence: %w", err)
			}
			ledger.AddAgentPassport(passportEvidence)
			authenticatedApprovals++
		}
		if approvalEvidence.PolicyReceipt != nil {
			recordData["approval_policy_receipt_id"] = approvalEvidence.PolicyReceipt.ID
			recordData["approval_policy_signer"] = approvalEvidence.PolicyReceipt.Signer
			receiptEvidence, err := evidence.NewPolicyReceiptEvidence(approvalEvidence.PolicyReceipt)
			if err != nil {
				return nil, nil, fmt.Errorf("finance/release_workflow: create approval policy receipt evidence: %w", err)
			}
			ledger.AddPolicyReceipt(receiptEvidence)
			approvalReceiptIDs = append(approvalReceiptIDs, approvalEvidence.PolicyReceipt.ID)

			if approvalEvidence.ActorIdentity != nil {
				approvalTraceLink, err := evidence.NewTraceLink(approvalEvidence.ActorIdentity, approvalEvidence.PolicyReceipt, *executionSeal, "treasury release approval trace")
				if err != nil {
					return nil, nil, fmt.Errorf("finance/release_workflow: create approval trace link: %w", err)
				}
				ledger.AddTraceLink(approvalTraceLink)
				approvalTraceLinkIDs = append(approvalTraceLinkIDs, approvalTraceLink.ID)
				recordData["approval_trace_link_id"] = approvalTraceLink.ID
			}
		}

		ledger.AddRecord(evidence.Record{
			ID:        approvalRecordID,
			Type:      "governance",
			Action:    "finance.treasury.approval_authenticated",
			Actor:     recordActor,
			Timestamp: recordTimestamp.Format(time.RFC3339Nano),
			Data:      recordData,
		})
		approvalDetailRecordIDs = append(approvalDetailRecordIDs, approvalRecordID)

		if approvalEvidence.ActorIdentity != nil && approvalEvidence.PolicyReceipt != nil {
			approvalAttestation, err := evidence.NewApproverAttestationEvidence(
				approvalEvidence.ActorIdentity,
				approvalEvidence.PolicyReceipt,
				approvalRecordID,
				recordData["approval_trace_link_id"],
				executionSeal.SealID,
				recordTimestamp,
				approvalEvidence.Comment,
				approvalEvidence.Metadata,
			)
			if err != nil {
				return nil, nil, fmt.Errorf("finance/release_workflow: create approver attestation: %w", err)
			}
			if err := ledger.AddApproverAttestation(approvalAttestation); err != nil {
				return nil, nil, fmt.Errorf("finance/release_workflow: add approver attestation: %w", err)
			}
			approvalAttestationIDs = append(approvalAttestationIDs, approvalAttestation.ID)
		}
	}

	soxPackage, err := w.config.AuditTrail.GenerateSOXEvidence(ctx, time.Now().UTC().Format("2006-01"))
	if err != nil {
		return nil, nil, fmt.Errorf("finance/release_workflow: generate sox evidence: %w", err)
	}
	ledger.AddRecord(evidence.Record{
		ID:        soxRecordID,
		Type:      "audit",
		Action:    "finance.treasury.sox_evidence_generated",
		Actor:     req.Identity.AgentID(),
		Timestamp: soxPackage.GeneratedAt.UTC().Format(time.RFC3339Nano),
		Data: map[string]string{
			"seal_id":         soxPackage.SealID,
			"period":          soxPackage.Period,
			"event_count":     fmt.Sprintf("%d", soxPackage.EventCount),
			"integrity_valid": fmt.Sprintf("%t", soxPackage.IntegrityValid),
		},
	})

	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "TREASURY-ID-01",
		ControlName: "Accountable Agent Passport",
		Description: "Treasury release carries sponsor-of-record, liability, and jurisdiction-bound identity evidence.",
		Status:      evidence.ControlSatisfied,
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs: []string{requestRecordID},
		},
		Metadata: map[string]string{
			"owner":                   "treasury_identity",
			"approver_passport_count": fmt.Sprintf("%d", maxInt(ledger.Summary.TotalPassports-1, 0)),
		},
	}); err != nil {
		return nil, nil, err
	}
	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "TREASURY-POL-01",
		ControlName: "Policy-Gated Treasury Authorization",
		Description: "Request and execute stages both emit signed policy receipts with a verifiable chain hash.",
		Status:      evidence.ControlSatisfied,
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs:              append([]string{requestRecordID, policyRecordID, approvalRecordID}, approvalDetailRecordIDs...),
			ApproverAttestationIDs: approvalAttestationIDs,
			ValueSettlementIDs:     []string{settlement.ID},
			PolicyReceiptIDs:       append([]string{current.RequestReceipt.ID, executeReceipt.ID, settlementReceipt.ID}, approvalReceiptIDs...),
			TraceLinkIDs:           append([]string{traceLink.ID}, approvalTraceLinkIDs...),
		},
		Metadata: map[string]string{
			"chain_hash":                   receiptChain.ChainHash,
			"authenticated_approval_count": fmt.Sprintf("%d", authenticatedApprovals),
		},
	}); err != nil {
		return nil, nil, err
	}
	if authenticatedApprovals > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "TREASURY-APP-01",
			ControlName: "Authenticated Multi-Party Approval",
			Description: "Approver passports and approval policy receipts are carried into the final treasury release evidence chain.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs:              append([]string{approvalRecordID}, approvalDetailRecordIDs...),
				ApproverAttestationIDs: approvalAttestationIDs,
				PolicyReceiptIDs:       approvalReceiptIDs,
				TraceLinkIDs:           approvalTraceLinkIDs,
			},
			Metadata: map[string]string{
				"authenticated_approval_count": fmt.Sprintf("%d", authenticatedApprovals),
			},
		}); err != nil {
			return nil, nil, err
		}
	}
	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "TREASURY-AUD-01",
		ControlName: "Attested Execution and Auditor Package",
		Description: "Execution is sealed, ledgered, and packaged into a portable auditor artifact.",
		Status:      evidence.ControlSatisfied,
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs:    []string{screeningRecordID, sealRecordID, soxRecordID},
			SealIDs:      []string{executionSeal.SealID},
			TraceLinkIDs: []string{traceLink.ID},
		},
		Metadata: map[string]string{
			"framework": w.config.Framework,
		},
	}); err != nil {
		return nil, nil, err
	}
	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "TREASURY-SET-01",
		ControlName: "Policy-Bound Treasury Settlement",
		Description: "Settlement is authorized separately, constrained by the settlement rail, and linked to the sealed execution outcome.",
		Status:      evidence.ControlSatisfied,
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs:          []string{settlementRecordID},
			ValueSettlementIDs: []string{settlement.ID},
			PolicyReceiptIDs:   []string{settlementReceipt.ID},
			SealIDs:            []string{executionSeal.SealID},
		},
		Metadata: map[string]string{
			"network":            settlement.Network,
			"token_denomination": settlement.TokenDenomination,
			"reason_code":        settlement.ReasonCode,
			"provider_id":        settlement.Metadata["provider_id"],
			"corridor_id":        settlement.Metadata["corridor_id"],
		},
	}); err != nil {
		return nil, nil, err
	}

	if err := ledger.Finalize(""); err != nil {
		return nil, nil, fmt.Errorf("finance/release_workflow: finalize control ledger: %w", err)
	}
	if err := ledger.Validate(); err != nil {
		return nil, nil, fmt.Errorf("finance/release_workflow: validate control ledger: %w", err)
	}

	return ledger, soxPackage, nil
}

func (w *TreasuryReleaseWorkflow) signAndAnchorPackage(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error {
	if pkg == nil {
		return fmt.Errorf("finance/release_workflow: nil portable package")
	}
	if w.config.PackageSignerFunc != nil {
		if err := w.config.PackageSignerFunc(ctx, pkg); err != nil {
			return fmt.Errorf("finance/release_workflow: external package signing failed: %w", err)
		}
	} else if len(w.config.PackageSigningKey) == ed25519.PrivateKeySize {
		if err := pkg.SignEd25519(w.config.PackageSigningKey, w.config.PackageSigner); err != nil {
			return fmt.Errorf("finance/release_workflow: package signing failed: %w", err)
		}
	}
	if w.config.PackageAnchorer != nil {
		if err := w.config.PackageAnchorer(ctx, pkg); err != nil {
			return fmt.Errorf("finance/release_workflow: package anchoring failed: %w", err)
		}
	}
	return nil
}

func (w *TreasuryReleaseWorkflow) evaluateStage(
	ctx context.Context,
	req TreasuryReleaseRequest,
	screening *ScreeningResult,
	stage string,
	approvalState string,
	previousReceiptHash string,
	approvalStatus *ApprovalStatus,
) (*policy.SignedPolicyReceipt, error) {
	evalReq := &policy.EvaluationRequest{
		Actor:    req.Identity.AgentID(),
		Action:   treasuryReleaseActionForStage(stage),
		Resource: req.Resource,
		Context: map[string]string{
			"sector":       "finance",
			"jurisdiction": req.Jurisdiction,
		},
		Metadata: w.policyMetadata(req, screening, stage, approvalState, approvalStatus),
	}

	_, receipt, err := w.config.PolicyEngine.EvaluateAndSign(ctx, evalReq, w.config.PolicySignerKey, w.config.PolicySigner, previousReceiptHash)
	if err != nil {
		return nil, fmt.Errorf("finance/release_workflow: evaluate %s stage: %w", stage, err)
	}
	if err := policy.VerifySignedPolicyReceipt(receipt, &w.config.PolicySignerKey.PublicKey); err != nil {
		return nil, fmt.Errorf("finance/release_workflow: verify %s stage receipt: %w", stage, err)
	}
	return receipt, nil
}

func (w *TreasuryReleaseWorkflow) buildSealRequest(
	req TreasuryReleaseRequest,
	current *TreasuryReleaseResult,
	executeReceipt *policy.SignedPolicyReceipt,
	receiptChain *policy.PolicyReceiptChain,
) sdk.SealRequest {
	modelHash := sha256.Sum256([]byte("finance/treasury_release/v1"))
	inputHash := sha256.Sum256(mustJSON(struct {
		WorkflowID string             `json:"workflow_id"`
		Operation  *TreasuryOperation `json:"operation"`
		Screening  *ScreeningResult   `json:"screening"`
		RequestID  string             `json:"request_receipt_id"`
	}{
		WorkflowID: req.Operation.ID,
		Operation:  current.Operation,
		Screening:  current.Screening,
		RequestID:  current.RequestReceipt.ID,
	}))
	outputHash := sha256.Sum256(mustJSON(struct {
		WorkflowID       string `json:"workflow_id"`
		ExecuteReceipt   string `json:"execute_receipt_id"`
		ReceiptChainHash string `json:"receipt_chain_hash"`
		ApprovalCount    int    `json:"approval_count"`
	}{
		WorkflowID:       req.Operation.ID,
		ExecuteReceipt:   executeReceipt.ID,
		ReceiptChainHash: receiptChain.ChainHash,
		ApprovalCount:    current.ApprovalStatus.CurrentApprovals,
	}))

	return sdk.SealRequest{
		ModelHash:  modelHash[:],
		InputHash:  inputHash[:],
		OutputHash: outputHash[:],
		Purpose:    "treasury_release",
		Metadata: map[string]string{
			"workflow":           "treasury_release",
			"workflow_id":        req.Operation.ID,
			"receipt_chain_hash": receiptChain.ChainHash,
			"request_receipt_id": current.RequestReceipt.ID,
			"execute_receipt_id": executeReceipt.ID,
			"resource":           req.Resource,
			"jurisdiction":       req.Jurisdiction,
			"counterparty":       req.Operation.Counterparty,
		},
	}
}

func (w *TreasuryReleaseWorkflow) buildExecutionSeal(workflowID string, executeReceipt *policy.SignedPolicyReceipt, sealResp *sdk.SealResponse) *evidence.Seal {
	timestamp := time.Now().UTC()
	if sealResp != nil && !sealResp.Timestamp.IsZero() {
		timestamp = sealResp.Timestamp.UTC()
	}
	return &evidence.Seal{
		SealID:         safeString(sealResp, func(in *sdk.SealResponse) string { return in.SealID }),
		JobID:          workflowID,
		OutputHash:     executeReceipt.ContentHash,
		ValidatorCount: safeInt(sealResp, func(in *sdk.SealResponse) int { return len(in.ValidatorSet) }),
		BlockHeight:    safeInt64(sealResp, func(in *sdk.SealResponse) int64 { return in.BlockHeight }),
		Timestamp:      timestamp.Format(time.RFC3339Nano),
	}
}

func (w *TreasuryReleaseWorkflow) buildScreeningTransaction(req TreasuryReleaseRequest) ScreeningTransaction {
	originator := req.Originator
	if strings.TrimSpace(originator.Name) == "" {
		originator = ScreeningEntity{
			Name:       req.Operation.Initiator,
			EntityType: "organization",
			Country:    req.Jurisdiction,
			Identifiers: map[string]string{
				"agent_did": req.Identity.AgentID(),
			},
		}
	}
	beneficiary := req.Beneficiary
	if strings.TrimSpace(beneficiary.Name) == "" {
		beneficiary = ScreeningEntity{
			Name:       req.Operation.Counterparty,
			EntityType: "organization",
			Country:    req.Jurisdiction,
		}
	}

	return ScreeningTransaction{
		TransactionID:      req.Operation.ID,
		Amount:             req.Operation.Amount,
		Currency:           req.Operation.Currency,
		Originator:         originator,
		Beneficiary:        beneficiary,
		OriginatorCountry:  originator.Country,
		BeneficiaryCountry: beneficiary.Country,
		Purpose:            req.Operation.Description,
	}
}

func (w *TreasuryReleaseWorkflow) policyMetadata(
	req TreasuryReleaseRequest,
	screening *ScreeningResult,
	stage string,
	approvalState string,
	approvalStatus *ApprovalStatus,
) map[string]string {
	sponsorOfRecord := ""
	liabilityPresent := "false"
	if req.Identity.Liability != nil {
		sponsorOfRecord = req.Identity.Liability.SponsorOfRecord
		liabilityPresent = "true"
	}
	approvalCount := 0
	requiredApprovals := 0
	if approvalStatus != nil {
		approvalCount = approvalStatus.CurrentApprovals
		requiredApprovals = approvalStatus.RequiredApprovals
	}

	metadata := cloneStringMap(req.Metadata)
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["workflow"] = "treasury_release"
	metadata["workflow_id"] = req.Operation.ID
	metadata["release_stage"] = stage
	metadata["amount"] = fmt.Sprintf("%.2f", req.Operation.Amount)
	metadata["currency"] = req.Operation.Currency
	metadata["transaction_type"] = string(req.Operation.Type)
	metadata["reason_code"] = req.ReasonCode
	metadata["approval_state"] = approvalState
	metadata["approval_count"] = fmt.Sprintf("%d", approvalCount)
	metadata["required_approvals"] = fmt.Sprintf("%d", requiredApprovals)
	metadata["tool_allowed"] = fmt.Sprintf("%t", req.Identity.AllowsTool(req.Tool))
	metadata["capability_present"] = fmt.Sprintf("%t", req.Identity.HasCapability(req.Tool))
	metadata["jurisdiction_allowed"] = fmt.Sprintf("%t", req.Identity.HasJurisdiction(req.Jurisdiction))
	metadata["sponsor_of_record_present"] = fmt.Sprintf("%t", strings.TrimSpace(sponsorOfRecord) != "")
	metadata["liability_profile_present"] = liabilityPresent
	metadata["sanctions_status"] = screeningStatusValue(screening)
	metadata["resource"] = req.Resource
	return metadata
}

func (w *TreasuryReleaseWorkflow) normalizeRequest(req TreasuryReleaseRequest) (TreasuryReleaseRequest, error) {
	if req.Identity == nil {
		return TreasuryReleaseRequest{}, fmt.Errorf("finance/release_workflow: identity is required")
	}
	if err := agent.VerifyIdentity(req.Identity); err != nil {
		return TreasuryReleaseRequest{}, fmt.Errorf("finance/release_workflow: invalid identity: %w", err)
	}
	if req.Operation == nil {
		return TreasuryReleaseRequest{}, fmt.Errorf("finance/release_workflow: operation is required")
	}

	normalized := req
	normalized.Operation = cloneTreasuryOperation(req.Operation)
	if normalized.Operation.ID == "" {
		normalized.Operation.ID = fmt.Sprintf("trl-%d", time.Now().UnixNano())
	}
	if normalized.Operation.Type == "" {
		normalized.Operation.Type = OpPayment
	}
	if strings.TrimSpace(normalized.Operation.Initiator) == "" {
		normalized.Operation.Initiator = req.Identity.AgentID()
	}
	if strings.TrimSpace(normalized.Operation.Counterparty) == "" && strings.TrimSpace(normalized.Beneficiary.Name) != "" {
		normalized.Operation.Counterparty = normalized.Beneficiary.Name
	}
	if strings.TrimSpace(normalized.Resource) == "" {
		normalized.Resource = "acct:treasury-main"
	}
	if strings.TrimSpace(normalized.Tool) == "" {
		normalized.Tool = treasuryReleaseTool
	}
	if strings.TrimSpace(normalized.Jurisdiction) == "" {
		if len(req.Identity.JurisdictionTags) > 0 {
			normalized.Jurisdiction = req.Identity.JurisdictionTags[0]
		} else {
			normalized.Jurisdiction = "global"
		}
	}
	if normalized.Operation.Metadata == nil {
		normalized.Operation.Metadata = make(map[string]string)
	}
	normalized.Operation.Metadata["workflow"] = "treasury_release"
	normalized.Operation.Metadata["resource"] = normalized.Resource
	normalized.Operation.Metadata["jurisdiction"] = normalized.Jurisdiction

	if strings.TrimSpace(normalized.Beneficiary.Name) == "" {
		normalized.Beneficiary = ScreeningEntity{
			Name:       normalized.Operation.Counterparty,
			EntityType: "organization",
			Country:    normalized.Jurisdiction,
		}
	}
	if strings.TrimSpace(normalized.Beneficiary.Name) == "" {
		return TreasuryReleaseRequest{}, fmt.Errorf("finance/release_workflow: beneficiary or counterparty is required")
	}
	if strings.TrimSpace(normalized.ReasonCode) == "" {
		normalized.ReasonCode = "treasury_release"
	}
	normalized.Operation.Metadata["reason_code"] = normalized.ReasonCode

	return normalized, nil
}

func (w *TreasuryReleaseWorkflow) refreshOperationState(ctx context.Context, workflowID string) (*TreasuryOperation, *ApprovalStatus, error) {
	operation, err := w.config.Controller.GetOperation(ctx, workflowID)
	if err != nil {
		return nil, nil, fmt.Errorf("finance/release_workflow: get operation: %w", err)
	}
	approvalStatus, err := w.config.Controller.GetApprovalStatus(ctx, workflowID)
	if err != nil {
		return nil, nil, fmt.Errorf("finance/release_workflow: get approval status: %w", err)
	}
	return cloneTreasuryOperation(operation), cloneApprovalStatus(approvalStatus), nil
}

func (w *TreasuryReleaseWorkflow) recordScreeningEvent(ctx context.Context, req TreasuryReleaseRequest, screening *ScreeningResult) error {
	return w.config.AuditTrail.RecordFinancialEvent(ctx, &FinancialEvent{
		Type:        EventScreening,
		Amount:      req.Operation.Amount,
		Currency:    req.Operation.Currency,
		Timestamp:   screening.Timestamp.UTC(),
		Regulation:  "SOX",
		Description: "Treasury release sanctions screening completed",
		SealID:      screening.SealID,
		Parties: []FinancialParty{
			{Name: req.Operation.Initiator, Role: "originator", Identifier: req.Identity.AgentID(), Jurisdiction: req.Jurisdiction},
			{Name: req.Operation.Counterparty, Role: "beneficiary", Identifier: req.Operation.Counterparty, Jurisdiction: req.Jurisdiction},
		},
		Evidence: []FinancialEvidenceItem{{
			Type:        "screening_result",
			Description: "Sanctions screening result",
			DataHash:    hashFinanceEvidence(screening),
			SealID:      screening.SealID,
		}},
	})
}

func (w *TreasuryReleaseWorkflow) recordInitiationEvent(ctx context.Context, req TreasuryReleaseRequest, result *TreasuryReleaseResult) error {
	return w.config.AuditTrail.RecordFinancialEvent(ctx, &FinancialEvent{
		Type:        EventTransaction,
		Amount:      req.Operation.Amount,
		Currency:    req.Operation.Currency,
		Timestamp:   time.Now().UTC(),
		Regulation:  "SOX",
		Description: "Treasury release request accepted into workflow",
		Evidence: []FinancialEvidenceItem{{
			Type:        "policy_receipt",
			Description: "Request-stage signed policy receipt",
			DataHash:    result.RequestReceipt.ContentHash,
		}},
		Parties: []FinancialParty{
			{Name: req.Operation.Initiator, Role: "originator", Identifier: req.Identity.AgentID(), Jurisdiction: req.Jurisdiction},
			{Name: req.Operation.Counterparty, Role: "counterparty", Identifier: req.Operation.Counterparty, Jurisdiction: req.Jurisdiction},
		},
	})
}

func (w *TreasuryReleaseWorkflow) recordApprovalEvent(ctx context.Context, req TreasuryReleaseRequest, result *TreasuryReleaseResult, approval TreasuryReleaseApprovalRequest) error {
	description := "Treasury release approval recorded"
	if strings.TrimSpace(approval.Comment) != "" {
		description += ": " + strings.TrimSpace(approval.Comment)
	}

	approverIdentifier := approval.Approver
	evidenceItems := []FinancialEvidenceItem{{
		Type:        "approval_status",
		Description: "Current approval status after approver action",
		DataHash:    hashFinanceEvidence(result.ApprovalStatus),
	}}
	if approval.ActorIdentity != nil {
		approverIdentifier = approval.ActorIdentity.AgentID()
		evidenceItems = append(evidenceItems, FinancialEvidenceItem{
			Type:        "approver_passport",
			Description: "Authenticated approver passport carried into the treasury release workflow",
			DataHash:    hashFinanceEvidence(approval.ActorIdentity),
		})
	}
	if approval.PolicyReceipt != nil {
		evidenceItems = append(evidenceItems, FinancialEvidenceItem{
			Type:        "approval_policy_receipt",
			Description: "Approval-stage policy receipt authorizing the approver action",
			DataHash:    approval.PolicyReceipt.ContentHash,
		})
	}

	return w.config.AuditTrail.RecordFinancialEvent(ctx, &FinancialEvent{
		Type:        EventApproval,
		Amount:      req.Operation.Amount,
		Currency:    req.Operation.Currency,
		Timestamp:   time.Now().UTC(),
		Regulation:  "SOX",
		Description: description,
		Parties: []FinancialParty{
			{Name: approval.Approver, Role: "approver", Identifier: approverIdentifier, Jurisdiction: req.Jurisdiction},
			{Name: req.Operation.Initiator, Role: "originator", Identifier: req.Identity.AgentID(), Jurisdiction: req.Jurisdiction},
		},
		Evidence: evidenceItems,
	})
}

func (w *TreasuryReleaseWorkflow) recordCompletionEvent(ctx context.Context, req TreasuryReleaseRequest, result *TreasuryReleaseResult) error {
	return w.config.AuditTrail.RecordFinancialEvent(ctx, &FinancialEvent{
		Type:        EventTransaction,
		Amount:      req.Operation.Amount,
		Currency:    req.Operation.Currency,
		Timestamp:   time.Now().UTC(),
		Regulation:  "SOX",
		Description: "Treasury release completed with sealed execution and portable auditor package",
		SealID:      result.ExecutionSeal.SealID,
		Parties: []FinancialParty{
			{Name: req.Operation.Initiator, Role: "originator", Identifier: req.Identity.AgentID(), Jurisdiction: req.Jurisdiction},
			{Name: req.Operation.Counterparty, Role: "beneficiary", Identifier: req.Operation.Counterparty, Jurisdiction: req.Jurisdiction},
		},
		Evidence: []FinancialEvidenceItem{
			{
				Type:        "execution_receipt",
				Description: "Execution-stage signed policy receipt",
				DataHash:    result.ExecuteReceipt.ContentHash,
			},
			{
				Type:        "portable_control_ledger_package",
				Description: "Portable auditor package for the treasury release",
				DataHash:    result.PortablePackage.PackageHash,
				SealID:      result.ExecutionSeal.SealID,
			},
		},
	})
}

func (w *TreasuryReleaseWorkflow) recordSettlementEvent(ctx context.Context, req TreasuryReleaseRequest, result *TreasuryReleaseResult) error {
	if result == nil || result.Settlement == nil {
		return nil
	}
	return w.config.AuditTrail.RecordFinancialEvent(ctx, &FinancialEvent{
		Type:       EventSettlement,
		Amount:     result.Settlement.FiatAmount,
		Currency:   result.Settlement.FiatCurrency,
		Timestamp:  time.Now().UTC(),
		Regulation: "SOX",
		Description: fmt.Sprintf(
			"Treasury settlement committed on %s via %s/%s with %s",
			result.Settlement.Network,
			firstNonEmpty(result.Settlement.Metadata["provider_id"], "provider"),
			firstNonEmpty(result.Settlement.Metadata["corridor_id"], "corridor"),
			result.Settlement.TokenDenomination,
		),
		SealID: result.ExecutionSeal.SealID,
		Parties: []FinancialParty{
			{Name: req.Operation.Initiator, Role: "originator", Identifier: req.Identity.AgentID(), Jurisdiction: req.Jurisdiction},
			{Name: req.Operation.Counterparty, Role: "counterparty", Identifier: req.Operation.Counterparty, Jurisdiction: req.Jurisdiction},
			{Name: firstNonEmpty(req.Beneficiary.Name, req.Operation.Counterparty), Role: "beneficiary", Identifier: firstNonEmpty(req.Beneficiary.Name, req.Operation.Counterparty), Jurisdiction: req.Jurisdiction},
		},
		Evidence: []FinancialEvidenceItem{
			{
				Type:        "settlement_receipt",
				Description: "Settlement-stage policy receipt authorizing the value transfer",
				DataHash:    result.Settlement.PolicyReceiptHash,
				SealID:      result.ExecutionSeal.SealID,
			},
			{
				Type:        "settlement_record",
				Description: "Committed value settlement bound to the sealed execution workflow",
				DataHash:    hashFinanceEvidence(result.Settlement),
				SealID:      result.ExecutionSeal.SealID,
			},
			{
				Type:        "settlement_corridor",
				Description: "Configured settlement provider and corridor metadata",
				DataHash:    hashFinanceEvidence(map[string]string{"provider_id": result.Settlement.Metadata["provider_id"], "corridor_id": result.Settlement.Metadata["corridor_id"]}),
				SealID:      result.ExecutionSeal.SealID,
			},
		},
	})
}

func (w *TreasuryReleaseWorkflow) recordRejectionEvent(ctx context.Context, req TreasuryReleaseRequest, result *TreasuryReleaseResult, reason string) error {
	return w.config.AuditTrail.RecordFinancialEvent(ctx, &FinancialEvent{
		Type:        EventException,
		Amount:      req.Operation.Amount,
		Currency:    req.Operation.Currency,
		Timestamp:   time.Now().UTC(),
		Regulation:  "SOX",
		Description: reason,
		Parties: []FinancialParty{
			{Name: req.Operation.Initiator, Role: "originator", Identifier: req.Identity.AgentID(), Jurisdiction: req.Jurisdiction},
			{Name: req.Operation.Counterparty, Role: "beneficiary", Identifier: req.Operation.Counterparty, Jurisdiction: req.Jurisdiction},
		},
		Evidence: []FinancialEvidenceItem{{
			Type:        "policy_receipt",
			Description: "Rejected request-stage policy receipt",
			DataHash:    safeReceiptHash(result.RequestReceipt),
		}},
	})
}

func (w *TreasuryReleaseWorkflow) getRun(workflowID string) (*treasuryReleaseRun, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	run, ok := w.runs[strings.TrimSpace(workflowID)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrReleaseNotFound, workflowID)
	}
	return run, nil
}

func (w *TreasuryReleaseWorkflow) setRun(run *treasuryReleaseRun) {
	if run == nil || run.result == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.runs[run.result.WorkflowID] = run
}

func newTreasuryReleaseWorkflowPolicySet() *policy.PolicySet {
	now := time.Now().UTC()
	return &policy.PolicySet{
		ID:          "finance-treasury-release-workflow-v1",
		Name:        "Finance Treasury Release Workflow",
		Description: "Identity-aware, sanctions-aware, approval-aware policy set for treasury release workflows",
		Priority:    500,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
		Scope: &policy.Scope{
			Sectors: []string{"finance"},
			Actions: []string{treasuryReleaseRequestAction, treasuryReleaseExecuteAction, treasuryReleaseSettlementAction},
		},
		Rules: []policy.Rule{
			policy.NewDenyRule("treasury_release_tool_guard", "agent passport does not authorize treasury release", []policy.Condition{
				{Field: "tool_allowed", Operator: policy.NotEquals, Value: "true"},
			}),
			policy.NewDenyRule("treasury_release_capability_guard", "agent capability missing for treasury release", []policy.Condition{
				{Field: "capability_present", Operator: policy.NotEquals, Value: "true"},
			}),
			policy.NewDenyRule("treasury_release_liability_guard", "liability profile is required", []policy.Condition{
				{Field: "liability_profile_present", Operator: policy.NotEquals, Value: "true"},
			}),
			policy.NewDenyRule("treasury_release_jurisdiction_guard", "jurisdiction is not allowed by passport", []policy.Condition{
				{Field: "jurisdiction_allowed", Operator: policy.NotEquals, Value: "true"},
			}),
			policy.NewDenyRule("treasury_release_sponsor_guard", "sponsor-of-record is required", []policy.Condition{
				{Field: "sponsor_of_record_present", Operator: policy.NotEquals, Value: "true"},
			}),
			policy.NewDenyRule("treasury_release_sanctions_guard", "transaction blocked by sanctions screening", []policy.Condition{
				{Field: "sanctions_status", Operator: policy.Equals, Value: "sanctioned"},
			}),
			policy.NewDenyRule("treasury_release_execute_requires_approval", "execution requires approved treasury workflow", []policy.Condition{
				{Field: "release_stage", Operator: policy.Equals, Value: "execute"},
				{Field: "approval_state", Operator: policy.NotEquals, Value: "approved"},
			}),
			policy.NewDenyRule("treasury_release_settlement_requires_approval", "settlement requires approved treasury workflow", []policy.Condition{
				{Field: "release_stage", Operator: policy.Equals, Value: "settlement"},
				{Field: "approval_state", Operator: policy.NotEquals, Value: "approved"},
			}),
			policy.NewAllowRule("treasury_release_request_allow", []policy.Condition{
				{Field: "release_stage", Operator: policy.Equals, Value: "request"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "sanctions_status", Operator: policy.Equals, Value: "clear"},
			}),
			policy.NewAllowRule("treasury_release_execute_allow", []policy.Condition{
				{Field: "release_stage", Operator: policy.Equals, Value: "execute"},
				{Field: "approval_state", Operator: policy.Equals, Value: "approved"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "sanctions_status", Operator: policy.Equals, Value: "clear"},
			}),
			policy.NewAllowRule("treasury_release_settlement_allow", []policy.Condition{
				{Field: "release_stage", Operator: policy.Equals, Value: "settlement"},
				{Field: "approval_state", Operator: policy.Equals, Value: "approved"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "sanctions_status", Operator: policy.Equals, Value: "clear"},
			}),
		},
	}
}

func treasuryReleaseActionForStage(stage string) string {
	if stage == "execute" {
		return treasuryReleaseExecuteAction
	}
	if stage == "settlement" {
		return treasuryReleaseSettlementAction
	}
	return treasuryReleaseRequestAction
}

func screeningStatusValue(screening *ScreeningResult) string {
	if screening == nil || screening.Clear {
		return "clear"
	}
	return "sanctioned"
}

func normalizeTreasuryReleaseApprovalRequest(req TreasuryReleaseApprovalRequest) (TreasuryReleaseApprovalRequest, error) {
	normalized := req
	normalized.Approver = strings.TrimSpace(req.Approver)
	normalized.Comment = strings.TrimSpace(req.Comment)
	normalized.Metadata = cloneStringMap(req.Metadata)
	if normalized.Metadata == nil {
		normalized.Metadata = make(map[string]string)
	}

	hasActorIdentity := normalized.ActorIdentity != nil
	hasPolicyReceipt := normalized.PolicyReceipt != nil
	if hasActorIdentity != hasPolicyReceipt {
		return TreasuryReleaseApprovalRequest{}, fmt.Errorf("finance/release_workflow: approver identity and approval policy receipt must be provided together")
	}
	if hasActorIdentity {
		if err := agent.VerifyIdentity(normalized.ActorIdentity); err != nil {
			return TreasuryReleaseApprovalRequest{}, fmt.Errorf("finance/release_workflow: invalid approval actor identity: %w", err)
		}
		actorDID := normalized.ActorIdentity.AgentID()
		if normalized.Approver == "" {
			normalized.Approver = actorDID
		}
		if normalized.Approver != actorDID {
			return TreasuryReleaseApprovalRequest{}, fmt.Errorf("finance/release_workflow: approver %q does not match approval actor DID %q", normalized.Approver, actorDID)
		}
		if normalized.PolicyReceipt.Actor != actorDID {
			return TreasuryReleaseApprovalRequest{}, fmt.Errorf("finance/release_workflow: approval policy receipt actor %q does not match approver DID %q", normalized.PolicyReceipt.Actor, actorDID)
		}
		if !strings.EqualFold(normalized.PolicyReceipt.Decision, policy.Allow.String()) {
			return TreasuryReleaseApprovalRequest{}, fmt.Errorf("finance/release_workflow: approval policy receipt decision %q does not authorize the approval", normalized.PolicyReceipt.Decision)
		}
	}
	if normalized.Approver == "" {
		return TreasuryReleaseApprovalRequest{}, fmt.Errorf("finance/release_workflow: approver is required")
	}

	return normalized, nil
}

func buildTreasuryReleaseApprovalEvidence(req TreasuryReleaseApprovalRequest) TreasuryReleaseApprovalEvidence {
	return TreasuryReleaseApprovalEvidence{
		Approver:      req.Approver,
		Comment:       req.Comment,
		ActorIdentity: req.ActorIdentity,
		PolicyReceipt: req.PolicyReceipt,
		Metadata:      cloneStringMap(req.Metadata),
		AuthorizedAt:  time.Now().UTC(),
	}
}

func findApprovalEntry(status *ApprovalStatus, approver string, index int) (ApprovalEntry, bool) {
	if status == nil {
		return ApprovalEntry{}, false
	}
	matches := make([]ApprovalEntry, 0, len(status.Entries))
	for _, entry := range status.Entries {
		if entry.Approver == approver {
			matches = append(matches, entry)
		}
	}
	if len(matches) == 0 {
		return ApprovalEntry{}, false
	}
	if index < len(matches) {
		return matches[index], true
	}
	return matches[len(matches)-1], true
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func hashFinanceEvidence(value any) string {
	return evidence.EvidenceHashHex(mustJSON(value))
}

func mustJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

func cloneTreasuryReleaseResult(in *TreasuryReleaseResult) (*TreasuryReleaseResult, error) {
	if in == nil {
		return nil, nil
	}
	data, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	var out TreasuryReleaseResult
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func cloneTreasuryOperation(in *TreasuryOperation) *TreasuryOperation {
	if in == nil {
		return nil
	}
	out := *in
	if len(in.Approvers) > 0 {
		out.Approvers = make([]ApprovalEntry, len(in.Approvers))
		copy(out.Approvers, in.Approvers)
	}
	out.Metadata = cloneStringMap(in.Metadata)
	return &out
}

func cloneApprovalStatus(in *ApprovalStatus) *ApprovalStatus {
	if in == nil {
		return nil
	}
	out := *in
	if len(in.Entries) > 0 {
		out.Entries = make([]ApprovalEntry, len(in.Entries))
		copy(out.Entries, in.Entries)
	}
	return &out
}

func cloneScreeningResult(in *ScreeningResult) *ScreeningResult {
	if in == nil {
		return nil
	}
	out := *in
	if len(in.Matches) > 0 {
		out.Matches = make([]SanctionsMatch, len(in.Matches))
		copy(out.Matches, in.Matches)
	}
	if len(in.Lists) > 0 {
		out.Lists = make([]SanctionsList, len(in.Lists))
		copy(out.Lists, in.Lists)
	}
	return &out
}

func cloneSignedPolicyReceipt(in *policy.SignedPolicyReceipt) *policy.SignedPolicyReceipt {
	if in == nil {
		return nil
	}
	out := *in
	out.Context = cloneStringMap(in.Context)
	out.Metadata = cloneStringMap(in.Metadata)
	if len(in.MatchedRules) > 0 {
		out.MatchedRules = make([]string, len(in.MatchedRules))
		copy(out.MatchedRules, in.MatchedRules)
	}
	if len(in.RequiredApprovals) > 0 {
		out.RequiredApprovals = make([]policy.PolicyReceiptApprovalRequirement, len(in.RequiredApprovals))
		copy(out.RequiredApprovals, in.RequiredApprovals)
	}
	if len(in.Conditions) > 0 {
		out.Conditions = make([]string, len(in.Conditions))
		copy(out.Conditions, in.Conditions)
	}
	return &out
}

func clonePolicyReceiptChain(in *policy.PolicyReceiptChain) *policy.PolicyReceiptChain {
	if in == nil {
		return nil
	}
	out := *in
	if len(in.Receipts) > 0 {
		out.Receipts = make([]*policy.SignedPolicyReceipt, len(in.Receipts))
		for i, receipt := range in.Receipts {
			out.Receipts[i] = cloneSignedPolicyReceipt(receipt)
		}
	}
	return &out
}

func cloneValueSettlement(in *evidence.ValueSettlementEvidence) *evidence.ValueSettlementEvidence {
	if in == nil {
		return nil
	}
	out := *in
	out.Metadata = cloneStringMap(in.Metadata)
	return &out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func safeString[T any](in *T, getter func(*T) string) string {
	if in == nil {
		return ""
	}
	return getter(in)
}

func safeInt[T any](in *T, getter func(*T) int) int {
	if in == nil {
		return 0
	}
	return getter(in)
}

func safeInt64[T any](in *T, getter func(*T) int64) int64 {
	if in == nil {
		return 0
	}
	return getter(in)
}

func safeReceiptHash(receipt *policy.SignedPolicyReceipt) string {
	if receipt == nil {
		return ""
	}
	return receipt.ContentHash
}
